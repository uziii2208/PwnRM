"""
core.transports — HTTP/HTTPS transport layer (Basic, Cert, SPNEGO, Kerberos, CredSSP)
"""

import ssl, logging
from base64    import b64decode
from struct    import pack, unpack
from random    import randbytes
from urllib.parse import urlparse

from requests           import Session, Request
from urllib3.util       import SKIP_HEADER
from urllib3.exceptions import InsecureRequestWarning
from urllib3            import disable_warnings
disable_warnings(category=InsecureRequestWarning)

from pyasn1.codec.ber import encoder, decoder
from pyasn1.type      import univ, namedtype

from impacket.krb5.asn1 import (_sequence_component, _sequence_optional_component)
from impacket.krb5.gssapi import KRB5_AP_REQ
from impacket.spnego    import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp

from Cryptodome.Hash import SHA256, MD5
from cryptography    import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .credentials import TransportError, NTCredential, KrbCredential
from .spnego      import SPNEGOProxyNTLM, SPNEGOProxyKerberos
from .utils       import (chunks, b64str, get_server_certificate,
                          tls_trailer_length, krb5_mech_indep_token_encode)


# ── CredSSP ASN.1 structures ─────────────────────────────────────────────────
class NegoData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("negoToken", 0, univ.OctetString())
    )

class TSRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("version", 0, univ.Integer()),
        _sequence_optional_component("negoTokens", 1, univ.SequenceOf(componentType=NegoData())),
        _sequence_optional_component("authInfo",   2, univ.OctetString()),
        _sequence_optional_component("pubKeyAuth", 3, univ.OctetString()),
        _sequence_optional_component("errorCode",  4, univ.Integer()),
        _sequence_optional_component("clientNonce",5, univ.OctetString())
    )
    @staticmethod
    def nego_response(token, version=6):
        tsreq = TSRequest()
        tsreq["version"] = version
        if token:
            d = NegoData(); d["negoToken"] = token
            tsreq["negoTokens"].extend([d])
        return tsreq

class TSPasswordCreds(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("domainName", 0, univ.OctetString()),
        _sequence_component("userName",   1, univ.OctetString()),
        _sequence_component("password",   2, univ.OctetString())
    )

class TSCredentials(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("credType",   0, univ.Integer()),
        _sequence_component("credentials",1, univ.OctetString())
    )


# ── Transport base ───────────────────────────────────────────────────────────
class Transport:
    def __init__(self, url):
        self.url     = url
        self.ssl     = urlparse(url).scheme == "https"
        self.session = Session()
        self.session.max_redirects = 0   # SECURITY: WinRM never redirects; block SSRF
        self.session.verify = False
        self.session.headers["User-Agent"]      = SKIP_HEADER
        self.session.headers["Accept-Encoding"] = SKIP_HEADER

    def send(self, req):
        rsp = self._send(req)
        if rsp.status_code == 401:
            self._auth()
            rsp = self._send(req)
        if rsp.status_code in (301, 302, 303, 307, 308):
            raise TransportError(
                f"Unexpected HTTP redirect ({rsp.status_code}) to "
                f"{rsp.headers.get('Location', '?')} — "
                "WinRM does not support redirects (possible SSRF attempt)"
            )
        if rsp.status_code not in (200, 500):
            raise TransportError(f"Unexpected HTTP {rsp.status_code}")
        return rsp.content

    def _send_auth(self, req, proto, phase=""):
        rsp      = self.session.post(self.url,
                                     headers={"Authorization": f"{proto} {b64str(req)}"},
                                     allow_redirects=False)
        www_auth = rsp.headers.get("WWW-Authenticate","")
        if rsp.status_code == 200 and not www_auth:
            return b""
        if not www_auth.startswith(f"{proto} "):
            raise TransportError(f"{proto}: {phase}")
        return b64decode(www_auth[len(proto)+1:])

    def _encrypted_request(self, req, proto, wrap_fn):
        protocol = f"application/HTTP-{proto}-session-encrypted"
        data = b""
        for chunk in chunks(req, 16384):
            data += b"--Encrypted Boundary\r\n"
            data += f"Content-Type: {protocol}\r\n".encode()
            data += (f"OriginalContent: type=application/soap+xml;"
                     f"charset=UTF-8;Length={len(chunk)}\r\n").encode()
            data += b"--Encrypted Boundary\r\n"
            sig, enc = wrap_fn(chunk)
            data += b"Content-Type: application/octet-stream\r\n" + pack("<I", len(sig)) + sig + enc
        data += b"--Encrypted Boundary--\r\n"
        return self.session.prepare_request(Request("POST", url=self.url, data=data, headers={
            "Content-Type": f'multipart/x-multi-encrypted;protocol="{protocol}";'
                             f'boundary="Encrypted Boundary"'
        }))

    def _decrypted_response(self, rsp, unwrap_fn):
        if rsp.status_code not in (200, 500):
            return rsp
        # If response is not encrypted (e.g. plaintext SOAP fault), return raw
        if b"--Encrypted Boundary" not in rsp.content:
            return rsp
        pref_space = b"\r\nContent-Type: application/octet-stream\r\n"
        pref_tab   = b"\r\n\tContent-Type: application/octet-stream\r\n"
        plaintext  = b""
        for i, part in enumerate(rsp.content.split(b"--Encrypted Boundary")):
            for pref in (pref_space, pref_tab):
                if part.startswith(pref):
                    part = part[len(pref):]
                    break
            else:
                continue
            if len(part) < 4: continue
            sig_len = unpack("<I", part[:4])[0]
            if len(part) < 4 + sig_len: continue
            try:
                plaintext += unwrap_fn(part[4:4+sig_len], part[4+sig_len:])
            except Exception as e:
                logging.debug(f"Decrypt part {i}: {e}")
                raise TransportError(f"Transport decryption failure: {e}") from e
        rsp.headers["Content-Type"]   = "application/soap+xml;charset=UTF-8"
        rsp.headers["Content-Length"] = str(len(plaintext))
        rsp._content = plaintext
        return rsp


# ── Concrete transports ──────────────────────────────────────────────────────
class BasicTransport(Transport):
    def __init__(self, url, username, password):
        super().__init__(url)
        self.session.auth = (username, password)
    def _send(self, req):
        return self.session.post(self.url, data=req,
                                 headers={"Content-Type":"application/soap+xml;charset=UTF-8"},
                                 allow_redirects=False)
    def _auth(self): pass


class ClientCertTransport(Transport):
    """
    Used for HTTPS mutual-authentication.
    Maps to ADCS abuse paths where the attacker holds a valid client certificate
    (e.g. from ESC1, ESC9, Shadow Credentials / pywhisker, or a forged cert via
    certipy forge).
    """
    def __init__(self, url, cert_pem, cert_key):
        super().__init__(url)
        self.session.cert = (cert_pem, cert_key)
        self.session.headers["Authorization"] = \
            "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual"
    def _send(self, req):
        return self.session.post(self.url, data=req,
                                 headers={"Content-Type":"application/soap+xml;charset=UTF-8"},
                                 allow_redirects=False)
    def _auth(self): pass


class SPNEGOTransport(Transport):
    """NTLM or Kerberos wrapped in SPNEGO with channel binding (EPA)."""
    def __init__(self, url, creds):
        super().__init__(url)
        self.creds = creds
        if self.ssl:
            cert     = SHA256.new(get_server_certificate(url)).digest()
            app_data = b"tls-server-end-point:" + cert
            self.gss_bindings = MD5.new(bytes(16) + pack("<I", len(app_data)) + app_data).digest()
        else:
            self.gss_bindings = None
        self._auth()

    def _send(self, req):
        rsp = self.session.send(self._encrypted_request(req, "SPNEGO", self.proxy.wrap))
        return self._decrypted_response(rsp, self.proxy.unwrap)

    def _auth(self):
        self.proxy  = (SPNEGOProxyNTLM(self.creds, self.gss_bindings)
                       if isinstance(self.creds, NTCredential)
                       else SPNEGOProxyKerberos(self.creds, self.gss_bindings))
        token_out   = self.proxy.step()
        while not self.proxy.complete:
            token_in  = self._send_auth(token_out, "Negotiate", "SPNEGO")
            token_out = self.proxy.step(token_in)


class KerberosTransport(Transport):
    """
    Pure Kerberos transport (Authorization: Kerberos header).
    Preferred over NTLM on modern AD — use with KRB5CCNAME or --ccache.
    """
    def __init__(self, url, creds):
        super().__init__(url)
        self.creds = creds
        if self.ssl:
            cert     = SHA256.new(get_server_certificate(url)).digest()
            app_data = b"tls-server-end-point:" + cert
            self.gss_bindings = MD5.new(bytes(16) + pack("<I", len(app_data)) + app_data).digest()
        else:
            self.gss_bindings = None
        self._auth()

    def _send(self, req):
        rsp = self.session.send(self._encrypted_request(req, "Kerberos", self.proxy.wrap))
        return self._decrypted_response(rsp, self.proxy.unwrap)

    def _auth(self):
        self.proxy = SPNEGOProxyKerberos(self.creds, self.gss_bindings)
        init   = self.proxy.step()
        ap_req = SPNEGO_NegTokenInit(init)["MechToken"]
        ap_req = krb5_mech_indep_token_encode("1.2.840.113554.1.2.2", KRB5_AP_REQ + ap_req)
        rsp    = self._send_auth(ap_req, "Kerberos", "AP_REQ")
        targ   = SPNEGO_NegTokenResp()
        targ["NegState"]     = b"\x00"
        targ["SupportedMech"]= b""
        targ["ResponseToken"]= rsp
        self.proxy.step(targ.getData())


class CredSSPTransport(Transport):
    """CredSSP — full credential delegation over TLS (ports 5985/5986)."""
    def __init__(self, url, creds):
        super().__init__(url)
        self.creds = creds
        self._auth()

    def _send(self, req):
        rsp = self.session.send(self._encrypted_request(req, "CredSSP", self._wrap))
        return self._decrypted_response(rsp, self._unwrap)

    def _auth(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.options |= ssl.OP_NO_COMPRESSION | 0x00000200 | 0x00000800
        self.tls_in  = ssl.MemoryBIO()
        self.tls_out = ssl.MemoryBIO()
        self.tls_obj = ctx.wrap_bio(self.tls_in, self.tls_out, server_side=False)
        while True:
            try: self.tls_obj.do_handshake()
            except: pass
            if req := self.tls_out.read():
                rsp = self._send_auth(req, "CredSSP", "tls handshake")
                self.tls_in.write(rsp)
            else:
                break
        cert   = self.tls_obj.getpeercert(True)
        if not cert:
            raise TransportError("CredSSP: TLS handshake incomplete — no server certificate received")
        pubkey = x509.load_der_x509_certificate(cert).public_key()
        pubkey = pubkey.public_bytes(Encoding.DER, PublicFormat.PKCS1)
        nonce  = randbytes(32)
        pkhash = SHA256.new(b"CredSSP Client-To-Server Binding Hash\x00" + nonce + pubkey).digest()
        def _send_credssp(req, phase=""):
            sig, enc = self._wrap(encoder.encode(req))
            if rsp := self._send_auth(sig + enc, "CredSSP", phase):
                rsp = decoder.decode(self._unwrap(b"", rsp), asn1Spec=TSRequest())[0]
                if rsp["errorCode"].hasValue():
                    err = int.to_bytes(rsp["errorCode"]._value, length=4, signed=True).hex()
                    raise TransportError(f"CredSSP: {phase} NT_ERROR=0x{err}")
            return rsp
        proxy = (SPNEGOProxyNTLM(self.creds) if isinstance(self.creds, NTCredential)
                 else SPNEGOProxyKerberos(self.creds))
        tsreq = TSRequest.nego_response(proxy.step())
        tsrsp = _send_credssp(tsreq, "SPNEGO init")
        t3    = proxy.step(tsrsp["negoTokens"][0]["negoToken"].asOctets())
        tsreq = TSRequest.nego_response(t3)
        tsreq["clientNonce"] = nonce
        tsreq["pubKeyAuth"]  = proxy.wrap(pkhash, joined=True)
        tsrsp2 = _send_credssp(tsreq, "public key exchange")
        if tsrsp2 and tsrsp2["pubKeyAuth"].hasValue():
            srv_expected = SHA256.new(
                b"CredSSP Server-To-Client Binding Hash\x00" + nonce + pubkey
            ).digest()
            raw_pubkey_auth = tsrsp2["pubKeyAuth"].asOctets()
            sig_len = 16
            if len(raw_pubkey_auth) < sig_len:
                raise TransportError("CredSSP: malformed pubKeyAuth token from server")
            try:
                unwrapped_auth = proxy.unwrap(raw_pubkey_auth[:sig_len], raw_pubkey_auth[sig_len:])
            except Exception as e:
                raise TransportError(f"CredSSP: failed to verify server pubKeyAuth: {e}") from e
            if unwrapped_auth != srv_expected:
                raise TransportError(
                    "CredSSP: server pubKeyAuth mismatch — possible MitM, aborting!"
                )
        else:
            raise TransportError("CredSSP: server did not return pubKeyAuth")
        tspass = TSPasswordCreds()
        tspass["domainName"] = self.creds.domain.encode("utf-16le")
        tspass["userName"]   = self.creds.username.encode("utf-16le")
        tspass["password"]   = self.creds.password.encode("utf-16le")
        tscred = TSCredentials()
        tscred["credType"]    = 1
        tscred["credentials"] = encoder.encode(tspass)
        tsreq                 = TSRequest()
        tsreq["version"]      = 6
        tsreq["authInfo"]     = proxy.wrap(encoder.encode(tscred), joined=True)
        _send_credssp(tsreq, "credential delegation")

    def _wrap(self, data):
        self.tls_obj.write(data)
        enc             = self.tls_out.read()
        cipher, proto, _ = self.tls_obj.cipher()
        tl              = tls_trailer_length(len(enc), proto, cipher)
        return enc[:tl], enc[tl:]

    def _unwrap(self, sig, data):
        self.tls_in.write(sig + data)
        parts = []
        while True:
            try:    parts.append(self.tls_obj.read())
            except ssl.SSLWantReadError: break
        return b"".join(parts)