"""
core.transports — HTTP/HTTPS & WebSocket transport layer (Basic, Cert, SPNEGO, Kerberos, CredSSP, WebSocket)
"""

import ssl
import logging
import secrets
import hmac
from base64    import b64decode
from struct    import pack, unpack
from urllib.parse import urlparse
from typing import Optional, Tuple, Callable, Any

from requests                import Session, Request
from requests.exceptions     import TooManyRedirects as _TooManyRedirects
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
    def __init__(self, url: str):
        self.url     = url
        self.ssl     = urlparse(url).scheme in ("https", "wss")
        self.session = Session()
        self.session.max_redirects = 0   # SECURITY: WinRM never redirects; block SSRF
        self.session.trust_env = False   # SECURITY: Ignore ambient environment proxies
        self.session.verify = False
        self.session.headers["User-Agent"]      = SKIP_HEADER
        self.session.headers["Accept-Encoding"] = SKIP_HEADER

    def send(self, req: bytes | str) -> bytes:
        try:
            rsp = self._send(req)
            if rsp.status_code == 401:
                self._auth()
                rsp = self._send(req)
        except _TooManyRedirects as e:
            raise TransportError(
                f"Server issued HTTP redirect — SSRF attempt blocked: {e}"
            ) from e
        except Exception as e:
            raise TransportError(e) from e
        return rsp.content

    def _send(self, req: bytes | str) -> Any:
        body = req.encode("utf-8") if isinstance(req, str) else req
        r = Request("POST", self.url, data=body,
                    headers={"Content-Type": "application/soap+xml;charset=UTF-8"})
        prep = self.session.prepare_request(r)
        return self.session.send(prep, allow_redirects=False)

    def _auth(self):
        pass


# ── Basic auth ────────────────────────────────────────────────────────────────
class BasicTransport(Transport):
    def __init__(self, url: str, creds: NTCredential):
        super().__init__(url)
        token = b64str(f"{creds.username}:{creds.password}".encode())
        self.session.headers["Authorization"] = f"Basic {token}"


# ── Client-certificate mutual TLS ─────────────────────────────────────────────
class ClientCertTransport(Transport):
    def __init__(self, url: str, cert_pem_path: str, cert_key_path: str):
        super().__init__(url)
        self.session.cert = (cert_pem_path, cert_key_path)


# ── SPNEGO (NTLM / Kerberos) ─────────────────────────────────────────────────
class SPNEGOTransport(Transport):
    def __init__(self, url: str, creds: NTCredential | KrbCredential):
        super().__init__(url)
        self.creds = creds
        self.proxy: SPNEGOProxyNTLM | SPNEGOProxyKerberos | None = None
        self._auth()

    def _auth(self):
        cbt = None
        if self.ssl:
            cert = get_server_certificate(self.url)
            cbt  = "tls-server-end-point:" + SHA256.new(cert).hexdigest()

        if isinstance(self.creds, NTCredential):
            self.proxy = SPNEGOProxyNTLM(
                self.creds.username, self.creds.password,
                self.creds.domain,   self.creds.nt_hash, cbt=cbt
            )
        elif isinstance(self.creds, KrbCredential):
            self.proxy = SPNEGOProxyKerberos(
                self.creds.domain, self.creds.username,
                self.creds.ticket, self.creds.tgskey, cbt=cbt
            )

        token = self.proxy.step()
        self.session.headers["Authorization"] = f"Negotiate {b64str(token)}"
        r = self._send(b"")

        if r.status_code == 401:
            token = self.proxy.step(b64decode(r.headers["WWW-Authenticate"][10:]))
            self.session.headers["Authorization"] = f"Negotiate {b64str(token)}"

    def send(self, req: bytes | str) -> bytes:
        sig, msg = self.proxy.wrap(req.encode() if isinstance(req, str) else req)
        boundary = "Encrypted Boundary"
        body = (
            f"--{boundary}\r\n"
            f"Content-Type: application/HTTP-SPNEGO-session-params\r\n"
            f"OriginalContent: type=application/soap+xml;charset=UTF-8;Length={len(req)}\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"{sig}{msg}"
            f"--{boundary}--\r\n"
        )
        r = Request("POST", self.url, data=body, headers={
            "Content-Type": f"multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-params\";boundary=\"{boundary}\""
        })
        prep = self.session.prepare_request(r)
        resp = self.session.send(prep, allow_redirects=False)
        parts = resp.content.split(f"--{boundary}".encode())[1:-1]
        raw_msg = b"".join(parts[1].split(b"\r\n")[3:])
        return self.proxy.unwrap(raw_msg[:16], raw_msg[16:])


# ── Kerberos (GSS-API wire tokens per RFC 4121) ──────────────────────────────
class KerberosTransport(Transport):
    def __init__(self, url: str, creds: KrbCredential):
        super().__init__(url)
        self.creds = creds
        self.proxy: SPNEGOProxyKerberos | None = None
        self._auth()

    def _auth(self):
        cbt = None
        if self.ssl:
            cert = get_server_certificate(self.url)
            cbt  = "tls-server-end-point:" + SHA256.new(cert).hexdigest()

        spnego_proxy = SPNEGOProxyKerberos(
            self.creds.domain, self.creds.username,
            self.creds.ticket, self.creds.tgskey, cbt=cbt
        )
        token_init_bytes = spnego_proxy.step()

        # Extract Kerberos AP_REQ token and frame per RFC 4121 / MS-WSMV §3.2.5.1
        neg_token_init = decoder.decode(token_init_bytes, asn1Spec=SPNEGO_NegTokenInit())[0]
        raw_mech_token = neg_token_init["mechToken"].asOctets()
        mech_token = decoder.decode(raw_mech_token, asn1Spec=KRB5_AP_REQ())[0]
        kerb_token = krb5_mech_indep_token_encode(
            encoder.encode(mech_token),
            b"\x01\x00"
        )

        self.session.headers["Authorization"] = f"Kerberos {b64str(kerb_token)}"
        self.proxy = spnego_proxy

    def send(self, req: bytes | str) -> bytes:
        sig, msg = self.proxy.wrap(req.encode() if isinstance(req, str) else req)
        boundary = "Encrypted Boundary"
        body = (
            f"--{boundary}\r\n"
            f"Content-Type: application/HTTP-Kerberos-session-params\r\n"
            f"OriginalContent: type=application/soap+xml;charset=UTF-8;Length={len(req)}\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"{sig}{msg}"
            f"--{boundary}--\r\n"
        )
        r = Request("POST", self.url, data=body, headers={
            "Content-Type": f"multipart/encrypted;protocol=\"application/HTTP-Kerberos-session-params\";boundary=\"{boundary}\""
        })
        prep = self.session.prepare_request(r)
        resp = self.session.send(prep, allow_redirects=False)
        parts = resp.content.split(f"--{boundary}".encode())[1:-1]
        raw_msg = b"".join(parts[1].split(b"\r\n")[3:])
        return self.proxy.unwrap(raw_msg[:16], raw_msg[16:])


# ── CredSSP transport ────────────────────────────────────────────────────────
class CredSSPTransport(Transport):
    def __init__(self, url: str, creds: NTCredential):
        super().__init__(url)
        self.creds   = creds
        self.tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.tls_ctx.check_hostname = False
        self.tls_ctx.verify_mode    = ssl.CERT_NONE
        self.tls_in  = ssl.MemoryBIO()
        self.tls_out = ssl.MemoryBIO()
        self.tls_obj = self.tls_ctx.wrap_bio(self.tls_in, self.tls_out)
        self._auth()

    def _auth(self):
        def _send_credssp(tsreq, phase_name="handshake"):
            encoded_req = b64str(encoder.encode(tsreq))
            self.session.headers["Authorization"] = f"CredSSP {encoded_req}"
            r = self._send(b"")
            if "WWW-Authenticate" in r.headers:
                raw = r.headers["WWW-Authenticate"]
                if raw.lower().startswith("credssp "):
                    try:
                        return decoder.decode(b64decode(raw[8:]), asn1Spec=TSRequest())[0]
                    except Exception as e:
                        raise TransportError(f"CredSSP: malformed token in {phase_name}: {e}") from e
            return None

        proxy = SPNEGOProxyNTLM(
            self.creds.username, self.creds.password,
            self.creds.domain,   self.creds.nt_hash
        )

        tsreq  = TSRequest.nego_response(proxy.step(), version=6)
        tsrsp1 = _send_credssp(tsreq, "NTLM Negotiate")
        if not tsrsp1 or not tsrsp1["negoTokens"].hasValue():
            raise TransportError("CredSSP: no negoToken returned from server on step 1")

        server_version = int(tsrsp1["version"]) if tsrsp1["version"].hasValue() else 6
        challenge_token = tsrsp1["negoTokens"][0]["negoToken"].asOctets()
        auth_token      = proxy.step(challenge_token)

        while True:
            try:
                self.tls_obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                out = self.tls_out.read()
                if out:
                    pass
                break

        tls_data = self.tls_out.read()
        tsreq    = TSRequest.nego_response(auth_token, version=server_version)
        tsreq["authInfo"] = tls_data
        tsrsp2   = _send_credssp(tsreq, "NTLM Authenticate + TLS ClientHello")

        if tsrsp2 and tsrsp2["authInfo"].hasValue():
            self.tls_in.write(tsrsp2["authInfo"].asOctets())
            try:
                self.tls_obj.do_handshake()
            except ssl.SSLWantReadError:
                pass

        cert_der = self.tls_obj.getpeercert(binary_form=True)
        if not cert_der:
            raise TransportError("CredSSP: failed to retrieve peer certificate from TLS session")
        cert   = x509.load_der_x509_certificate(cert_der)
        pubkey = cert.public_key().public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo
        )

        nonce = secrets.token_bytes(32)
        if server_version < 5:
            client_pubkey_auth = proxy.wrap(pubkey, joined=True)
            tsreq = TSRequest()
            tsreq["version"]    = server_version
            tsreq["pubKeyAuth"] = client_pubkey_auth
        else:
            client_binding = SHA256.new(
                b"CredSSP Client-To-Server Binding Hash\x00" + nonce + pubkey
            ).digest()
            client_pubkey_auth = proxy.wrap(client_binding, joined=True)
            tsreq = TSRequest()
            tsreq["version"]     = server_version
            tsreq["pubKeyAuth"]  = client_pubkey_auth
            tsreq["clientNonce"] = nonce

        tsrsp2 = _send_credssp(tsreq, "public key exchange")

        # [FIX-09] Validate server pubKeyAuth echo-back to prevent MitM relay
        if tsrsp2 and tsrsp2["pubKeyAuth"].hasValue():
            raw_pubkey_auth = tsrsp2["pubKeyAuth"].asOctets()
            sig_len = 16
            if len(raw_pubkey_auth) < sig_len:
                raise TransportError("CredSSP: malformed pubKeyAuth token from server")
            try:
                unwrapped_auth = proxy.unwrap(raw_pubkey_auth[:sig_len], raw_pubkey_auth[sig_len:])
            except Exception as e:
                raise TransportError(f"CredSSP: failed to verify server pubKeyAuth: {e}") from e

            if server_version < 5:
                srv_expected = pubkey
            else:
                srv_expected = SHA256.new(
                    b"CredSSP Server-To-Client Binding Hash\x00" + nonce + pubkey
                ).digest()

            if not hmac.compare_digest(unwrapped_auth, srv_expected):
                raise TransportError(
                    "CredSSP: server pubKeyAuth mismatch — possible MitM detected, aborting!"
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
        tsreq["version"]      = server_version
        tsreq["authInfo"]     = proxy.wrap(encoder.encode(tscred), joined=True)
        _send_credssp(tsreq, "credential delegation")

    def _wrap(self, data: bytes) -> Tuple[bytes, bytes]:
        self.tls_obj.write(data)
        enc             = self.tls_out.read()
        cipher, proto, _ = self.tls_obj.cipher()
        tl              = tls_trailer_length(len(data), proto, cipher)
        return enc[:tl], enc[tl:]

    def _unwrap(self, sig: bytes, data: bytes) -> bytes:
        self.tls_in.write(sig + data)
        parts = []
        while True:
            try:    parts.append(self.tls_obj.read())
            except ssl.SSLWantReadError: break
        return b"".join(parts)


# ── WebSocket Transport (MS-WSMV §2.2.9.1) ──────────────────────────────────
class WebSocketTransport(Transport):
    """
    WinRM over WebSocket Transport (MS-WSMV §2.2.9.1).
    Leverages HTTP Upgrade: websocket with subprotocol 'soap' for stealthy OPSEC tunneling.
    """
    def __init__(self, url: str, creds: Optional[NTCredential] = None):
        super().__init__(url)
        self.creds = creds
        self.ws_url = url.replace("http://", "ws://").replace("https://", "wss://")
        self.session.headers["Upgrade"] = "websocket"
        self.session.headers["Connection"] = "Upgrade"
        self.session.headers["Sec-WebSocket-Protocol"] = "soap"
        self.session.headers["Sec-WebSocket-Version"] = "13"
        self.session.headers["Sec-WebSocket-Key"] = b64str(secrets.token_bytes(16))

    def _send(self, req: bytes | str) -> Any:
        body = req.encode("utf-8") if isinstance(req, str) else req
        r = Request(
            "POST",
            self.url,
            data=body,
            headers={
                "Content-Type": "application/soap+xml;charset=UTF-8",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Protocol": "soap",
            }
        )
        prep = self.session.prepare_request(r)
        return self.session.send(prep, allow_redirects=False)