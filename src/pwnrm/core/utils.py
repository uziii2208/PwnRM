"""
core.utils — shared helpers (encoding, TLS, ccache / pfx loading)
"""

import os, re, ssl, uuid, logging, tempfile
from base64   import b64encode, b64decode
from pathlib  import Path
from urllib.parse import urlparse

from pyasn1.codec.ber import encoder, decoder
from pyasn1.type.univ import ObjectIdentifier

from impacket.krb5.ccache import CCache
from impacket.krb5.types  import Ticket
from impacket.krb5.crypto import Key

from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates


# ── encoding helpers ─────────────────────────────────────────────────────────
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

# ── terminal output sanitizer ────────────────────────────────────────────────
_ANSI_RE = re.compile(
    r'\x1b'
    r'(?:'
    r'\[[\x20-\x3f]*[\x40-\x7e]'                      # CSI  — ESC [ ... final
    r'|\](?:[^\x07\x1b]|\x1b(?!\\))*(?:\x07|\x1b\\)'  # OSC  — ESC ] ... BEL/ST
    r'|P(?:[^\x1b]|\x1b(?!\\))*(?:\x1b\\)'            # DCS  — ESC P ... ST
    r'|[NOno78MNPX^_c\\]'                              # Fe single-char sequences
    r'|[\x40-\x5f]'                                    # other Fe sequences
    r')'
)
_CTRL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

def strip_ansi(s: str) -> str:
    """Strip ANSI/VT100 escape sequences and dangerous control chars.
    Preserves \\t (\\x09), \\n (\\x0a), \\r (\\x0d) for normal formatting."""
    if s is None:
        return ""
    return _CTRL_RE.sub('', _ANSI_RE.sub('', str(s)))

zero_uuid = str(uuid.UUID(bytes_le=bytes(16))).upper()


# ── Kerberos mech-independent token helpers ──────────────────────────────────
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
    if len(data) < 2:
        raise ValueError("Token too short for GSS-API framing")
    if data[1] < 128:
        skip = 2
    else:
        skip = 2 + (data[1] - 128)
    return decoder.decode(data[skip:], asn1Spec=ObjectIdentifier())


# ── TLS helpers ──────────────────────────────────────────────────────────────
def get_server_certificate(url):
    default_port = 5986 if urlparse(url).scheme == "https" else 5985
    addr = (urlparse(url).hostname, urlparse(url).port or default_port)
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
    hash_length     = {"MD5":16, "SHA":20, "SHA256":32, "SHA384":48}.get(hash_algorithm, 0)
    pre_pad         = data_length + hash_length
    if   "RC4"  in cipher_suite: pad = 0
    elif "DES" in cipher_suite or "3DES" in cipher_suite: pad = 8 - (pre_pad % 8)
    else: pad = 16 - (pre_pad % 16)
    return (pre_pad + pad) - data_length


# ── ccache loader ────────────────────────────────────────────────────────────
def load_kerberos_ccache(ccache_path: str | None = None):
    """
    Returns (domain, username, ticket, tgskey) from a .ccache file or
    the KRB5CCNAME environment variable.  Raises FileNotFoundError if not found.
    """
    raw_path = ccache_path or os.environ.get("KRB5CCNAME", "")
    path = raw_path.removeprefix("FILE:") if raw_path.startswith("FILE:") else raw_path
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


# ── pfx loader ───────────────────────────────────────────────────────────────
def load_pfx(pfx_path: str, password: str | None = None) -> tuple[str, str]:
    """
    Converts a PKCS#12 (.pfx) to a pair of temporary PEM files.
    Returns (cert_pem_path, key_pem_path).

    Security: files are created inside a chmod-700 temp directory using
    O_CREAT|O_EXCL to prevent TOCTOU races; key file has mode 0o600.
    Caller must delete the temp directory (and its contents) when done.
    Use atexit or a try/finally to guarantee cleanup.
    """
    import stat
    pwd = password.encode() if password else None
    with open(pfx_path, "rb") as f:
        data = f.read()
    key, cert, chain = load_key_and_certificates(data, pwd)
    if key is None or cert is None:
        raise ValueError(
            f"PFX file {pfx_path!r} must contain both a private key and a certificate"
        )
    cert_pem = cert.public_bytes(Encoding.PEM)
    key_pem  = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())

    # Create an isolated temp directory accessible only by this user
    tmp_dir = tempfile.mkdtemp(prefix="pwnrm_")
    os.chmod(tmp_dir, stat.S_IRWXU)   # 0o700 — owner only

    cert_path = os.path.join(tmp_dir, "cert.pem")
    key_path  = os.path.join(tmp_dir, "key.pem")

    # O_CREAT | O_EXCL prevents a race between creation and write;
    # mode 0o600 ensures no other user can read the private key.
    for path, content in ((cert_path, cert_pem), (key_path, key_pem)):
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, content)
        finally:
            os.close(fd)

    return cert_path, key_path