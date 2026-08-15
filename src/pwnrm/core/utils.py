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

_utfstr = re.compile(r'x([0-9a-fA-F]{4})')
def utfstr(s):
    try:
        return _utfstr.sub(lambda m: bytes.fromhex(m.group(1)).decode("utf-16be"), s)
    except:
        return s

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
    skip = 2 + (data[1] if data[1] < 128 else (data[1] - 128))
    return decoder.decode(data[skip:], asn1Spec=ObjectIdentifier())


# ── TLS helpers ──────────────────────────────────────────────────────────────
def get_server_certificate(url):
    addr = (urlparse(url).hostname, urlparse(url).port or 443)
    cert = ssl.get_server_certificate(addr)
    cert = cert.replace("-----BEGIN CERTIFICATE-----\n", "")
    cert = cert.replace("-----END CERTIFICATE-----\n", "")
    return b64decode(cert)

def tls_trailer_length(data_length, protocol, cipher_suite):
    if protocol == "TLSv1.3":
        return 17
    if re.match(r"^.[-_]GCM[-_][\w\d]$", cipher_suite):
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
    path = ccache_path or os.environ.get("KRB5CCNAME", "").lstrip("FILE:")
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
    Caller should delete the temp files when done.
    """
    pwd = password.encode() if password else None
    with open(pfx_path, "rb") as f:
        data = f.read()
    key, cert, chain = load_key_and_certificates(data, pwd)
    cert_pem = cert.public_bytes(Encoding.PEM)
    key_pem  = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    tf_cert = tempfile.NamedTemporaryFile(suffix="_pwnrm_cert.pem", delete=False)
    tf_key  = tempfile.NamedTemporaryFile(suffix="_pwnrm_key.pem",  delete=False)
    tf_cert.write(cert_pem); tf_cert.close()
    tf_key.write(key_pem);   tf_key.close()
    return tf_cert.name, tf_key.name