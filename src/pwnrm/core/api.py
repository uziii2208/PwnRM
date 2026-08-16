"""
core.api — public CLI argument parser & transport factory
"""

import logging
from argparse     import ArgumentParser
from urllib.parse import urlparse

from impacket.examples.utils import parse_target

from .credentials import NTCredential, KrbCredential
from .transports  import (ClientCertTransport, KerberosTransport,
                          CredSSPTransport, SPNEGOTransport)
from .utils       import load_kerberos_ccache, load_pfx


def argument_parser():
    parser = ArgumentParser(
        prog="pwnrm",
        description="PwnRM v1.0.1 — Advanced WinRM / AD post-exploitation shell",
        epilog="Example: pwnrm -u Administrator -p 'P@ss1' 192.168.1.10\n"
               "         pwnrm -u user@DOMAIN -k --ccache /tmp/user.ccache dc01.domain.local\n"
               "         pwnrm -u user@DOMAIN --pfx user.pfx --pfx-pass secret https://dc01:5986",
    )
    parser.add_argument("target",
        help="[[domain/]username[:password]@] <host> or plain <host>")
    # Auth
    auth = parser.add_argument_group("Authentication")
    auth.add_argument("-u", "--username", default="", help="Username (overrides target string)")
    auth.add_argument("-p", "--password", default="", help="Password")
    auth.add_argument("-d", "--domain",   default="", help="Domain / workgroup")
    auth.add_argument("-H", "--hash",     metavar="NTHASH",
        help="NT hash for Pass-the-Hash (format: [LM:]NT or :NT)")
    auth.add_argument("-k", "--kerberos", action="store_true",
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


def create_transport(args) -> "Transport":
    """
    Resolves credentials and returns the appropriate Transport instance.
    Priority:
       1. --pfx            → ClientCertTransport   (ADCS cert-based auth)
       2. --kerberos / -k  → KerberosTransport     (ccache or KRB5CCNAME)
       3. --credssp        → CredSSPTransport       (full cred delegation)
       4. default          → SPNEGOTransport        (NTLM or Kerberos via SPNEGO)
    """
    domain, username, password, host = parse_target(args.target)
    if args.domain:   domain   = args.domain
    if args.username: username = args.username
    if args.password: password = args.password

    use_ssl = args.ssl or (args.port == 5986) or \
              (urlparse(args.target).scheme == "https")
    port    = args.port or (5986 if use_ssl else 5985)
    scheme  = "https" if use_ssl else "http"
    url     = f"{scheme}://{host}:{port}/wsman"

    # 1. Client certificate (.pfx)
    if getattr(args, "pfx", None):
        import atexit, os as _os
        cert_pem, key_pem = load_pfx(args.pfx, getattr(args,"pfx_pass","") or None)
        logging.info(f"[+] Using client-cert transport ({args.pfx})")
        atexit.register(lambda c=cert_pem, k=key_pem: [
            _os.unlink(p) for p in (c, k) if _os.path.exists(p)
        ])
        return ClientCertTransport(url, cert_pem, key_pem)

    # 2. Kerberos (ccache)
    if getattr(args, "kerberos", False):
        dom, user, ticket, tgskey = load_kerberos_ccache(getattr(args,"ccache",None))
        domain   = domain   or dom
        username = username or user
        logging.info(f"[+] Kerberos transport as {domain}\\{username}")
        creds = KrbCredential(domain, username, ticket, tgskey, password=password)
        return KerberosTransport(url, creds)

    # 3. CredSSP
    if getattr(args, "credssp", False):
        nt_hash = ""
        if getattr(args,"hash",""):
            nt_hash = args.hash.split(":")[-1]
        creds = NTCredential(domain, username, password, nt_hash)
        logging.info(f"[+] CredSSP transport as {domain}\\{username}")
        return CredSSPTransport(url, creds)

    # 4. Default: SPNEGO
    nt_hash = ""
    if getattr(args,"hash",""):
        nt_hash = args.hash.split(":")[-1]
    creds = NTCredential(domain, username, password, nt_hash)
    logging.info(f"[+] SPNEGO transport as {domain}\\{username} "
                 f"({'NTLM' if not nt_hash else 'PtH'})")
    return SPNEGOTransport(url, creds)