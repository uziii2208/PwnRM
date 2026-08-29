"""
core.credentials — credential containers & exceptions
"""

from typing import Any, Optional


class TransportError(Exception):
    """Raised when transport communication fails or SSRF/MitM is detected."""
    pass


class SPNEGOError(Exception):
    """Raised when SPNEGO / Kerberos GSSAPI authentication negotiation fails."""
    pass


class NTCredential:
    """Username + password or NT hash."""
    def __init__(self, domain: str, username: str, password: str = "", nt_hash: str = ""):
        self.domain   = domain
        self.username = username
        self.password = password
        self.nt_hash  = nt_hash


class KrbCredential:
    """Kerberos TGS ticket + session key (from ccache)."""
    def __init__(self, domain: str, username: str, ticket: Any, tgskey: Any, password: str = ""):
        self.domain   = domain
        self.username = username
        self.password = password   # needed by CredSSP delegation
        self.ticket   = ticket
        self.tgskey   = tgskey