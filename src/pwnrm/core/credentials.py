"""
core.credentials — credential containers & exceptions
"""


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