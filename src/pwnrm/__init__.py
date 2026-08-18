"""
PwnRM — Advanced WinRM / AD Post-Exploitation Shell

A Python library and CLI tool for WinRM-based post-exploitation
and Active Directory enumeration.
"""

__version__ = "1.1.1"
__author__  = "uziii2208"

from .core import (
    Runspace, create_transport, argument_parser,
    NTCredential, KrbCredential, TransportError, SPNEGOError,
    Transport, BasicTransport, ClientCertTransport,
    SPNEGOTransport, KerberosTransport, CredSSPTransport,
)
from .shell import PwnShell

__all__ = [
    "__version__",
    # core
    "Runspace", "create_transport", "argument_parser",
    "NTCredential", "KrbCredential", "TransportError", "SPNEGOError",
    "Transport", "BasicTransport", "ClientCertTransport",
    "SPNEGOTransport", "KerberosTransport", "CredSSPTransport",
    # shell
    "PwnShell",
]