"""
PwnRM — Advanced WinRM / AD Post-Exploitation Platform (2026-2027 TTPs)

A modular Python framework and operator platform for WinRM-based post-exploitation,
multi-session graph orchestration, in-band SOCKS5 tunneling, and Active Directory / Entra ID abuse.
"""

__version__ = "2.0.1"
__author__  = "uziii2208"

from .core import (
    Runspace, create_transport, argument_parser,
    NTCredential, KrbCredential, TransportError, SPNEGOError,
    Transport, BasicTransport, ClientCertTransport,
    SPNEGOTransport, KerberosTransport, CredSSPTransport,
    SessionManager, SessionNode, Socks5Server, PortForwarder,
    LootManager, OPSECProfile,
)
from .shell import PwnShell
from .modules import BaseModule, ModuleManager

__all__ = [
    "__version__",
    # core
    "Runspace", "create_transport", "argument_parser",
    "NTCredential", "KrbCredential", "TransportError", "SPNEGOError",
    "Transport", "BasicTransport", "ClientCertTransport",
    "SPNEGOTransport", "KerberosTransport", "CredSSPTransport",
    "SessionManager", "SessionNode",
    "Socks5Server", "PortForwarder",
    "LootManager", "OPSECProfile",
    # shell
    "PwnShell",
    # modules
    "BaseModule", "ModuleManager",
]