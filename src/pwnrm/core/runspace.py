"""
core.runspace — MS-PSRP Runspace (command execution layer)

Hotfix v1.2.1-fix1: replaced custom PSRP wire format with pypsrp backend.

Root cause: original _fragment() encodes GUIDs as 32-byte ASCII hex strings
instead of 16-byte binary (MS-PSRP spec §2.2.1), and places ObjectId inside
the blob instead of the fragment header (§2.2.4).  Windows 10 Desktop WinRM
rejects all pipeline requests with w:InternalError; Windows Server may be
more lenient.  pypsrp implements MS-PSRP correctly and is used as the PSRP
backend while PwnRM's own transport layer (SPNEGO / Kerberos / CredSSP /
ClientCert) continues to handle authentication.

Requires: pip install pypsrp
"""

import logging
from urllib.parse import urlparse

from pypsrp.wsman      import WSMan
from pypsrp.powershell  import RunspacePool, PowerShell

from .credentials import NTCredential, KrbCredential
from .transports  import (SPNEGOTransport, KerberosTransport,
                          CredSSPTransport, ClientCertTransport)


class Runspace:
    def __init__(self, transport, timeout=30):
        self.timeout = timeout

        # ── Extract connection params from PwnRM transport object ────────────
        parsed   = urlparse(transport.url)
        host     = parsed.hostname
        port     = parsed.port or (5986 if parsed.scheme == "https" else 5985)
        use_ssl  = parsed.scheme == "https"

        # Determine auth method from transport type
        if isinstance(transport, ClientCertTransport):
            auth = "certificate"
        elif isinstance(transport, CredSSPTransport):
            auth = "credssp"
        elif isinstance(transport, KerberosTransport):
            auth = "kerberos"
        else:
            auth = "negotiate"

        # Extract credentials from transport
        creds    = getattr(transport, "creds", None)
        username = ""
        password = ""
        if isinstance(creds, NTCredential):
            username = creds.username
            password = creds.password
            if not password and creds.nt_hash:
                # pass-the-hash: prepend colon for NTLM hash format
                password = f":{creds.nt_hash}"
        elif isinstance(creds, KrbCredential):
            username = (f"{creds.username}@{creds.domain}"
                        if creds.domain else creds.username)
            password = creds.password

        # ── Create pypsrp WSMan + RunspacePool ───────────────────────────────
        self._wsman = WSMan(
            host,
            port              = port,
            ssl               = use_ssl,
            auth              = auth,
            username          = username,
            password          = password,
            cert_validation   = False,
            connection_timeout= timeout,
            read_timeout      = timeout,
        )
        self._pool      = None
        self.shell_id   = None
        self.command_id = None

    # ── Context manager ──────────────────────────────────────────────────────
    def __enter__(self):
        self._wsman.__enter__()
        self._pool = RunspacePool(self._wsman)
        self._pool.open()
        self.shell_id = str(self._pool.id)
        return self

    def __exit__(self, *exc):
        try:
            if self._pool:
                self._pool.close()
        except Exception:
            pass
        try:
            self._wsman.__exit__(*exc)
        except Exception:
            pass

    # ── Command execution (generator — same API as original) ─────────────────
    def run_command(self, cmd):
        """
        Execute a PowerShell command and yield results as dicts.
        Compatible with PwnShell's run_sync / run_with_interrupt.

        Yields:
            {"stdout": str}    — standard output lines
            {"error": str}     — error records
            {"warn": str}      — warning records
            {"verbose": str}   — verbose records
            {"info": str, "endl": str} — information records
            {"progress": str}  — progress records
        """
        try:
            ps = PowerShell(self._pool)
            ps.add_script(cmd)
            ps.add_cmdlet("Out-String").add_parameter("Stream")
            ps.invoke()
            self.command_id = str(ps.id) if hasattr(ps, "id") else None

            # stdout
            for item in ps.output:
                text = str(item)
                if text:
                    yield {"stdout": text + "\n"}

            # errors
            for err in ps.streams.error:
                yield {"error": str(err)}

            # warnings
            for warn in ps.streams.warning:
                yield {"warn": str(warn)}

            # verbose
            for v in ps.streams.verbose:
                yield {"verbose": str(v)}

            # information
            for info in ps.streams.information:
                msg = getattr(info, "message_data", str(info))
                yield {"info": str(msg), "endl": "\n"}

            # progress
            for prog in ps.streams.progress:
                activity = getattr(prog, "activity", "")
                status   = getattr(prog, "status_description", "")
                yield {"progress": str(status or activity)}

        except Exception as e:
            yield {"error": str(e)}
        finally:
            self.command_id = None

    # ── Interrupt (Ctrl+C) ───────────────────────────────────────────────────
    def interrupt(self):
        # pypsrp's invoke() is blocking; Ctrl+C raises KeyboardInterrupt
        # which PwnShell already catches via CtrlCHandler.
        pass
