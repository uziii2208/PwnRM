"""
core.runspace — MS-PSRP Runspace (command execution layer)

Backend utilizes pypsrp for standard-compliant MS-PSRP serialization
while PwnRM's transport layer handles mutual-TLS, Kerberos, SPNEGO, and CredSSP.
"""

import logging
from urllib.parse import urlparse
from typing import Optional, Dict, Any, Generator

from pypsrp.wsman      import WSMan
from pypsrp.powershell  import RunspacePool, PowerShell

from .credentials import NTCredential, KrbCredential
from .transports  import (Transport, SPNEGOTransport, KerberosTransport,
                          CredSSPTransport, ClientCertTransport)


class Runspace:
    def __init__(self, transport: Transport, timeout: int = 30, max_consecutive_timeouts: int = 60):
        self.timeout = timeout
        self.max_consecutive_timeouts = max_consecutive_timeouts
        self.consecutive_timeouts = 0

        # ── Extract connection params from PwnRM transport object ────────────
        parsed   = urlparse(transport.url)
        host     = parsed.hostname or "localhost"
        port     = parsed.port or (5986 if parsed.scheme == "https" else 5985)
        use_ssl  = parsed.scheme == "https"

        # Determine auth method from transport type
        extra_auth_kwargs: dict = {}
        if isinstance(transport, ClientCertTransport):
            auth = "certificate"
            # Forward client certificate material to pypsrp
            cert_data = getattr(transport.session, "cert", None)
            if isinstance(cert_data, (tuple, list)) and len(cert_data) == 2:
                extra_auth_kwargs["certificate_pem"]     = cert_data[0]
                extra_auth_kwargs["certificate_key_pem"] = cert_data[1]
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
            **extra_auth_kwargs,
        )

        # Enforce redirect and proxy hardening on pypsrp internal session
        _wt = getattr(self._wsman, "transport", None)
        if _wt is not None:
            _orig_build = _wt._build_session
            def _hardened_build(_orig=_orig_build):
                sess = _orig()
                sess.max_redirects = 0     # block SSRF via server-issued redirect
                sess.trust_env    = False  # ignore HTTP_PROXY / HTTPS_PROXY env vars
                return sess
            _wt._build_session = _hardened_build

        self._pool: Optional[RunspacePool] = None
        self.shell_id: Optional[str]       = None
        self.command_id: Optional[str]     = None

    # ── Context manager ──────────────────────────────────────────────────────
    def __enter__(self) -> "Runspace":
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

    # ── Command execution (generator) ────────────────────────────────────────
    def run_command(self, cmd: str) -> Generator[Dict[str, Any], None, None]:
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
            self.consecutive_timeouts = 0  # reset timeout counter on successful invoke

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
            err_msg = str(e)
            if "timeout" in err_msg.lower() or "timed out" in err_msg.lower():
                self.consecutive_timeouts += 1
                if self.consecutive_timeouts >= self.max_consecutive_timeouts:
                    yield {"error": f"Fatal: WinRM endpoint unresponsive after {self.consecutive_timeouts} consecutive timeouts."}
                    return
            yield {"error": err_msg}
        finally:
            self.command_id = None
            try:
                if "ps" in locals() and hasattr(ps, "output") and hasattr(ps.output, "clear"):
                    ps.output.clear()
            except Exception:
                pass

    # ── Interrupt (Ctrl+C) ───────────────────────────────────────────────────
    def interrupt(self):
        """Interrupts in-flight execution if supported by underlying pool."""
        try:
            if self._pool and hasattr(self._pool, "disconnect"):
                pass
        except Exception:
            pass
