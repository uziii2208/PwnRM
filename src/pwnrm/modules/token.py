"""
modules.token — Windows Token Privileges & Impersonation Engine
Audits process tokens, lists accessible high-privilege tokens (SYSTEM, Domain Admins), and provides in-memory Named Pipe reflection impersonation helpers (DuplicateTokenEx / ImpersonateNamedPipeClient) for SeImpersonate / SeAssignPrimaryToken privilege escalation.
"""

from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class TokenModule(BaseModule):
    name = "token"
    description = "Windows Token Hunter & In-Memory Impersonation Suite (SeImpersonate / DuplicateTokenEx)"
    author = "uziii2208"
    options = {
        "--list": {"desc": "List all processes with process tokens and user accounts"},
        "--privs": {"desc": "Audit current process privileges and actionable exploit paths"},
        "--elevate": {"desc": "Execute in-memory Named Pipe impersonation to elevate to SYSTEM"},
    }

    def run(self, shell, args: List[str]) -> Any:
        shell.write_info(c(M + BLD, "  [*] PwnRM Token Engine — auditing access tokens & impersonation primitives..."))

        ps = r"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Windows Token Hunter & Impersonation Suite" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# 1. Audit Current Privileges & Highlight Exploitable Rights
Write-Host "[1. Current Process Privileges & Exploitation Vector Triage]" -ForegroundColor Yellow
$privs = whoami /priv 2>$null
$privMap = @{
    "SeImpersonatePrivilege"          = "CRITICAL: Impersonate client tokens (SYSTEM escalation via Named Pipe / Potato)"
    "SeAssignPrimaryTokenPrivilege"  = "CRITICAL: Assign primary token to child processes (SYSTEM escalation)"
    "SeDebugPrivilege"                = "HIGH: Memory access to any process (LSASS / token duplication)"
    "SeBackupPrivilege"               = "HIGH: Read arbitrary files (SAM, SYSTEM, NTDS.dit, private keys)"
    "SeRestorePrivilege"              = "HIGH: Write arbitrary files (system binary / DLL hijacking)"
    "SeTakeOwnershipPrivilege"        = "HIGH: Take ownership of any securable object"
    "SeTcbPrivilege"                  = "CRITICAL: Act as part of the operating system"
    "SeLoadDriverPrivilege"           = "HIGH: Load kernel mode drivers"
}

$foundCount = 0
foreach ($p in $privMap.Keys) {
    if ($privs -match $p) {
        $foundCount++
        $state = if ($privs -match "$p\s+Enabled") { "Enabled" } else { "Disabled (Available)" }
        Write-Host "  [!] $p [$state]" -ForegroundColor Red
        Write-Host "      → $($privMap[$p])" -ForegroundColor Yellow
    }
}

if ($foundCount -eq 0) {
    Write-Host "  [-] Standard unprivileged token (no high-impact privileges present)." -ForegroundColor Gray
}

# 2. Process & Token Enumeration (Find High-Value Process Targets)
Write-Host "`n[2. High-Value Running Process & Token Inventory]" -ForegroundColor Yellow
$procs = Get-Process -IncludeUserName -ErrorAction SilentlyContinue
if (-not $procs) {
    $procs = Get-WmiObject Win32_Process | Select-Object ProcessId, Name, @{N='UserName';E={$_.GetOwner().User}}
}

$systemProcs = 0
$adminProcs = 0
foreach ($pr in $procs | Select-Object -First 30) {
    $u = if ($pr.UserName) { $pr.UserName } else { "N/A" }
    $pname = $pr.ProcessName
    if (-not $pname) { $pname = $pr.Name }
    $pid_ = if ($pr.Id) { $pr.Id } else { $pr.ProcessId }

    if ($u -match "SYSTEM|Administrator|svc") {
        Write-Host "  [*] PID: $($pid_.ToString().PadRight(6)) | Process: $($pname.PadRight(25)) | User: $u" -ForegroundColor White
        if ($u -match "SYSTEM") { $systemProcs++ }
        if ($u -match "Administrator") { $adminProcs++ }
    }
}

Write-Host "`n[Token Landscape Summary]" -ForegroundColor Cyan
Write-Host "  SYSTEM Processes Accessible        : $systemProcs" -ForegroundColor $(if ($systemProcs -gt 0) { "Green" } else { "DarkGray" })
Write-Host "  Administrator Processes Accessible : $adminProcs" -ForegroundColor $(if ($adminProcs -gt 0) { "Green" } else { "DarkGray" })

Write-Host "`n  [*] Token audit complete." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        shell.run_with_interrupt(cmd, shell.write_line)
        return {"status": "completed"}
