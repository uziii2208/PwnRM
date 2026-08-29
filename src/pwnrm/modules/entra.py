"""
modules.entra — Hybrid Entra ID & Cloud Pivot
Extracts Entra ID PRT artifacts, inspects Azure AD join state, and enumerates cloud pivot vectors.
"""

from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class EntraModule(BaseModule):
    name = "entra"
    description = "Hybrid Entra ID / Azure AD Cloud Pivot (PRT & Join State Recon)"
    author = "uziii2208"
    options = {
        "-s": {"desc": "Run full dsregcmd join status and WAM token probe"},
    }

    def run(self, shell, args: List[str]) -> Any:
        shell.write_info(c(M + BLD, "  [*] PwnRM Entra Suite — running Azure AD / Hybrid Join reconnaissance..."))

        ps = r"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Hybrid Entra ID / Azure AD Cloud Pivot Recon" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# 1. Device Join Status (AzureADJoined / DomainJoined)
Write-Host "[1. Device Join & PRT Status]" -ForegroundColor Yellow
$dsreg = dsregcmd /status 2>$null
if ($dsreg) {
    $dsreg | Where-Object { $_ -match "AzureAdJoined|DomainJoined|EnterpriseJoined|TenantName|TenantId|UserEmail|AzureAdPrt" } | ForEach-Object {
        Write-Host "  $_" -ForegroundColor White
    }
} else {
    Write-Host "  [-] dsregcmd not available or returned no data." -ForegroundColor Gray
}

# 2. Token Broker / WAM Cache Presence
Write-Host "`n[2. Web Account Manager (WAM) & Cloud Token Stores]" -ForegroundColor Yellow
$wamPath = "$env:LOCALAPPDATA\\Packages\\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy"
if (Test-Path $wamPath) {
    Write-Host "  [+] WAM Broker Plugin folder found: $wamPath" -ForegroundColor Green
    Write-Host "      (Potential PRT / Primary Refresh Token artifact location)" -ForegroundColor Gray
} else {
    Write-Host "  [-] No WAM Broker Plugin folder for current profile." -ForegroundColor Gray
}

# Check for Azure CLI / PowerShell token caches
$azPath = "$env:USERPROFILE\\.azure\\accessTokens.json"
if (Test-Path $azPath) {
    Write-Host "  [!] FOUND Azure CLI Token Cache: $azPath" -ForegroundColor Red
}

$azCtx = "$env:USERPROFILE\\.Azure\\AzureRmContext.json"
if (Test-Path $azCtx) {
    Write-Host "  [!] FOUND Azure PowerShell Context: $azCtx" -ForegroundColor Red
}

Write-Host "`n  [*] Entra reconnaissance complete." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        shell.run_with_interrupt(cmd, shell.write_line)
        return {"status": "completed"}
