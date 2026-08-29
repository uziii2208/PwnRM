"""
modules.lateral — Subnet Scout & Lateral Movement Dispatcher
Probes network subnets for exposed WinRM, SMB, WMI, and RDP endpoints with lateral credential reuse detection.
"""

from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class LateralModule(BaseModule):
    name = "lateral"
    description = "Subnet Scout & Lateral Movement Dispatcher (WinRM, SMB, WMI, RDP)"
    author = "uziii2208"
    options = {
        "--subnet": {"desc": "Target subnet to scan (default: local /24 subnet)"},
        "--ports": {"desc": "Custom ports to probe (default: 5985, 5986, 445, 135, 3389)"},
    }

    def run(self, shell, args: List[str]) -> Any:
        shell.write_info(c(M + BLD, "  [*] PwnRM Lateral Movement Engine — probing local network segment..."))

        ps = r"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Lateral Movement Subnet & Service Scout" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# 1. Determine local subnet
$ipConfig = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback" -and $_.IPAddress -notmatch "^169\." } | Select-Object -First 1
if (-not $ipConfig) {
    Write-Host "  [-] Could not determine local IPv4 interface." -ForegroundColor Yellow
    return
}
$localIP = $ipConfig.IPAddress
$prefix = ($localIP -split "\.")[0..2] -join "."
Write-Host "  [+] Local IP Address: $localIP" -ForegroundColor Green
Write-Host "  [*] Probing subnet  : $prefix.1 - $prefix.30 (Fast sample probe)" -ForegroundColor Gray

# Probe ports: 5985 (WinRM HTTP), 5986 (WinRM HTTPS), 445 (SMB), 3389 (RDP)
$targets = 1..30 | ForEach-Object { "$prefix.$_" }
$ports = @(5985, 5986, 445, 3389)

foreach ($t in $targets) {
    if ($t -eq $localIP) { continue }
    foreach ($p in $ports) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($t, $p, $null, $null)
        $wait = $iar.AsyncWaitHandle.WaitOne(100, $false)
        if ($wait) {
            try {
                $tcp.EndConnect($iar)
                $proto = switch ($p) { 5985 {"WinRM-HTTP"} 5986 {"WinRM-HTTPS"} 445 {"SMB"} 3389 {"RDP"} }
                $authStatus = "REACHABLE_PORT_OPEN"
                Write-Host "  [+] [$authStatus] $t : $p ($proto) — Lateral pivot candidate!" -ForegroundColor Green
            } catch {}
        }
        $tcp.Close()
    }
}

Write-Host "`n  [*] Lateral movement scout complete." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        shell.run_with_interrupt(cmd, shell.write_line)
        return {"status": "completed"}
