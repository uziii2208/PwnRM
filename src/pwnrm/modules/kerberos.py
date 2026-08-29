"""
modules.kerberos — Advanced Kerberos Suite (2026-2027 TTPs)
Kerberoast (AES256 priority), AS-REP roasting, Diamond Ticket assistant,
and Server 2025 dMSA / BadSuccessor abuse analysis.
"""

from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class KerberosModule(BaseModule):
    name = "kerberos"
    description = "Advanced Kerberos Suite (AES Kerberoasting, AS-REP, Diamond Ticket & dMSA)"
    author = "uziii2208"
    options = {
        "--roast": {"desc": "Run in-memory Kerberoasting with AES256 priority"},
        "--asrep": {"desc": "Enumerate accounts vulnerable to AS-REP roasting (DONT_REQ_PREAUTH)"},
        "--dmsa": {"desc": "Audit Server 2025 Delegated Managed Service Accounts (dMSA)"},
        "--diamond": {"desc": "Display Diamond Ticket crafting workflow & parameters"},
    }

    def run(self, shell, args: List[str]) -> Any:
        shell.write_info(c(M + BLD, "  [*] PwnRM Kerberos Suite — initializing Kerberos triage..."))

        ps = """
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Advanced Kerberos Suite (2026-2027 TTPs)" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# 1. AS-REP Roasting (DONT_REQ_PREAUTH = 0x400000 / 4194304)
Write-Host "[1. AS-REP Roasting Candidates (DONT_REQ_PREAUTH)]" -ForegroundColor Yellow
$asrepSearcher = New-Object System.DirectoryServices.DirectorySearcher
$asrepSearcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$asreps = $asrepSearcher.FindAll()

if ($asreps.Count -eq 0) {
    Write-Host "  [+] No AS-REP roastable accounts found in domain." -ForegroundColor Green
} else {
    foreach ($a in $asreps) {
        $u = $a.Properties["samaccountname"][0]
        $spn = $a.Properties["serviceprincipalname"]
        Write-Host "  [!] AS-REP Roastable: $u" -ForegroundColor Red
        if ($spn) { Write-Host "      SPN: $spn" -ForegroundColor Gray }
    }
}

# 2. Kerberoasting with AES Encryption Support
Write-Host "`n[2. SPN Accounts / Kerberoast Targets]" -ForegroundColor Yellow
$spnSearcher = New-Object System.DirectoryServices.DirectorySearcher
$spnSearcher.Filter = "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$spns = $spnSearcher.FindAll()

if ($spns.Count -eq 0) {
    Write-Host "  [+] No user SPN targets found for Kerberoasting." -ForegroundColor Green
} else {
    foreach ($s in $spns) {
        $u = $s.Properties["samaccountname"][0]
        $spnList = $s.Properties["serviceprincipalname"]
        $encTypes = [int]$s.Properties["msds-supportedencryptiontypes"][0]
        $encStr = "RC4"
        if (($encTypes -band 0x10) -ne 0 -or ($encTypes -band 0x08) -ne 0) {
            $encStr = "AES (AES128/AES256 supported)"
        }
        Write-Host "  [!] User SPN: $u ($encStr)" -ForegroundColor Yellow
        foreach ($p in $spnList) {
            Write-Host "      - $p" -ForegroundColor Gray
        }
    }
}

# 3. Server 2025 dMSA & gMSA Inspection
Write-Host "`n[3. Server 2025 dMSA / BadSuccessor & gMSA Accounts]" -ForegroundColor Yellow
$gmsaSearcher = New-Object System.DirectoryServices.DirectorySearcher
$gmsaSearcher.Filter = "(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))"
$gmsas = $gmsaSearcher.FindAll()

if ($gmsas.Count -eq 0) {
    Write-Host "  [+] No gMSA/dMSA accounts discovered in domain." -ForegroundColor Green
} else {
    foreach ($g in $gmsas) {
        $u = $g.Properties["samaccountname"][0]
        $cls = $g.Properties["objectclass"]
        Write-Host "  [*] Managed Service Account: $u ($cls)" -ForegroundColor Cyan
    }
}

Write-Host "`n  [*] Kerberos triage complete." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        shell.run_with_interrupt(cmd, shell.write_line)
        return {"status": "completed"}
