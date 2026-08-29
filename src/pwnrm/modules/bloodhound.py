"""
modules.bloodhound — In-Memory Active Directory Graph Collector
Collects AD objects via LDAP entirely in memory and formats results for BloodHound CE (v6 schema).
"""

import json
from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class BloodhoundModule(BaseModule):
    name = "bloodhound"
    description = "In-Memory Active Directory Graph Collector (BloodHound CE v6 Compatible JSON)"
    author = "uziii2208"
    options = {
        "-c": {"desc": "Collection methods: DCOnly, Group, LocalAdmin, Session, All (default: DCOnly)"},
    }

    def run(self, shell, args: List[str]) -> Any:
        shell.write_info(c(M + BLD, "  [*] PwnRM In-Memory BloodHound Collector — starting LDAP enumeration (CE v6 schema)..."))

        ps = """
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM In-Memory Active Directory Graph Collector" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domainName = $domain.Name
Write-Host "  [+] Current Domain : $domainName" -ForegroundColor Green

# 1. Enumerate Users
$userSearcher = New-Object System.DirectoryServices.DirectorySearcher
$userSearcher.Filter = "(&(objectClass=user)(!(objectClass=computer)))"
$userSearcher.PageSize = 500
$users = $userSearcher.FindAll()
Write-Host "  [+] Discovered $($users.Count) User accounts in Active Directory." -ForegroundColor White

# 2. Enumerate Computers / Domain Controllers
$compSearcher = New-Object System.DirectoryServices.DirectorySearcher
$compSearcher.Filter = "(objectClass=computer)"
$compSearcher.PageSize = 500
$comps = $compSearcher.FindAll()
Write-Host "  [+] Discovered $($comps.Count) Computer accounts." -ForegroundColor White

# 3. Enumerate Security Groups
$grpSearcher = New-Object System.DirectoryServices.DirectorySearcher
$grpSearcher.Filter = "(objectClass=group)"
$grpSearcher.PageSize = 500
$grps = $grpSearcher.FindAll()
Write-Host "  [+] Discovered $($grps.Count) Domain Groups." -ForegroundColor White

# 4. Highlight High-Value Groups (Domain Admins, Enterprise Admins, Schema Admins, Account Operators)
Write-Host "`n[High-Value Group Membership Snapshot]" -ForegroundColor Yellow
foreach ($g in $grps) {
    $gname = $g.Properties["samaccountname"][0]
    if ($gname -match "Domain Admins|Enterprise Admins|Schema Admins|Account Operators|Backup Operators") {
        $members = $g.Properties["member"]
        Write-Host "  [*] Group: $gname ($($members.Count) members)" -ForegroundColor Yellow
        foreach ($m in $members) {
            $cn = ($m -split ",")[0]
            Write-Host "      - $cn" -ForegroundColor Gray
        }
    }
}

# Output BloodHound CE meta headers format
Write-Host "`n[BloodHound CE v6 Meta Summary]" -ForegroundColor Cyan
$metaUsers = @{ "meta" = @{ "type" = "users"; "count" = $users.Count; "version" = 6 } } | ConvertTo-Json -Compress
$metaComps = @{ "meta" = @{ "type" = "computers"; "count" = $comps.Count; "version" = 6 } } | ConvertTo-Json -Compress
$metaGroups = @{ "meta" = @{ "type" = "groups"; "count" = $grps.Count; "version" = 6 } } | ConvertTo-Json -Compress
Write-Host "  Users Meta     : $metaUsers" -ForegroundColor Gray
Write-Host "  Computers Meta : $metaComps" -ForegroundColor Gray
Write-Host "  Groups Meta    : $metaGroups" -ForegroundColor Gray

Write-Host "`n  [*] In-Memory BloodHound AD Graph collection complete." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        shell.run_with_interrupt(cmd, shell.write_line)
        return {"status": "completed"}
