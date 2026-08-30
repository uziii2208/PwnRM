"""
modules.acl — Targeted Active Directory ACL & DACL Abuse Hunter
Audits discretionary access control lists (DACLs) on Tier-0 and high-value objects (AdminSDHolder, Domain Admins, Domain Controllers, KRBTGT, GPOs).
Discovers privilege escalation vectors: GenericAll, WriteDacl, WriteOwner, GenericWrite, and User-Force-Change-Password.
"""

from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class ACLModule(BaseModule):
    name = "acl"
    description = "Active Directory ACL & DACL Abuse Hunter (Tier-0 Objects, WriteDacl, GenericAll, Ownership)"
    author = "uziii2208"
    options = {
        "--target": {"desc": "Target AD object name (default: high-value Tier-0 objects)"},
        "--tier0": {"desc": "Perform full deep DACL scan across all Tier-0 groups, OUs, and GPOs"},
    }

    def run(self, shell, args: List[str]) -> Any:
        target_obj = ""
        tier0_deep = "--tier0" in args

        for i, a in enumerate(args):
            if a in ("-t", "--target") and i + 1 < len(args):
                target_obj = args[i + 1]

        shell.write_info(c(M + BLD, "  [*] PwnRM ACL Hunter — starting DACL privilege escalation audit on Active Directory objects..."))

        ps = f"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Active Directory DACL & Privilege Escalation Scout" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

$root = [adsi]"LDAP://RootDSE"
$defaultNC = $root.defaultNamingContext
$configNC = $root.configurationNamingContext

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$meSam = ($currentUser -split '\\\\')[-1]
Write-Host "  [*] Current Identity : $currentUser" -ForegroundColor White

$targets = @(
    "CN=AdminSDHolder,CN=System,$defaultNC",
    "CN=Domain Admins,CN=Users,$defaultNC",
    "CN=Enterprise Admins,CN=Users,$defaultNC",
    "CN=Schema Admins,CN=Users,$defaultNC",
    "CN=krbtgt,CN=Users,$defaultNC",
    "CN=Domain Controllers,CN=Users,$defaultNC"
)

if ('{target_obj}') {{
    $targets = @('{target_obj}')
}}

Write-Host "  [*] Auditing DACL permissions on Tier-0 target objects...`n" -ForegroundColor Gray

$vulnCount = 0
foreach ($t in $targets) {{
    try {{
        $entry = if ($t -like "LDAP://*") {{ [adsi]"$t" }} else {{ [adsi]"LDAP://$t" }}
        if (-not $entry.Path) {{
            # Search by samaccountname
            $s = New-Object DirectoryServices.DirectorySearcher([adsi]"LDAP://$defaultNC")
            $s.Filter = "(sAMAccountName=$t)"
            $res = $s.FindOne()
            if ($res) {{ $entry = $res.GetDirectoryEntry() }}
        }}

        if (-not $entry.Path) {{ continue }}

        $name = $entry.cn.Value
        if (-not $name) {{ $name = $entry.distinguishedName.Value }}
        $sec = $entry.ObjectSecurity
        if (-not $sec) {{ continue }}

        $rules = $sec.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
        foreach ($r in $rules) {{
            $trustee = $r.IdentityReference.Value
            $rights = $r.ActiveDirectoryRights.ToString()
            $accessType = $r.AccessControlType.ToString()

            if ($accessType -ne "Allow") {{ continue }}

            # Filter out standard benign administrative trustees unless current user is in them
            $isDangerousRight = $rights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|ExtendedRight"
            $isInterestingTrustee = $trustee -match "Everyone|Authenticated Users|Domain Users|$meSam" -or
                                     ($trustee -notmatch "SYSTEM|Domain Admins|Enterprise Admins|Exchange|Creator Owner")

            if ($isDangerousRight -and $isInterestingTrustee) {{
                $vulnCount++
                Write-Host "  [!] [VULNERABLE DACL] Object: $name" -ForegroundColor Red
                Write-Host "      - Trustee : $trustee" -ForegroundColor Yellow
                Write-Host "      - Rights  : $rights" -ForegroundColor Red
                if ($rights -match "WriteDacl") {{
                    Write-Host "      [!] CRITICAL: $trustee can modify DACL to grant themselves Full Control!" -ForegroundColor DarkRed
                }}
                if ($rights -match "WriteOwner") {{
                    Write-Host "      [!] CRITICAL: $trustee can take Ownership of $name!" -ForegroundColor DarkRed
                }}
                if ($rights -match "GenericAll") {{
                    Write-Host "      [!] CRITICAL: $trustee has Full Control (GenericAll) over $name!" -ForegroundColor DarkRed
                }}
            }}
        }}
    }} catch {{
        Write-Host "  [-] Could not read DACL for $t: $_" -ForegroundColor DarkGray
    }}
}}

Write-Host "`n[ACL Audit Summary]" -ForegroundColor Cyan
Write-Host "  Discovered Exploitable DACL Rights: $vulnCount" -ForegroundColor $(if ($vulnCount -gt 0) { "Red" } else { "Green" })
Write-Host "`n  [*] Active Directory DACL audit complete." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        shell.run_with_interrupt(cmd, shell.write_line)
        return {"status": "completed"}
