# ── AD Triage PowerShell payloads ─────────────────────────────────────────────
# Self-contained LDAP/WMI enumeration that runs entirely inside the remote
# PowerShell session — no extra tools required on the target.

function Invoke-PwnRMTriage {
    param([switch]$Quick)
    $sep = '=' * 72
    function hdr($t) { Write-Host "`n$sep`n  [*] $t`n$sep" -ForegroundColor Cyan }
    function ok($m)  { Write-Host "  [+] $m" -ForegroundColor Green }
    function inf($m) { Write-Host "  [-] $m" }
    function wrn($m) { Write-Host "  [!] $m" -ForegroundColor Yellow }

    # ── 0. Basic identity ────────────────────────────────────────────────────
    hdr "Identity & Session"
    $me = [Security.Principal.WindowsIdentity]::GetCurrent()
    ok  "User     : $($me.Name)"
    ok  "SID      : $($me.User)"
    $groups = $me.Groups | ForEach-Object { try { $_.Translate([Security.Principal.NTAccount]).Value } catch { $_.Value } }
    ok  "Groups   : $($groups -join ', ')"
    $privs = whoami /priv 2>$null | Select-String "Se\w+" | ForEach-Object { ($_ -split '\s{2,}')[0].Trim() }
    ok  "Privs    : $($privs -join ', ')"

    # ── 1. Domain basics ─────────────────────────────────────────────────────
    hdr "Domain Basics"
    try {
        $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        ok  "Domain   : $($dom.Name)"
        ok  "Forest   : $($dom.Forest.Name)"
        $dcs = $dom.DomainControllers | Select -Expand Name
        ok  "DCs      : $($dcs -join ', ')"
        $trusts = $dom.GetAllTrustRelationships()
        if ($trusts) { $trusts | ForEach-Object { wrn "Trust → $($_.TargetName)  [$($_.TrustType) / $($_.TrustDirection)]" } }
        else { inf "No external trusts found." }

        # ── OS version check → flag Server 2025 (BadSuccessor) ──────────────
        foreach ($dc in $dom.DomainControllers) {
            $os = $dc.OSVersion
            if ($os -match "2025") {
                wrn "DC $($dc.Name) runs Windows Server 2025 → check BadSuccessor (dMSA)!"
            } else { inf "DC $($dc.Name) OS: $os" }
        }
    } catch { wrn "Could not query domain: $_" }

    if ($Quick) { return }

    # ── 2. High-value groups ──────────────────────────────────────────────────
    hdr "High-Value Group Members"
    $hvg = @("Domain Admins","Enterprise Admins","Schema Admins",
             "Administrators","Account Operators","Backup Operators",
             "DNSAdmins","Group Policy Creator Owners","Remote Management Users")
    $root = "LDAP://$(([adsi]'').distinguishedName)"
    foreach ($g in $hvg) {
        try {
            $grp = [adsi]"LDAP://CN=$g,CN=Users,$(([adsi]'').distinguishedName)"
            if (-not $grp.Path) {
                # Try common OUs
                $s = New-Object DirectoryServices.DirectorySearcher([adsi]$root)
                $s.Filter = "(&(objectCategory=group)(cn=$g))"
                $grp = $s.FindOne().GetDirectoryEntry()
            }
            $members = @($grp.member)
            if ($members.Count -gt 0) {
                ok "$g ($($members.Count) member(s)):"
                $members | ForEach-Object { inf "    $_" }
            }
        } catch { }
    }

    # ── 3. Kerberoastable SPNs ────────────────────────────────────────────────
    hdr "Kerberoastable Accounts (SPNs on user objects)"
    $s = New-Object DirectoryServices.DirectorySearcher([adsi]$root)
    $s.Filter = "(&(objectCategory=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $s.PropertiesToLoad.AddRange(@("sAMAccountName","servicePrincipalName","memberOf","adminCount","pwdLastSet"))
    $s.PageSize = 1000
    $res = $s.FindAll()
    if ($res.Count -eq 0) { inf "None found." }
    $res | ForEach-Object {
        $sam  = $_.Properties["samaccountname"][0]
        $spns = $_.Properties["serviceprincipalname"]
        $adm  = if ($_.Properties["admincount"][0] -eq 1) { " [adminCount=1!]" } else { "" }
        ok "${sam}${adm}"
        $spns | ForEach-Object { inf "    SPN: $_" }
    }

    # ── 4. AS-REP roastable accounts ─────────────────────────────────────────
    hdr "AS-REP Roastable (DONT_REQ_PREAUTH)"
    $s.Filter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $s.PropertiesToLoad.Clear(); $s.PropertiesToLoad.AddRange(@("sAMAccountName","distinguishedName"))
    $res = $s.FindAll()
    if ($res.Count -eq 0) { inf "None found." } else { $res | ForEach-Object { ok $_.Properties["samaccountname"][0] } }

    # ── 5. Unconstrained delegation ───────────────────────────────────────────
    hdr "Unconstrained Delegation"
    $s.Filter = "(&(|(objectCategory=computer)(objectCategory=user))(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $s.PropertiesToLoad.Clear(); $s.PropertiesToLoad.AddRange(@("sAMAccountName","objectCategory"))
    $res = $s.FindAll()
    if ($res.Count -eq 0) { inf "None found." }
    $res | ForEach-Object {
        wrn "$($_.Properties["samaccountname"][0])  ← coerce + capture TGT → DCSync"
    }

    # ── 6. Constrained delegation (including S4U2Self) ────────────────────────
    hdr "Constrained Delegation (msDS-AllowedToDelegateTo)"
    $s.Filter = "(msDS-AllowedToDelegateTo=*)"
    $s.PropertiesToLoad.Clear(); $s.PropertiesToLoad.AddRange(@("sAMAccountName","msDS-AllowedToDelegateTo","userAccountControl"))
    $res = $s.FindAll()
    if ($res.Count -eq 0) { inf "None found." }
    $res | ForEach-Object {
        $proto = if (($_.Properties["useraccountcontrol"][0] -band 0x1000000) -ne 0) { "(Protocol-Transition / S4U2Self)" } else { "" }
        ok "$($_.Properties["samaccountname"][0]) $proto"
        $_.Properties["msds-allowedtodelegateto"] | ForEach-Object { inf "    → $_" }
    }

    # ── 7. Resource-Based Constrained Delegation ──────────────────────────────
    hdr "RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity set)"
    $s.Filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
    $s.PropertiesToLoad.Clear(); $s.PropertiesToLoad.AddRange(@("sAMAccountName","distinguishedName"))
    $res = $s.FindAll()
    if ($res.Count -eq 0) { inf "None found." }
    $res | ForEach-Object { wrn "$($_.Properties["samaccountname"][0])  ← RBCD writable" }

    # ── 8. ADCS — Certificate Templates ──────────────────────────────────────
    hdr "ADCS — Vulnerable Certificate Templates (ESC1/ESC3/ESC4 quick scan)"
    try {
        $pki = "CN=Configuration," + ([adsi]'').distinguishedName
        $s2  = New-Object DirectoryServices.DirectorySearcher([adsi]"LDAP://$pki")
        $s2.Filter = "(objectClass=pKICertificateTemplate)"
        $s2.PropertiesToLoad.AddRange(@("cn","msPKI-Certificate-Name-Flag","msPKI-Enrollment-Flag","pKIExtendedKeyUsage","nTSecurityDescriptor"))
        $s2.PageSize = 500
        $tpls = $s2.FindAll()
        $esc_count = 0
        $tpls | ForEach-Object {
            $cn    = $_.Properties["cn"][0]
            $cnf   = [int]$_.Properties["mspki-certificate-name-flag"][0]
            $enf   = [int]$_.Properties["mspki-enrollment-flag"][0]
            $ekus  = @($_.Properties["pkiextendedkeyusage"])
            # ESC1: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x1) + client auth EKU
            $clientAuth = $ekus -contains "1.3.6.1.5.5.7.3.2"
            if (($cnf -band 0x1) -and $clientAuth) {
                wrn "ESC1 candidate : $cn  (enrollee supplies SAN + Client Auth)"
                $esc_count++
            }
            # ESC3: Certificate Request Agent EKU
            if ($ekus -contains "1.3.6.1.4.1.311.20.2.1") {
                wrn "ESC3 candidate : $cn  (Certificate Request Agent EKU)"
                $esc_count++
            }
            # ESC4: if WRITE rights for low-priv — need ACL inspection
            if ($enf -band 0x200) {   # CT_FLAG_PUBLISHED_IN_DS
                inf "Template $cn is published — check ACLs with Certipy for ESC4/ESC9"
            }
        }
        if ($esc_count -eq 0) { inf "No obvious ESC1/ESC3 templates. Run Certipy for full ADCS audit." }
    } catch { inf "Could not enumerate ADCS (not joined to PKI or no ADCS role): $_" }

    # ── 9. gMSA / dMSA accounts ───────────────────────────────────────────────
    hdr "gMSA / dMSA Accounts"
    $s.Filter = "(objectClass=msDS-GroupManagedServiceAccount)"
    $s.PropertiesToLoad.Clear(); $s.PropertiesToLoad.AddRange(@("sAMAccountName","msDS-GroupMSAMembership","distinguishedName"))
    $gmsa = $s.FindAll()
    if ($gmsa.Count -eq 0) { inf "No gMSA found." }
    $gmsa | ForEach-Object {
        ok "gMSA: $($_.Properties["samaccountname"][0])"
        inf "    DN: $($_.Properties["distinguishedname"][0])"
    }
    $s.Filter = "(objectClass=msDS-DelegatedManagedServiceAccount)"
    $dmsa = $s.FindAll()
    if ($dmsa.Count -eq 0) { inf "No dMSA found." }
    $dmsa | ForEach-Object {
        wrn "dMSA: $($_.Properties["samaccountname"][0]) ← potential BadSuccessor target"
    }

    # ── 10. ACL quick-wins (WriteDACL / GenericAll / GenericWrite) ────────────
    hdr "ACL Quick-Wins (DA/EA/DC objects)"
    # Check if current user has interesting rights on DA/DC objects
    $targets = @("Domain Admins","Domain Controllers","krbtgt")
    $me_sam  = ($me.Name -split '\\')[-1]
    foreach ($t in $targets) {
        try {
            $obj  = (New-Object DirectoryServices.DirectorySearcher([adsi]$root,"(sAMAccountName=$t)")).FindOne()
            if ($obj) {
                $de   = $obj.GetDirectoryEntry()
                $acl  = $de.ObjectSecurity.Access
                $hit  = $acl | Where-Object {
                    ($_.IdentityReference -match [regex]::Escape($me_sam) -or
                     $_.IdentityReference -match "Everyone|Authenticated Users") -and
                    ($_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword")
                }
                if ($hit) { $hit | ForEach-Object { wrn "ACL on $t : $($_.IdentityReference) → $($_.ActiveDirectoryRights)" } }
                else { inf "No obvious writable ACLs on $t for current identity." }
            }
        } catch { }
    }

    # ── 11. Pre-Windows 2000 compatible access ────────────────────────────────
    hdr "Pre-Windows 2000 Compatible Access"
    try {
        $compat = [adsi]"LDAP://CN=Pre-Windows 2000 Compatible Access,CN=Builtin,$($([adsi]'').distinguishedName)"
        $members = $compat.member
        if ($members -match "S-1-1-0|S-1-5-7") {
            wrn "Anonymous / Everyone in 'Pre-Windows 2000 Compatible Access' → anonymous LDAP reads possible!"
        } else { inf "Group appears restricted." }
    } catch { }

    # ── 12. Enabled local Administrators check ────────────────────────────────
    hdr "Local Admin Candidates (enabled, password never expires)"
    $s.Filter = "(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=65536)(adminCount=1))"
    $s.PropertiesToLoad.Clear(); $s.PropertiesToLoad.AddRange(@("sAMAccountName","distinguishedName","pwdLastSet"))
    $res = $s.FindAll()
    if ($res.Count -eq 0) { inf "None found." }
    $res | ForEach-Object {
        $pls = $_.Properties["pwdlastset"][0]
        $d   = if ($pls) { [datetime]::FromFileTime($pls).ToString("yyyy-MM-dd") } else { "never" }
        wrn "$($_.Properties["samaccountname"][0])  ← password never expires, last set: $d"
    }

    Write-Host "`n$sep" -ForegroundColor Cyan
    Write-Host "  [*] Triage complete. Next steps:" -ForegroundColor Cyan
    Write-Host "  [-]  Kerberoast : GetUserSPNs.py / nxc ldap -M kerberoast" -ForegroundColor White
    Write-Host "  [-]  AS-REP     : GetNPUsers.py / nxc ldap --asreproast" -ForegroundColor White
    Write-Host "  [-]  ADCS       : certipy find --vulnerable / nxc ldap -M adcs" -ForegroundColor White
    Write-Host "  [-]  BadSucces. : nxc ldap -M badsuccessor (Server 2025 DCs)" -ForegroundColor White
    Write-Host "  [-]  BloodHound : bloodhound-python -d DOMAIN -u user -p pass" -ForegroundColor White
    Write-Host "$sep`n" -ForegroundColor Cyan
}

Invoke-PwnRMTriage -Quick:$([bool]::Parse('__QUICK__'))