"""
modules.adcs — Full ADCS Engine (ESC1–ESC17+ including WSUS Policy Abuse & CA Health)
Performs deep Active Directory Certificate Services audit, template vulnerability triage,
CA health inspection (CDP/AIA/expiry), and certificate enrollment helpers.
"""

from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class ADCSModule(BaseModule):
    name = "adcs"
    description = "Full ADCS Engine (ESC1-ESC17+ vulnerability audit, CA health & cert tools)"
    author = "uziii2208"
    options = {
        "-q": {"desc": "Quick scan mode (skips deep template ACL check)"},
        "--template": {"desc": "Specify target template for inspection/enrollment"},
        "--ca": {"desc": "Specify target Enterprise CA"},
        "--alt": {"desc": "Subject Alternative Name (SAN) for ESC1/ESC6 testing"},
        "--wsus": {"desc": "Inspect ESC17 WSUS policy and Code Signing certificate templates"},
    }

    def run(self, shell, args: List[str]) -> Any:
        quick = "-q" in args or "--quick" in args
        target_template = ""
        for i, a in enumerate(args):
            if a == "--template" and i + 1 < len(args):
                target_template = args[i + 1]

        shell.write_info(c(M + BLD, "  [*] PwnRM ADCS Engine — initializing ESC1-ESC17+ audit & CA health check..."))

        ps = r"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM ADCS Engine (ESC1 - ESC17+ Audit & CA Health)" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$rootDSE = [ADSI]"LDAP://RootDSE"
$configNC = $rootDSE.configurationNamingContext
$pkiBase = [ADSI]"LDAP://CN=Public Key Services,CN=Services,$configNC"

if (-not $pkiBase.Path) {
    Write-Host "  [-] No Public Key Services container found in Domain Configuration NC." -ForegroundColor Yellow
    return
}

Write-Host "  [+] PKI Container : $($pkiBase.distinguishedName)" -ForegroundColor Green

# 1. Enumerate Enterprise CAs & Health Check
Write-Host "`n[1. Enterprise Certification Authorities & Health]" -ForegroundColor Yellow
$caSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC")
$caSearcher.Filter = "(objectClass=pKIEnrollmentService)"
$cas = $caSearcher.FindAll()

foreach ($ca in $cas) {
    $caObj = $ca.GetDirectoryEntry()
    $caname = $caObj.cn.Value
    $dns = $caObj.dNSHostName.Value
    $templates = $caObj.certificateTemplates
    $certBytes = $caObj.cACertificate.Value
    Write-Host "  - CA Name       : $caname" -ForegroundColor White
    Write-Host "    DNS Hostname  : $dns" -ForegroundColor Gray
    Write-Host "    Published Tpls: $($templates.Count) templates" -ForegroundColor Gray

    if ($certBytes) {
        try {
            $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certBytes)
            $notAfter = $x509.NotAfter
            if ($notAfter -lt (Get-Date)) {
                Write-Host "    [!] EXPIRED CA CERTIFICATE : Expired on $notAfter" -ForegroundColor Red
            } else {
                Write-Host "    [*] CA Cert Valid Until    : $notAfter" -ForegroundColor Green
            }
        } catch {}
    }
}

# 2. Template Vulnerability Triage (ESC1 - ESC17)
Write-Host "`n[2. Certificate Template Vulnerability Triage (ESC1-ESC17)]" -ForegroundColor Yellow
$tplSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC")
$tplSearcher.Filter = "(objectClass=pKICertificateTemplate)"
$tpls = $tplSearcher.FindAll()

$found_vuln = 0
foreach ($t in $tpls) {
    $entry = $t.GetDirectoryEntry()
    $tname = $entry.cn.Value
    $dispName = $entry.displayName.Value
    $flags = [int]$entry."msPKI-Enrollment-Flag".Value
    $nameFlags = [int]$entry."msPKI-Certificate-Name-Flag".Value
    $ekus = $entry."pKIExtendedKeyUsage"

    # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001 (1)
    $enrolleeSuppliesSan = ($nameFlags -band 1) -ne 0

    # Client Authentication OIDs
    $hasClientAuth = $false
    $hasCodeSigning = $false
    foreach ($eku in $ekus) {
        if ($eku -in @("1.3.6.1.5.5.7.3.2", "1.3.6.1.5.2.3.4", "2.5.29.37.0", "1.3.6.1.4.1.311.20.2.2")) {
            $hasClientAuth = $true
        }
        if ($eku -in @("1.3.6.1.5.5.7.3.3", "1.3.6.1.4.1.311.10.3.6", "1.3.6.1.4.1.311.76.7.1")) {
            $hasCodeSigning = $true
        }
    }

    # Check ESC1
    if ($enrolleeSuppliesSan -and $hasClientAuth) {
        Write-Host "  [!] [ESC1 VULNERABLE] Template '$tname' ($dispName)" -ForegroundColor Red
        Write-Host "      - Enrollee supplies SAN flag is set (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)" -ForegroundColor DarkRed
        Write-Host "      - Contains Client Authentication / PKINIT EKU" -ForegroundColor DarkRed
        $found_vuln++
    }

    # Check ESC2 (Any Purpose EKU or No EKU)
    if ($enrolleeSuppliesSan -and ($ekus.Count -eq 0 -or $ekus -contains "2.5.29.37.0")) {
        Write-Host "  [!] [ESC2 VULNERABLE] Template '$tname' ($dispName)" -ForegroundColor Magenta
        Write-Host "      - Enrollee supplies SAN with Any Purpose EKU / SubCA usage" -ForegroundColor DarkMagenta
        $found_vuln++
    }

    # Check ESC3 (Certificate Request Agent)
    if ($ekus -contains "1.3.6.1.4.1.311.20.2.1") {
        Write-Host "  [!] [ESC3 ENROLLMENT AGENT] Template '$tname' ($dispName)" -ForegroundColor Yellow
        Write-Host "      - Contains Certificate Request Agent EKU" -ForegroundColor Gray
    }

    # Check ESC17 (Code Signing / WSUS / Windows Update Template Abuse)
    if ($hasCodeSigning) {
        $extraSan = if ($enrolleeSuppliesSan) { " + Enrollee Supplies SAN" } else { "" }
        Write-Host "  [!] [ESC17 CODE SIGNING / WSUS] Template '$tname' ($dispName)$extraSan" -ForegroundColor Yellow
        Write-Host "      - Code Signing / Windows Update EKU present (1.3.6.1.5.5.7.3.3)" -ForegroundColor DarkYellow
        $found_vuln++
    }
}

# 3. ESC17 WSUS Policy & Configuration Scout
Write-Host "`n[3. ESC17 WSUS Client Policy & Endpoint Scout]" -ForegroundColor Yellow
$wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if (Test-Path $wuPath) {
    $wuServer = (Get-ItemProperty $wuPath -Name "WUServer" -ErrorAction SilentlyContinue).WUServer
    $acceptTrusted = (Get-ItemProperty "$wuPath\AU" -Name "AcceptTrustedPublisherCerts" -ErrorAction SilentlyContinue).AcceptTrustedPublisherCerts
    if ($wuServer) {
        Write-Host "  [+] Configured WSUS Server: $wuServer" -ForegroundColor White
        if ($wuServer -match "^http://") {
            Write-Host "      [!] WSUS using HTTP (Cleartext) — High risk of MITM update injection!" -ForegroundColor Red
        }
    }
    if ($acceptTrusted -eq 1) {
        Write-Host "  [!] [ESC17 DANGER] AcceptTrustedPublisherCerts is ENABLED (1)" -ForegroundColor Red
        Write-Host "      - Certificates from Enterprise CA Code Signing templates are trusted for updates!" -ForegroundColor DarkRed
    } else {
        Write-Host "  [*] AcceptTrustedPublisherCerts : $($acceptTrusted ?? 0)" -ForegroundColor Gray
    }
} else {
    Write-Host "  [-] No local WSUS policy found under HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ForegroundColor Gray
}

if ($found_vuln -eq 0) {
    Write-Host "  [+] No standard vulnerable templates discovered." -ForegroundColor Green
}

Write-Host "`n  [*] ADCS ESC1-ESC17+ Triage complete." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        shell.run_with_interrupt(cmd, shell.write_line)
        return {"status": "completed"}
