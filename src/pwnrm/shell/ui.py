"""
shell.ui — ANSI colors, banner, tab-completion word list
"""

# ── ANSI palette ─────────────────────────────────────────────────────────────
R   = "\x1b[31m";  G   = "\x1b[32m";  Y   = "\x1b[33m"
B   = "\x1b[34m";  M   = "\x1b[35m";  C   = "\x1b[36m"
W   = "\x1b[37m";  DIM = "\x1b[2m";   BLD = "\x1b[1m"
RST = "\x1b[0m"

def c(col, s):
    return f"{col}{s}{RST}"

# ── Banner ────────────────────────────────────────────────────────────────────
_BANNER = rf"""
{M}{BLD}
██████╗ ██╗    ██╗███╗   ██╗██████╗ ███╗   ███╗
██╔══██╗██║    ██║████╗  ██║██╔══██╗████╗ ████║
██████╔╝██║ █╗ ██║██╔██╗ ██║██████╔╝██╔████╔██║
██╔═══╝ ██║███╗██║██║╚██╗██║██╔══██╗██║╚██╔╝██║
██║     ╚███╔███╔╝██║ ╚████║██║  ██║██║ ╚═╝ ██║
╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝
{RST}{DIM}  Advanced WinRM / AD Post-Exploitation Shell  {BLD}v1.0.5{RST}
{DIM}  github.com/uziii2208/PwnRM  ·  For authorized engagements only.{RST}
"""

# ── Tab-completion word list ──────────────────────────────────────────────────
_COMPLETIONS = [
    "!download", "!upload", "!amsi", "!psrun", "!netrun",
    "!revshell", "!log", "!stoplog", "!adtriage", "!sysinfo",
    "!creds", "!help", "exit", "quit",
    # common PS one-liners operators may want fast access to:
    "Get-Process", "Get-Service", "whoami", "ipconfig", "net user",
    "net localgroup administrators", "systeminfo",
]