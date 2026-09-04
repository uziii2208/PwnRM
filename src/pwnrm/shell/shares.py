"""
shell.shares — Share Scout PowerShell payload loader
"""

from pathlib import Path
from typing import Optional, List


def get_shares_ps(quick: bool = False, targets: Optional[List[str]] = None) -> str:
    """
    Load shares.ps1 from resources/, inject -Quick and -Targets flags.

    targets: list of hostnames/IPs to scan. Empty list → auto-discover via AD.
    """
    resource_path = Path(__file__).parent.parent / "resources" / "shares.ps1"
    with open(resource_path, "r", encoding="utf-8") as f:
        ps = f.read()

    ps = ps.replace("__QUICK__", "True" if quick else "False")

    if targets:
        # [NICHE AUDIT 2 FIX] Embed as PS string array with proper single-quote escaping: @('host1','host2')
        target_str = ",".join("'" + t.strip().replace("'", "''") + "'" for t in targets if t.strip())
        ps = ps.replace("'__TARGETS__'", target_str)
    else:
        # Replace the entire @('__TARGETS__') expression so the result is @()
        # not @('') — a one-element array that bypasses both discovery branches.
        ps = ps.replace("@('__TARGETS__')", "@()")

    return ps
