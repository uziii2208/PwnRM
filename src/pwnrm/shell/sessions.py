"""
shell.sessions — Session Scout PowerShell payload loader
"""

from pathlib import Path


def get_sessions_ps(quick: bool = False) -> str:
    """
    Load sessions.ps1 from resources/ and inject the -Quick flag.
    """
    resource_path = Path(__file__).parent.parent / "resources" / "sessions.ps1"
    with open(resource_path, "r", encoding="utf-8") as f:
        ps = f.read()
    return ps.replace("__QUICK__", "True" if quick else "False")
