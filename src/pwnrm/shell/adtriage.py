"""
shell.adtriage — AD Triage PowerShell payload loader
"""

from pathlib import Path


def get_adtriage_ps(quick=False) -> str:
    """
    Load the AD Triage PowerShell script from resources/adtriage.ps1
    and inject the -Quick flag.
    """
    resource_path = Path(__file__).parent.parent / "resources" / "adtriage.ps1"
    with open(resource_path, "r", encoding="utf-8") as f:
        ps = f.read()
    return ps.replace("'__QUICK__'", "$true" if quick else "$false")