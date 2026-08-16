#!/usr/bin/env python3
"""
bump_version.py - PwnRM version bumper (auto-detect repo root)

Usage:
    python bump_version.py 1.0.2 [--dry]
"""
import re, sys, shutil
from pathlib import Path

SEMVER = re.compile(r"^\d+\.\d+\.\d+([\w.\-+]+)?$")

def find_repo_root():
    p = Path(__file__).resolve().parent
    while True:
        if (p / "pyproject.toml").exists():
            return p
        if p.parent == p:
            sys.exit("[!] Cannot find repo root (pyproject.toml)")
        p = p.parent

ROOT = find_repo_root()

TARGETS = [
    ("pyproject.toml",              r'^version\s*=\s*"{old}"',      'version = "{new}"'),
    ("src/pwnrm/__init__.py",       r'^__version__\s*=\s*"{old}"',  '__version__ = "{new}"'),
    ("src/pwnrm/shell/ui.py",       r'\bv{old}\b',                  'v{new}'),
    ("src/pwnrm/core/api.py",       r'PwnRM v{old}',                'PwnRM v{new}'),
    ("src/pwnrm/shell/pwnshell.py", r'^(\s*)VERSION\s*=\s*"{old}"', r'\g<1>VERSION = "{new}"'),
]

def read_old_version():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^\s*version\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        sys.exit("[!] Cannot read current version from pyproject.toml")
    return m.group(1)

def cleanup_build_artifacts():
    print("[*] Cleaning build artifacts...")
    for d in ("dist", "build", "src/pwnrm.egg-info"):
        p = ROOT / d
        if p.exists():
            shutil.rmtree(p)
    for p in ROOT.glob("src/**/__pycache__"):
        shutil.rmtree(p, ignore_errors=True)

def main():
    args = sys.argv[1:]
    dry  = "--dry" in args
    args = [a for a in args if a != "--dry"]

    if len(args) != 1 or not SEMVER.match(args[0]):
        sys.exit("Usage: python bump_version.py <X.Y.Z> [--dry]")

    new = args[0]
    old = read_old_version()
    if old == new:
        sys.exit(f"[*] Already at version {old} - nothing to do.")

    print(f"[*] Bumping {old} -> {new}" + (" (DRY RUN)" if dry else ""))
    if not dry:
        cleanup_build_artifacts()

    print("[*] Updating version strings...")
    changed = 0
    for rel, pat, rep in TARGETS:
        path = ROOT / rel
        if not path.exists():
            print(f"  [!] MISSING : {rel}")
            continue
        text = path.read_text(encoding="utf-8")
        new_text, n = re.subn(pat.format(old=re.escape(old)),
                              rep.format(new=new), text, flags=re.M)
        if n == 0:
            print(f"  [?] NO MATCH: {rel}  (check manually)")
        else:
            if not dry:
                path.write_text(new_text, encoding="utf-8")
            print(f"  [+] UPDATED : {rel}  ({n} replacement)")
            changed += n

    if changed == 0:
        sys.exit("[!] Nothing changed - abort.")
    print(f"[+] Done. {changed} occurrence(s) updated to {new}.")

if __name__ == "__main__":
    main()