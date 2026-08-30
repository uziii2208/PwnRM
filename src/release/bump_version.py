#!/usr/bin/env python3
"""
bump_version.py - PwnRM version bumper (auto-detect repo root)

Usage:
    python bump_version.py 2.1.1 [--dry]
"""
import re
import sys
import shutil
from pathlib import Path

SEMVER = re.compile(r"^\d+\.\d+\.\d+([\w.\-+]+)?$")


def find_repo_root() -> Path:
    """Accurately resolves repository root directory across execution contexts."""
    candidates = [
        Path(__file__).resolve().parent,
        Path.cwd().resolve()
    ]
    for start in candidates:
        p = start
        while True:
            if (p / "pyproject.toml").is_file() and (p / "src" / "pwnrm").is_dir():
                return p
            if p.parent == p:
                break
            p = p.parent
    sys.exit("[!] Cannot find repo root (pyproject.toml / src/pwnrm)")


ROOT = find_repo_root()

TARGETS = [
    ("pyproject.toml",        r'^version\s*=\s*"{old}"',         'version = "{new}"'),
    ("src/pwnrm/__init__.py", r'^__version__\s*=\s*"{old}"',     '__version__ = "{new}"'),
    ("src/pwnrm/shell/ui.py", r'\bv{old}\b',                     'v{new}'),
    ("src/pwnrm/core/api.py", r'PwnRM v{old}',                   'PwnRM v{new}'),
    ("README.md",             r'Changelog-v{old}',               'Changelog-v{new}'),
]


def read_old_version() -> str:
    proj_path = (ROOT / "pyproject.toml").resolve()
    if not proj_path.is_file():
        sys.exit("[!] pyproject.toml not found at repo root")
    text = proj_path.read_text(encoding="utf-8")
    m = re.search(r'^\s*version\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        sys.exit("[!] Cannot read current version from pyproject.toml")
    return m.group(1)


def cleanup_build_artifacts():
    print("[*] Cleaning build artifacts...")
    for d in ("dist", "build", "src/pwnrm.egg-info"):
        p = (ROOT / d).resolve()
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
    for p in ROOT.glob("src/**/__pycache__"):
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)


def main():
    args = sys.argv[1:]
    dry = "--dry" in args
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
        path = (ROOT / rel).resolve()
        if not path.is_file():
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