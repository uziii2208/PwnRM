#!/usr/bin/env python3
"""
bump_version.py — PwnRM version bumper

Cập nhật version string ở TẤT CẢ các file tham chiếu nó:
  1. pyproject.toml              → version = "X.Y.Z"
  2. src/pwnrm/__init__.py       → __version__ = "X.Y.Z"
  3. src/pwnrm/shell/ui.py       → banner "vX.Y.Z"
  4. src/pwnrm/core/api.py       → description "PwnRM vX.Y.Z —"
  5. src/pwnrm/shell/pwnshell.py → VERSION = "X.Y.Z"

Usage:
    python bump_version.py 1.0.2 --dry   # chỉ preview, chưa ghi file
    python bump_version.py 1.0.2         # áp dụng thật
"""

import re
import sys
import shutil
from pathlib import Path

ROOT   = Path(__file__).resolve().parent
SEMVER = re.compile(r"^\d+\.\d+\.\d+([\w.\-+]+)?$")

# (file, pattern chứa {old}, replacement chứa {new})
TARGETS = [
    ("pyproject.toml",          r'^version\s*=\s*"{old}"',     'version = "{new}"'),
    ("src/pwnrm/__init__.py",   r'^__version__\s*=\s*"{old}"', '__version__ = "{new}"'),
    ("src/pwnrm/shell/ui.py",   r'\bv{old}\b',                 'v{new}'),
    ("src/pwnrm/core/api.py",   r'PwnRM v{old}',               'PwnRM v{new}'),
    ("src/pwnrm/shell/pwnshell.py", r'^VERSION\s*=\s*"{old}"', 'VERSION = "{new}"'),
]


def read_old_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        sys.exit("[!] Không đọc được version hiện tại từ pyproject.toml")
    return m.group(1)


def cleanup_build_artifacts():
    """Xóa __pycache__, dist, build, .egg-info"""
    patterns = [
        "src/**/__pycache__",
        "dist",
        "build", 
        "src/pwnrm.egg-info",
    ]
    
    cleaned = []
    for pattern in patterns:
        for path in ROOT.glob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
                cleaned.append(str(path.relative_to(ROOT)))
    
    if cleaned:
        print(f"  [+] Cleaned {len(cleaned)} directories:")
        for c in cleaned[:5]:  # Show first 5
            print(f"      - {c}")
        if len(cleaned) > 5:
            print(f"      ... and {len(cleaned) - 5} more")


def main():
    args = sys.argv[1:]
    dry  = "--dry" in args
    args = [a for a in args if a != "--dry"]

    if len(args) != 1 or not SEMVER.match(args[0]):
        sys.exit("Usage: python bump_version.py <X.Y.Z> [--dry]")

    new = args[0]
    old = read_old_version()

    if old == new:
        sys.exit(f"[*] Đã ở version {old} — không có gì để làm.")

    print(f"[*] Bumping {old} -> {new}" + (" (DRY RUN)" if dry else ""))
    print()

    # Cleanup build artifacts first
    if not dry:
        print("[*] Cleaning build artifacts...")
        cleanup_build_artifacts()
        print()

    # Update version strings
    print("[*] Updating version strings...")
    changed = 0
    for rel, pat, rep in TARGETS:
        path = ROOT / rel
        if not path.exists():
            print(f"  [!] MISSING : {rel}")
            continue

        text = path.read_text(encoding="utf-8")
        new_text, n = re.subn(
            pat.format(old=re.escape(old)),
            rep.format(new=new),
            text,
            flags=re.M,
        )

        if n == 0:
            print(f"  [?] NO MATCH: {rel}  (kiểm tra tay)")
        else:
            if not dry:
                path.write_text(new_text, encoding="utf-8")
            print(f"  [+] UPDATED : {rel}  ({n} replacement)")
            changed += n

    if changed == 0:
        sys.exit("[!] Không thay đổi gì — abort.")

    print()
    print(f"[+] Done. {changed} vị trí đã cập nhật sang {new}.")

    if not dry:
        print(f"""
Next steps:
  1. python -m build
  2. twine upload dist/*
  3. git add -A && git commit -m "release: v{new}"
  4. git tag v{new} && git push origin master --tags
""")


if __name__ == "__main__":
    main()