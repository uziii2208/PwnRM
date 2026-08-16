#!/bin/bash
# -----------------------------------------------------------------------------
#  PwnRM Release Automation Script (Linux)
#  Mirror of release.ps1 - automates the whole release pipeline:
#    1. Bump version (bump_version.py)
#    2. Create fresh venv (in temp dir, repo never polluted)
#    3. Build package (python -m build)
#    4. Verify version + packaged resources
#    5. Upload to PyPI (skipped with --dry)
#    6. --dry => rollback version bump + artifacts; always cleanup venv
#
#  Usage:
#    ./release.sh 1.0.3            # full release
#    ./release.sh 1.0.3 --dry      # everything except upload, then rollback
#    ./release.sh 1.0.3 --keep     # keep temp venv for debugging
# -----------------------------------------------------------------------------

set -Eeuo pipefail

# ---- Args --------------------------------------------------------------------
VERSION="${1:-}"
shift || true
DRY=0; KEEP=0
for arg in "$@"; do
    case "$arg" in
        --dry)  DRY=1 ;;
        --keep) KEEP=1 ;;
        *) echo "Unknown flag: $arg"; exit 1 ;;
    esac
done

if [[ -z "$VERSION" ]] || ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([a-zA-Z0-9.\-+]+)?$ ]]; then
    echo "Usage: ./release.sh <X.Y.Z> [--dry] [--keep]"
    exit 1
fi

# ---- Locate repo root: walk up until pyproject.toml is found ------------------
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT="$SCRIPT_DIR"
while [[ -n "$ROOT" && ! -f "$ROOT/pyproject.toml" ]]; do
    parent="$( dirname "$ROOT" )"
    if [[ "$parent" == "$ROOT" ]]; then ROOT=""; break; fi
    ROOT="$parent"
done
if [[ -z "$ROOT" ]]; then
    echo "[!] Cannot find repo root (pyproject.toml) above $SCRIPT_DIR" >&2
    exit 1
fi
cd "$ROOT"

BUMP_SCRIPT="$ROOT/bump_version.py"
if [[ ! -f "$BUMP_SCRIPT" ]]; then BUMP_SCRIPT="$SCRIPT_DIR/bump_version.py"; fi
if [[ ! -f "$BUMP_SCRIPT" ]]; then
    echo "[!] bump_version.py not found" >&2
    exit 1
fi

# venv lives in a temp dir so the repo is never polluted (no git accidents)
VENV_PATH="$(mktemp -d "${TMPDIR:-/tmp}/pwnrm_release_temp.XXXXXX")"
VENV_PY="$VENV_PATH/bin/python"
VENV_TWINE="$VENV_PATH/bin/twine"
DIST_PATH="$ROOT/dist"

# remember current version BEFORE bump (needed for --dry rollback)
OLD_VERSION="$(grep -m1 -E '^version[[:space:]]*=' pyproject.toml | cut -d'"' -f2)"

ROLLED_BACK=0

# ---- Colors / helpers ----------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

step() { echo -e "\n${CYAN}[*] $1${NC}"; }
ok()   { echo -e "${GREEN}[+] $1${NC}"; }
warn() { echo -e "${YELLOW}[!] $1${NC}"; }

cleanup() {
    if [[ $KEEP -eq 1 ]]; then
        warn "--keep set: keeping venv at $VENV_PATH"
        return
    fi
    step "Cleanup - deleting temporary venv"
    rm -rf "$VENV_PATH"
    ok "Venv deleted"
}

rollback() {
    if [[ $ROLLED_BACK -eq 1 ]]; then return; fi
    ROLLED_BACK=1
    if [[ -z "${OLD_VERSION:-}" ]]; then
        warn "Cannot rollback - old version unknown"
        return
    fi
    step "DryRun rollback - restoring version $OLD_VERSION"
    python3 "$BUMP_SCRIPT" "$OLD_VERSION" >/dev/null
    ok "Version strings + artifacts restored to $OLD_VERSION"
}

fail() {
    echo -e "${RED}[!] $1${NC}" >&2
    if [[ $DRY -eq 1 ]]; then rollback; fi
    cleanup
    exit 1
}

on_error() {
    local code=$?
    echo
    echo -e "${RED}[!] Release FAILED (exit $code) - cleaning up...${NC}"
    if [[ $DRY -eq 1 ]]; then rollback; fi
    cleanup
    exit "$code"
}
trap on_error ERR

echo -e "${MAGENTA}========================================${NC}"
echo -e "${MAGENTA}  PwnRM Release Automation (Linux)${NC}"
echo -e "${MAGENTA}  Target version: $VERSION  (repo root: $ROOT)${NC}"
echo -e "${MAGENTA}========================================${NC}"

# ---- Step 1: bump version -------------------------------------------------------
step "Step 1/6: Bumping version to $VERSION"
python3 "$BUMP_SCRIPT" "$VERSION" || fail "bump_version.py failed"
ok "Version bumped successfully"

# ---- Step 2: fresh venv + activate ------------------------------------------------
step "Step 2/6: Creating fresh virtual environment (in temp dir)"
command -v python3 >/dev/null 2>&1 || fail "python3 not found"
python3 -m venv "$VENV_PATH" || fail "Failed to create venv (missing python3-venv?)"
[[ -x "$VENV_PY" ]] || fail "venv python not found at $VENV_PY"
# "activate" for this session: prepend venv bin to PATH
export PATH="$VENV_PATH/bin:$PATH"
ok "Venv created + activated (PATH) at $VENV_PATH"

# ---- Step 3: build tools + build ----------------------------------------------------
step "Step 3/6: Installing build tools and building package"
# python -m pip (never bare pip) to avoid self-upgrade weirdness
"$VENV_PY" -m pip install --upgrade -q pip setuptools wheel \
    || warn "pip self-upgrade failed (non-fatal) - continuing"
"$VENV_PY" -m pip install -q build twine || fail "Failed to install build tools"

step "Cleaning old build artifacts"
for d in dist build src/pwnrm.egg-info; do
    if [[ -e "$ROOT/$d" ]]; then
        rm -rf "$ROOT/$d"
        ok "Deleted $d"
    fi
done

step "Building package from $ROOT"
"$VENV_PY" -m build || fail "Build failed"

WHEEL="$DIST_PATH/pwnrm-$VERSION-py3-none-any.whl"
TARBALL="$DIST_PATH/pwnrm-$VERSION.tar.gz"
[[ -f "$WHEEL"   ]] || fail "Wheel not found: $WHEEL"
[[ -f "$TARBALL" ]] || fail "Tarball not found: $TARBALL"
ok "Build successful"
ok "  Wheel   : $(basename "$WHEEL")   ($(du -h "$WHEEL"   | cut -f1))"
ok "  Tarball : $(basename "$TARBALL") ($(du -h "$TARBALL" | cut -f1))"

# ---- Step 4: verify --------------------------------------------------------------------
step "Step 4/6: Verifying version in built package"
"$VENV_PY" -m pip install -q "$WHEEL" || fail "Failed to install wheel"

"$VENV_PY" - "$VERSION" <<'EOF' || fail "Version or packaging verification failed"
import sys, pwnrm
from pathlib import Path
target = sys.argv[1]
assert pwnrm.__version__ == target, f"Version mismatch: {pwnrm.__version__} != {target}"
print(f"[OK] pwnrm v{pwnrm.__version__} verified")
ps1 = Path(pwnrm.__file__).parent / "resources" / "adtriage.ps1"
assert ps1.exists(), f"adtriage.ps1 not found at {ps1}"
print(f"[OK] adtriage.ps1 found ({ps1.stat().st_size} bytes)")
EOF
ok "All verifications passed"

# ---- Step 5: upload -----------------------------------------------------------------------
step "Step 5/6: Upload to PyPI"
if [[ $DRY -eq 1 ]]; then
    warn "DryRun mode - skipping PyPI upload"
    warn "Artifacts ready in $DIST_PATH"
else
    warn "Twine will prompt for your API token (username: __token__)"
    "$VENV_TWINE" upload "$DIST_PATH"/* || fail "PyPI upload failed"
    ok "Successfully uploaded to PyPI"
    ok "View at: https://pypi.org/project/pwnrm/$VERSION/"
fi

# ---- Step 6: rollback (dry) + cleanup --------------------------------------------------------
if [[ $DRY -eq 1 ]]; then rollback; fi
cleanup

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Release Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "Version   : ${CYAN}$VERSION${NC}"
echo -e "Artifacts : ${CYAN}$DIST_PATH${NC}"
if [[ $DRY -eq 1 ]]; then
    echo -e "Rolled back to: ${YELLOW}$OLD_VERSION (DryRun)${NC}"
else
    echo -e "PyPI      : ${CYAN}https://pypi.org/project/pwnrm/$VERSION/${NC}"
fi
echo
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. git add -A"
echo "  2. git commit -m \"release: v$VERSION\""
echo "  3. git tag v$VERSION"
echo "  4. git push origin master --tags"
echo "  5. Create GitHub Release for v$VERSION"
echo
echo -e "${MAGENTA}ENJOY YOUR MEAL!${NC}"