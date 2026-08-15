#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  PwnRM Installation Script for Linux
#  Supports: Kali, Ubuntu, Debian & derivatives
#
#  Mode 1: git clone + sudo ./install.sh   → editable install into venv
#  Mode 2: pip install pwnrm               → from PyPI (no script needed)
# ─────────────────────────────────────────────────────────────────────────────
set -e

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  PwnRM Installation Script${NC}"
echo -e "${GREEN}================================${NC}"
echo

# ── 0. Root check ────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This script must be run as root${NC}"
    echo "Please run: sudo bash install.sh"
    exit 1
fi

# ── 1. Detect / install Python 3 ─────────────────────────────────────────────
echo -e "${YELLOW}[*] Detecting Python version...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 is not installed${NC}"
    echo -e "${YELLOW}[*] Installing Python 3...${NC}"
    apt-get update
    apt-get install -y python3 python3-pip python3-venv
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d'.' -f2)
echo -e "${GREEN}[+] Python ${PYTHON_VERSION} found${NC}"

if [[ "$PYTHON_MINOR" -lt 9 ]]; then
    echo -e "${RED}[!] PwnRM requires Python >= 3.9 (found ${PYTHON_VERSION})${NC}"
    exit 1
fi

# ── 2. System dependencies ───────────────────────────────────────────────────
echo -e "${YELLOW}[*] Installing system dependencies...${NC}"
apt-get update
apt-get install -y git build-essential libssl-dev libffi-dev python3-dev

# ── 3. Locate project & sanity check ─────────────────────────────────────────
INSTALL_DIR="/opt/pwnrm"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ ! -f "$SCRIPT_DIR/pyproject.toml" ]; then
    echo -e "${RED}[!] pyproject.toml not found in ${SCRIPT_DIR}${NC}"
    echo -e "${RED}[!] Make sure you are running install.sh from the PwnRM repo root${NC}"
    exit 1
fi

if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}[*] Copying project to ${INSTALL_DIR}...${NC}"
    mkdir -p "$INSTALL_DIR"
    cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
    cd "$INSTALL_DIR"
else
    cd "$INSTALL_DIR"
fi

# ── 4. Create / reuse virtual environment ────────────────────────────────────
echo -e "${YELLOW}[*] Creating Python virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}[+] Virtual environment created${NC}"
else
    echo -e "${GREEN}[+] Virtual environment already exists${NC}"
fi

VENV_PYTHON="$INSTALL_DIR/venv/bin/python3"
VENV_PIP="$INSTALL_DIR/venv/bin/pip"

# ── 5. Upgrade pip / setuptools / wheel ──────────────────────────────────────
echo -e "${YELLOW}[*] Upgrading pip, setuptools, wheel...${NC}"
"$VENV_PYTHON" -m pip install --upgrade pip setuptools wheel
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Failed to upgrade pip${NC}"
    exit 1
fi

# ── 6. Install PwnRM as editable package ─────────────────────────────────────
echo -e "${YELLOW}[*] Installing PwnRM (editable mode)...${NC}"
"$VENV_PIP" install -e .
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Failed to install PwnRM package${NC}"
    exit 1
fi
echo -e "${GREEN}[+] PwnRM package installed${NC}"

# ── 7. Verify installation ───────────────────────────────────────────────────
echo -e "${YELLOW}[*] Verifying installation...${NC}"

if [ -f "$INSTALL_DIR/venv/bin/pwnrm" ]; then
    echo -e "${GREEN}[+] CLI entry point found: venv/bin/pwnrm${NC}"
else
    echo -e "${RED}[!] CLI entry point NOT found${NC}"
    exit 1
fi

"$VENV_PYTHON" -c "
from pwnrm import __version__
from pwnrm.core import Runspace, create_transport, argument_parser
from pwnrm.shell import PwnShell
print(f'[+] PwnRM v{__version__} — all modules loaded successfully')
"
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Import verification FAILED${NC}"
    exit 1
fi

# ── 8. Create system-wide wrapper ─────────────────────────────────────────────
echo -e "${YELLOW}[*] Creating system-wide wrapper at /usr/local/bin/pwnrm...${NC}"
cat > /usr/local/bin/pwnrm << 'EOF'
#!/bin/bash
# PwnRM Wrapper Script
INSTALL_DIR="/opt/pwnrm"

if [ ! -d "$INSTALL_DIR" ]; then
    echo -e "\033[0;31m[!] Error: PwnRM not found at $INSTALL_DIR\033[0m"
    exit 1
fi

# Activate venv and run pwnrm CLI entry point
exec "$INSTALL_DIR/venv/bin/pwnrm" "$@"
EOF

chmod +x /usr/local/bin/pwnrm
echo -e "${GREEN}[+] Wrapper script created${NC}"

# ── 9. Done ──────────────────────────────────────────────────────────────────
echo
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}================================${NC}"
echo
echo -e "${GREEN}[+] Usage:${NC}"
echo -e "${CYAN}    pwnrm -h${NC}                              Show help"
echo -e "${CYAN}    pwnrm -u admin -p 'pass' 10.10.10.10${NC} Interactive shell"
echo -e "${CYAN}    pwnrm -u admin -p 'pass' 10.10.10.10 -X 'whoami'${NC} Single command"
echo
echo -e "${GREEN}[+] Use as Python library:${NC}"
echo -e "${CYAN}    source /opt/pwnrm/venv/bin/activate${NC}"
echo -e "${CYAN}    python3 -c \"from pwnrm import PwnShell, Runspace\"${NC}"
echo
echo -e "${YELLOW}[*] Installation directory: ${INSTALL_DIR}${NC}"
echo -e "${YELLOW}[*] To uninstall: sudo rm -rf ${INSTALL_DIR} && sudo rm /usr/local/bin/pwnrm${NC}"
echo
echo -e "${GREEN}[+] Enjoy your meal!${NC}"