#!/bin/bash

# PwnRM Installation Script for Linux
# Supports Kali Linux, Ubuntu, Debian, and other Debian-based distributions

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  PwnRM Installation Script${NC}"
echo -e "${GREEN}================================${NC}\n"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root${NC}"
   echo "Please run: sudo bash install.sh"
   exit 1
fi

# Detect Python version
echo -e "${YELLOW}[*] Detecting Python version...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 is not installed${NC}"
    echo -e "${YELLOW}[*] Installing Python 3...${NC}"
    apt-get update
    apt-get install -y python3 python3-pip python3-venv
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo -e "${GREEN}[+] Python ${PYTHON_VERSION} found${NC}"

# Install system dependencies
echo -e "${YELLOW}[*] Installing system dependencies...${NC}"
apt-get update
apt-get install -y git build-essential libssl-dev libffi-dev python3-dev

# Determine installation directory
INSTALL_DIR="/opt/pwnrm"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Create installation directory
if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}[*] Creating installation directory at ${INSTALL_DIR}...${NC}"
    mkdir -p "$INSTALL_DIR"
    cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
    cd "$INSTALL_DIR"
fi

# Create virtual environment
echo -e "${YELLOW}[*] Creating Python virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}[+] Virtual environment created${NC}"
else
    echo -e "${GREEN}[+] Virtual environment already exists${NC}"
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo -e "${YELLOW}[*] Upgrading pip...${NC}"
pip install --upgrade pip setuptools wheel > /dev/null 2>&1

# Install Python dependencies
echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    echo -e "${GREEN}[+] Dependencies installed${NC}"
else
    echo -e "${RED}[!] requirements.txt not found${NC}"
    exit 1
fi

# Make main script executable
chmod +x "$INSTALL_DIR/pwnrm"

# Create wrapper script in /usr/local/bin
echo -e "${YELLOW}[*] Creating command wrapper...${NC}"
cat > /usr/local/bin/pwnrm << 'EOF'
#!/bin/bash
# PwnRM Wrapper Script

INSTALL_DIR="/opt/pwnrm"

if [ ! -d "$INSTALL_DIR" ]; then
    echo -e "\033[0;31m[!] Error: PwnRM not found at $INSTALL_DIR\033[0m"
    exit 1
fi

# Run pwnrm with virtual environment Python
"$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/pwnrm" "$@"
EOF

chmod +x /usr/local/bin/pwnrm
echo -e "${GREEN}[+] Wrapper script created at /usr/local/bin/pwnrm${NC}"

# Deactivate virtual environment
deactivate

echo -e "\n${GREEN}================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}================================${NC}\n"

echo -e "${GREEN}[+] You can now run PwnRM from anywhere:${NC}"
echo -e "${YELLOW}    pwnrm -h${NC}\n"

echo -e "${YELLOW}[*] Installation directory: ${INSTALL_DIR}${NC}"
echo -e "${YELLOW}[*] To uninstall, run: sudo rm -rf ${INSTALL_DIR} && sudo rm /usr/local/bin/pwnrm${NC}\n"

echo -e "${GREEN}[+] Enjoy your meal!${NC}"
