![](/photos/image.png)
# PwnRM - WinRM Remote Management Shell

A rewritten and enhanced WinRM execution tool based on `wmiexec` and `winrmexec`, providing a comprehensive remote management shell with advanced capabilities for Windows target systems.

---

## Features

- **Remote Shell Access**: Interactive command execution on WinRM targets
- **File Upload/Download**: Transfer files to/from target with XOR encryption support
- **AMSI Bypass**: Built-in AMSI evasion capabilities
- **PowerShell Script Execution**: Run PS1 scripts with obfuscation
- **.NET Assembly Execution**: Execute .NET assemblies remotely
- **Reverse Shell**: Pop reverse shells with full I/O redirection
- **Session Logging**: Automatic logging of all operations

---

## Installation

### Quick Install (Recommended)

On **Kali Linux** or other Debian-based systems:

```bash
sudo bash install.sh
```

The installer will:
- Check and install Python 3 if needed
- Install system dependencies
- Create a Python virtual environment
- Install required Python packages
- Create a global command wrapper for easy access

### Manual Installation

If you prefer manual installation:

```bash
# 1. Clone or navigate to the PwnRM directory
cd PwnRM

# 2. Install system dependencies (Debian/Ubuntu/Kali)
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv build-essential libssl-dev libffi-dev

# 3. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install Python dependencies
pip install -r requirements.txt

# 5. Run PwnRM
python3 pwnrm -h
```

---

## Usage

### After Installation

If you installed using `install.sh`, you can run PwnRM from anywhere:

```bash
pwnrm -h
pwnrm -u username -p password -d domain target.example.com
```

### Manual Execution

```bash
source venv/bin/activate
python3 pwnrm [options]
```

### Basic Example

```bash
pwnrm -u Administrator -p 'P@ssw0rd!' 192.168.1.100
```

---

## Available Commands

Once connected to a target, use these commands:

### File Operations
- **`!download RPATH [LPATH]`** - Download files/directories from target (directories compressed as ZIP)
- **`!upload [-xor] LPATH [RPATH]`** - Upload files to target with optional XOR encryption

### Code Execution
- **`!amsi`** - Disable AMSI (run before loading .NET assemblies)
- **`!psrun [-xor] URL`** - Execute PowerShell scripts via URL
- **`!netrun [-xor] URL [ARG] [ARG]`** - Execute .NET assemblies from URL

### Advanced
- **`!revshell IP PORT`** - Establish reverse shell with full I/O redirection
- **`!log`** - Start logging session output
- **`!stoplog`** - Stop logging

### Navigation
- **`!help`** or **`?`** - Show help menu
- **`exit`** or **`quit`** - Close connection

---

## Requirements

### System Requirements
- Python 3.7+
- Linux (Kali, Ubuntu, Debian, or other Debian-based distros)
- Root/sudo access for installation

### Python Dependencies
- `impacket>=0.11.0` - WinRM protocol and utilities
- `prompt_toolkit>=3.0.0` - Enhanced command line interface
- `pycryptodomex>=3.15.0` - Cryptographic operations

---

## Troubleshooting

### `pwnrm: command not found`
The wrapper script didn't install properly. Try:
```bash
sudo bash /opt/pwnrm/install.sh
```

### Python module import errors
Ensure the virtual environment is active and dependencies are installed:
```bash
source /opt/pwnrm/venv/bin/activate
pip install -r /opt/pwnrm/requirements.txt
```

### Permission denied on target
Ensure your credentials have sufficient privileges on the WinRM service.

### Connection refused
- Verify WinRM is enabled on the target: `Enable-PSRemoting -Force` (PowerShell as Admin)
- Check firewall rules (default WinRM port is 5985 HTTP, 5986 HTTPS)

---

## Uninstallation

To completely remove PwnRM:

```bash
sudo rm -rf /opt/pwnrm
sudo rm /usr/local/bin/pwnrm
```

---

## Directory Structure

```
PwnRM/
├── pwnrm                  # Main executable script
├── core.py                # Core WinRM module (if separated)
├── requirements.txt       # Python dependencies
├── install.sh             # Installation script
└── README.md              # This file
```

---

## Development & Contributing

For development work, clone and set up manually:

```bash
git clone https://github.com/uziii2208/PwnRM.git
cd PwnRM
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Security Notes

⚠️ **Important Considerations:**

- Always use HTTPS when possible (port 5986)
- Credentials are sensitive - avoid command history logging
- Use the `!amsi` command cautiously as it modifies runtime behavior
- Test in controlled environments before production use
- Keep credentials out of command-line history:
  ```bash
  pwnrm -u username -p "$(read -sp 'Password: '; echo)" target
  ```

---

## Disclaimer

This tool is for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before using this tool on any systems. The authors assume no liability for misuse or damage.

---

## Credits

- **Original Work**: evil_winrmexec.py
- **Impacket Library**: SecureAuth Corporation
- **Rewritten/Enhanced by**: uziii2208

---

## License

Refer to the original project for licensing information.

---

## Support

For issues and questions:
- Check the help menu: `pwnrm -h`
- Review the troubleshooting section above
- Refer to impacket documentation: https://github.com/fortra/impacket

---

**ENJOY YOUR MEAL :)**
