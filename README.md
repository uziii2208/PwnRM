<div align="center">

![PwnRM ASCII](src/photos/logo.png)

**Advanced WinRM Post-Exploitation Shell for Windows Active Directory Testing**

![GitHub stars](https://img.shields.io/github/stars/uziii2208/PwnRM?style=for-the-badge&color=gold&logo=github)
[![Hall of Fame](https://img.shields.io/badge/Hall_of_Fame-🏆_h4x0rc-gold?style=for-the-badge&logo=trophy)](HALL_OF_FAME.md)
![GitHub forks](https://img.shields.io/github/forks/uziii2208/PwnRM?style=for-the-badge&color=blue&logo=github)
![GitHub issues](https://img.shields.io/github/issues/uziii2208/PwnRM?style=for-the-badge&color=red&logo=github)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative)
![PyPI](https://img.shields.io/pypi/v/pwnrm?style=for-the-badge&color=cyan&logo=pypi)
[![Changelog](https://img.shields.io/badge/Changelog-v2.0.1-blueviolet?style=for-the-badge&logo=git)](CHANGELOG.md)
![Platform](https://img.shields.io/badge/Platform-Cross--Platform-orange?style=for-the-badge&logo=windows)
[![Documentation](https://img.shields.io/badge/Documentation-Complete_Suite-success?style=for-the-badge&logo=readthedocs)](docs/README.md)

An operator-grade WinRM execution and red team platform for authorized Active Directory security assessments (2026–2027 TTPs): multi-session graph orchestration, in-band SOCKS5 multiplexing, full ADCS ESC1-ESC17+ (incl. WSUS abuse), Diamond Ticket suite, hybrid Entra ID pivoting, polymorphic evasion runtime, in-memory BloodHound collection, and structured loot pipeline - usable as a CLI tool **and** as a Python library.

[Installation](#installation) · [Usage](#usage) · [Commands](#commands) · [AD Triage](#ad-triage) · [Documentation](docs/README.md) · [Share Scout](#share-scout) · [Session Scout](#session-scout) · [Changelog](CHANGELOG.md) · [Library Usage](#library-usage) · [Troubleshooting](#troubleshooting) · [Disclaimer](#disclaimer) · [Hall Of Fame](HALL_OF_FAME.md)

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
| `!session [list, switch, save, exec-all]` | Multi-session manager & jump graph orchestrator  |
| `!socks [PORT, stop, status]` | In-band SOCKS5 proxy multiplexer (default: 1080)  |
| `!portfwd [LPORT RHOST:RPORT, list, stop]` | Local & remote port forwarding multiplexer  |
| `!module [list, run <name>]` | Extensible plugin subsystem & module runner  |
| `!adcs [-q, --template <T>, --wsus]` | Full ADCS ESC1-ESC17+ engine & certificate/WSUS triage |
| `!kerberos [--roast, --asrep, --dmsa]` | Advanced Kerberos suite (AES roasting, dMSA/BadSuccessor)  |
| `!entra [-s]` | Hybrid Entra ID / Azure AD PRT pivot & join state recon  |
| `!creds [--vault, --dpapi, --history]` | Deep credential & token artifact hunter  |
| `!bloodhound [-c <methods>]` | In-memory Active Directory graph collector (BloodHound CE)  |
| `!lateral [--subnet <s>]` | Subnet scout & lateral movement engine  |
| `!evasion [--edr, --amsi, --etw]` | Polymorphic AMSI/ETW memory patching & EDR scout  |
| `!playbook [--list, --run <name>]` | Declarative red team playbook runner  |
| `!loot` | Structured credential & artifact inventory viewer  |
| `!opsec [stealth, balanced, aggressive]` | Dynamic execution jitter & OPSEC profile switcher  |
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
| `!log` / `!stoplog` | Toggle session transcript |
| `exit` / `Ctrl+D` | Close session · `Ctrl+C` interrupts a running command|

Tab-completion for all built-ins via `prompt_toolkit`.

<a id="ad-triage"></a>
## AD Triage & Identity Abuse

### AD Triage (`!adtriage`)
`!adtriage` runs a self-contained LDAP/WMI enumeration entirely inside the remote PowerShell session - no extra binaries on target. `-q` = quick mode (identity + domain + Server 2025 / BadSuccessor check).
Covers: identity & privileges · domain / forest / DCs / trusts · high-value groups · Kerberoastable SPNs · AS-REP roastables · unconstrained / constrained / RBCD delegation · ADCS templates · gMSA / dMSA (BadSuccessor) · ACL quick-wins on DA/DC/krbtgt.

### Full ADCS Engine (`!adcs`) [v2.0.0]
Comprehensive Active Directory Certificate Services audit covering **ESC1 through ESC17+**:
- **ESC1 / ESC2**: Enrollee supplies SAN + Client Auth / Any Purpose EKUs.
- **ESC3 / ESC4**: Certificate Request Agent & vulnerable template ACL abuse.
- **ESC6 / ESC7**: CA `EDITF_ATTRIBUTESUBJECTALTNAME2` & vulnerable CA permissions.
- **ESC17 (WSUS & Code Signing Policy Abuse)**: Detects Code Signing (`1.3.6.1.5.5.7.3.3`) / Windows Update templates and scans client registry (`HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`) for `AcceptTrustedPublisherCerts = 1` and cleartext HTTP `WUServer` endpoints.

### Advanced Kerberos Suite (`!kerberos`) [v2.0.0]
- **Kerberoast & AS-REP Roast**: AES256-CTS-HMAC-SHA1-96 priority (for modern RC4-deprecated AD).
- **Diamond Ticket**: Identity-swap TGT crafting workflow (evading KDC anomaly detection).
- **Server 2025 dMSA / BadSuccessor**: Delegated Managed Service Account object & ownership takeover inspection.

### Hybrid Entra ID / Cloud Pivot (`!entra`) [v2.0.0]
- Device join status (`AzureAdJoined`, `DomainJoined`, `EnterpriseJoined`) via `dsregcmd`.
- Web Account Manager (WAM) token cache & Primary Refresh Token (PRT) artifact detection.
- Azure CLI (`accessTokens.json`) and Azure PowerShell context hunting.

---

<a id="platform-features"></a>
## Operator Platform Features [v2.0.0]

### In-Band PSRP SOCKS5 Proxy & Port Forwarding (`!socks`, `!portfwd`)
- `!socks 1080`: Spawns a local RFC 1928 SOCKS5 proxy multiplexed over existing WinRM PSRP streams — **no listening ports opened on target, zero binary drops**.
- `!portfwd <LPORT> <RHOST>:<RPORT>`: Direct local port forwarding to internal subnet targets.

### Multi-Session Manager & Jump Graph (`!session`)
- `!session list`: View all active concurrent target runspaces.
- `!session switch <id>`: Switch interactive context instantly.
- `!session exec-all <cmd>`: Fan-out command execution across all target nodes.
- `!session save`: Encrypted session state serialization under `~/.pwnrm/sessions/`.

### Modular Attack Engine & Playbooks (`!module`, `!playbook`)
- `!module list / run <name>`: Dynamic plugin loader for Python and PowerShell modules.
- `!playbook --run <name>`: Declarative automation runner (`default_triage`, `ad_recon`, `stealth_audit`).
- `!loot`: Structured credential and artifact inventory organized per target (`~/.pwnrm/loot/<target>/`).
- `!opsec [stealth|balanced|aggressive|hybrid-cloud]`: Configurable traffic shaping and jitter sleep.

---

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
from pwnrm import Runspace, PwnShell, create_transport, argument_parser, SessionManager, Socks5Server

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
│   ├── __init__.py            # public API & version 2.0.0
│   ├── __main__.py            # python -m pwnrm
│   ├── cli.py                 # CLI entry point (UTF-8 hardened)
│   ├── core/                  # Transport, Runspace, SessionMgr, Tunnel, Loot, OPSEC
│   ├── modules/               # ADCS (ESC1-17+), Kerberos, Entra, Creds, Evasion, BloodHound, Lateral, Playbook
│   ├── shell/                 # PwnShell v2.0 REPL, built-in commands, UI
│   └── resources/             # adtriage.ps1 · shares.ps1 · sessions.ps1
├── tests/                     # 15 automated unit & security regression tests
├── CHANGELOG.md               # Full release & security advisory history
├── pyproject.toml             # PyPI packaging (v2.0.0)
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