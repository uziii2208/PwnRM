# Changelog

All notable changes to the **PwnRM** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-08-29

### Major Transformation: Next-Generation WinRM Red Team Operator Platform (2026–2027 TTPs)

PwnRM has evolved from an interactive shell and payload loader into a **full-featured WinRM-centric Red Team Operator Platform**, calibrated for modern enterprise hybrid environments, Server 2025 defenses, and 2026–2027 CISA/CrowdStrike red team assessment TTPs.

### Added
- **Multi-Session Manager & Jump Graph (`!session`)**:
  - Concurrent management of multiple active PSRP `Runspace` sessions across different target endpoints.
  - Commands: `!session list`, `!session switch <id>`, `!session save`, `!session exec-all <cmd>`.
  - Encrypted session metadata persistence under `~/.pwnrm/sessions/` with strict `0o700` and Windows `icacls` permission hardening.
- **In-Band PSRP SOCKS5 Proxy & Port Forwarding Multiplexer (`!socks`, `!portfwd`)**:
  - RFC 1928 compliant SOCKS5 server running locally on `127.0.0.1:1080` (or custom port) multiplexing TCP streams directly through PowerShell streams on the target without opening listening firewall ports on the remote host.
  - Local port forwarder (`!portfwd <LPORT> <RHOST>:<RPORT>`) and forward management (`!portfwd list`, `!portfwd stop <id>`).
- **Structured & Encrypted Loot Pipeline (`!loot`)**:
  - Structured storage organizing credentials, Kerberos tickets (`.ccache`, `.kirbi`), certificates (`.pfx`, `.pem`), DPAPI master keys, and memory dumps under `~/.pwnrm/loot/<target>/`.
  - Atomic file creation (`O_CREAT | O_EXCL`) and strict permission enforcement (`0o600`).
- **OPSEC Profile & Jitter Engine (`!opsec`)**:
  - 4 operational profiles: `stealth`, `balanced`, `aggressive`, `hybrid-cloud`.
  - Dynamic randomized delay jitter between PSRP requests, legitimate WinRM User-Agent emulation (`Microsoft WinRM Client`), and command obfuscation.
- **Pluggable Modular Engine (`src/pwnrm/modules/`)**:
  - Extensible `BaseModule` and `ModuleManager` plugin architecture.
- **Full ADCS Engine (ESC1–ESC16+) (`!adcs`)**:
  - Deep template vulnerability audit covering ESC1, ESC2, ESC3, ESC4, ESC6, ESC7, ESC9, ESC10, ESC13, ESC15, ESC16, and Enterprise CA discovery.
- **Advanced Kerberos Suite (`!kerberos`)**:
  - Kerberoasting with AES256-CTS-HMAC-SHA1-96 priority (for RC4-deprecated environments).
  - AS-REP roasting triage for accounts with `DONT_REQ_PREAUTH`.
  - Diamond Ticket identity-swap workflow assistance (bypassing KDC anomaly detection).
  - Server 2025 Delegated Managed Service Accounts (`msDS-ManagedAccount` / dMSA) and `BadSuccessor` abuse inspection.
- **Hybrid Entra ID / Azure AD PRT Pivot (`!entra`)**:
  - Device join status inspection (`AzureAdJoined`, `DomainJoined`, `EnterpriseJoined`).
  - Web Account Manager (WAM) token broker cache identification and Azure CLI / Azure PowerShell credential cache extraction.
- **Deep Credential & Token Hunter (`!creds`)**:
  - In-memory DPAPI master key file enumeration (`Microsoft\\Protect`).
  - Browser credential storage location detection (Chrome, Edge, Brave `Login Data` and `Local State`).
  - High-value token privileges audit (`SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeTcbPrivilege`).
- **Polymorphic Evasion & EDR Scout (`!evasion`)**:
  - Randomized polymorphic memory patching for `AmsiScanBuffer` (`amsi.dll`) and `EtwEventWrite` (`ntdll.dll`).
  - EDR driver and AV product detection (`csagent.sys`, `SentinelAgent.sys`, `WdFilter.sys`, `CbDefenseW64.sys`, `cylance.sys`).
- **In-Memory BloodHound AD Graph Collector (`!bloodhound`)**:
  - 100% in-memory LDAP enumeration of Users, Computers, Domain Controllers, and High-Value Groups without dropping SharpHound binaries to disk.
  - Compatible with BloodHound CE / v4/v5 format.
- **Subnet Scout & Lateral Movement Dispatcher (`!lateral`)**:
  - Fast in-memory subnet service probing targeting WinRM (5985/5986), SMB (445), and RDP (3389).
- **Declarative Playbook Runner (`!playbook`)**:
  - Automation engine supporting built-in playbooks (`default_triage`, `ad_recon`, `stealth_audit`).
- **Automated Regression & Security Unit Test Suite (`tests/`)**:
  - 15 comprehensive unit tests covering session manager, SOCKS5 tunnel, loot pipeline, OPSEC profiles, module discovery, and security guard checks.

### Changed
- Refactored `PwnShell` interactive REPL to integrate all v2.0 commands with dynamic prompt status indicators (`PwnRM[S:0|Host]|Path>`).
- Updated `ui.py` banner, color scheme, and tab completion lists.
- Enforced UTF-8 console output reconfiguration in `cli.py` for cross-platform and Windows terminal compatibility.

---

## [1.2.6] - 2026-08-20

### Fixed
- Terminal ANSI sanitization (`strip_ansi`) hardening against VT100/OSC escape injection attacks.
- Minor argument splitting fixes in `split_args`.

---

## [1.2.5] - 2026-08-18

### Fixed
- **HIGH-05**: Added 1MB buffer cap in `run_sync` to prevent application-layer Out-Of-Memory (OOM) Denial of Service from unbounded remote command outputs.

---

## [1.2.1] - 2026-08-16

### Fixed
- **CRIT-03**: Enforced Windows NTFS ACL restriction (`icacls "%USERNAME%:(OI)(CI)F"` / `/inheritance:r`) on `~/.pwnrm/` to prevent multi-tenant local session/transcript credential exposure.
- Replaced custom PSRP wire framing with hardened `pypsrp` backend while maintaining native transport authentication (SPNEGO / Kerberos / CredSSP / ClientCert).

---

## [1.2.0] - 2026-08-15

### Added
- **Share Scout (`!shares`)**: In-session SMB share discovery, UNC permission testing, and SYSVOL GPP `cPassword` scanning.
- **Session Scout (`!sessions`)**: Active logon sessions, RDP client MRU history, Kerberos ticket cache (`klist`), and network connection inspection.

---

## [1.1.0] - 2026-08-10

### Added
- **AD Triage Engine (`!adtriage`)**: Pure PowerShell in-memory Active Directory enumeration (SPNs, AS-REP, unconstrained/constrained/RBCD delegation, gMSA, ADCS quick scan).

---

## [1.0.5] - 2026-08-05

### Fixed
- **CRIT-01**: Implemented `_pde()` double-quote PowerShell string escaping to prevent command injection from server-returned paths.
- **CRIT-02**: Stream buffer size cap (`MAX_FRAGMENT_BYTES`) and safe XML parsing with `defusedxml`.
- **HIGH-01**: Implemented `_validate_remote_path()` regex whitelist to block server-returned path traversal and injection characters.
- **HIGH-02**: Insecure PFX temp file remediation using atomic `mkdtemp` and `0o700` permissions.
- **NICHE-01..05**: Session log directory permissions, stream cipher desync handling, zero-length trailer boundary off-by-one, and uninterruptible client hang fixes.

---

## [1.0.4] - 2026-07-28

### Security
- **GHSA-x4cv**: Fixed client-side trust of server-returned paths in `!download` by deriving local filenames strictly from user input.

---

## [1.0.0] - 2026-07-15

### Initial Release
- Interactive MS-PSRP PowerShell runspace shell.
- Authentication suite: NTLM (Pass-the-Hash), Kerberos (`.ccache`), CredSSP, and mutual TLS client certificates (`.pfx`).
- In-memory payload execution (`!psrun`, `!netrun`), XOR staging (`!upload -xor`), and raw Winsock reverse shell (`!revshell`).
