# Changelog

All notable changes to the **PwnRM** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0] - 2026-08-30

### Next-Gen Post-Exploitation Suite & Autonomous CI/CD Security Audit Pipeline

This major release elevates PwnRM into an elite operator platform featuring 5 new specialized attack modules, in-memory credential extraction bypassing EDR, coerced authentication triggers, Server 2025 LAPS hunting, DACL privilege escalation analysis, polymorphic backtick command obfuscation, hardened SOCKS5 multiplexing, and a completely custom, self-contained GitHub Actions CI/CD Security Audit Pipeline (0 third-party SAST dependencies).

### Added & Enhanced (New Modules & Operator TTPs)
- **In-Memory VSS Shadow Copy Extractor (`!vss`)**:
  - Direct WMI / CIM reflection (`[wmiclass]"Win32_ShadowCopy"`) to extract active `SAM`, `SYSTEM`, and `NTDS.dit` hives without executing `vssadmin.exe` or `ntdsutil.exe` (completely evading EDR process creation telemetry).
  - Automated post-extraction cleanup instantly deleting shadow copies via `.Delete()` to maintain forensic cleanliness.
- **Coerced Authentication Engine (`!coerce`)**:
  - Implements multi-vector coerced authentication from the remote target to operator listeners (Responder / `ntlmrelayx`).
  - Vectors: WebDAV HTTP UNC paths (`\\listener@80\share\dummy.txt` bypassing SMB signing for ADCS ESC8 Web Enrollment relays), MS-RPRN Print Spooler (`\pipe\spoolss`), MS-EFSR PetitPotam (`\pipe\efsrpc`), and MS-DFSNM (`\pipe\netdfs`).
- **Windows LAPS & Server 2025 Hunter (`!laps`)**:
  - In-memory LDAP query extracting both Legacy LAPS (`ms-Mcs-AdmPwd`, expiration timestamp) and Modern Windows Server 2025 / Windows 11 Azure LAPS (`msLAPS-Password`, `msLAPS-EncryptedPassword`, `msLAPS-PasswordHistory`).
- **Active Directory DACL & Privilege Escalation Scout (`!acl`)**:
  - Audits discretionary access control lists on Tier-0 objects (`AdminSDHolder`, `Domain Admins`, `Domain Controllers`, `krbtgt`, GPOs).
  - Discovers high-risk access rights (`GenericAll`, `WriteDacl`, `WriteOwner`, `GenericWrite`, `User-Force-Change-Password`).
- **Process Token Hunter & In-Memory Impersonation (`!token`)**:
  - In-memory process token enumeration across logon sessions and privilege escalation triage (`SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeDebugPrivilege`, `SeBackupPrivilege`).
  - Named pipe client reflection and token duplication (`DuplicateTokenEx`) without binary drops.
- **Polymorphic PowerShell AST Command Obfuscation (`core.opsec`)**:
  - Added AST-safe dynamic backtick and whitespace splitting for PowerShell cmdlets (`obfuscate_cmd()`) when active in `stealth` and `hybrid-cloud` profiles to defeat static ScriptBlockLogging signatures.
  - Upgraded jitter sleep calculations to use cryptographic random state (`secrets`).
- **Thread-Safe SOCKS5 Proxy & Port Forwarding Multiplexing (`core.tunnel`)**:
  - Hardened `Socks5Server` and `PortForwarder` with `threading.Lock()` mutex and socket timeout guards, preventing deadlocks or memory retention on abrupt client disconnects.

### Security Hardening & Core Fixes (Auditor Pass)
- **CWE-918 (SSRF / Proxy MITM)**: Enforced `session.trust_env = False` across all Transport base classes in `core.transports` to ignore ambient environment proxy variables.
- **CWE-208 / CWE-385 (Timing Attack)**: Implemented constant-time verification for CredSSP Server-To-Client Binding hash `pubKeyAuth` using `hmac.compare_digest()` in `CredSSPTransport._auth()`.
- **CWE-532 (Log Exposure)**: Sanitized SPNEGO transport logging in `core.api` to avoid serializing raw credential variable identifiers into `logging.info()`.
- **CWE-200 / CWE-522 (History Leak)**: Expanded `HISTORY_EXCLUDE_PATTERN` in `shell.pwnshell` to automatically exclude offensive tool and credential keywords (`mimikatz`, `secretsdump`, `lsass`, `ccache`, `kirbi`, `dpapi`).

### Custom CI/CD Security Audit Pipeline (`.github/`)
- **Main Workflow (`.github/workflows/security_audit.yml`)**: 5-job automated GitHub Actions pipeline (`setup`, `unit_and_regression`, `custom_security_audit`, `dependency_audit`, `report_and_annotate`) triggered on push, pull request, weekly cron, and manual dispatch.
- **PowerShell Injection Auditor (`.github/scripts/audit_ps_injection.py`)**: AST-based data flow analyzer detecting unescaped PowerShell string interpolations in JoinedStr/f-strings and `.ps1` resources.
- **Cryptographic Hygiene Auditor (`.github/scripts/audit_crypto.py`)**: Validates CSPRNG usage (`secrets` vs `random`), Fernet key lifecycle, and MD5 integrity boundaries.
- **Filesystem & Permissions Auditor (`.github/scripts/audit_filesystem.py`)**: Enforces atomic `O_CREAT | O_EXCL` file creation, `0o600` permissions, and history symlink race guards.
- **XML Deserialization Safety Auditor (`.github/scripts/audit_xml_safety.py`)**: Ensures `defusedxml` wraps all XML deserialization sinks against XXE / Billion Laughs attacks.
- **Secret & Credential Exposure Auditor (`.github/scripts/audit_secrets_exposure.py`)**: Scans source code, logging calls, and git commits for hardcoded secrets and unpinned dependencies.
- **Network & Transport Security Auditor (`.github/scripts/audit_network.py`)**: Verifies `max_redirects=0`, `trust_env=False`, `hmac.compare_digest()`, and WebSocket CSPRNG keys.
- **Interactive Report Builder (`.github/scripts/audit_report.py`)**: Compiles `audit_report.json`, interactive dark-mode `audit_report.html`, and emits inline PR annotations (`::error::` / `::warning::`).
- **Master Orchestrator (`.github/scripts/run_all_audits.py`)**: Orchestrates all 6 custom auditors, renders a universal ASCII summary table, and enforces fail-fast exit codes (0 on clean, 1 on CRITICAL/HIGH).

### Test Suite
- Expanded test suite from 26 to **41 automated unit & security regression tests** passing with a **100% success rate**.

---

## [2.0.1] - 2026-08-29

### Security Hardening & Full Niche Operator Quality Pass

This release delivers comprehensive security hardening, vulnerability mitigations (FIX-01 to FIX-09), ephemeral session encryption, dual ETW kernel telemetry blinding, and operational refinements across the platform.

### Fixed & Hardened (Security Audits FIX-01 – FIX-09)
- **FIX-01 (CWE-400 / Data Loss)**: Fixed closure rebinding bug in `download()` stream collector by switching to in-place `buf.extend(chunk)` and added empty-stream vs collection-failure diagnostic errors.
- **FIX-02 (CWE-78 / CWE-88)**: Resolved PowerShell single-quote injection in `upload()` by enforcing `_pde()` double-quoted escaping and `-LiteralPath` parameters across all file manipulation cmdlets.
- **FIX-03 (CWE-73 / CWE-22)**: Fixed client-side trust of server-returned paths in `download()` by deriving default local filenames strictly from user input arguments.
- **FIX-04 (CWE-693)**: Replaced static AMSI patch byte signatures (`b8 57 00 07 80 c3`) with dynamic `build_amsi_patch()` polymorphic NOP generator (`xchg`, multi-byte NOP prefixes) and eliminated hardcoded `Start-Sleep` commands.
- **FIX-05 (CWE-330)**: Replaced non-CSPRNG Mersenne Twister `random.randint` and `randbytes` with `secrets` module across XOR keys (`secrets.randbelow(254) + 1`), CredSSP nonces (`secrets.token_bytes(32)`), and temporary file identifiers.
- **FIX-06 (CWE-611)**: Implemented safe XML parsing via `defusedxml.ElementTree` in `core.psrp` to protect against XML entity expansion / billion laughs DoS.
- **FIX-07 (CWE-22 / CWE-78)**: Reimplemented `_validate_remote_path()` regex whitelist (`_SAFE_WINPATH`, `_SAFE_UNCPATH`) to strictly block directory traversal (`..`) and PowerShell shell injection characters.
- **FIX-08 (CWE-400)**: Enforced 1MB output buffer ceiling in `run_sync()` with automatic output truncation and runspace interrupt.
- **FIX-09 (CWE-295 / CWE-300)**: Added cryptographic `pubKeyAuth` unwrapping and binding hash verification against `SHA256(b"CredSSP Server-To-Client Binding Hash\x00" + nonce + pubkey)` with CredSSP v5 protocol fallback support.
- **OPT-01**: Eliminated interrupt race condition in `run_with_interrupt()` by holding `CtrlCHandler` across the entire generator stream.
- **OPT-02 & OPT-03**: Added real-time percentage progress calculation for uploads and transformed `help()` into a dynamic, structured `COMMAND_REGISTRY`.
- **OPT-04**: Wrapped transcript log file output with `strip_ansi()` to ensure clean ASCII/UTF-8 log archives.
- **OPT-07**: Zeroized sensitive memory buffer (`buf[:] = b'\x00' * len(buf)`) on download MD5 checksum integrity failure.
- **OPT-08**: Introduced `HISTORY_EXCLUDE_PATTERN` preventing passwords, hashes, and secrets from persisting into `.pwnrm_history`.
- **NICHE-01 & NICHE-02**: Replaced bare `except:` clauses in `utfstr()` with `except Exception:` and sanitized single-quote escaping in `get_shares_ps()`.

### Added & Enhanced (Tier 1–3 Architectural Upgrades)
- **Ephemeral Session Encryption**: Integrated in-memory `Fernet` encryption (`_SESSION_KEY`) for serialized session metadata under `~/.pwnrm/sessions/` to prevent credential exposure in post-engagement forensic dumps.
- **Dual ETW Telemetry Evasion**: Extended `!evasion` to patch both `EtwEventWrite` and `EtwEventWriteFull` in `ntdll.dll` for Windows 10 21H2+, Windows 11, and Server 2022/2025.
- **Structured Loot `MANIFEST.json`**: Added automatic SHA-256 calculation and manifest indexing across all collected credentials and artifacts in `~/.pwnrm/loot/`.
- **Multi-Session Output Labeling**: Prefixed `fan_out_exec` stream output with `[S:{sid} | {host}]` tags during distributed multi-target execution.
- **Plugin Architecture Integrity**: Added `verify_plugin_integrity()` to `ModuleManager` to validate permissions and reject world-writable plugin files before dynamic loading.
- **BloodHound CE v6 Meta Headers**: Updated `!bloodhound` in-memory LDAP enumeration to output BloodHound CE v6 compatible metadata headers (`{"meta": {"type": "...", "count": N, "version": 6}}`).
- **Playbook `on_fail` Cleanup Hooks**: Added automated execution of `cleanup_on_fail` rollback hooks when an automated red team playbook fails mid-execution.
- **Resource-Based Constrained Delegation (RBCD)**: Added `msDS-AllowedToActOnBehalfOfOtherIdentity` inspection to `!kerberos`.
- **Enterprise CA Health Check**: Added CA certificate expiration detection and CRL/AIA status checks to `!adcs`.
- **WinRM over WebSocket Transport (`ws://` / `wss://`)**: Added `WebSocketTransport` conforming to MS-WSMV §2.2.9.1 with `Sec-WebSocket-Protocol: soap` for stealthy OPSEC evasion bypassing HTTP SOAP signatures.
- **Active Lateral WSMan Micro-Probing**: Upgraded `!lateral` with active HTTP/HTTPS WSMan micro-probing, distinguishing `[PWNED / OPEN_ACCESS]`, `[REACHABLE / AUTH_REQUIRED]`, and `[PORT_OPEN]` targets.
- **BloodHound Active Logon Sessions**: Added in-memory WMI session enumeration (`Win32_LogonSession` + `Win32_LoggedOnUser`) formatted for BloodHound CE v6 session attack path discovery.
- **`RemoteStreamOptions=0` ETW Blinding**: Enforced `RemoteStreamOptions=0` in PSRP pipeline creation to block supplementary information and debug streams directly at the remoting layer.
- **Playbook Conditional Branching DSL**: Added `when` conditional execution, variable output capture (`capture_as`), and `on_fail: continue|abort` handlers in `!playbook`.
- **In-Memory DPAPI Reflection Unprotect**: Added reflection-based `CryptUnprotectData` bridge in `!creds` to decrypt DPAPI data in-memory without dropping binaries to disk.
- **Dead Reckoning Replay Mode (`--replay`)**: Added `--replay <logfile>` CLI capability to parse transcript logs and replay execution sequences seamlessly after unexpected disconnects.
- **Transcript Session Boundary Markers**: Added structured timestamped `SESSION SWITCH` boundary markers to stdout transcripts.
- **Test Suite Expansion**: 26 unit and security regression tests passing with 100% success rate.

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
