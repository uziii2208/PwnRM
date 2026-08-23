<div align="center">

# Security Policy

### PwnRM Vulnerability Disclosure Program

[![Security Policy](https://img.shields.io/badge/security-policy-red?style=flat-square&logo=github)](SECURITY.md)
[![Last Updated](https://img.shields.io/badge/updated-2026--08--15-blue?style=flat-square)]()
[![Severity Gate](https://img.shields.io/badge/min%20severity-HIGH%20%7C%20CRITICAL-critical?style=flat-square)](#-severity-guidelines)

**Reporting security vulnerabilities in PwnRM - serious bugs only.**

</div>

---

## Overview

PwnRM is an **offensive security tool** designed for authorized penetration testing, CTF competitions, and red team operations. Due to the nature of this software, our vulnerability acceptance criteria are **significantly stricter** than typical open-source projects.

**⚠️ Read this entire document before submitting.** Low-severity, informational, or out-of-scope reports will be **closed without response**.

---

## Supported Versions

We only accept vulnerability reports against actively maintained versions.

| Version | Status | Security Updates |
|---------|--------|------------------|
| **1.2.x** (latest) | ✅ Supported | Full support |
| **1.1.x** | ⚠️ Critical-only | Critical fixes backported only |
| **1.0.x** | ❌ End of Life | No updates |
| **0.x** (legacy) | ❌ End of Life | No updates |
| Pre-release | ❌ Not supported | Use at own risk |

**Always verify your issue exists on the latest release before reporting.**

---

## Severity Guidelines (Strict Gate)

We operate a **HIGH/CRITICAL-only** vulnerability acceptance policy. This is intentional - we reject noise to focus on issues that genuinely compromise operator security.

### 🔴 CRITICAL (Accepted - Priority Response)

Vulnerabilities that directly compromise **the operator's machine** running PwnRM:

- **Remote Code Execution on operator's host** when running PwnRM against a malicious target
- **Arbitrary command execution** via crafted responses from compromised targets
- **Credential theft** from PwnRM's local configuration/credential store (Kerberos ccache, stored passwords, tokens)
- **Path traversal leading to arbitrary file read/write** on the operator's filesystem via `!download` / `!upload` handlers
- **Deserialization attacks** via malicious WinRM/PSRP responses
- **Sandbox escape** from the virtual environment to the host system
- **Supply chain compromise** in our published artifacts (PyPI, releases)

**Example (Critical):**
> A malicious WinRM server returns a crafted PSRP response that triggers command execution on the operator's machine when PwnRM parses it.

### 🟠 HIGH (Accepted - Standard Response)

Serious vulnerabilities with clear security impact on the operator:

- **SSRF from operator's host** via PwnRM's outbound requests (coerced connections to internal networks)
- **Authentication bypass** in PwnRM's own components (if any)
- **Cryptographic weaknesses** in XOR encryption / credential handling leading to recovery
- **Dependency compromise** with a **specific, reproducible CVE** affecting PwnRM's runtime path
- **Information disclosure** of operator's credentials to unintended destinations

**Example (High):**
> The `!upload -xor` routine uses a weak/static XOR key that allows a MITM attacker to recover the uploaded payload contents.

### 🟡 MEDIUM (NOT Accepted)

Issues with limited impact or requiring unrealistic attack scenarios:

- Information disclosure of non-sensitive metadata
- DoS of PwnRM itself (it's a CLI tool - just restart it)
- Theoretical attacks requiring physical access to operator's unlocked machine

### 🔵 LOW / INFORMATIONAL (NOT Accepted - Auto-Closed)

**Do NOT submit these. They will be closed without review:**

- ❌ Outdated dependencies without a specific exploitable CVE
- ❌ Missing security headers (PwnRM is a CLI client, not a web server)
- ❌ Cosmetic issues, typos, or documentation errors → use regular Issues
- ❌ Feature requests or "nice to have" hardening → use Discussions
- ❌ AV/EDR detection of PwnRM itself (it's an offensive tool - this is expected)
- ❌ "Tool can be used maliciously" - this is the intended use case
- ❌ Target-side vulnerabilities (we don't own the targets)
- ❌ Generic security best-practice suggestions without demonstrated impact
- ❌ Automated scanner output without proof-of-concept
- ❌ **CVEs in transitive dependencies** (Impacket, Cryptodome, requests, etc.) that have not been demonstrated to affect PwnRM's runtime execution path with a working exploit
- ❌ **Theoretical MITM attacks on unencrypted WinRM (HTTP)** - operators who choose HTTP over HTTPS accept this risk explicitly; the threat model is documented
- ❌ **"Hardcoded" XOR key or "weak" XOR encryption** - this is obfuscation for AV evasion, not a confidentiality mechanism; see Known & Accepted Design Decisions
- ❌ **`run_sync` / `!download` memory caps being bypassable by a cooperative operator** - bounds exist to prevent accidental OOM, not adversarial exploitation by the local user
- ❌ **Missing rate limiting, input length caps, or request throttling** on a CLI tool with no network-facing surface
- ❌ **PowerShell payloads being detectable by EDR** on the target - detection evasion is an operational concern, not a PwnRM vulnerability
- ❌ **Lack of code signing on the PyPI package** - this is a PyPI-level limitation, not a PwnRM vulnerability; verify via `pip install pwnrm` SHA256 checksums in release notes
- ❌ Reports submitted by anyone who has not read and can demonstrate understanding of this policy - we will ask a follow-up question; failure to answer closes the report

---

## Out of Scope

The following are explicitly **out of scope** and will not be accepted:

### Target-Side Issues
PwnRM is an **attacker-side tool**. Vulnerabilities in the target systems it attacks (Windows, Active Directory, WinRM servers) are **not PwnRM bugs**. Report those to the respective vendors.

### Intended Behavior
These are features, not bugs:
- PwnRM executing arbitrary commands on targets (that's the whole point)
- AMSI bypass techniques working
- Credentials being stored in memory during a session
- Network traffic being unencrypted when not using `-ssl` (operator's choice)
- Reverse shell functionality establishing outbound connections

### Operational Security
- Operator using weak passwords for their own credential store
- Operator running PwnRM as root unnecessarily
- Operator exposing their own listener (`!revshell`) to the internet
- Failure to rotate credentials after an engagement

### Third-Party Tool Vulnerabilities
Bugs in Impacket, NetExec, Certipy, BloodHound, Rubeus, etc. that PwnRM wraps → report to upstream projects.

### Known & Accepted Design Decisions

The following are intentional design decisions. Reports about them will be closed
unless a concrete attack with **operator-side impact** (beyond the threat model
below) is demonstrated:

- **XOR on uploads (`!upload -xor`)** is *obfuscation for AV/AMSI evasion on the
  target*, not a confidentiality mechanism. The WinRM channel is the security
  boundary - use `-ssl` for TLS. An interceptor of plaintext HTTP WinRM traffic
  already sees everything, with or without XOR.
- **Hashes on file transfers** are for accidental-corruption detection only, not
  for security. An active MITM on an unencrypted WinRM channel can already
  modify traffic regardless of the hash algorithm.
- **`run_sync` 1 MB output cap and `!download` 256 MB stream cap** are OOM guards against accidental runaway output, not security boundaries. A local attacker who controls the operator's shell already has full access.
- **Session history and logs stored under `~/.pwnrm/`** with `0o700` permissions - this is operator-side data on the operator's own machine. Key material in those files is the operator's responsibility.
- **Random per-session identifiers** for reflective .NET class names are AMSI/EDR evasion, not a security control. Their randomness strength is intentionally scoped to operational use, not cryptographic use.

---

## Reporting a Vulnerability

### Before You Submit

1. ✅ Verify the issue exists on the **latest release** of PwnRM
2. ✅ Confirm it meets **HIGH or CRITICAL** severity above
3. ✅ Build a **working proof-of-concept** (not theoretical)
4. ✅ Check existing [Issues](../../issues) and [Security Advisories](../../security/advisories) for duplicates
5. ✅ Reproduce on a clean install (`rm -rf /opt/pwnrm && bash install.sh`)
6. ✅ Confirm the vulnerability is **reproducible without operator error** - reports that require the operator to already be compromised, running as root unnecessarily, or ignoring obvious warnings will be rejected
7. ✅ **Do not submit output from automated scanners** (Bandit, Semgrep, Trivy, Snyk, etc.) as-is. If a scanner finding is your starting point, you must manually verify exploitability and include a working PoC before submitting
8. ✅ Confirm your report targets **PwnRM's own code**, not a transitive dependency CVE that has not been demonstrated to affect PwnRM's actual execution path
9. ✅ If your finding involves the XOR upload mechanism or hash-based transfer integrity - **read the [Known & Accepted Design Decisions](#known--accepted-design-decisions) section first**. These will be closed without review
10. ✅ Verify the attack is **achievable from the defined threat model**: a malicious WinRM/PSRP server the operator connects to, or a MITM on an unencrypted transport. Attacks requiring local access to the operator's machine, a pre-compromised Python environment, or access to the operator's credentials are out of scope

### Submission Channels

**Preferred: GitHub Private Vulnerability Reporting**

Use GitHub's built-in private reporting for the fastest, most secure handling:

1. Go to **[Report a vulnerability](../../security/advisories/new)**
2. Select the appropriate repository
3. Fill in the template completely (see format below)
4. Submit - only maintainers will see it

> ⚠️ Do NOT report security issues via public GitHub Issues, Discord, Twitter/X, or any other public channel.

### Required Report Format

Incomplete reports will be closed. Include ALL of the following:

```markdown
## Summary
One-sentence description of the vulnerability.

## Severity Assessment
- [ ] Critical  - [ ] High
- Justification (reference our severity guidelines above)

## Affected Component
File(s), function(s), and version(s) affected.

## Attack Scenario
Who is the attacker? What is their position? What do they need?

Example: "A malicious WinRM server operator can achieve RCE on the
PwnRM client's machine when the operator connects using `pwnrm`."

## Proof of Concept
Step-by-step reproduction with code/commands. MUST include:
- Setup (attacker infrastructure)
- Trigger (what the victim/operator does)
- Observable impact (shell, file read, cred leak, etc.)

## Impact
Concrete impact on confidentiality, integrity, or availability
of the OPERATOR's system (not the target).

## Suggested Fix (optional)
If you have a proposed patch, include it.

## Environment
- PwnRM version: 
- Python version: 
- OS: 
- Reproduced on clean install: [ ] Yes [ ] No
```

---

## ⏱️ Response Timeline

| Phase | Timeline |
|-------|----------|
| **Initial triage** | 72 hours |
| **Severity confirmation** | 7 days |
| **Fix development** (Critical) | 14 days |
| **Fix development** (High) | 30 days |
| **Public disclosure** | After fix release + 7-day grace period |

We will:
- ✅ Acknowledge receipt within 72 hours
- ✅ Provide regular status updates
- ✅ Credit you in the advisory (unless you request anonymity)
- ❌ Not engage with reports that don't meet severity threshold

---

## Safe Harbor

### For Researchers

If you conduct security research on PwnRM in good faith and follow this policy:

- We will **not** pursue legal action for research activities
- We consider research conducted under this policy to be **authorized**
- We will work with you to understand and resolve issues collaboratively
- We will not issue DMCA takedowns for good-faith security research

### Conditions

Safe harbor applies only if you:

1. Follow this disclosure policy
2. Do not access, modify, or delete data that isn't yours
3. Do not intentionally harm PwnRM users
4. Do not use findings for extortion or blackmail
5. Stop testing once you've confirmed a vulnerability
6. Report findings promptly and do not disclose before fix release

---

## Recognition

Researchers who report valid HIGH or CRITICAL vulnerabilities will be:

- **Credited** in the published GitHub Security Advisory (by handle or name, your choice)
- **Listed** in our `HALL_OF_FAME.md` (opt-in)
- **Mentioned** in release notes for the fixing version

We do **not** offer monetary bounties at this time. PwnRM is a community-driven project without a security budget. If this changes, this policy will be updated.

---

## 📚 Related Security Documentation

- [`LICENSE`](LICENSE) - MIT License (includes disclaimer of liability)
- [`README.md#disclaimer`](README.md) - Operational security guidance for users

---

## Questions?

If you're unsure whether something qualifies, **ask first** via the private reporting channel with `[PRE-SUBMIT]` in the title. We'd rather triage a borderline report than miss a real issue.

But please - **do your homework first**. Read this document, check the code, build a PoC. Our time is limited and we prioritize reports that demonstrate effort.

---

<div align="center">

**Thank you for helping keep the offensive security community safe.** 🛡️

*Last reviewed: 2026-08-22*

</div>
