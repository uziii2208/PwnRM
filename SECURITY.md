<div align="center">

# Security Policy

### PwnRM Vulnerability Disclosure Program

[![Security Policy](https://img.shields.io/badge/security-policy-red?style=flat-square&logo=github)](SECURITY.md)
[![Last Updated](https://img.shields.io/badge/updated-2026--08--15-blue?style=flat-square)]()
[![Severity Gate](https://img.shields.io/badge/min%20severity-HIGH%20%7C%20CRITICAL-critical?style=flat-square)](#-severity-guidelines)

**Reporting security vulnerabilities in PwnRM — serious bugs only.**

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
| **1.0.x** (latest) | ✅ Supported | Full support |
| **0.x** (legacy) | ❌ End of Life | No updates |
| Pre-release | ❌ Not supported | Use at own risk |

**Always verify your issue exists on the latest release before reporting.**

---

## Severity Guidelines (Strict Gate)

We operate a **HIGH/CRITICAL-only** vulnerability acceptance policy. This is intentional — we reject noise to focus on issues that genuinely compromise operator security.

### 🔴 CRITICAL (Accepted — Priority Response)

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

### 🟠 HIGH (Accepted — Standard Response)

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
- DoS of PwnRM itself (it's a CLI tool — just restart it)
- Theoretical attacks requiring physical access to operator's unlocked machine

### 🔵 LOW / INFORMATIONAL (NOT Accepted — Auto-Closed)

**Do NOT submit these. They will be closed without review:**

- ❌ Outdated dependencies without a specific exploitable CVE
- ❌ Missing security headers (PwnRM is a CLI client, not a web server)
- ❌ Cosmetic issues, typos, or documentation errors → use regular Issues
- ❌ Feature requests or "nice to have" hardening → use Discussions
- ❌ AV/EDR detection of PwnRM itself (it's an offensive tool — this is expected)
- ❌ "Tool can be used maliciously" — this is the intended use case
- ❌ Target-side vulnerabilities (we don't own the targets)
- ❌ Generic security best-practice suggestions without demonstrated impact
- ❌ Automated scanner output without proof-of-concept

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
  boundary — use `-ssl` for TLS. An interceptor of plaintext HTTP WinRM traffic
  already sees everything, with or without XOR.
- **Hashes on file transfers** are for accidental-corruption detection only, not
  for security. An active MITM on an unencrypted WinRM channel can already
  modify traffic regardless of the hash algorithm.

---

## Reporting a Vulnerability

### Before You Submit

1. ✅ Verify the issue exists on the **latest release** of PwnRM
2. ✅ Confirm it meets **HIGH or CRITICAL** severity above
3. ✅ Build a **working proof-of-concept** (not theoretical)
4. ✅ Check existing [Issues](../../issues) and [Security Advisories](../../security/advisories) for duplicates
5. ✅ Reproduce on a clean install (`rm -rf /opt/pwnrm && bash install.sh`)

### Submission Channels

**Preferred: GitHub Private Vulnerability Reporting**

Use GitHub's built-in private reporting for the fastest, most secure handling:

1. Go to **[Report a vulnerability](../../security/advisories/new)**
2. Select the appropriate repository
3. Fill in the template completely (see format below)
4. Submit — only maintainers will see it

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

- [`AGENT-WINDOWS.md`](AGENT-WINDOWS.md) — AD attack methodology (methodology only, no secrets)
- [`LICENSE`](LICENSE) — MIT License (includes disclaimer of liability)
- [`README.md#disclaimer`](README.md) — Operational security guidance for users

---

## Questions?

If you're unsure whether something qualifies, **ask first** via the private reporting channel with `[PRE-SUBMIT]` in the title. We'd rather triage a borderline report than miss a real issue.

But please — **do your homework first**. Read this document, check the code, build a PoC. Our time is limited and we prioritize reports that demonstrate effort.

---

<div align="center">

**Thank you for helping keep the offensive security community safe.** 🛡️

*Last reviewed: 2026-08-15*

</div>
