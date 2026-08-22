<div align="center">

# Hall of Fame

### Security Researchers Who Made PwnRM Safer

**Recognizing the community members who helped harden PwnRM through responsible disclosure.**

![Hall of Fame](https://img.shields.io/badge/Hall%20of%20Fame-2026-gold?style=for-the-badge&logo=trophy)
![Researchers](https://img.shields.io/badge/Researchers-2-blue?style=for-the-badge)

</div>

---

## Overview

This page recognizes security researchers who have reported valid vulnerabilities through our [responsible disclosure program](SECURITY.md). We deeply appreciate the time, effort, and expertise these individuals contribute to making PwnRM more secure for the offensive security community.

**Criteria for inclusion:**
- Reported a valid HIGH or CRITICAL severity vulnerability
- Followed our [Security Policy](SECURITY.md) disclosure guidelines
- Provided a working proof-of-concept or detailed reproduction steps
- Maintained confidentiality during the embargo period

---

## Researchers

| Advisory ID | Severity | Vulnerability Type | Details | Reporter | Fixed In |
|:-----------:|:--------:|:------------------:|:--------|:--------:|:--------:|
| [GHSA-x4cv-p53p-wh3w](https://github.com/uziii2208/PwnRM/security/advisories/GHSA-x4cv-p53p-wh3w) | 🔴 **CRITICAL** (9.6) | **Remote Code Execution** via Arbitrary File Write | Malicious WinRM server could spoof `!download` destination path, allowing attacker-controlled content to be written to arbitrary locations on the operator's host (e.g., `~/.bashrc`, `~/.ssh/authorized_keys`), leading to full RCE on next shell/SSH session. | [@h4x0rc](https://github.com/h4x0rc) | **[v1.0.1](https://github.com/uziii2208/PwnRM/releases/tag/v1.0.1)** |
| [GHSA-jwc5-6vfh-r4h2](https://github.com/uziii2208/PwnRM/security/advisories/GHSA-jwc5-6vfh-r4h2) | 🟠**HIGH** (7.4) | **Server-Side Request Forgery (SSRF)** | Malicious WinRM server could issue HTTP 307 redirect to arbitrary internal endpoints, causing PwnRM to forward operator requests to unintended services (e.g., AWS IMDS `/latest/meta-data/iam/`).| [@phamthanhnhat](https://github.com/phamthanhnhat) | **[v1.1.1](https://github.com/uziii2208/PwnRM/releases/tag/v1.1.1)** |

---

## Want to Join the Hall of Fame?

Found a security issue in PwnRM? We welcome responsible disclosures:

1. **Read** our [Security Policy](SECURITY.md) thoroughly
2. **Verify** the issue is valid and meets HIGH/CRITICAL severity
3. **Build** a working proof-of-concept
4. **Report** via [GitHub Private Vulnerability Reporting](https://github.com/uziii2208/PwnRM/security/advisories/new)
5. **Maintain** confidentiality until the fix is released

**We offer:**
```c
[+] Credit in GitHub Security Advisory
[+] Entry in this Hall of Fame
[+] Public acknowledgment in release notes
[+] Safe Harbor for good-faith research
```
---

## Timeline

| Date | Event |
|:----:|:------|
| **2026-08-15** | **[GHSA-x4cv-p53p-wh3w](https://github.com/uziii2208/PwnRM/security/advisories/GHSA-x4cv-p53p-wh3w)** reported by **[@h4x0rc](https://github.com/h4x0rc)** |
| **2026-08-15** | Vulnerability confirmed, triage initiated |
| **2026-08-16** | Security patch developed and tested |
| **2026-08-16** | **[v1.0.1](https://github.com/uziii2208/PwnRM/releases/tag/v1.0.1)** released with fix |
| **2026-08-18** | **[GHSA-jwc5-6vfh-r4h2](https://github.com/uziii2208/PwnRM/security/advisories/GHSA-jwc5-6vfh-r4h2)** reported by [@phamthanhnhat](https://github.com/phamthanhnhat) |
| **2026-08-18** | Vulnerability confirmed, triage initiated |
| **2026-08-18** | Security patch developed and tested |
| **2026-08-18** | **[v1.1.1](https://github.com/uziii2208/PwnRM/releases/tag/v1.0.1)** released with fix |

---

<div align="center">

**Thank you for helping keep the offensive security community safe.**

*Last updated: 2026-08-18*

</div>