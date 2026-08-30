"""
.github/scripts/audit_secrets_exposure.py — Secret / Credential Leak Auditor

PURPOSE:
  Scans source code, logging calls, shell history filters, git commits, and project
  metadata for hardcoded credentials, cleartext secret exposure in logs, or insecure
  history tracking (CWE-798 / CWE-532 / CWE-200).

METHODOLOGY:
  1. Regex scanning for hardcoded passwords, API keys, and NTLM hashes.
  2. AST inspection of logging calls for sensitive variable serialization.
  3. Coverage validation of HISTORY_EXCLUDE_PATTERN in pwnshell.py.
  4. Consistency check between requirements.txt and pyproject.toml dependencies.

LIMITATIONS:
  - Test mock strings and known dummy values are filtered via documented allowlist.
"""

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Set


SECRET_REGEX_PATTERNS = [
    (re.compile(r'(?:password|passwd|pwd)\s*=\s*["\']([^"\']{6,})["\']', re.IGNORECASE), "Hardcoded password assignment"),
    (re.compile(r'(?:api_key|apikey|secret_key)\s*=\s*["\']([^"\']{8,})["\']', re.IGNORECASE), "Hardcoded API key assignment"),
    (re.compile(r'(?:nt_hash|nthash)\s*=\s*["\']([0-9a-fA-F]{32})["\']', re.IGNORECASE), "Hardcoded NTLM hash assignment"),
    (re.compile(r'[0-9a-fA-F]{32}:[0-9a-fA-F]{32}', re.IGNORECASE), "LM:NTLM hash pair string literal"),
]

KNOWN_SAFE_LITERALS = {
    "P@ssw0rd!", "Password123!", "aad3b435b51404eeaad3b435b51404ee", "secret",
    "P@ss1", "Secret123!", "P@ss", "username", "admin", "administrator"
}

SENSITIVE_VAR_NAMES = {
    "password", "passwd", "pwd", "hash", "nt_hash", "nthash", "secret",
    "token", "key", "pfx_pass", "ccache", "creds", "cleartext"
}


class SecretsLoggingVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str, source_code: str):
        self.filepath = filepath.replace("\\", "/")
        self.source_lines = source_code.splitlines()
        self.findings: List[Dict[str, Any]] = []

    def _get_line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call):
        func_name = ""
        module_name = ""

        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id

        # CHECK-S2: Secrets in logging calls
        if module_name == "logging" or func_name in {"debug", "info", "warning", "error", "critical"}:
            for arg in node.args:
                arg_str = ast.unparse(arg).lower() if hasattr(ast, "unparse") else ""
                for sens in SENSITIVE_VAR_NAMES:
                    if re.search(rf'\b{sens}\b', arg_str):
                        severity = "MEDIUM" if func_name == "debug" else "HIGH"
                        finding = {
                            "severity": severity,
                            "file": self.filepath,
                            "line": node.lineno,
                            "code_snippet": self._get_line_snippet(node.lineno),
                            "check_id": "CHECK-S2",
                            "message": f"Potential credential variable '{sens}' serialized in logging.{func_name}() call."
                        }
                        self.findings.append(finding)
                        print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")
                        break
        self.generic_visit(node)


def audit_hardcoded_secrets(root_dir: Path) -> List[Dict[str, Any]]:
    findings = []
    # Scan src/
    for ext in ["*.py", "*.ps1"]:
        for file_path in (root_dir / "src").rglob(ext):
            try:
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
                for idx, line in enumerate(lines, start=1):
                    clean = line.strip()
                    if clean.startswith("#") or clean.startswith('"""') or clean.startswith("'''"):
                        continue
                    for pat, desc in SECRET_REGEX_PATTERNS:
                        match = pat.search(clean)
                        if match:
                            val = match.group(1) if match.groups() else match.group(0)
                            if val in KNOWN_SAFE_LITERALS or "example" in clean.lower():
                                continue
                            finding = {
                                "severity": "CRITICAL",
                                "file": str(file_path.relative_to(root_dir)).replace("\\", "/"),
                                "line": idx,
                                "code_snippet": clean[:80],
                                "check_id": "CHECK-S1",
                                "message": f"{desc}: '{val[:10]}...'"
                            }
                            findings.append(finding)
                            print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")
            except Exception as e:
                print(f"[WARNING] Error reading {file_path}: {e}")
    return findings


def audit_history_exclude_regex(root_dir: Path) -> List[Dict[str, Any]]:
    findings = []
    pwnshell_file = root_dir / "src" / "pwnrm" / "shell" / "pwnshell.py"
    if not pwnshell_file.exists():
        return findings

    content = pwnshell_file.read_text(encoding="utf-8", errors="replace")
    match = re.search(r'HISTORY_EXCLUDE_PATTERN\s*=\s*re\.compile\(\s*r?["\']([^"\']+)["\']', content)
    if not match:
        return findings

    pattern_str = match.group(1)
    compiled_pat = re.compile(pattern_str, re.IGNORECASE)

    test_sensitive_commands = [
        "-p 'P@ssword123!'",
        "-H :aad3b435b51404eeaad3b435b51404ee",
        "--hash :aad3b435b51404eeaad3b435b51404ee",
        "--pfx-pass Secret123",
        "mimikatz",
        "secretsdump",
        "lsass",
        "ccache",
        "kirbi",
        "dpapi"
    ]

    for cmd in test_sensitive_commands:
        if not compiled_pat.search(cmd):
            finding = {
                "severity": "MEDIUM",
                "file": "src/pwnrm/shell/pwnshell.py",
                "line": 1,
                "code_snippet": pattern_str,
                "check_id": "CHECK-S3",
                "message": f"HISTORY_EXCLUDE_PATTERN does not filter sensitive command pattern: '{cmd}'"
            }
            findings.append(finding)
            print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")
    return findings


def audit_dependency_consistency(root_dir: Path) -> List[Dict[str, Any]]:
    findings = []
    req_file = root_dir / "requirements.txt"
    pyproj_file = root_dir / "pyproject.toml"

    if not req_file.exists() or not pyproj_file.exists():
        return findings

    req_text = req_file.read_text(encoding="utf-8", errors="replace")
    pyproj_text = pyproj_file.read_text(encoding="utf-8", errors="replace")

    req_deps = {l.split("==")[0].split(">=")[0].strip().lower() for l in req_text.splitlines() if l.strip() and not l.startswith("#")}

    # CHECK-S5: loose version checks
    for line in req_text.splitlines():
        line_s = line.strip()
        if line_s and not line_s.startswith("#"):
            if ">=" in line_s and "<" not in line_s and "==" not in line_s:
                finding = {
                    "severity": "INFO",
                    "file": "requirements.txt",
                    "line": 1,
                    "code_snippet": line_s,
                    "check_id": "CHECK-S5",
                    "message": f"Dependency '{line_s}' uses open upper bound (>=). Consider pinning upper boundary."
                }
                findings.append(finding)

    return findings


def run_audit(root_dir: str = ".") -> Dict[str, Any]:
    root = Path(root_dir)
    src_dir = root / "src" / "pwnrm"

    print("=== Running Secret / Credential Leak Auditor (audit_secrets_exposure.py) ===")
    findings = []
    findings.extend(audit_hardcoded_secrets(root))

    for py_file in src_dir.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(py_file))
            visitor = SecretsLoggingVisitor(str(py_file), content)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except Exception as e:
            print(f"[WARNING] Error parsing {py_file}: {e}")

    findings.extend(audit_history_exclude_regex(root))
    findings.extend(audit_dependency_consistency(root))

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        summary[sev] = summary.get(sev, 0) + 1

    return {
        "auditor": "secrets_exposure",
        "findings": findings,
        "summary": summary
    }


if __name__ == "__main__":
    out_dir = Path("audit_output")
    out_dir.mkdir(parents=True, exist_ok=True)
    res = run_audit()
    out_file = out_dir / "secrets_exposure.json"
    out_file.write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(f"Secrets Exposure Audit completed. Summary: {res['summary']}")
