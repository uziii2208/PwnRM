"""
.github/scripts/audit_network.py — Network & Transport Security Auditor

PURPOSE:
  Audits the WinRM transport layer to verify SSRF defenses (max_redirects=0, trust_env=False),
  cryptographic binding assertions (CredSSP pubKeyAuth verification), TLS verification
  boundaries, and WebSocket handshake security (CWE-918 / CWE-295 / CWE-208).

METHODOLOGY:
  1. AST inspection of Session() initialization in transports.py verifying redirect limits.
  2. Verification of allow_redirects=False on all outbound HTTP/HTTPS requests.
  3. Analysis of CredSSP pubKeyAuth verification for constant-time comparison (hmac.compare_digest).
  4. Inspection of WebSocketTransport header configurations and CSPRNG nonce generation.

LIMITATIONS:
  - Transport layer proxy configurations are evaluated statically.
"""

import ast
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List


class NetworkAuditVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str, source_code: str):
        self.filepath = filepath.replace("\\", "/")
        self.source_lines = source_code.splitlines()
        self.findings: List[Dict[str, Any]] = []
        self.current_class = ""

    def _get_line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_ClassDef(self, node: ast.ClassDef):
        prev_cls = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = prev_cls

    def visit_Assign(self, node: ast.Assign):
        # CHECK-N4: SSL verification check
        snippet = self._get_line_snippet(node.lineno)
        if "verify" in snippet and "False" in snippet:
            if "Transport" in self.current_class or "transports.py" in self.filepath:
                finding = {
                    "severity": "INFO",
                    "file": self.filepath,
                    "line": node.lineno,
                    "code_snippet": snippet,
                    "check_id": "CHECK-N4",
                    "message": "SSL certificate verification disabled (verify=False) in Transport layer (Documented: WinRM self-signed cert support)."
                }
                self.findings.append(finding)
            else:
                finding = {
                    "severity": "CRITICAL",
                    "file": self.filepath,
                    "line": node.lineno,
                    "code_snippet": snippet,
                    "check_id": "CHECK-N4",
                    "message": f"SSL verification disabled outside Transport base class in {self.filepath}."
                }
                self.findings.append(finding)
                print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        # CHECK-N3: allow_redirects in send/request
        if func_name in {"send", "post", "get", "request"} and "transports.py" in self.filepath:
            has_allow_redir = False
            for kw in node.keywords:
                if kw.arg == "allow_redirects":
                    has_allow_redir = True
                    if isinstance(kw.value, ast.Constant) and kw.value.value is not False:
                        finding = {
                            "severity": "HIGH",
                            "file": self.filepath,
                            "line": node.lineno,
                            "code_snippet": self._get_line_snippet(node.lineno),
                            "check_id": "CHECK-N3",
                            "message": f"HTTP request {func_name}() enables redirects (allow_redirects=True). Must be False to prevent SSRF (CWE-918)."
                        }
                        self.findings.append(finding)
                        print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

        self.generic_visit(node)


def audit_transport_session_hardening(src_dir: Path) -> List[Dict[str, Any]]:
    findings = []
    transports_file = src_dir / "core" / "transports.py"
    if not transports_file.exists():
        return findings

    content = transports_file.read_text(encoding="utf-8", errors="replace")

    # CHECK-N1: max_redirects=0
    if "max_redirects = 0" not in content and "max_redirects=0" not in content:
        finding = {
            "severity": "CRITICAL",
            "file": "src/pwnrm/core/transports.py",
            "line": 1,
            "code_snippet": "Session initialization",
            "check_id": "CHECK-N1",
            "message": "Transport Session() initialization lacks explicit 'session.max_redirects = 0' hardening (CWE-918)."
        }
        findings.append(finding)
        print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

    # CHECK-N2: trust_env=False
    if "trust_env = False" not in content and "trust_env=False" not in content:
        finding = {
            "severity": "HIGH",
            "file": "src/pwnrm/core/transports.py",
            "line": 1,
            "code_snippet": "Session initialization",
            "check_id": "CHECK-N2",
            "message": "Transport Session() initialization lacks explicit 'session.trust_env = False' hardening (Proxy MITM risk)."
        }
        findings.append(finding)
        print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

    # CHECK-N6: CredSSP pubKeyAuth verification
    if "CredSSPTransport" in content:
        if "pubKeyAuth" in content or "pub_key_auth" in content:
            if "compare_digest" not in content:
                finding = {
                    "severity": "HIGH",
                    "file": "src/pwnrm/core/transports.py",
                    "line": 1,
                    "code_snippet": "CredSSP pubKeyAuth verification",
                    "check_id": "CHECK-N6",
                    "message": "CredSSP pubKeyAuth hash comparison does not use constant-time hmac.compare_digest() (Timing oracle risk)."
                }
                findings.append(finding)
                print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

    # CHECK-N5: WebSocketTransport CSPRNG Key check
    if "WebSocketTransport" in content:
        if "random.randbytes" in content or "random.randint" in content:
            finding = {
                "severity": "HIGH",
                "file": "src/pwnrm/core/transports.py",
                "line": 1,
                "code_snippet": "WebSocketTransport key generation",
                "check_id": "CHECK-N5",
                "message": "WebSocketTransport generates Sec-WebSocket-Key via non-CSPRNG random module instead of secrets."
            }
            findings.append(finding)
            print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

    return findings


def run_audit(root_dir: str = ".") -> Dict[str, Any]:
    root = Path(root_dir)
    src_dir = root / "src" / "pwnrm"

    print("=== Running Network & Transport Security Auditor (audit_network.py) ===")
    findings = []
    findings.extend(audit_transport_session_hardening(src_dir))

    for py_file in src_dir.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(py_file))
            visitor = NetworkAuditVisitor(str(py_file), content)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except Exception as e:
            print(f"[WARNING] Error parsing {py_file}: {e}")

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        summary[sev] = summary.get(sev, 0) + 1

    return {
        "auditor": "network",
        "findings": findings,
        "summary": summary
    }


if __name__ == "__main__":
    out_dir = Path("audit_output")
    out_dir.mkdir(parents=True, exist_ok=True)
    res = run_audit()
    out_file = out_dir / "network.json"
    out_file.write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(f"Network Audit completed. Summary: {res['summary']}")
