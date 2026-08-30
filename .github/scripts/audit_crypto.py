"""
.github/scripts/audit_crypto.py — Cryptographic Hygiene Auditor

PURPOSE:
  Performs AST analysis and pattern matching to detect weak PRNGs (random vs secrets),
  insecure cryptographic implementations (MD5 in auth, unencrypted key persistence),
  and hardcoded key material across the PwnRM codebase (CWE-330 / CWE-327 / CWE-798).

METHODOLOGY:
  1. AST inspection for `random` module imports and security-sensitive function invocations.
  2. Evaluation of `secrets` calls (randbelow, token_bytes) for entropy boundaries.
  3. Validation of Fernet in-memory key lifecycles preventing disk leakage.
  4. Discrimination of MD5 usage (file integrity verification vs auth hashing).

LIMITATIONS:
  - Dynamic runtime key generation paths are statically evaluated.
"""

import ast
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set


SECURITY_SENSITIVE_NAMES = {
    "key", "secret", "token", "nonce", "iv", "session_id", "password", "passwd",
    "auth", "xorenc", "encrypt", "decrypt"
}

ALLOWED_BYTE_LITERAL_FUNCS = {"build_amsi_patch", "build_etw_patch", "_make_patch"}


class CryptoAuditVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str, source_code: str):
        self.filepath = filepath.replace("\\", "/")
        self.source_lines = source_code.splitlines()
        self.findings: List[Dict[str, Any]] = []
        self.random_imported = False
        self.secrets_imported = False
        self.current_function = ""

    def _get_line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "random":
                self.random_imported = True
            elif alias.name == "secrets":
                self.secrets_imported = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "random":
            self.random_imported = True
        elif node.module == "secrets":
            self.secrets_imported = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev_func = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = prev_func

    def visit_Call(self, node: ast.Call):
        func_name = ""
        module_name = ""

        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        # CHECK-C1: random in security context
        if module_name == "random" or (self.random_imported and func_name in {"randint", "choice", "randbytes", "random"}):
            snippet = self._get_line_snippet(node.lineno)
            is_sec = any(sec in snippet.lower() for sec in SECURITY_SENSITIVE_NAMES)
            severity = "CRITICAL" if "key" in snippet.lower() else ("HIGH" if is_sec else "MEDIUM")
            finding = {
                "severity": severity,
                "file": self.filepath,
                "line": node.lineno,
                "code_snippet": snippet,
                "check_id": "CHECK-C1",
                "message": f"Non-CSPRNG 'random.{func_name}()' used in {'security' if is_sec else 'general'} context. Replace with 'secrets' module."
            }
            self.findings.append(finding)
            print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

        # CHECK-C2: secrets module correctness
        if module_name == "secrets" and func_name == "randbelow":
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, int):
                val = node.args[0].value
                if val <= 1:
                    finding = {
                        "severity": "CRITICAL",
                        "file": self.filepath,
                        "line": node.lineno,
                        "code_snippet": self._get_line_snippet(node.lineno),
                        "check_id": "CHECK-C2",
                        "message": f"Invalid 'secrets.randbelow({val})' invocation: Upper bound must be greater than 1."
                    }
                    self.findings.append(finding)
                    print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

        if module_name == "secrets" and func_name == "token_bytes":
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, int):
                val = node.args[0].value
                if val < 16:
                    finding = {
                        "severity": "HIGH",
                        "file": self.filepath,
                        "line": node.lineno,
                        "code_snippet": self._get_line_snippet(node.lineno),
                        "check_id": "CHECK-C2",
                        "message": f"Weak entropy: 'secrets.token_bytes({val})' requests fewer than 16 bytes."
                    }
                    self.findings.append(finding)
                    print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

        # CHECK-C3: XOR-only encryption
        if func_name == "xorenc":
            finding = {
                "severity": "MEDIUM",
                "file": self.filepath,
                "line": node.lineno,
                "code_snippet": self._get_line_snippet(node.lineno),
                "check_id": "CHECK-C3",
                "message": "XOR stream cipher invocation (xorenc). Note: Suitable for staging/obfuscation only, not credential storage."
            }
            self.findings.append(finding)
            print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

        # CHECK-C5: MD5 usage check
        if func_name == "md5" or (module_name == "hashlib" and func_name == "md5"):
            snippet = self._get_line_snippet(node.lineno)
            is_auth = any(term in snippet.lower() for term in ["pass", "auth", "token", "sign", "login"])
            severity = "HIGH" if is_auth else "INFO"
            finding = {
                "severity": severity,
                "file": self.filepath,
                "line": node.lineno,
                "code_snippet": snippet,
                "check_id": "CHECK-C5",
                "message": "MD5 hash instantiated. " + ("CRITICAL: MD5 used in authentication path!" if is_auth else "Acceptable: Used for file transfer integrity checksum.")
            }
            self.findings.append(finding)
            print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        # CHECK-C6: Hardcoded byte sequences
        if isinstance(node.value, bytes) and len(node.value) > 16:
            if self.current_function not in ALLOWED_BYTE_LITERAL_FUNCS:
                snippet = self._get_line_snippet(node.lineno)
                if not any(allow in self.filepath for allow in ["test", "resources"]):
                    finding = {
                        "severity": "INFO",
                        "file": self.filepath,
                        "line": node.lineno,
                        "code_snippet": snippet[:60] + "...",
                        "check_id": "CHECK-C6",
                        "message": f"Byte literal of length {len(node.value)} detected in function '{self.current_function}'. Verify not hardcoded credential."
                    }
                    self.findings.append(finding)
                    print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")
        self.generic_visit(node)


def audit_fernet_persistence(src_dir: Path) -> List[Dict[str, Any]]:
    findings = []
    for py_file in src_dir.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            # CHECK-C4: Check if Fernet key is written to disk or logged
            if "Fernet" in content:
                for idx, line in enumerate(content.splitlines(), start=1):
                    if re.search(r'(?:open|write_bytes|write_text|json\.dump|logging\.info).*_SESSION_KEY', line):
                        finding = {
                            "severity": "CRITICAL",
                            "file": str(py_file).replace("\\", "/"),
                            "line": idx,
                            "code_snippet": line.strip(),
                            "check_id": "CHECK-C4",
                            "message": "Ephemeral Fernet key (_SESSION_KEY) appears to be persisted or logged."
                        }
                        findings.append(finding)
                        print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")
        except Exception as e:
            print(f"[WARNING] Error checking Fernet in {py_file}: {e}")
    return findings


def run_audit(root_dir: str = ".") -> Dict[str, Any]:
    root = Path(root_dir)
    src_dir = root / "src" / "pwnrm"

    print("=== Running Cryptographic Hygiene Auditor (audit_crypto.py) ===")
    findings = []

    for py_file in src_dir.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(py_file))
            visitor = CryptoAuditVisitor(str(py_file), content)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except Exception as e:
            print(f"[WARNING] Error parsing {py_file}: {e}")

    findings.extend(audit_fernet_persistence(src_dir))

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        summary[sev] = summary.get(sev, 0) + 1

    return {
        "auditor": "crypto",
        "findings": findings,
        "summary": summary
    }


if __name__ == "__main__":
    out_dir = Path("audit_output")
    out_dir.mkdir(parents=True, exist_ok=True)
    res = run_audit()
    out_file = out_dir / "crypto.json"
    out_file.write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(f"Crypto Audit completed. Summary: {res['summary']}")
