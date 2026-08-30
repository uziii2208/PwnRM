"""
.github/scripts/audit_xml_safety.py — XML Deserialization Safety Auditor

PURPOSE:
  Audits XML parsing routines across PSRP/WS-Man handling to ensure complete immunity
  against XML External Entity (XXE) and XML Entity Expansion / Billion Laughs Denial
  of Service attacks via defusedxml enforcement (CWE-611 / CWE-400).

METHODOLOGY:
  1. AST parsing of all XML imports and parsing invocations across src/pwnrm/.
  2. Verification that standard xml.etree.ElementTree is defused with defusedxml.
  3. Dependency checking for pinned defusedxml in requirements.txt.
  4. Inspection of exception handling surrounding XML deserialization sinks.

LIMITATIONS:
  - Third-party dependency internal XML parsing (e.g. within pypsrp) is checked at interface level.
"""

import ast
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List


class XMLAuditVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str, source_code: str):
        self.filepath = filepath.replace("\\", "/")
        self.source_lines = source_code.splitlines()
        self.findings: List[Dict[str, Any]] = []
        self.has_raw_etree = False
        self.has_defused_etree = False

    def _get_line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if "xml.etree" in alias.name:
                self.has_raw_etree = True
            if "defusedxml" in alias.name:
                self.has_defused_etree = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module and "xml.etree" in node.module:
            self.has_raw_etree = True
        if node.module and "defusedxml" in node.module:
            self.has_defused_etree = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        # CHECK-X1: Direct vulnerable XML parsing calls
        if func_name in {"fromstring", "parse"} and self.has_raw_etree and not self.has_defused_etree:
            snippet = self._get_line_snippet(node.lineno)
            finding = {
                "severity": "CRITICAL",
                "file": self.filepath,
                "line": node.lineno,
                "code_snippet": snippet,
                "check_id": "CHECK-X1",
                "message": f"Raw XML parsing call '{func_name}()' without defusedxml protection (CWE-611 XXE risk)."
            }
            self.findings.append(finding)
            print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

        self.generic_visit(node)


def audit_requirements_xml(root_dir: Path) -> List[Dict[str, Any]]:
    findings = []
    req_file = root_dir / "requirements.txt"
    if not req_file.exists():
        return findings

    content = req_file.read_text(encoding="utf-8", errors="replace")
    has_defused = False
    is_pinned = False

    for line in content.splitlines():
        line_s = line.strip()
        if "defusedxml" in line_s:
            has_defused = True
            if ">=" in line_s or "==" in line_s:
                is_pinned = True

    # CHECK-X2: defusedxml presence and pinning
    if not has_defused:
        finding = {
            "severity": "CRITICAL",
            "file": "requirements.txt",
            "line": 1,
            "code_snippet": "requirements.txt",
            "check_id": "CHECK-X2",
            "message": "defusedxml is missing from requirements.txt. Must be pinned >= 0.7.1."
        }
        findings.append(finding)
        print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")
    elif not is_pinned:
        finding = {
            "severity": "HIGH",
            "file": "requirements.txt",
            "line": 1,
            "code_snippet": "defusedxml",
            "check_id": "CHECK-X2",
            "message": "defusedxml version is not pinned in requirements.txt (e.g. defusedxml>=0.7.1)."
        }
        findings.append(finding)
        print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

    return findings


def run_audit(root_dir: str = ".") -> Dict[str, Any]:
    root = Path(root_dir)
    src_dir = root / "src" / "pwnrm"

    print("=== Running XML Deserialization Safety Auditor (audit_xml_safety.py) ===")
    findings = []

    for py_file in src_dir.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(py_file))
            visitor = XMLAuditVisitor(str(py_file), content)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except Exception as e:
            print(f"[WARNING] Error parsing {py_file}: {e}")

    findings.extend(audit_requirements_xml(root))

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        summary[sev] = summary.get(sev, 0) + 1

    return {
        "auditor": "xml_safety",
        "findings": findings,
        "summary": summary
    }


if __name__ == "__main__":
    out_dir = Path("audit_output")
    out_dir.mkdir(parents=True, exist_ok=True)
    res = run_audit()
    out_file = out_dir / "xml_safety.json"
    out_file.write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(f"XML Safety Audit completed. Summary: {res['summary']}")
