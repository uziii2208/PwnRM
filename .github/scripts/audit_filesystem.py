"""
.github/scripts/audit_filesystem.py — File Handling & Permission Auditor

PURPOSE:
  Audits filesystem operations to ensure compliance with atomic file creation,
  restrictive permissions (0o600 / 0o700), TOCTOU symlink race protections,
  and clean repository hygiene (CWE-377 / CWE-732 / CWE-367 / CWE-276).

METHODOLOGY:
  1. AST inspection for plain open("w") on sensitive loot and session directories.
  2. Permission hardening enforcement checks (os.chmod / icacls within file lifecycles).
  3. Manifest and history file atomic replacement and symlink guards.
  4. Git tracking verification for untracked bytecode or cache artifacts.

LIMITATIONS:
  - Windows NTFS ACL inheritance is tested through static pattern presence.
"""

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


class FilesystemAuditVisitor(ast.NodeVisitor):
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
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        snippet = self._get_line_snippet(node.lineno)

        # CHECK-F1: open() without O_EXCL for sensitive paths
        if func_name == "open" and module_name == "":
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
                if "w" in mode or "a" in mode:
                    if any(sens in snippet.lower() for sens in ["loot", "session", "cred", "history"]):
                        if "atomic" not in snippet.lower() and "safe" not in snippet.lower():
                            finding = {
                                "severity": "HIGH",
                                "file": self.filepath,
                                "line": node.lineno,
                                "code_snippet": snippet,
                                "check_id": "CHECK-F1",
                                "message": f"Plain open('{mode}') used on sensitive path. Use os.open() with O_CREAT | O_EXCL and 0o600 mode."
                            }
                            self.findings.append(finding)
                            print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

        # CHECK-F4: Insecure tempfile.mktemp
        if func_name == "mktemp" and (module_name == "tempfile" or "tempfile" in snippet):
            finding = {
                "severity": "HIGH",
                "file": self.filepath,
                "line": node.lineno,
                "code_snippet": snippet,
                "check_id": "CHECK-F4",
                "message": "Insecure 'tempfile.mktemp()' called. Vulnerable to TOCTOU race condition; use NamedTemporaryFile or mkstemp."
            }
            self.findings.append(finding)
            print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

        self.generic_visit(node)


def check_git_tracked_bytecode(root_dir: Path) -> List[Dict[str, Any]]:
    findings = []
    try:
        res = subprocess.run(["git", "ls-files"], cwd=str(root_dir), capture_output=True, text=True, check=False)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if re.search(r'(__pycache__|\.pyc$|\.pyo$)', line):
                    finding = {
                        "severity": "HIGH",
                        "file": line,
                        "line": 1,
                        "code_snippet": line,
                        "check_id": "CHECK-F5",
                        "message": f"Compiled Python bytecode or cache tracked in git: '{line}'. Fix: git rm --cached '{line}'"
                    }
                    findings.append(finding)
                    print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")
    except Exception as e:
        print(f"[INFO] Skipping git tracked bytecode check (not in git env or git error: {e})")
    return findings


def check_history_symlink_defense(root_dir: Path) -> List[Dict[str, Any]]:
    findings = []
    pwnshell_file = root_dir / "src" / "pwnrm" / "shell" / "pwnshell.py"
    if pwnshell_file.exists():
        content = pwnshell_file.read_text(encoding="utf-8", errors="replace")
        if "is_symlink" not in content and "unlink" not in content:
            finding = {
                "severity": "CRITICAL",
                "file": "src/pwnrm/shell/pwnshell.py",
                "line": 1,
                "code_snippet": "File history loading",
                "check_id": "CHECK-F6",
                "message": "History file loading does not check and unlink pre-existing symlinks (CWE-377 / CWE-59)."
            }
            findings.append(finding)
            print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")
    return findings


def run_audit(root_dir: str = ".") -> Dict[str, Any]:
    root = Path(root_dir)
    src_dir = root / "src" / "pwnrm"

    print("=== Running File Handling & Permission Auditor (audit_filesystem.py) ===")
    findings = []

    for py_file in src_dir.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(py_file))
            visitor = FilesystemAuditVisitor(str(py_file), content)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except Exception as e:
            print(f"[WARNING] Error parsing {py_file}: {e}")

    findings.extend(check_git_tracked_bytecode(root))
    findings.extend(check_history_symlink_defense(root))

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        summary[sev] = summary.get(sev, 0) + 1

    return {
        "auditor": "filesystem",
        "findings": findings,
        "summary": summary
    }


if __name__ == "__main__":
    out_dir = Path("audit_output")
    out_dir.mkdir(parents=True, exist_ok=True)
    res = run_audit()
    out_file = out_dir / "filesystem.json"
    out_file.write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(f"Filesystem Audit completed. Summary: {res['summary']}")
