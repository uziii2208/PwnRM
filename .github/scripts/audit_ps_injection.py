"""
.github/scripts/audit_ps_injection.py — PowerShell String Injection Auditor

PURPOSE:
  Performs AST-level data flow analysis across Python codebase and regex inspection
  on PowerShell resource scripts to detect unescaped PowerShell string interpolations
  that could lead to Command Injection (CWE-78 / CWE-88).

METHODOLOGY:
  1. Walks all Python AST nodes in src/pwnrm/ discovering f-strings (JoinedStr),
     format calls, and concatenations feeding into PowerShell execution sinks.
  2. Evaluates escape functions (_pde, _pse, str_b64, b64str) and distinguishes
     server-returned data, user-supplied args, and local constants.
  3. Scans .ps1 resource scripts for dangerous double-quoted variable interpolations.

LIMITATIONS:
  - Complex inter-procedural taint flows across dynamic reflection boundaries are approximated.
"""

import ast
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


SAFE_ESCAPE_WRAPPERS = {
    "_pde", "_pse", "str_b64", "b64str", "b64encode", "base64.b64encode",
    "build_amsi_patch", "int", "len", "bool", "float", "secrets.token_hex",
    "secrets.token_bytes", "quote"
}

SAFE_VAR_PATTERNS = {
    r"^rport$", r"^lport$", r"^port$", r"^timeout$", r"^sid$", r"^session_id$",
    r"^key_int$", r"^xor_key$", r"^nonce$", r"^chunk_size$"
}

SINK_FUNCTION_NAMES = {"run_sync", "run_with_interrupt", "run_command", "send_command"}
TARGET_VAR_NAMES = {"cmd", "ps", "script", "command", "ps_cmd", "ps_script", "payload"}


class PSInjectionVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str, source_code: str):
        self.filepath = filepath
        self.source_lines = source_code.splitlines()
        self.findings: List[Dict[str, Any]] = []
        self.assigned_safe_vars: Set[str] = set()
        self.assigned_tainted_vars: Dict[str, str] = {}

    def _get_line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _is_safe_node(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = getattr(node.func, "attr", "")
            if func_name in SAFE_ESCAPE_WRAPPERS:
                return True
        if isinstance(node, ast.Name):
            if node.id in self.assigned_safe_vars:
                return True
            for pat in SAFE_VAR_PATTERNS:
                if re.match(pat, node.id, re.IGNORECASE):
                    return True
        return False

    def _inspect_fstring(self, node: ast.JoinedStr, context_desc: str):
        for val in node.values:
            if isinstance(val, ast.FormattedValue):
                expr = val.value
                if self._is_safe_node(expr):
                    continue

                var_repr = ast.unparse(expr) if hasattr(ast, "unparse") else "expr"
                snippet = self._get_line_snippet(node.lineno)

                # Determine origin & severity
                origin = "local_variable"
                severity = "MEDIUM"

                if "args" in var_repr or "user" in var_repr or "input" in var_repr:
                    origin = "user-supplied argument"
                    severity = "HIGH"
                elif "out" in var_repr or "resp" in var_repr or "server" in var_repr:
                    origin = "server-returned response data"
                    severity = "CRITICAL"
                elif var_repr in self.assigned_tainted_vars:
                    origin = self.assigned_tainted_vars[var_repr]
                    severity = "HIGH" if "user" in origin else "CRITICAL"

                finding = {
                    "severity": severity,
                    "file": self.filepath.replace("\\", "/"),
                    "line": node.lineno,
                    "code_snippet": snippet,
                    "variable": var_repr,
                    "origin": origin,
                    "escape_applied": False,
                    "message": f"PowerShell command string interpolates '{var_repr}' without _pde()/_pse() escaping in {context_desc}"
                }
                self.findings.append(finding)
                print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")

    def visit_Assign(self, node: ast.Assign):
        # Track variable assignments
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if isinstance(node.value, ast.Call):
                    if self._is_safe_node(node.value):
                        self.assigned_safe_vars.add(var_name)
                elif isinstance(node.value, ast.JoinedStr) and var_name.lower() in TARGET_VAR_NAMES:
                    self._inspect_fstring(node.value, f"assignment to '${var_name}'")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in SINK_FUNCTION_NAMES:
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):
                    self._inspect_fstring(arg, f"call to '{func_name}()'")
        self.generic_visit(node)


def audit_python_files(src_dir: Path) -> List[Dict[str, Any]]:
    all_findings = []
    for py_file in src_dir.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(py_file))
            visitor = PSInjectionVisitor(str(py_file), content)
            visitor.visit(tree)
            all_findings.extend(visitor.findings)
        except SyntaxError as e:
            print(f"[INFO] Skipping file due to parse error: {py_file} ({e})")
        except Exception as e:
            print(f"[WARNING] Error inspecting {py_file}: {e}")
    return all_findings


def audit_powershell_resources(res_dir: Path) -> List[Dict[str, Any]]:
    findings = []
    if not res_dir.exists():
        return findings

    for ps_file in res_dir.rglob("*.ps1"):
        try:
            lines = ps_file.read_text(encoding="utf-8", errors="replace").splitlines()
            for idx, line in enumerate(lines, start=1):
                clean_line = line.strip()
                if clean_line.startswith("#"):
                    continue
                # Flag unvalidated subexpression expansion in double quoted string with dangerous verbs
                if re.search(r'"[^"]*\$\([^\)]*(?:Invoke-Expression|iex|cmd\.exe|download)[^\)]*\)[^"]*"', clean_line, re.IGNORECASE):
                    finding = {
                        "severity": "HIGH",
                        "file": str(ps_file).replace("\\", "/"),
                        "line": idx,
                        "code_snippet": clean_line,
                        "variable": "$() subexpression",
                        "origin": "resource script",
                        "escape_applied": False,
                        "message": "PowerShell script embeds active subexpression inside double-quoted string"
                    }
                    findings.append(finding)
                    print(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['message']}")
        except Exception as e:
            print(f"[WARNING] Could not read PS1 resource {ps_file}: {e}")
    return findings


def run_audit(root_dir: str = ".") -> Dict[str, Any]:
    root = Path(root_dir)
    src_dir = root / "src" / "pwnrm"
    res_dir = root / "src" / "pwnrm" / "resources"

    print("=== Running PowerShell Injection Auditor (audit_ps_injection.py) ===")
    findings = []
    findings.extend(audit_python_files(src_dir))
    findings.extend(audit_powershell_resources(res_dir))

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        summary[sev] = summary.get(sev, 0) + 1

    result = {
        "auditor": "ps_injection",
        "findings": findings,
        "summary": summary
    }
    return result


if __name__ == "__main__":
    out_dir = Path("audit_output")
    out_dir.mkdir(parents=True, exist_ok=True)
    res = run_audit()
    out_file = out_dir / "ps_injection.json"
    out_file.write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(f"PowerShell Injection Audit completed. Summary: {res['summary']}")
