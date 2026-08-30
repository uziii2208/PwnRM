"""
.github/scripts/run_all_audits.py — Security Audit Orchestrator

PURPOSE:
  Master orchestrator that executes all custom security auditors in sequence,
  aggregates findings into structured JSON, compiles executive HTML reports,
  renders an ASCII summary table, and enforces CI/CD build exit gates.

METHODOLOGY:
  1. Executes all 6 auditors:
     - audit_ps_injection.py
     - audit_crypto.py
     - audit_filesystem.py
     - audit_xml_safety.py
     - audit_secrets_exposure.py
     - audit_network.py
  2. Saves individual JSON files to audit_output/<auditor>.json.
  3. Invokes audit_report.py to create audit_report.json, audit_report.html, and emit GitHub annotations.
  4. Formats a Unicode/ASCII tabular overview of findings across all categories.
  5. Enforces deterministic exit codes:
     - Exit 0: If CRITICAL == 0 and HIGH == 0 (or AUDIT_ALLOW_HIGH=1 is set).
     - Exit 1: If any CRITICAL finding or unallowed HIGH finding is discovered.
"""

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


AUDITOR_SCRIPTS = [
    ("ps_injection", "audit_ps_injection.py"),
    ("crypto", "audit_crypto.py"),
    ("filesystem", "audit_filesystem.py"),
    ("xml_safety", "audit_xml_safety.py"),
    ("secrets_exposure", "audit_secrets_exposure.py"),
    ("network", "audit_network.py"),
]


def load_and_run_auditor(script_path: Path) -> Dict[str, Any]:
    spec = importlib.util.spec_from_file_location(script_path.stem, script_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load auditor spec from {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if hasattr(module, "run_audit"):
        return module.run_audit()
    raise AttributeError(f"Auditor {script_path} does not export run_audit()")


def print_summary_table(auditor_results: List[Tuple[str, Dict[str, int]]], total_summary: Dict[str, int]):
    print("\n" + "=" * 70)
    print("                    PWNRM SECURITY AUDIT SUMMARY")
    print("=" * 70)
    
    # Universal ASCII Table headers
    header = f"| {'Auditor':<23} | {'CRITICAL':^8} | {'HIGH':^6} | {'MEDIUM':^8} | {'LOW':^5} | {'INFO':^6} |"
    div_top = "+-------------------------+----------+------+--------+-----+------+"
    div_mid = "+-------------------------+----------+------+--------+-----+------+"
    div_bot = "+-------------------------+----------+------+--------+-----+------+"

    print(div_top)
    print(header)
    print(div_mid)

    for name, s in auditor_results:
        crit = s.get("CRITICAL", 0)
        high = s.get("HIGH", 0)
        med = s.get("MEDIUM", 0)
        low = s.get("LOW", 0)
        info = s.get("INFO", 0)
        row = f"| {name:<23} | {crit:^8} | {high:^6} | {med:^8} | {low:^5} | {info:^6} |"
        print(row)

    print(div_mid)
    total_row = (
        f"| {'TOTAL':<23} | "
        f"{total_summary.get('CRITICAL', 0):^8} | "
        f"{total_summary.get('HIGH', 0):^6} | "
        f"{total_summary.get('MEDIUM', 0):^8} | "
        f"{total_summary.get('LOW', 0):^5} | "
        f"{total_summary.get('INFO', 0):^6} |"
    )
    print(total_row)
    print(div_bot)


def main():
    root_dir = Path(__file__).resolve().parent.parent.parent
    scripts_dir = root_dir / ".github" / "scripts"
    output_dir = root_dir / "audit_output"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Starting PwnRM Full Security Audit Pipeline from: {root_dir}")
    auditor_table_data: List[Tuple[str, Dict[str, int]]] = []
    total_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for name, filename in AUDITOR_SCRIPTS:
        script_file = scripts_dir / filename
        if not script_file.exists():
            print(f"[ERROR] Auditor script missing: {script_file}")
            continue

        try:
            result = load_and_run_auditor(script_file)
            summary = result.get("summary", {})
            auditor_table_data.append((name, summary))

            for k in total_summary:
                total_summary[k] += summary.get(k, 0)

            # Write JSON output
            out_file = output_dir / f"{name}.json"
            out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"[CRITICAL ERROR] Failed executing {name}: {e}")
            total_summary["CRITICAL"] += 1

    # Print summary table
    print_summary_table(auditor_table_data, total_summary)

    # Build final reports
    report_script = scripts_dir / "audit_report.py"
    if report_script.exists():
        spec = importlib.util.spec_from_file_location("audit_report", report_script)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "build_reports"):
                mod.build_reports(str(output_dir))

    # Evaluate exit conditions
    allow_high = os.environ.get("AUDIT_ALLOW_HIGH", "0") == "1"
    crit_count = total_summary.get("CRITICAL", 0)
    high_count = total_summary.get("HIGH", 0)

    print("\n=== Audit Gate Evaluation ===")
    if crit_count > 0:
        print(f"[FAIL] Pipeline rejected: {crit_count} CRITICAL finding(s) detected.")
        sys.exit(1)
    elif high_count > 0 and not allow_high:
        print(f"[FAIL] Pipeline rejected: {high_count} HIGH finding(s) detected. Set AUDIT_ALLOW_HIGH=1 to override.")
        sys.exit(1)
    else:
        print("[SUCCESS] All security gates passed clean!")
        sys.exit(0)


if __name__ == "__main__":
    main()
