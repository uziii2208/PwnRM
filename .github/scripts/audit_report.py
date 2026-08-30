"""
.github/scripts/audit_report.py — Security Report Builder & GitHub Annotator

PURPOSE:
  Aggregates structured JSON outputs from all custom auditors into:
  1. audit_report.json (machine-readable aggregate report)
  2. audit_report.html (interactive, zero-external-dependency HTML executive report)
  3. GitHub Actions workflow command annotations (::error:: and ::warning::).

METHODOLOGY:
  - Collects all *.json in audit_output/.
  - Calculates global severity totals and pass/fail status (Pass if CRITICAL==0 and HIGH==0).
  - Emits formatted workflow command annotations for PR inline diff review.
  - Builds a standalone HTML5 report with responsive dark mode UI and collapsible finding panels.
"""

import datetime
import html
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


def get_git_info() -> Dict[str, str]:
    commit_sha = os.environ.get("GITHUB_SHA", "local-dev")
    branch = os.environ.get("GITHUB_REF_NAME", "master")

    if commit_sha == "local-dev":
        try:
            res_commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
            if res_commit.returncode == 0:
                commit_sha = res_commit.stdout.strip()
            res_branch = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True, check=False)
            if res_branch.returncode == 0:
                branch = res_branch.stdout.strip()
        except Exception:
            pass

    return {"commit": commit_sha, "branch": branch}


def count_scanned_files() -> int:
    try:
        py_files = list(Path("src").rglob("*.py"))
        ps_files = list(Path("src").rglob("*.ps1"))
        return len(py_files) + len(ps_files)
    except Exception:
        return 0


def emit_github_annotations(auditors: Dict[str, Any]):
    print("\n=== Emitting GitHub Actions Annotations ===")
    for auditor_name, data in auditors.items():
        for f in data.get("findings", []):
            sev = f.get("severity", "MEDIUM").upper()
            file_path = f.get("file", "unknown")
            line = f.get("line", 1)
            msg = f.get("message", "Security finding")

            if sev in {"CRITICAL", "HIGH"}:
                print(f"::error file={file_path},line={line}::[{auditor_name}] {msg}")
            elif sev == "MEDIUM":
                print(f"::warning file={file_path},line={line}::[{auditor_name}] {msg}")


def generate_html_report(report_data: Dict[str, Any]) -> str:
    summary = report_data["summary"]
    is_pass = summary["pass"]
    badge_color = "#10b981" if is_pass else "#ef4444"
    status_text = "PASSED" if is_pass else "FAILED (CRITICAL/HIGH DETECTED)"

    auditor_sections = []
    for aud_name, aud_data in report_data.get("auditors", {}).items():
        findings = aud_data.get("findings", [])
        findings_html = []

        if not findings:
            findings_html.append('<div class="no-findings">No security findings recorded for this auditor. Clean!</div>')
        else:
            for f in findings:
                sev = f.get("severity", "MEDIUM")
                sev_badge_class = f"badge-{sev.lower()}"
                code_snippet = f.get("code_snippet", "")
                snippet_block = f'<pre class="code-box"><code>{html.escape(code_snippet)}</code></pre>' if code_snippet else ''

                findings_html.append(f"""
                <div class="finding-card">
                    <div class="finding-header">
                        <span class="badge {sev_badge_class}">{html.escape(sev)}</span>
                        <span class="finding-file">{html.escape(f.get("file", ""))} : Line {f.get("line", "")}</span>
                    </div>
                    <div class="finding-msg">{html.escape(f.get("message", ""))}</div>
                    {snippet_block}
                </div>
                """)

        auditor_sections.append(f"""
        <div class="auditor-panel">
            <h3 class="auditor-title">Auditor: {html.escape(aud_name)} <span class="count-pill">({len(findings)} findings)</span></h3>
            {"".join(findings_html)}
        </div>
        """)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PwnRM Security Audit Report</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #3b82f6;
            --info: #64748b;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        .title {{
            font-size: 1.8rem;
            font-weight: 700;
            margin: 0;
        }}
        .meta-info {{
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }}
        .status-badge {{
            padding: 0.5rem 1.2rem;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 1rem;
            background-color: {badge_color};
            color: #ffffff;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2.5rem;
        }}
        .summary-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.2rem;
            text-align: center;
        }}
        .summary-num {{
            font-size: 2.2rem;
            font-weight: 800;
            margin-bottom: 0.2rem;
        }}
        .crit-num {{ color: var(--critical); }}
        .high-num {{ color: var(--high); }}
        .med-num  {{ color: var(--medium); }}
        .low-num  {{ color: var(--low); }}
        .info-num {{ color: var(--info); }}
        .summary-label {{
            color: var(--text-muted);
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .auditor-panel {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .auditor-title {{
            margin-top: 0;
            font-size: 1.25rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.75rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .count-pill {{
            font-size: 0.85rem;
            color: var(--text-muted);
            font-weight: normal;
        }}
        .finding-card {{
            background-color: #0b1120;
            border: 1px solid var(--border-color);
            border-left: 4px solid #64748b;
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 1rem;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.5rem;
        }}
        .badge {{
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-critical {{ background-color: var(--critical); color: #fff; }}
        .badge-high {{ background-color: var(--high); color: #fff; }}
        .badge-medium {{ background-color: var(--medium); color: #000; }}
        .badge-low {{ background-color: var(--low); color: #fff; }}
        .badge-info {{ background-color: var(--info); color: #fff; }}
        .finding-file {{
            font-family: monospace;
            font-size: 0.9rem;
            color: #38bdf8;
        }}
        .finding-msg {{
            margin-bottom: 0.5rem;
            font-size: 0.95rem;
        }}
        .code-box {{
            background-color: #020617;
            padding: 0.75rem;
            border-radius: 4px;
            font-family: Consolas, Monaco, "Courier New", monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            color: #e2e8f0;
            border: 1px solid #1e293b;
        }}
        .no-findings {{
            color: #10b981;
            font-size: 0.95rem;
            padding: 0.5rem 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 class="title">PwnRM Security Audit Report</h1>
                <div class="meta-info">
                    Commit: <code>{html.escape(report_data["commit"][:8])}</code> | 
                    Branch: <code>{html.escape(report_data["branch"])}</code> | 
                    Generated: {html.escape(report_data["generated_at"])} |
                    Scanned Files: {report_data["summary"]["total_files_scanned"]}
                </div>
            </div>
            <div class="status-badge">{status_text}</div>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-num crit-num">{summary["CRITICAL"]}</div>
                <div class="summary-label">Critical</div>
            </div>
            <div class="summary-card">
                <div class="summary-num high-num">{summary["HIGH"]}</div>
                <div class="summary-label">High</div>
            </div>
            <div class="summary-card">
                <div class="summary-num med-num">{summary["MEDIUM"]}</div>
                <div class="summary-label">Medium</div>
            </div>
            <div class="summary-card">
                <div class="summary-num low-num">{summary["LOW"]}</div>
                <div class="summary-label">Low</div>
            </div>
            <div class="summary-card">
                <div class="summary-num info-num">{summary["INFO"]}</div>
                <div class="summary-label">Info</div>
            </div>
        </div>

        <div class="auditors-container">
            {"".join(auditor_sections)}
        </div>
    </div>
</body>
</html>
"""
    return html_content


def build_reports(output_dir: str = "audit_output"):
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    git_info = get_git_info()
    total_files = count_scanned_files()

    auditors_data: Dict[str, Any] = {}
    global_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for json_file in out_path.glob("*.json"):
        if json_file.name in {"audit_report.json"}:
            continue
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            auditor_name = data.get("auditor", json_file.stem)
            auditors_data[auditor_name] = data
            for sev, count in data.get("summary", {}).items():
                global_summary[sev] = global_summary.get(sev, 0) + count
        except Exception as e:
            print(f"[WARNING] Could not parse auditor output {json_file}: {e}")

    is_pass = (global_summary["CRITICAL"] == 0 and global_summary["HIGH"] == 0)
    global_summary["total_files_scanned"] = total_files
    global_summary["pass"] = is_pass

    report_payload = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "commit": git_info["commit"],
        "branch": git_info["branch"],
        "summary": global_summary,
        "auditors": auditors_data
    }

    # Write JSON report
    json_report_file = Path("audit_report.json")
    json_report_file.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
    print(f"Generated JSON audit report at: {json_report_file}")

    # Write HTML report
    html_report_file = Path("audit_report.html")
    html_content = generate_html_report(report_payload)
    html_report_file.write_text(html_content, encoding="utf-8")
    print(f"Generated HTML audit report at: {html_report_file}")

    # Emit annotations for GitHub Actions
    emit_github_annotations(auditors_data)

    return report_payload


if __name__ == "__main__":
    build_reports()
