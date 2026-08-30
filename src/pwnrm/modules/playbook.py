"""
modules.playbook — Declarative Playbook & Automation Workflow Engine
Runs structured operation workflows with conditional branching (when), variable capture, and automated on_fail cleanup handlers.
"""

import json
import re
from io import StringIO
from pathlib import Path
from typing import List, Any, Dict, Union
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST


class PlaybookModule(BaseModule):
    name = "playbook"
    description = "Declarative Automation Engine (Conditional branching, on_fail cleanup, output capture)"
    author = "uziii2208"
    options = {
        "--file": {"desc": "Path to playbook JSON file with conditional branching & cleanup hooks"},
        "--list": {"desc": "List built-in operation playbooks"},
        "--run": {"desc": "Run built-in playbook: default_triage, ad_recon, stealth_audit, smart_triage"},
    }

    BUILTIN_PLAYBOOKS = {
        "default_triage": [
            {"cmd": "!evasion"},
            {"cmd": "!sysinfo"},
            {"cmd": "!sessions -q"},
            {"cmd": "!shares -q"},
            {"cmd": "!creds"},
        ],
        "ad_recon": [
            {"cmd": "!evasion"},
            {"cmd": "!adtriage -q", "capture_as": "triage"},
            {"cmd": "!adcs", "when": "triage contains 'ADCS'"},
            {"cmd": "!kerberos", "when": "triage contains 'SPN'"},
            {"cmd": "!bloodhound"},
        ],
        "smart_triage": [
            {"cmd": "!evasion"},
            {"cmd": "!sysinfo", "capture_as": "sysinfo"},
            {"cmd": "!adtriage -q", "capture_as": "triage"},
            {"cmd": "!adcs", "when": "triage contains 'Certificate'"},
            {"cmd": "!kerberos", "when": "triage contains 'SPN'"},
            {"cmd": "!creds"},
        ],
        "stealth_audit": [
            {"cmd": "!evasion"},
            {"cmd": "!sysinfo"},
            {"cmd": "!entra"},
            {"cmd": "!creds"},
        ]
    }

    @staticmethod
    def _evaluate_condition(when: str, context: Dict[str, str], last_output: str) -> bool:
        """Evaluates simple conditional DSL: '<var> contains <substring>' or direct regex."""
        if not when:
            return True
        m = re.match(r"^(\w+)\s+contains\s+['\"]?([^'\"]+)['\"]?$", when.strip(), re.IGNORECASE)
        if m:
            var_name, expected = m.group(1), m.group(2)
            source_text = context.get(var_name, last_output if var_name in ("output", "last_output") else "")
            return expected.lower() in source_text.lower()
        # Direct substring in last_output
        return when.lower() in last_output.lower()

    def run(self, shell, args: List[str]) -> Any:
        if "--list" in args or not args:
            shell.write_info(c(C + BLD, "  [*] Built-in Playbooks:"))
            for name, steps in self.BUILTIN_PLAYBOOKS.items():
                shell.write_info(f"    - {c(Y, name)} ({len(steps)} steps)")
                for s in steps:
                    cmd_str = s if isinstance(s, str) else s.get("cmd", "")
                    when_str = f" [when: {s.get('when')}]" if isinstance(s, dict) and s.get("when") else ""
                    shell.write_info(f"        -> {cmd_str}{when_str}")
            return {"status": "listed"}

        pb_name = ""
        pb_file = ""
        for i, a in enumerate(args):
            if a == "--run" and i + 1 < len(args):
                pb_name = args[i + 1]
            elif a == "--file" and i + 1 < len(args):
                pb_file = args[i + 1]
            elif a in self.BUILTIN_PLAYBOOKS:
                pb_name = a

        steps = []
        if pb_file:
            try:
                with open(pb_file, "r", encoding="utf-8") as f:
                    steps = json.load(f)
                pb_name = Path(pb_file).stem
            except Exception as e:
                shell.write_error(f"Failed to load playbook file {pb_file}: {e}")
                return {"status": "error"}
        elif pb_name in self.BUILTIN_PLAYBOOKS:
            steps = self.BUILTIN_PLAYBOOKS[pb_name]

        if steps:
            shell.write_info(c(M + BLD, f"  [*] Executing Playbook: '{pb_name}' ({len(steps)} steps)"))
            cleanup_stack = []
            context: Dict[str, str] = {}
            last_output = ""

            for idx, step in enumerate(steps, 1):
                cmd_str = step if isinstance(step, str) else step.get("cmd", "")
                when_cond = step.get("when") if isinstance(step, dict) else None
                capture_var = step.get("capture_as") if isinstance(step, dict) else None
                on_fail = step.get("on_fail", "abort") if isinstance(step, dict) else "abort"
                cleanup_cmd = step.get("cleanup_on_fail") if isinstance(step, dict) else None

                if when_cond and not self._evaluate_condition(when_cond, context, last_output):
                    shell.write_info(c(DIM, f"  [-] [Step {idx}/{len(steps)}] Skipped: condition '{when_cond}' was not met."))
                    continue

                if cleanup_cmd:
                    cleanup_stack.append(cleanup_cmd)

                shell.write_info(c(Y + BLD, f"\n  ==> [Step {idx}/{len(steps)}] Executing: {cmd_str}"))

                # Capture output for conditional evaluation
                captured_lines = []
                orig_write_line = shell.write_line

                def capturing_writer(out):
                    if "stdout" in out:
                        captured_lines.append(out["stdout"])
                    orig_write_line(out)

                try:
                    shell.write_line = capturing_writer
                    shell.repl(inputs=[cmd_str])
                except Exception as e:
                    shell.write_error(f"  [!] Step {idx} failed: {e}")
                    if on_fail == "continue":
                        shell.write_warning("  [*] Continuing playbook execution (on_fail: continue)...")
                        continue
                    if cleanup_stack:
                        shell.write_warning(f"  [*] Executing {len(cleanup_stack)} on_fail cleanup tasks...")
                        for clean in reversed(cleanup_stack):
                            try:
                                shell.repl(inputs=[clean])
                            except Exception as c_err:
                                shell.write_error(f"Cleanup error: {c_err}")
                    return {"status": "failed", "step": idx}
                finally:
                    shell.write_line = orig_write_line

                last_output = "\n".join(captured_lines)
                if capture_var:
                    context[capture_var] = last_output

            shell.write_info(c(G + BLD, f"\n  [+] Playbook '{pb_name}' completed successfully."))
            return {"status": "completed", "playbook": pb_name}

        shell.write_warning("Unknown playbook or syntax. Use !playbook --list")
        return {"status": "error"}
