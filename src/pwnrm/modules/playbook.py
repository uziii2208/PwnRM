"""
modules.playbook — Declarative Playbook & Automation Workflow Engine
Runs structured operation workflows with automated on_fail cleanup handlers.
"""

import json
from pathlib import Path
from typing import List, Any, Dict, Union
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST


class PlaybookModule(BaseModule):
    name = "playbook"
    description = "Declarative Automation Engine (Run multi-step red team playbooks with on_fail cleanup)"
    author = "uziii2208"
    options = {
        "--file": {"desc": "Path to playbook JSON file with optional cleanup_on_fail hooks"},
        "--list": {"desc": "List built-in operation playbooks"},
        "--run": {"desc": "Run built-in playbook: default_triage, ad_recon, stealth_audit"},
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
            {"cmd": "!adtriage -q"},
            {"cmd": "!adcs"},
            {"cmd": "!kerberos"},
            {"cmd": "!bloodhound"},
        ],
        "stealth_audit": [
            {"cmd": "!evasion"},
            {"cmd": "!sysinfo"},
            {"cmd": "!entra"},
            {"cmd": "!creds"},
        ]
    }

    def run(self, shell, args: List[str]) -> Any:
        if "--list" in args or not args:
            shell.write_info(c(C + BLD, "  [*] Built-in Playbooks:"))
            for name, steps in self.BUILTIN_PLAYBOOKS.items():
                shell.write_info(f"    - {c(Y, name)} ({len(steps)} steps)")
                for s in steps:
                    cmd_str = s if isinstance(s, str) else s.get("cmd", "")
                    shell.write_info(f"        -> {cmd_str}")
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
            for idx, step in enumerate(steps, 1):
                cmd_str = step if isinstance(step, str) else step.get("cmd", "")
                cleanup_cmd = step.get("cleanup_on_fail") if isinstance(step, dict) else None
                if cleanup_cmd:
                    cleanup_stack.append(cleanup_cmd)

                shell.write_info(c(Y + BLD, f"\n  ==> [Step {idx}/{len(steps)}] Executing: {cmd_str}"))
                try:
                    shell.repl(inputs=[cmd_str])
                except Exception as e:
                    shell.write_error(f"  [!] Step {idx} failed: {e}")
                    if cleanup_stack:
                        shell.write_warning(f"  [*] Executing {len(cleanup_stack)} on_fail cleanup tasks...")
                        for clean in reversed(cleanup_stack):
                            try:
                                shell.repl(inputs=[clean])
                            except Exception as c_err:
                                shell.write_error(f"Cleanup error: {c_err}")
                    return {"status": "failed", "step": idx}

            shell.write_info(c(G + BLD, f"\n  [+] Playbook '{pb_name}' completed successfully."))
            return {"status": "completed", "playbook": pb_name}

        shell.write_warning("Unknown playbook or syntax. Use !playbook --list")
        return {"status": "error"}
