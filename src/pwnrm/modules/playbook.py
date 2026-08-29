"""
modules.playbook — Declarative Playbook & Automation Workflow Engine
Runs structured operation workflows (recon -> triage -> creds -> lateral -> persist).
"""

import json
from pathlib import Path
from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST


class PlaybookModule(BaseModule):
    name = "playbook"
    description = "Declarative Automation Engine (Run multi-step red team playbooks)"
    author = "uziii2208"
    options = {
        "--file": {"desc": "Path to playbook JSON/YAML file"},
        "--list": {"desc": "List built-in operation playbooks"},
        "--run": {"desc": "Run built-in playbook: default_triage, ad_recon, stealth_audit"},
    }

    BUILTIN_PLAYBOOKS = {
        "default_triage": [
            "!evasion",
            "!sysinfo",
            "!sessions -q",
            "!shares -q",
            "!creds",
        ],
        "ad_recon": [
            "!evasion",
            "!adtriage -q",
            "!adcs",
            "!kerberos",
            "!bloodhound",
        ],
        "stealth_audit": [
            "!evasion",
            "!sysinfo",
            "!entra",
            "!creds",
        ]
    }

    def run(self, shell, args: List[str]) -> Any:
        if "--list" in args or not args:
            shell.write_info(c(C + BLD, "  [*] Built-in Playbooks:"))
            for name, steps in self.BUILTIN_PLAYBOOKS.items():
                shell.write_info(f"    - {c(Y, name)} ({len(steps)} steps)")
                for s in steps:
                    shell.write_info(f"        -> {s}")
            return {"status": "listed"}

        pb_name = ""
        for i, a in enumerate(args):
            if a == "--run" and i + 1 < len(args):
                pb_name = args[i + 1]
            elif a in self.BUILTIN_PLAYBOOKS:
                pb_name = a

        if pb_name in self.BUILTIN_PLAYBOOKS:
            steps = self.BUILTIN_PLAYBOOKS[pb_name]
            shell.write_info(c(M + BLD, f"  [*] Executing Playbook: '{pb_name}' ({len(steps)} steps)"))
            for idx, step in enumerate(steps, 1):
                shell.write_info(c(Y + BLD, f"\n  ==> [Step {idx}/{len(steps)}] Executing: {step}"))
                shell.repl(inputs=[step])
            shell.write_info(c(G + BLD, f"\n  [+] Playbook '{pb_name}' completed successfully."))
            return {"status": "completed", "playbook": pb_name}

        shell.write_warning(f"Unknown playbook or syntax. Use !playbook --list")
        return {"status": "error"}
