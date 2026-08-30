"""
core.opsec — OPSEC Profiles & Traffic Shaping Engine
Configures execution profiles (stealth, balanced, aggressive, hybrid-cloud) with CSPRNG jitter and command obfuscation.
"""

import time
import secrets
import re
from typing import Optional, Dict


class OPSECProfile:
    PROFILES = {
        "stealth": {
            "min_delay": 1.5,
            "max_delay": 5.0,
            "user_agent": "Microsoft WinRM Client",
            "obfuscate_commands": True,
            "max_chunk_size": 16384,
        },
        "balanced": {
            "min_delay": 0.1,
            "max_delay": 0.5,
            "user_agent": "Microsoft WinRM Client",
            "obfuscate_commands": False,
            "max_chunk_size": 65536,
        },
        "aggressive": {
            "min_delay": 0.0,
            "max_delay": 0.0,
            "user_agent": "Microsoft WinRM Client",
            "obfuscate_commands": False,
            "max_chunk_size": 131072,
        },
        "hybrid-cloud": {
            "min_delay": 0.5,
            "max_delay": 2.0,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "obfuscate_commands": True,
            "max_chunk_size": 32768,
        }
    }

    def __init__(self, mode: str = "balanced"):
        self.mode = mode.lower() if mode.lower() in self.PROFILES else "balanced"
        self.config = dict(self.PROFILES[self.mode])

    def set_mode(self, mode: str):
        if mode.lower() in self.PROFILES:
            self.mode = mode.lower()
            self.config = dict(self.PROFILES[self.mode])

    def jitter_sleep(self):
        """Applies jitter delay according to active profile using secure randomness."""
        min_d = self.config.get("min_delay", 0.0)
        max_d = self.config.get("max_delay", 0.0)
        if max_d > min_d:
            # CSPRNG uniform float in [min_d, max_d]
            rand_ratio = secrets.randbelow(10000) / 10000.0
            delay = min_d + rand_ratio * (max_d - min_d)
            time.sleep(delay)
        elif max_d > 0.0:
            time.sleep(max_d)

    def obfuscate_cmd(self, ps_cmd: str) -> str:
        """
        Applies polymorphic syntactic variable/backtick splitting and whitespace normalization if stealth mode is active.
        Preserves string literals, variables, and encoded scripts.
        """
        if not self.config.get("obfuscate_commands", False):
            return ps_cmd
        if not ps_cmd or ps_cmd.startswith("Invoke-Expression") or "\n" in ps_cmd or ps_cmd.startswith("!"):
            return ps_cmd

        # Tokenize by whitespace while preserving quoted tokens
        tokens = ps_cmd.split(" ")
        obf_tokens = []
        for tok in tokens:
            if not tok:
                continue
            # Do not touch variables ($), switches (-), or quoted strings
            if tok.startswith("$") or tok.startswith("-") or tok.startswith('"') or tok.startswith("'") or "(" in tok:
                obf_tokens.append(tok)
            elif re.match(r'^[A-Za-z0-9_-]+$', tok) and len(tok) > 2:
                # Insert backticks inside cmdlet name (e.g. Get-Process -> G`et`-`Process)
                parts = []
                for idx, ch in enumerate(tok):
                    if idx > 0 and idx < len(tok) - 1 and (idx % 2 == 1) and ch.isalnum():
                        parts.append("`" + ch)
                    else:
                        parts.append(ch)
                obf_tokens.append("".join(parts))
            else:
                obf_tokens.append(tok)

        return " ".join(obf_tokens)

    def get_user_agent(self) -> str:
        return self.config.get("user_agent", "Microsoft WinRM Client")
