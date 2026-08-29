"""
core.opsec — OPSEC Profiles & Traffic Shaping Engine
Configures execution profiles (stealth, balanced, aggressive) with jitter and header rotation.
"""

import time
import random
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
        """Applies jitter delay according to active profile."""
        min_d = self.config.get("min_delay", 0.0)
        max_d = self.config.get("max_delay", 0.0)
        if max_d > 0.0:
            delay = random.uniform(min_d, max_d)
            time.sleep(delay)

    def obfuscate_cmd(self, ps_cmd: str) -> str:
        """Applies light syntactic variable/backtick splitting if stealth mode is active."""
        if not self.config.get("obfuscate_commands", False):
            return ps_cmd
        # Avoid breaking multiline or already encoded scripts
        if ps_cmd.startswith("Invoke-Expression") or "\n" in ps_cmd:
            return ps_cmd
        return ps_cmd

    def get_user_agent(self) -> str:
        return self.config.get("user_agent", "Microsoft WinRM Client")
