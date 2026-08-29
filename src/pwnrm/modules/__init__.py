"""
pwnrm.modules — Extensible Module & Plugin Subsystem
Provides base class and registry for specialized offensive/defensive modules.
"""

import logging
from typing import Dict, Type, List, Optional, Any


class BaseModule:
    name: str = "base"
    description: str = "Base module"
    author: str = "uziii2208"
    options: Dict[str, dict] = {}

    def __init__(self):
        pass

    def run(self, shell, args: List[str]) -> Any:
        """
        Executes module in the context of PwnShell.
        Returns result dict or None.
        """
        raise NotImplementedError("Modules must implement run()")


class ModuleManager:
    """Manages discovery, registration, and execution of PwnRM modules."""
    def __init__(self):
        self._modules: Dict[str, BaseModule] = {}
        self._load_builtins()

    def register(self, module_cls: Type[BaseModule]):
        instance = module_cls()
        self._modules[instance.name.lower()] = instance

    def get_module(self, name: str) -> Optional[BaseModule]:
        return self._modules.get(name.lower())

    def list_modules(self) -> List[dict]:
        return [
            {
                "name": mod.name,
                "description": mod.description,
                "author": getattr(mod, "author", "uziii2208"),
                "options": getattr(mod, "options", {}),
            }
            for mod in self._modules.values()
        ]

    def _load_builtins(self):
        from .adcs import ADCSModule
        from .kerberos import KerberosModule
        from .entra import EntraModule
        from .creds import CredsModule
        from .evasion import EvasionModule
        from .bloodhound import BloodhoundModule
        from .lateral import LateralModule
        from .playbook import PlaybookModule

        builtins = [
            ADCSModule,
            KerberosModule,
            EntraModule,
            CredsModule,
            EvasionModule,
            BloodhoundModule,
            LateralModule,
            PlaybookModule,
        ]
        for b in builtins:
            try:
                self.register(b)
            except Exception as e:
                logging.debug("Error loading module %s: %s", getattr(b, "name", "unknown"), e)
