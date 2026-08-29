"""
pwnrm.modules — Extensible Module & Plugin Subsystem
Provides base class, registry, and secure plugin discovery for specialized operations.
"""

import os
import stat
import importlib.util
import logging
from pathlib import Path
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
    """Manages discovery, integrity verification, registration, and execution of PwnRM modules."""
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

    @staticmethod
    def verify_plugin_integrity(path: Path) -> bool:
        """Verifies plugin file permissions and safety before dynamic importing."""
        try:
            if not path.is_file() or path.is_symlink():
                return False
            st = path.stat()
            # Enforce non-world-writable permission on POSIX systems
            if os.name == "posix" and hasattr(stat, "S_IWOTH") and (st.st_mode & stat.S_IWOTH):
                logging.warning("Refusing to load world-writable plugin: %s", path)
                return False
            return True
        except OSError:
            return False

    def load_external_plugin(self, path: Path) -> bool:
        """Securely loads an external plugin from file."""
        if not self.verify_plugin_integrity(path):
            return False
        try:
            spec = importlib.util.spec_from_file_location(f"pwnrm_plugin_{path.stem}", path)
            if not spec or not spec.loader:
                return False
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for attr in dir(mod):
                obj = getattr(mod, attr)
                if isinstance(obj, type) and issubclass(obj, BaseModule) and obj is not BaseModule:
                    self.register(obj)
                    return True
            return False
        except Exception as e:
            logging.error("Failed to load external plugin %s: %s", path, e)
            return False

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
