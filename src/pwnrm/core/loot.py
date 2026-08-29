"""
core.loot — Automated Structured Loot Pipeline
Manages credentials, tickets, certificates, and extracted artifacts with permission hardening and JSON manifests.
"""

import os
import json
import stat
import time
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any


class LootManager:
    """
    Structured loot collection and storage engine with strict permission hardening.
    Organizes findings per target host/domain and maintains an operational MANIFEST.json.
    """
    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path(os.environ.get("PWNRM_DIR", str(Path.home() / ".pwnrm")))
        self.loot_root = self.base_dir / "loot"
        self._ensure_secure_dir(self.loot_root)
        self.manifest_file = self.loot_root / "MANIFEST.json"

    def _ensure_secure_dir(self, d: Path):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, stat.S_IRWXU)
            import platform
            if platform.system() == "Windows":
                import subprocess
                user = os.environ.get("USERNAME")
                if user:
                    subprocess.run(
                        ["icacls", str(d), "/inheritance:r", "/grant", f"{user}:(OI)(CI)F"],
                        capture_output=True,
                        creationflags=0x08000000
                    )
        except OSError:
            pass

    def _update_manifest(self, entry: dict):
        manifest_data = {"artifacts": []}
        if self.manifest_file.exists():
            try:
                with open(self.manifest_file, "r", encoding="utf-8") as f:
                    manifest_data = json.load(f)
            except Exception:
                manifest_data = {"artifacts": []}

        manifest_data.setdefault("artifacts", []).append(entry)
        fd = os.open(str(self.manifest_file), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            with open(fd, "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2)
        except Exception:
            os.close(fd)
            raise

    def get_target_dir(self, target: str) -> Path:
        sanitized = "".join(c for c in target if c.isalnum() or c in "._-").strip() or "general"
        tdir = self.loot_root / sanitized
        self._ensure_secure_dir(tdir)
        for sub in ("tickets", "certs", "dpapi", "bloodhound", "dumps"):
            self._ensure_secure_dir(tdir / sub)
        return tdir

    def store_credential(self, target: str, cred_type: str, account: str, secret: str, source: str = "triage") -> dict:
        tdir = self.get_target_dir(target)
        creds_file = tdir / "credentials.json"
        creds_list = []
        if creds_file.exists():
            try:
                with open(creds_file, "r", encoding="utf-8") as f:
                    creds_list = json.load(f)
            except Exception:
                creds_list = []

        entry = {
            "type": cred_type,
            "account": account,
            "secret": secret,
            "source": source,
            "timestamp": datetime.now().isoformat()
        }
        creds_list.append(entry)

        fd = os.open(str(creds_file), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            with open(fd, "w", encoding="utf-8") as f:
                json.dump(creds_list, f, indent=2)
        except Exception:
            os.close(fd)
            raise

        self._update_manifest({
            "filename": "credentials.json",
            "type": f"credential_{cred_type}",
            "category": "credentials",
            "source_command": source,
            "timestamp": entry["timestamp"],
            "sha256": hashlib.sha256(secret.encode()).hexdigest(),
            "target": target,
            "account": account
        })
        return entry

    def store_artifact(self, target: str, category: str, filename: str, data: bytes, source_command: str = "loot") -> str:
        """Stores binary or text artifact (cert, ticket, dump) under the target category and updates manifest."""
        tdir = self.get_target_dir(target)
        cat_dir = tdir / category
        self._ensure_secure_dir(cat_dir)
        safe_name = "".join(c for c in filename if c.isalnum() or c in "._-").strip() or "artifact.bin"
        dst = cat_dir / safe_name
        fd = os.open(str(dst), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            with open(fd, "wb") as f:
                f.write(data)
        except Exception:
            os.close(fd)
            raise

        file_sha256 = hashlib.sha256(data).hexdigest()
        self._update_manifest({
            "filename": safe_name,
            "type": category,
            "category": category,
            "source_command": source_command,
            "timestamp": datetime.now().isoformat(),
            "sha256": file_sha256,
            "target": target,
            "path": str(dst)
        })
        return str(dst)

    def list_target_loot(self, target: str) -> dict:
        tdir = self.get_target_dir(target)
        creds = []
        creds_file = tdir / "credentials.json"
        if creds_file.exists():
            try:
                with open(creds_file, "r", encoding="utf-8") as f:
                    creds = json.load(f)
            except Exception:
                pass
        artifacts = {}
        for sub in ("tickets", "certs", "dpapi", "bloodhound", "dumps"):
            sub_dir = tdir / sub
            if sub_dir.exists():
                artifacts[sub] = [f.name for f in sub_dir.iterdir() if f.is_file()]
        return {"target": target, "credentials": creds, "artifacts": artifacts}

    def summary(self) -> dict:
        summary_data = {}
        for item in self.loot_root.iterdir():
            if item.is_dir():
                summary_data[item.name] = self.list_target_loot(item.name)
        return summary_data
