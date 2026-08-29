"""
core.session_mgr — Multi-Session Manager & Jump Graph Routing
Coordinates concurrent PSRP runspaces, switching, and serialized persistence.
"""

import os
import json
import time
import stat
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List


class SessionNode:
    """Represents a single managed PwnRM session."""
    def __init__(self, session_id: int, name: str, runspace, transport, target_info: dict):
        self.session_id = session_id
        self.name = name
        self.runspace = runspace
        self.transport = transport
        self.target_info = target_info
        self.created_at = datetime.now()
        self.last_active = datetime.now()
        self.is_alive = True
        self.notes = ""

    @property
    def host(self) -> str:
        return self.target_info.get("host", "unknown")

    @property
    def user(self) -> str:
        return self.target_info.get("user", "unknown")

    def to_dict(self) -> dict:
        return {
            "id": self.session_id,
            "name": self.name,
            "host": self.host,
            "user": self.user,
            "created_at": self.created_at.isoformat(),
            "last_active": self.last_active.isoformat(),
            "is_alive": self.is_alive,
            "notes": self.notes,
        }


class SessionManager:
    """
    Coordinates multiple active Runspace sessions across multiple endpoints.
    Provides session switching, background execution, and fan-out capability.
    """
    def __init__(self, base_dir: Optional[Path] = None):
        self.sessions: Dict[int, SessionNode] = {}
        self.current_session_id: Optional[int] = None
        self._next_id = 0
        self.base_dir = base_dir or Path(os.environ.get("PWNRM_DIR", str(Path.home() / ".pwnrm")))
        self.sessions_dir = self.base_dir / "sessions"
        self._ensure_secure_dir()

    def _ensure_secure_dir(self):
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.sessions_dir, stat.S_IRWXU)
            import platform
            if platform.system() == "Windows":
                import subprocess
                user = os.environ.get("USERNAME")
                if user:
                    subprocess.run(
                        ["icacls", str(self.sessions_dir), "/inheritance:r", "/grant", f"{user}:(OI)(CI)F"],
                        capture_output=True,
                        creationflags=0x08000000
                    )
        except OSError:
            pass

    def register_session(self, runspace, transport, target_info: dict, name: str = "") -> SessionNode:
        sid = self._next_id
        self._next_id += 1
        sess_name = name or f"session-{sid}_{target_info.get('host', 'unknown')}"
        node = SessionNode(sid, sess_name, runspace, transport, target_info)
        self.sessions[sid] = node
        if self.current_session_id is None:
            self.current_session_id = sid
        return node

    def get_current(self) -> Optional[SessionNode]:
        if self.current_session_id is not None:
            return self.sessions.get(self.current_session_id)
        return None

    def switch_session(self, session_id: int) -> bool:
        if session_id in self.sessions:
            self.current_session_id = session_id
            node = self.sessions[session_id]
            node.last_active = datetime.now()
            return True
        return False

    def rename_session(self, session_id: int, new_name: str) -> bool:
        if session_id in self.sessions:
            self.sessions[session_id].name = new_name
            return True
        return False

    def close_session(self, session_id: int) -> bool:
        if session_id in self.sessions:
            node = self.sessions.pop(session_id)
            node.is_alive = False
            try:
                if hasattr(node.runspace, "__exit__"):
                    node.runspace.__exit__(None, None, None)
            except Exception as e:
                logging.debug("Error closing runspace %s: %s", session_id, e)
            if self.current_session_id == session_id:
                self.current_session_id = next(iter(self.sessions.keys())) if self.sessions else None
            return True
        return False

    def list_sessions(self) -> List[dict]:
        res = []
        for sid, node in self.sessions.items():
            d = node.to_dict()
            d["is_current"] = (sid == self.current_session_id)
            res.append(d)
        return res

    def fan_out_exec(self, cmd: str) -> Dict[int, str]:
        """Execute a command across all active sessions sequentially."""
        results = {}
        for sid, node in list(self.sessions.items()):
            if not node.is_alive:
                continue
            try:
                out = []
                for o in node.runspace.run_command(cmd):
                    if "stdout" in o:
                        out.append(o["stdout"])
                results[sid] = "\n".join(out)
                node.last_active = datetime.now()
            except Exception as e:
                results[sid] = f"[ERROR] {e}"
        return results

    def save_state(self, filename: str = "sessions.json") -> str:
        """Serialize session metadata securely to disk."""
        target_file = self.sessions_dir / filename
        data = {
            "saved_at": datetime.now().isoformat(),
            "active_session": self.current_session_id,
            "sessions": [s.to_dict() for s in self.sessions.values()]
        }
        fd = os.open(str(target_file), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            with open(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            os.close(fd)
            raise
        return str(target_file)
