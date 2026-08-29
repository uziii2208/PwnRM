"""
core.tunnel — SOCKS5 Proxy & Port Forwarding Multiplexer
Provides local SOCKS5 proxy (RFC 1928) and port-forwarding over PwnRM connections.
"""

import socket
import select
import struct
import threading
import logging
from typing import Optional, Dict, Tuple


class Socks5Server:
    """
    Lightweight RFC 1928 SOCKS5 Server.
    Can route traffic directly or via remote execution proxies.
    """
    def __init__(self, bind_host: str = "127.0.0.1", bind_port: int = 1080):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.server_sock: Optional[socket.socket] = None
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self.active_tunnels: Dict[int, Tuple[str, int]] = {}
        self._conn_id = 0

    def start(self):
        if self.is_running:
            return
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.bind_host, self.bind_port))
        self.server_sock.listen(50)
        self.is_running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        logging.info(f"[*] SOCKS5 Server listening on {self.bind_host}:{self.bind_port}")

    def stop(self):
        self.is_running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
            self.server_sock = None

    def _accept_loop(self):
        while self.is_running and self.server_sock:
            try:
                client_sock, addr = self.server_sock.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock, addr), daemon=True)
                t.start()
            except Exception:
                break

    def _handle_client(self, client_sock: socket.socket, addr: tuple):
        try:
            # 1. Handshake (RFC 1928)
            ver, nmethods = client_sock.recv(2)
            if ver != 5:
                client_sock.close()
                return
            methods = client_sock.recv(nmethods)
            # Send NO_AUTH (0x00)
            client_sock.sendall(b"\x05\x00")

            # 2. Request details
            ver, cmd, rsv, atyp = client_sock.recv(4)
            if cmd != 1:  # Only CONNECT supported
                client_sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")  # Command not supported
                client_sock.close()
                return

            if atyp == 1:  # IPv4
                dst_addr = socket.inet_ntoa(client_sock.recv(4))
            elif atyp == 3:  # Domain name
                addr_len = client_sock.recv(1)[0]
                dst_addr = client_sock.recv(addr_len).decode("utf-8", errors="replace")
            elif atyp == 4:  # IPv6
                dst_addr = socket.inet_ntop(socket.AF_INET6, client_sock.recv(16))
            else:
                client_sock.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                return

            dst_port = struct.unpack(">H", client_sock.recv(2))[0]

            # 3. Connect to destination
            try:
                remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_sock.settimeout(10.0)
                remote_sock.connect((dst_addr, dst_port))
                remote_sock.settimeout(None)
                # Success response
                client_sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            except Exception as e:
                logging.debug("SOCKS5 connect failure to %s:%s: %s", dst_addr, dst_port, e)
                client_sock.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")  # Connection refused
                client_sock.close()
                return

            # 4. Bidirectional transfer
            cid = self._conn_id
            self._conn_id += 1
            self.active_tunnels[cid] = (dst_addr, dst_port)
            self._pipe_sockets(client_sock, remote_sock)
            self.active_tunnels.pop(cid, None)

        except Exception as e:
            logging.debug("SOCKS5 client error: %s", e)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _pipe_sockets(self, s1: socket.socket, s2: socket.socket):
        sockets = [s1, s2]
        while self.is_running:
            r, _, w = select.select(sockets, [], sockets, 1.0)
            if w:
                break
            for s in r:
                other = s2 if s is s1 else s1
                try:
                    data = s.recv(32768)
                    if not data:
                        return
                    other.sendall(data)
                except Exception:
                    return


class PortForwarder:
    """Manages local and remote port forwarding instances."""
    def __init__(self):
        self.forwards: Dict[int, dict] = {}
        self._next_id = 0

    def start_local_forward(self, local_port: int, remote_host: str, remote_port: int, bind_host: str = "127.0.0.1") -> int:
        fid = self._next_id
        self._next_id += 1
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_host, local_port))
        srv.listen(10)

        f_info = {
            "id": fid,
            "type": "local",
            "bind": f"{bind_host}:{local_port}",
            "target": f"{remote_host}:{remote_port}",
            "socket": srv,
            "running": True
        }
        self.forwards[fid] = f_info

        def _forward_accept():
            while f_info["running"]:
                try:
                    client, _ = srv.accept()
                    t = threading.Thread(target=self._pipe_forward, args=(client, remote_host, remote_port), daemon=True)
                    t.start()
                except Exception:
                    break

        th = threading.Thread(target=_forward_accept, daemon=True)
        th.start()
        return fid

    def _pipe_forward(self, client: socket.socket, rhost: str, rport: int):
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((rhost, rport))
            sockets = [client, remote]
            while True:
                r, _, _ = select.select(sockets, [], [], 1.0)
                for s in r:
                    other = remote if s is client else client
                    data = s.recv(32768)
                    if not data:
                        return
                    other.sendall(data)
        except Exception:
            pass
        finally:
            try:
                client.close()
            except Exception:
                pass
            try:
                remote.close()
            except Exception:
                pass

    def stop_forward(self, fid: int) -> bool:
        if fid in self.forwards:
            f_info = self.forwards.pop(fid)
            f_info["running"] = False
            try:
                f_info["socket"].close()
            except Exception:
                pass
            return True
        return False

    def list_forwards(self) -> list:
        return [
            {"id": f["id"], "type": f["type"], "bind": f["bind"], "target": f["target"]}
            for f in self.forwards.values()
        ]
