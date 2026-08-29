"""
tests.test_tunnel — Unit tests for SOCKS5 and Port Forwarder
"""

import socket
import time
import unittest
from pwnrm.core.tunnel import Socks5Server, PortForwarder


class TestTunnel(unittest.TestCase):
    def test_socks5_lifecycle(self):
        server = Socks5Server(bind_host="127.0.0.1", bind_port=11080)
        self.assertFalse(server.is_running)
        server.start()
        self.assertTrue(server.is_running)

        # Test connecting and handshake
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 11080))
        # Send SOCKS5 Greeting (VER=5, NMETHODS=1, METHOD=0)
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        self.assertEqual(resp, b"\x05\x00")
        s.close()

        server.stop()
        self.assertFalse(server.is_running)

    def test_port_forwarder_lifecycle(self):
        fwd = PortForwarder()
        fid = fwd.start_local_forward(11081, "127.0.0.1", 11082)
        forwards = fwd.list_forwards()
        self.assertEqual(len(forwards), 1)
        self.assertEqual(forwards[0]["id"], fid)
        self.assertTrue(fwd.stop_forward(fid))
        self.assertEqual(len(fwd.list_forwards()), 0)


if __name__ == "__main__":
    unittest.main()
