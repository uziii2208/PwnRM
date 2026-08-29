"""
tests.test_opsec — Unit tests for OPSEC profile engine
"""

import unittest
from pwnrm.core.opsec import OPSECProfile


class TestOPSECProfile(unittest.TestCase):
    def test_profile_switching(self):
        prof = OPSECProfile(mode="stealth")
        self.assertEqual(prof.mode, "stealth")
        self.assertTrue(prof.config["obfuscate_commands"])

        prof.set_mode("aggressive")
        self.assertEqual(prof.mode, "aggressive")
        self.assertEqual(prof.config["min_delay"], 0.0)

    def test_user_agents(self):
        prof = OPSECProfile(mode="hybrid-cloud")
        ua = prof.get_user_agent()
        self.assertIn("Mozilla", ua)


if __name__ == "__main__":
    unittest.main()
