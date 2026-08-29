"""
tests.test_loot — Unit tests for LootManager
"""

import tempfile
import unittest
from pathlib import Path
from pwnrm.core.loot import LootManager


class TestLootManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.loot = LootManager(base_dir=Path(self.temp_dir.name))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_store_and_retrieve_credentials(self):
        target = "dc01.corp.local"
        entry = self.loot.store_credential(target, "NTLM", "CORP\\Administrator", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", "sam_dump")
        self.assertEqual(entry["account"], "CORP\\Administrator")

        loot_data = self.loot.list_target_loot(target)
        self.assertEqual(len(loot_data["credentials"]), 1)
        self.assertEqual(loot_data["credentials"][0]["secret"], "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")

    def test_store_artifact(self):
        target = "srv01"
        saved = self.loot.store_artifact(target, "certs", "admin.pfx", b"PFXDATA123")
        self.assertTrue(Path(saved).exists())
        summary = self.loot.summary()
        self.assertIn("srv01", summary)
        self.assertIn("admin.pfx", summary["srv01"]["artifacts"]["certs"])


if __name__ == "__main__":
    unittest.main()
