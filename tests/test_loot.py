"""
tests.test_loot — Unit tests for LootManager & MANIFEST.json tracking
"""

import json
import hashlib
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

    def test_store_artifact_and_manifest(self):
        target = "srv01"
        data = b"PFXDATA123"
        saved = self.loot.store_artifact(target, "certs", "admin.pfx", data, source_command="!adcs")
        self.assertTrue(Path(saved).exists())
        summary = self.loot.summary()
        self.assertIn("srv01", summary)
        self.assertIn("admin.pfx", summary["srv01"]["artifacts"]["certs"])

        # Check MANIFEST.json
        manifest_path = self.loot.manifest_file
        self.assertTrue(manifest_path.exists())
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertTrue(len(manifest.get("artifacts", [])) >= 1)
        found = [a for a in manifest["artifacts"] if a.get("filename") == "admin.pfx"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(found[0]["source_command"], "!adcs")


if __name__ == "__main__":
    unittest.main()
