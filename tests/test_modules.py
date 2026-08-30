"""
tests.test_modules — Unit tests for ModuleManager, module loading, and plugin integrity
"""

import tempfile
import unittest
from pathlib import Path
from pwnrm.modules import ModuleManager, BaseModule


class TestModules(unittest.TestCase):
    def test_builtin_discovery(self):
        mgr = ModuleManager()
        modules = mgr.list_modules()
        mod_names = [m["name"] for m in modules]
        self.assertIn("adcs", mod_names)
        self.assertIn("kerberos", mod_names)
        self.assertIn("entra", mod_names)
        self.assertIn("creds", mod_names)
        self.assertIn("evasion", mod_names)
        self.assertIn("bloodhound", mod_names)
        self.assertIn("lateral", mod_names)
        self.assertIn("playbook", mod_names)
        self.assertIn("vss", mod_names)
        self.assertIn("coerce", mod_names)
        self.assertIn("laps", mod_names)
        self.assertIn("acl", mod_names)
        self.assertIn("token", mod_names)

    def test_get_module(self):
        mgr = ModuleManager()
        adcs = mgr.get_module("adcs")
        self.assertIsNotNone(adcs)
        self.assertEqual(adcs.name, "adcs")

    def test_plugin_integrity_verification(self):
        mgr = ModuleManager()
        with tempfile.TemporaryDirectory() as td:
            dummy_file = Path(td) / "custom_mod.py"
            dummy_file.write_text("from pwnrm.modules import BaseModule\nclass CustomMod(BaseModule):\n    name = 'custom'\n")
            self.assertTrue(mgr.verify_plugin_integrity(dummy_file))
            self.assertTrue(mgr.load_external_plugin(dummy_file))
            self.assertIsNotNone(mgr.get_module("custom"))

            # Non-existent file must fail verification
            fake_file = Path(td) / "nonexistent.py"
            self.assertFalse(mgr.verify_plugin_integrity(fake_file))
            self.assertFalse(mgr.load_external_plugin(fake_file))


if __name__ == "__main__":
    unittest.main()
