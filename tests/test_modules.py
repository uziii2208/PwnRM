"""
tests.test_modules — Unit tests for ModuleManager and module loading
"""

import unittest
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

    def test_get_module(self):
        mgr = ModuleManager()
        adcs = mgr.get_module("adcs")
        self.assertIsNotNone(adcs)
        self.assertEqual(adcs.name, "adcs")


if __name__ == "__main__":
    unittest.main()
