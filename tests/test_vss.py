"""
tests.test_vss — Unit tests for VSSModule (In-Memory Volume Shadow Copy Service)
"""

import unittest
from unittest.mock import MagicMock
from pwnrm.modules.vss import VSSModule


class TestVSSModule(unittest.TestCase):
    def setUp(self):
        self.mod = VSSModule()
        self.mock_shell = MagicMock()
        self.mock_shell.run_with_interrupt = MagicMock(return_value=False)
        self.mock_shell.write_line = MagicMock()
        self.mock_shell.write_info = MagicMock()
        self.mock_shell.write_warning = MagicMock()
        self.mock_shell.write_error = MagicMock()

    def test_module_metadata(self):
        self.assertEqual(self.mod.name, "vss")
        self.assertIn("SAM", self.mod.description)
        self.assertIn("--drive", self.mod.options)
        self.assertIn("--sam", self.mod.options)
        self.assertIn("--ntds", self.mod.options)
        self.assertIn("--clean", self.mod.options)

    def test_run_default_options(self):
        res = self.mod.run(self.mock_shell, [])
        self.assertEqual(res.get("status"), "completed")
        self.mock_shell.run_with_interrupt.assert_called_once()
        cmd = self.mock_shell.run_with_interrupt.call_args[0][0]
        self.assertIn("Invoke-Expression", cmd)

    def test_run_custom_drive_and_ntds(self):
        res = self.mod.run(self.mock_shell, ["--drive", "D:", "--ntds"])
        self.assertEqual(res.get("status"), "completed")
        self.mock_shell.run_with_interrupt.assert_called_once()


if __name__ == "__main__":
    unittest.main()
