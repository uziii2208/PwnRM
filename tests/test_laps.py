"""
tests.test_laps — Unit tests for LAPSModule (Windows LAPS & Server 2025 Hunter)
"""

import unittest
from unittest.mock import MagicMock
from pwnrm.modules.laps import LAPSModule


class TestLAPSModule(unittest.TestCase):
    def setUp(self):
        self.mod = LAPSModule()
        self.mock_shell = MagicMock()
        self.mock_shell.run_with_interrupt = MagicMock(return_value=False)
        self.mock_shell.write_line = MagicMock()
        self.mock_shell.write_info = MagicMock()
        self.mock_shell.write_warning = MagicMock()
        self.mock_shell.write_error = MagicMock()

    def test_module_metadata(self):
        self.assertEqual(self.mod.name, "laps")
        self.assertIn("LAPS", self.mod.description)
        self.assertIn("-a", self.mod.options)
        self.assertIn("--encrypted", self.mod.options)

    def test_run_default(self):
        res = self.mod.run(self.mock_shell, [])
        self.assertEqual(res.get("status"), "completed")
        self.mock_shell.run_with_interrupt.assert_called_once()
        cmd = self.mock_shell.run_with_interrupt.call_args[0][0]
        self.assertIn("Invoke-Expression", cmd)

    def test_run_with_encrypted_flag(self):
        res = self.mod.run(self.mock_shell, ["--encrypted"])
        self.assertEqual(res.get("status"), "completed")
        self.mock_shell.run_with_interrupt.assert_called_once()


if __name__ == "__main__":
    unittest.main()
