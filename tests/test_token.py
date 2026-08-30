"""
tests.test_token — Unit tests for TokenModule (Windows Token Privileges & Impersonation Engine)
"""

import unittest
from unittest.mock import MagicMock
from pwnrm.modules.token import TokenModule


class TestTokenModule(unittest.TestCase):
    def setUp(self):
        self.mod = TokenModule()
        self.mock_shell = MagicMock()
        self.mock_shell.run_with_interrupt = MagicMock(return_value=False)
        self.mock_shell.write_line = MagicMock()
        self.mock_shell.write_info = MagicMock()
        self.mock_shell.write_warning = MagicMock()
        self.mock_shell.write_error = MagicMock()

    def test_module_metadata(self):
        self.assertEqual(self.mod.name, "token")
        self.assertIn("Token", self.mod.description)
        self.assertIn("--list", self.mod.options)
        self.assertIn("--privs", self.mod.options)
        self.assertIn("--elevate", self.mod.options)

    def test_run_default(self):
        res = self.mod.run(self.mock_shell, [])
        self.assertEqual(res.get("status"), "completed")
        self.mock_shell.run_with_interrupt.assert_called_once()
        cmd = self.mock_shell.run_with_interrupt.call_args[0][0]
        self.assertIn("Invoke-Expression", cmd)

    def test_run_with_flags(self):
        res = self.mod.run(self.mock_shell, ["--privs", "--list"])
        self.assertEqual(res.get("status"), "completed")
        self.mock_shell.run_with_interrupt.assert_called_once()


if __name__ == "__main__":
    unittest.main()
