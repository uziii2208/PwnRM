"""
tests.test_coerce — Unit tests for CoerceModule (Coerced Authentication Engine)
"""

import unittest
from unittest.mock import MagicMock
from pwnrm.modules.coerce import CoerceModule


class TestCoerceModule(unittest.TestCase):
    def setUp(self):
        self.mod = CoerceModule()
        self.mock_shell = MagicMock()
        self.mock_shell.run_with_interrupt = MagicMock(return_value=False)
        self.mock_shell.write_line = MagicMock()
        self.mock_shell.write_info = MagicMock()
        self.mock_shell.write_warning = MagicMock()
        self.mock_shell.write_error = MagicMock()

    def test_module_metadata(self):
        self.assertEqual(self.mod.name, "coerce")
        self.assertIn("WebDAV", self.mod.description)
        self.assertIn("--listener", self.mod.options)
        self.assertIn("--method", self.mod.options)
        self.assertIn("--port", self.mod.options)

    def test_run_missing_listener(self):
        res = self.mod.run(self.mock_shell, [])
        self.assertEqual(res.get("status"), "error")
        self.mock_shell.write_warning.assert_called_once()
        self.mock_shell.run_with_interrupt.assert_not_called()

    def test_run_with_listener(self):
        res = self.mod.run(self.mock_shell, ["--listener", "10.10.10.10", "--method", "webdav", "--port", "8080"])
        self.assertEqual(res.get("status"), "completed")
        self.mock_shell.run_with_interrupt.assert_called_once()
        cmd = self.mock_shell.run_with_interrupt.call_args[0][0]
        self.assertIn("Invoke-Expression", cmd)


if __name__ == "__main__":
    unittest.main()
