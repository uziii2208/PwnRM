"""
tests.test_security_guards — Security regression tests & anti-hallucination boundary checks
"""

import unittest
from pwnrm.shell.pwnshell import PwnShell
from pwnrm.core.utils import strip_ansi


class TestSecurityGuards(unittest.TestCase):
    def test_pse_escaping(self):
        # Single quote escaping for single-quoted strings: ' -> ''
        raw = "C:\\Path'With'Quotes"
        escaped = PwnShell._pse(raw)
        self.assertEqual(escaped, "C:\\Path''With''Quotes")

    def test_pde_escaping(self):
        # Double quote escaping for double-quoted strings: ` -> ``, $ -> `$ , " -> `"
        raw = 'C:\\temp\\`dir`\\$user\\"test"'
        escaped = PwnShell._pde(raw)
        self.assertEqual(escaped, 'C:\\temp\\``dir``\\`$user\\`"test`"')

    def test_remote_path_validation(self):
        # Valid paths
        valid_paths = [
            r"C:\Windows\System32\cmd.exe",
            r"D:\Data\File_123.txt",
            r"\\server\share\path\file.log",
        ]
        for p in valid_paths:
            self.assertEqual(PwnShell._validate_remote_path(p), p)

        # Dangerous paths that must be rejected
        invalid_paths = [
            'C:\\Windows\\$(calc.exe)',
            'C:\\Windows\\`whoami`',
            'C:\\temp\\" | Invoke-Expression "malicious"',
            'C:\\temp\\file.txt; rm -rf /',
            'C:\\temp\\file.txt&calc.exe',
        ]
        for p in invalid_paths:
            with self.assertRaises(ValueError):
                PwnShell._validate_remote_path(p)

    def test_strip_ansi_sanitization(self):
        # Clean terminal output from ANSI escape sequences
        dirty = "\x1b[31mRed Text\x1b[0m and \x1b]0;Title\x07rest"
        clean = strip_ansi(dirty)
        self.assertEqual(clean, "Red Text and rest")


if __name__ == "__main__":
    unittest.main()
