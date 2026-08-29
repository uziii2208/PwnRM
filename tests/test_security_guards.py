"""
tests.test_security_guards — Security regression tests & anti-hallucination boundary checks
"""

import unittest
from pwnrm.shell.pwnshell import PwnShell, HISTORY_EXCLUDE_PATTERN
from pwnrm.shell.commands import build_amsi_patch, _xor_key, split_args
from pwnrm.shell.shares import get_shares_ps
from pwnrm.core.utils import strip_ansi, utfstr
import pwnrm.core.psrp as psrp
import defusedxml.ElementTree as _defusedET


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
            'C:\\temp\\..\\..\\Windows\\System32',
        ]
        for p in invalid_paths:
            with self.assertRaises(ValueError):
                PwnShell._validate_remote_path(p)

    def test_strip_ansi_sanitization(self):
        # Clean terminal output from ANSI escape sequences
        dirty = "\x1b[31mRed Text\x1b[0m and \x1b]0;Title\x07rest"
        clean = strip_ansi(dirty)
        self.assertEqual(clean, "Red Text and rest")

    def test_amsi_polymorphic_generator(self):
        # Verify polymorphic patch generator builds non-static byte array and valid nop offsets
        samples = set()
        for _ in range(20):
            arr, patch_len, offset = build_amsi_patch()
            self.assertGreaterEqual(patch_len, 7)
            self.assertGreaterEqual(offset, 1)
            self.assertIn("0xb8", arr)
            self.assertIn("0xc3", arr)
            samples.add(arr)
        # Should generate multiple variations across 20 samples
        self.assertGreater(len(samples), 1)

    def test_xor_key_csprng(self):
        # XOR key must never be 0 and within 1-254
        self.assertGreaterEqual(_xor_key, 1)
        self.assertLessEqual(_xor_key, 254)

    def test_defusedxml_usage(self):
        # Verify safe XML parsing module is active
        self.assertTrue(hasattr(psrp.ET, "fromstring"))
        self.assertEqual(psrp.ET.fromstring, _defusedET.fromstring)

    def test_history_exclude_pattern(self):
        # History filter must catch sensitive credential inputs
        sensitive_cmds = [
            "pwnrm -u Admin -p 'Secret123' host",
            "!upload -password admin123 secret.txt",
            "invoke-something --hash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "set-secret -nt_hash 12345",
        ]
        for cmd in sensitive_cmds:
            self.assertIsNotNone(HISTORY_EXCLUDE_PATTERN.search(cmd))

    def test_shares_single_quote_escaping(self):
        # Target list with injection attempts must be sanitized
        crafted = ["host'1", "dc01'; calc.exe; '"]
        ps = get_shares_ps(targets=crafted)
        self.assertIn("'host''1'", ps)
        self.assertIn("'dc01''; calc.exe; '''", ps)

    def test_utfstr_exception_handling(self):
        # Invalid sequence should not throw unhandled exception
        result = utfstr("_xZZZZ_invalid")
        self.assertEqual(result, "_xZZZZ_invalid")


if __name__ == "__main__":
    unittest.main()
