"""Version classification tests — the fallback signal must never lie."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from php2shell.version import (  # noqa: E402
    PatchStatus,
    extract_from_body,
    extract_from_headers,
    parse_version,
)


class TestParseVersion(unittest.TestCase):
    def test_vulnerable_8_4(self):
        info = parse_version("PHP/8.4.26")
        self.assertIsNotNone(info)
        self.assertIs(info.status, PatchStatus.VULNERABLE)
        self.assertEqual(info.fixed_in, "8.4.27")

    def test_fixed_8_4(self):
        info = parse_version("PHP/8.4.27")
        self.assertIs(info.status, PatchStatus.FIXED)

    def test_fixed_above(self):
        info = parse_version("PHP/8.4.30")
        self.assertIs(info.status, PatchStatus.FIXED)

    def test_boundary_each_branch(self):
        # One below the fix is vulnerable, the fix itself is patched.
        cases = [
            ("8.2.34", PatchStatus.VULNERABLE), ("8.2.35", PatchStatus.FIXED),
            ("8.3.35", PatchStatus.VULNERABLE), ("8.3.36", PatchStatus.FIXED),
            ("8.4.26", PatchStatus.VULNERABLE), ("8.4.27", PatchStatus.FIXED),
            ("8.5.11", PatchStatus.VULNERABLE), ("8.5.12", PatchStatus.FIXED),
        ]
        for version, expected in cases:
            with self.subTest(version=version):
                info = parse_version(f"PHP/{version}")
                self.assertIs(info.status, expected)

    def test_eol_branches(self):
        for version in ("5.4.0", "5.6.40", "7.4.33", "8.0.30", "8.1.31"):
            with self.subTest(version=version):
                info = parse_version(f"PHP/{version}")
                self.assertIs(info.status, PatchStatus.EOL)
                self.assertTrue(info.is_vulnerable)

    def test_too_old(self):
        info = parse_version("PHP/5.3.29")
        self.assertIs(info.status, PatchStatus.TOO_OLD)
        self.assertFalse(info.is_vulnerable)

    def test_unknown_branch(self):
        # 8.6 is newer than the advisory; we must not guess.
        info = parse_version("PHP/8.6.0")
        self.assertIs(info.status, PatchStatus.UNKNOWN_BRANCH)
        self.assertFalse(info.is_vulnerable)

    def test_no_version(self):
        self.assertIsNone(parse_version(""))
        self.assertIsNone(parse_version("nginx/1.24.0"))
        self.assertIsNone(parse_version("just some text"))

    def test_bare_version_requires_opt_in(self):
        # A bare version is only accepted when explicitly requested, so that
        # "nginx/1.24.0" is never mistaken for PHP.
        self.assertIsNone(parse_version("8.4.26"))
        info = parse_version("8.4.26", allow_bare=True)
        self.assertIsNotNone(info)
        self.assertIs(info.status, PatchStatus.VULNERABLE)

    def test_non_php_versions_rejected(self):
        # These appear in Server / X-Powered-By headers constantly.
        for raw in ("nginx/1.24.0", "OpenSSL/3.0.11", "Apache/2.4.62",
                    "jQuery/3.6.0", "Bootstrap/5.3.0"):
            with self.subTest(raw=raw):
                self.assertIsNone(parse_version(raw))

    def test_case_insensitive(self):
        for raw in ("php/8.4.26", "PHP 8.4.26", "Php/8.4.26"):
            with self.subTest(raw=raw):
                info = parse_version(raw)
                self.assertIsNotNone(info)
                self.assertIs(info.status, PatchStatus.VULNERABLE)


class TestHeaderExtraction(unittest.TestCase):
    def test_x_powered_by(self):
        info = extract_from_headers({"X-Powered-By": "PHP/8.4.26"})
        self.assertIsNotNone(info)
        self.assertIs(info.status, PatchStatus.VULNERABLE)

    def test_case_insensitive_headers(self):
        info = extract_from_headers({"x-powered-by": "PHP/8.4.27"})
        self.assertIsNotNone(info)
        self.assertIs(info.status, PatchStatus.FIXED)

    def test_no_php_header(self):
        self.assertIsNone(extract_from_headers({"Server": "nginx/1.24.0"}))

    def test_empty(self):
        self.assertIsNone(extract_from_headers({}))


class TestBodyExtraction(unittest.TestCase):
    def test_php_version_in_body(self):
        info = extract_from_body(b"<div>Powered by PHP/8.4.26</div>")
        self.assertIsNotNone(info)
        self.assertIs(info.status, PatchStatus.VULNERABLE)

    def test_ignores_unrelated_versions(self):
        # jQuery/Bootstrap versions must not be mistaken for PHP.
        body = b"<script src='jquery-3.6.0.min.js'></script>"
        self.assertIsNone(extract_from_body(body))

    def test_empty_body(self):
        self.assertIsNone(extract_from_body(b""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
