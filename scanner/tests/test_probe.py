"""
Signal-detection tests.

These are the accuracy-critical tests. Every case here is a real response shape
observed in the wild or documented in the advisories. The false-positive cases
matter more than the true-positive ones: a scanner that cries wolf is worse
than no scanner.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from php2shell.probe import (  # noqa: E402
    DEFAULT_POST_MAX_SIZE,
    MEMORY_AMPLIFICATION,
    NESTED_KEYS,
    PROBE_LADDER,
    Signal,
    build_control_body,
    build_oversize_body,
    build_probe_body,
    detect_signal,
    is_rejected,
    memory_cost,
    normalize_body,
    parse_post_max_size,
)
from php2shell.transport import Response  # noqa: E402


def resp(status=200, body=b"", error=None, headers=None):
    return Response(status=status, body=body, error=error,
                    headers=headers or {})


# Real PHP fatal, plain-text rendering (html_errors=Off).
PLAIN_FATAL = (
    b"PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted "
    b"(tried to allocate 4096 bytes) in Unknown on line 0"
)

# Real PHP fatal, HTML rendering (html_errors=On, the DEFAULT).
HTML_FATAL = (
    b"<br />\n<b>Fatal error</b>:  Allowed memory size of 8388608 bytes "
    b"exhausted (tried to allocate 4096 bytes) in <b>Unknown</b> on line "
    b"<b>0</b><br />\n"
)

# OOM in application code: names a real file and line. NOT the vulnerability.
APP_OOM = (
    b"PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted "
    b"(tried to allocate 20480 bytes) in /var/www/html/app.php on line 88"
)

# The memory_limit=-1 variant, where the OS allocation fails instead.
OS_OOM = (
    b"PHP Fatal error:  Out of memory (allocated 2097152) "
    b"(tried to allocate 4096 bytes) in Unknown on line 0"
)


class TestNormalizeBody(unittest.TestCase):
    def test_strips_html_tags(self):
        out = normalize_body(HTML_FATAL)
        self.assertIn(b"Unknown on line 0", out)
        self.assertNotIn(b"<b>", out)

    def test_plain_text_unchanged(self):
        out = normalize_body(PLAIN_FATAL)
        self.assertIn(b"Unknown on line 0", out)

    def test_empty(self):
        self.assertEqual(normalize_body(b""), b"")

    def test_binary_safe(self):
        # Must not explode on non-UTF8 bytes.
        out = normalize_body(b"\x00\xff\xfe binary <not a tag>")
        self.assertIsInstance(out, bytes)


class TestTruePositives(unittest.TestCase):
    """Cases that MUST be detected."""

    def setUp(self):
        self.control = resp(200, b"hello from the app")

    def test_plain_text_fatal(self):
