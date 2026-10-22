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
        signal, detail = detect_signal(self.control, resp(200, PLAIN_FATAL))
        self.assertIs(signal, Signal.IN_BAND_FATAL)
        self.assertIn("Unknown on line 0", detail)

    def test_html_fatal(self):
        # The critical regression: html_errors=On is the default.
        signal, _ = detect_signal(self.control, resp(200, HTML_FATAL))
        self.assertIs(signal, Signal.IN_BAND_FATAL)

    def test_os_oom_variant(self):
        signal, _ = detect_signal(self.control, resp(200, OS_OOM))
        self.assertIs(signal, Signal.IN_BAND_FATAL)

    def test_differential_empty_500(self):
        signal, _ = detect_signal(self.control, resp(500, b""))
        self.assertIs(signal, Signal.EMPTY_500)

    def test_upstream_dead_502(self):
        signal, _ = detect_signal(self.control, resp(502, b""), sapi="fpm")
        self.assertIs(signal, Signal.UPSTREAM_DEAD)

    def test_upstream_dead_503(self):
        signal, _ = detect_signal(self.control, resp(503, b""), sapi="fpm")
        self.assertIs(signal, Signal.UPSTREAM_DEAD)

    def test_empty_200_fpm(self):
        signal, _ = detect_signal(self.control, resp(200, b""), sapi="fpm")
        self.assertIs(signal, Signal.EMPTY_200)


class TestFalsePositives(unittest.TestCase):
    """Cases that MUST NOT be reported as vulnerable."""

    def setUp(self):
        self.control = resp(200, b"hello from the app")

    def test_app_level_oom_is_not_a_signal(self):
        # Names a real file/line -> ordinary application error.
        signal, detail = detect_signal(self.control, resp(200, APP_OOM))
        self.assertIsNone(signal)
        self.assertIn("application code", detail)

    def test_empty_500_without_control_output(self):
        # If the control produced nothing, an empty 500 is meaningless.
        control = resp(200, b"")
        signal, _ = detect_signal(control, resp(500, b""))
        self.assertIsNone(signal)

    def test_500_with_body_is_not_a_signal(self):
        # A 500 that renders an error page is an app error, not a crash.
        signal, _ = detect_signal(self.control, resp(500, b"<h1>Server Error</h1>"))
        self.assertIsNone(signal)

    def test_404_is_not_a_signal(self):
        signal, _ = detect_signal(self.control, resp(404, b"not found"))
        self.assertIsNone(signal)

    def test_403_is_not_a_signal(self):
        signal, _ = detect_signal(self.control, resp(403, b"forbidden"))
        self.assertIsNone(signal)

    def test_413_is_not_a_signal(self):
        signal, _ = detect_signal(self.control, resp(413, b"too large"))
        self.assertIsNone(signal)

    def test_502_when_control_also_failed(self):
        # Backend was already down; not evidence of anything.
        control = resp(502, b"")
        signal, _ = detect_signal(control, resp(502, b""), sapi="fpm")
        self.assertIsNone(signal)

    def test_502_in_mod_php_mode(self):
        # mod_php does not produce frontend 502s for this bug.
        signal, _ = detect_signal(self.control, resp(502, b""), sapi="mod_php")
        self.assertIsNone(signal)

    def test_normal_200_with_body(self):
        signal, _ = detect_signal(self.control, resp(200, b"normal page"))
        self.assertIsNone(signal)

    def test_oom_word_without_location(self):
        # Mentions memory but not an initialization-time location.
        body = b"Warning: memory exhausted while rendering template"
        signal, _ = detect_signal(self.control, resp(200, body))
        self.assertIsNone(signal)


class TestRejectedStatuses(unittest.TestCase):
    def test_rejected_set(self):
        for status in (400, 403, 411, 413, 414, 417, 422, 429, 431):
