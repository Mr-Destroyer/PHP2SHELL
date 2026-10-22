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
            with self.subTest(status=status):
                self.assertTrue(is_rejected(resp(status)))

    def test_not_rejected(self):
        for status in (200, 500, 502, 404):
            with self.subTest(status=status):
                self.assertFalse(is_rejected(resp(status)))


class TestProbeBody(unittest.TestCase):
    def test_control_body_is_small(self):
        self.assertLess(len(build_control_body()), 100)

    def test_probe_size_approximately_correct(self):
        for size_mib in (1, 8):
            with self.subTest(size_mib=size_mib):
                body = build_probe_body(size_mib, 1020)
                expected = size_mib << 20
                # Within 1% of the requested size.
                self.assertLess(abs(len(body) - expected), expected * 0.01)

    def test_probe_contains_nested_keys(self):
        body = build_probe_body(1, 10)
        self.assertIn(b"a[]" + b"[a]" * NESTED_KEYS, body)

    def test_probe_contains_empty_filename(self):
        # The empty filename is what bypasses max_file_uploads.
        body = build_probe_body(1, 10)
        self.assertIn(b';filename=\n', body)

    def test_too_small_for_parts_raises(self):
        with self.assertRaises(ValueError):
            build_probe_body(1, 10_000_000)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestPostMaxSizeDiscovery(unittest.TestCase):
    """
    Regression tests for the post_max_size blind spot.

    A probe larger than post_max_size is discarded by PHP during request
    startup, before the multipart parser runs. Such a probe cannot crash, so
    treating its silence as "no signal" is a false negative. These tests pin
    the discovery mechanism and the ladder shape that avoids the trap.
    """

    def test_parses_limit_from_php_warning(self):
        body = (
            b"<br />\n<b>Warning</b>:  PHP Request Startup: POST Content-Length "
            b"of 12582915 bytes exceeds the limit of 8388608 bytes in "
            b"<b>Unknown</b> on line <b>0</b><br />\n"
        )
        self.assertEqual(parse_post_max_size(body), 8388608)

    def test_returns_none_without_warning(self):
        self.assertIsNone(parse_post_max_size(b"<html>normal page</html>"))
        self.assertIsNone(parse_post_max_size(b""))

    def test_returns_none_when_warning_suppressed(self):
        # display_errors=Off: PHP discards the body silently.
        self.assertIsNone(parse_post_max_size(b""))

    def test_ladder_stays_under_default_post_max_size(self):
        # Every rung must be strictly below the 8M default, or PHP discards it
        # before parsing and the probe is a guaranteed no-op.
        for size_mib, _parts in PROBE_LADDER:
            self.assertLess(
                size_mib << 20, DEFAULT_POST_MAX_SIZE,
                f"{size_mib} MiB rung is not below post_max_size=8M",
            )

    def test_ladder_escalates_memory_cost(self):
        # Escalation must be monotonic in the memory it forces, not just in
        # wire size, otherwise a later rung is weaker than an earlier one.
        costs = [memory_cost(mib) for mib, _ in PROBE_LADDER]
        self.assertEqual(costs, sorted(costs))
        self.assertEqual(len(set(costs)), len(costs))

    def test_amplification_is_measured_not_guessed(self):
        # 1 MiB of wire filler costs ~106 MB of PHP memory (measured against
        # PHP 8.4.8). Guard the constant against silent drift.
        self.assertGreaterEqual(MEMORY_AMPLIFICATION, 100)
        self.assertLessEqual(MEMORY_AMPLIFICATION, 110)

    def test_oversize_body_is_large_enough_to_trip_the_limit(self):
        body = build_oversize_body(DEFAULT_POST_MAX_SIZE + (1 << 20))
        self.assertGreater(len(body), DEFAULT_POST_MAX_SIZE)
