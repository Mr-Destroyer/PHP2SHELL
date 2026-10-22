"""
Integration tests against a local mock HTTP server.

These exercise the full scan flow (control -> probes -> verdict) without
needing the Docker lab, so the suite runs anywhere.
"""

import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from php2shell.probe import Confidence, Signal, Verdict  # noqa: E402
from php2shell.scanner import Scanner  # noqa: E402


class MockHandler(BaseHTTPRequestHandler):
    """Configurable mock PHP target."""

    # Set per-test via the server instance.
    mode = "vulnerable"
    powered_by = None

    def log_message(self, *args):  # silence
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        # Read the body so the client does not block on a full socket buffer.
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)

        mode = self.server.mode  # type: ignore[attr-defined]
        powered_by = self.server.powered_by  # type: ignore[attr-defined]

        if mode == "vulnerable":
            body = (b"<br />\n<b>Fatal error</b>:  Allowed memory size of "
                    b"8388608 bytes exhausted (tried to allocate 4096 bytes) "
                    b"in <b>Unknown</b> on line <b>0</b><br />\n")
            self._send(200, body, powered_by)

        elif mode == "patched":
            # Patched PHP: no fatal, normal output.
            self._send(200, b"hello from the app", powered_by)

        elif mode == "patched_oom":
            # Patched PHP that still OOMs but names a real file/line.
            body = (b"PHP Fatal error:  Allowed memory size of 8388608 bytes "
                    b"exhausted (tried to allocate 4096 bytes) in "
                    b"/var/www/html/index.php on line 12")
            self._send(200, body, powered_by)

        elif mode == "empty500":
            # Differential: the small control body gets a normal 200, the
            # large probe body kills the worker -> empty 500. That difference
            # is the signal; a target that always returns empty 500s is not.
            if length < 1024:
                self._send(200, b"hello from the app", powered_by)
            else:
                self._send(500, b"", powered_by)

        elif mode == "waf":
            # Control passes, the large probe is blocked before PHP sees it.
            if length < 1024:
                self._send(200, b"hello from the app", powered_by)
            else:
                self._send(403, b"blocked by WAF", powered_by)

        elif mode == "broken":
            self._send(500, b"<h1>Internal Server Error</h1>", powered_by)

        else:
            self._send(200, b"ok", powered_by)

    def _send(self, status, body, powered_by=None):
        self.send_response(status)
        if powered_by:
            self.send_header("X-Powered-By", powered_by)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class MockServer:
    def __init__(self, mode, powered_by=None):
        self.httpd = HTTPServer(("127.0.0.1", 0), MockHandler)
        self.httpd.mode = mode
        self.httpd.powered_by = powered_by
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return f"http://127.0.0.1:{self.port}/index.php"

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def scan(mode, powered_by=None, **kwargs):
    with MockServer(mode, powered_by) as url:
        scanner = Scanner(timeout=15, verify_ssl=False, **kwargs)
        return scanner.scan(url)


class TestVerdicts(unittest.TestCase):
    def test_vulnerable_detected(self):
        result = scan("vulnerable", powered_by="PHP/8.4.26")
        self.assertIs(result.verdict, Verdict.VULNERABLE)
        self.assertIs(result.confidence, Confidence.HIGH)
        self.assertIs(result.signal, Signal.IN_BAND_FATAL)

    def test_vulnerable_without_version_header(self):
        # Detection must not depend on expose_php.
        result = scan("vulnerable", powered_by=None)
        self.assertIs(result.verdict, Verdict.VULNERABLE)
        self.assertIs(result.confidence, Confidence.HIGH)

    def test_patched_with_version(self):
        result = scan("patched", powered_by="PHP/8.4.27")
        self.assertIs(result.verdict, Verdict.FIXED)
        self.assertFalse(result.is_vulnerable)

    def test_patched_oom_is_not_vulnerable(self):
        # The key false-positive case: patched PHP that still OOMs.
        result = scan("patched_oom", powered_by="PHP/8.4.27")
        self.assertFalse(result.is_vulnerable)
        self.assertIs(result.verdict, Verdict.FIXED)

    def test_patched_oom_without_version_is_not_vulnerable(self):
        # No version header, app-level OOM -> must not claim vulnerable.
        result = scan("patched_oom", powered_by=None)
        self.assertFalse(result.is_vulnerable)

    def test_empty_500_detected(self):
        result = scan("empty500", powered_by=None)
        self.assertIs(result.verdict, Verdict.VULNERABLE)
        self.assertIs(result.signal, Signal.EMPTY_500)

    def test_waf_block_is_inconclusive(self):
        result = scan("waf", powered_by=None)
        self.assertIs(result.verdict, Verdict.INCONCLUSIVE)
        self.assertFalse(result.is_vulnerable)

    def test_broken_target_is_inconclusive(self):
        # Control returns 500 -> cannot baseline -> inconclusive.
        result = scan("broken", powered_by=None)
        self.assertIs(result.verdict, Verdict.INCONCLUSIVE)

    def test_no_signal_no_version(self):
        result = scan("patched", powered_by=None)
        self.assertIs(result.verdict, Verdict.NOT_VULNERABLE)
        self.assertIs(result.confidence, Confidence.NONE)

    def test_version_fallback_likely(self):
        # No crash, but version says unpatched -> LIKELY, MEDIUM.
        result = scan("patched", powered_by="PHP/8.4.26")
        self.assertIs(result.verdict, Verdict.LIKELY_VULNERABLE)
        self.assertIs(result.confidence, Confidence.MEDIUM)


class TestEscalation(unittest.TestCase):
    def test_stops_after_first_signal(self):
        result = scan("vulnerable", powered_by="PHP/8.4.26")
        # Should stop at probe 1, not send all three.
        self.assertEqual(len(result.probes), 1)

    def test_max_probe_mib_caps_ladder(self):
        result = scan("patched", powered_by=None, max_probe_mib=1)
        self.assertTrue(all(p.size_mib <= 1 for p in result.probes))


class TestErrorHandling(unittest.TestCase):
    def test_unreachable_target(self):
        scanner = Scanner(timeout=2, connect_timeout=2, verify_ssl=False)
        result = scanner.scan("http://127.0.0.1:1/index.php")
        self.assertIs(result.verdict, Verdict.INCONCLUSIVE)
        self.assertIsNotNone(result.error)

    def test_invalid_url(self):
        scanner = Scanner(timeout=2, verify_ssl=False)
        result = scanner.scan("ftp://example.com")
        self.assertIs(result.verdict, Verdict.ERROR)


if __name__ == "__main__":
    unittest.main(verbosity=2)
