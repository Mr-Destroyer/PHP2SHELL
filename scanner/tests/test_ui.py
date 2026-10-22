"""
Tests for the browser UI plumbing: scanner events, the local server's auth
boundary, and the replayable job log.

The animation itself is not unit-testable, but everything it depends on is:
if the event order or the token check regresses, these fail.
"""

import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from php2shell.scanner import Scanner  # noqa: E402
from php2shell.ui import UiApp, UiServer  # noqa: E402


class MockHandler(BaseHTTPRequestHandler):
    """Just enough PHP to trigger the in-band fatal signal."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
        body = (b"<b>Fatal error</b>: Allowed memory size of 8388608 bytes "
                b"exhausted in <b>Unknown</b> on line <b>0</b>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class MockTarget:
    def __enter__(self):
        self.httpd = HTTPServer(("127.0.0.1", 0), MockHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.port}/index.php"

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestScannerEvents(unittest.TestCase):
    def test_vulnerable_run_emits_ordered_events(self):
        events = []
        with MockTarget() as url:
            Scanner(timeout=15, max_probe_mib=1,
                    on_event=events.append).scan(url)

        kinds = [e["type"] for e in events]
        self.assertEqual(kinds[0], "start")
        self.assertEqual(kinds[1], "control_start")
        self.assertIn("control", kinds)
        self.assertIn("probe_start", kinds)
        self.assertIn("probe", kinds)
        self.assertEqual(kinds[-1], "result")

        # The result event carries the same shape as ScanResult.to_dict().
        result = events[-1]["result"]
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertEqual(result["signal"], "in-band PHP fatal (memory exhausted in Unknown)")
        self.assertGreater(result["bytes_sent"], 0)

        # A probe event is emitted for the probe that produced the signal.
        probe = [e for e in events if e["type"] == "probe"][0]
        self.assertEqual(probe["index"], 1)
        self.assertIsNotNone(probe["signal"])

    def test_event_callback_is_optional(self):
        # No on_event handler must still work (the CLI path).
        with MockTarget() as url:
            result = Scanner(timeout=15, max_probe_mib=1).scan(url)
        self.assertTrue(result.is_vulnerable)


class TestJobReplay(unittest.TestCase):
    def test_follow_replays_from_zero_and_ends(self):
        options = {
            "timeout": 15.0, "connect_timeout": 5.0, "verify_ssl": False,
            "sapi": "auto", "headers": {}, "max_probe_mib": 1,
        }
        app = UiApp(options, [])
        with MockTarget() as url:
            job = app.start_job(url)
