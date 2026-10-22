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
