"""
Local browser UI.

`php2shell-scan --ui -u https://example.com` starts a small HTTP server bound
to 127.0.0.1, opens a browser, and streams scan events to it over
Server-Sent Events. The page animates a one-punch hero against the target:
the punch lands only when the scanner has a behavioural signal.

Design constraints, in order:

  1. **Zero dependencies.** http.server + json + a static page. The scanner
     ships with no dependencies and the UI must not change that.
  2. **Localhost only.** The UI can be told to scan arbitrary hosts, so it is
     an SSRF-shaped tool if exposed. We bind 127.0.0.1 and require a random
     per-run token on every API route, which also blocks CSRF from a random
     web page that guesses the port.
  3. **The animation follows the scan, not the other way round.** Events are
     emitted by Scanner as the real requests happen; the page never invents
     progress.
"""

from __future__ import annotations

import json
import secrets
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlsplit

from .scanner import ScanResult, Scanner

WEB_ROOT = Path(__file__).with_name("web")

# Only these files are servable. A whitelist beats path-traversal checks.
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}

MAX_BODY = 64 << 10


class Job:
    """One scan, with a replayable event log that SSE clients can follow."""

    def __init__(self, job_id: str, target: str, options: dict[str, Any]) -> None:
        self.id = job_id
        self.target = target
        self.options = options
        self.log: list[dict] = []
        self.closed = False
        self.cond = threading.Condition()

    # -- producer --------------------------------------------------------

    def emit(self, event: dict) -> None:
        with self.cond:
            self.log.append(event)
            if event.get("type") == "done":
                self.closed = True
            self.cond.notify_all()

    def run(self) -> None:
        options = self.options
        try:
            scanner = Scanner(
                timeout=options["timeout"],
                connect_timeout=options["connect_timeout"],
                verify_ssl=options["verify_ssl"],
                sapi=options["sapi"],
                headers=options["headers"],
                max_probe_mib=options["max_probe_mib"],
                on_event=self.emit,
            )
            result = scanner.scan(self.target)
            _report(result)
        except Exception as exc:  # noqa: BLE001 - surface it in the UI
            self.emit({"type": "fatal", "error": f"{type(exc).__name__}: {exc}"})
        finally:
            self.emit({"type": "done"})

    # -- consumer --------------------------------------------------------

    def follow(self, index: int = 0):
        """Yield events from `index`, or None as a keep-alive heartbeat."""
        while True:
            with self.cond:
                if index >= len(self.log) and not self.closed:
                    self.cond.wait(timeout=10.0)
                events = self.log[index:]
                index += len(events)
                closed = self.closed
            if not events:
                if closed:
                    return
                yield None
                continue
            for event in events:
                yield event
            if closed:
                return


def _report(result: ScanResult) -> None:
    """One terminal line per result, so UI mode is still script-friendly."""
    mark = "!!" if result.is_vulnerable else "--"
    print(f"  {mark} {result.verdict.value:<15} {result.target}  "
          f"({result.confidence.value} confidence, {result.elapsed:.2f}s)",
          flush=True)


class UiApp:
    def __init__(self, options: dict[str, Any], targets: list[str],
                 host: str = "127.0.0.1") -> None:
        self.options = options
        self.targets = targets
        self.host = host
        self.token = secrets.token_urlsafe(24)
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        self.httpd: Optional[ThreadingHTTPServer] = None

    # -- jobs ------------------------------------------------------------

    def start_job(self, target: str) -> Job:
        job = Job(secrets.token_hex(8), target, self.options)
        with self.lock:
            self.jobs[job.id] = job
            # Keep the registry small; results are printed to the terminal.
            if len(self.jobs) > 32:
                for stale in list(self.jobs)[:-16]:
                    self.jobs.pop(stale, None)
        threading.Thread(target=job.run, daemon=True).start()
        return job

    def job(self, job_id: str) -> Optional[Job]:
        with self.lock:
            return self.jobs.get(job_id)


class UiHandler(BaseHTTPRequestHandler):
    server_version = "php2shell-ui"
    protocol_version = "HTTP/1.1"

    # -- plumbing --------------------------------------------------------

    @property
    def app(self) -> UiApp:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        # The terminal output belongs to the scanner, not to request noise.
        pass

    def _query(self) -> dict[str, list[str]]:
        return parse_qs(urlsplit(self.path).query)

    def _authorised(self) -> bool:
        supplied = (self._query().get("token") or [""])[0]
        if not supplied:
            supplied = self.headers.get("X-Auth-Token", "")
        return secrets.compare_digest(supplied, self.app.token)

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status: int, payload: Any) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    # -- routes ----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path

        if path in ASSETS:
            name, ctype = ASSETS[path]
            # The page's own <link>/<script> requests cannot carry the token,
            # so only the document itself is gated. Static assets are inert.
            if path in ("/", "/index.html") and not self._authorised():
                self._send(403, _DENIED, "text/html; charset=utf-8")
                return
            try:
                data = (WEB_ROOT / name).read_bytes()
            except OSError:
                self._send(500, b"asset missing", "text/plain")
                return
            self._send(200, data, ctype)
            return

        if not self._authorised():
            self._send(403, _DENIED, "text/html; charset=utf-8")
            return

        if path == "/api/config":
            self._json(200, {
                "targets": self.app.targets,
                "options": {
                    "max_probe_mib": self.app.options["max_probe_mib"],
                    "sapi": self.app.options["sapi"],
                },
            })
            return

        if path == "/api/events":
            job_id = (self._query().get("id") or [""])[0]
            job = self.app.job(job_id)
            if job is None:
                self._json(404, {"error": "unknown job"})
                return
            self._stream(job)
            return

        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if not self._authorised():
            self._json(403, {"error": "bad token"})
            return

        if path == "/api/scan":
            self._start_scan()
            return

        if path == "/api/quit":
            self._json(200, {"ok": True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return

        self._json(404, {"error": "not found"})

    def _start_scan(self) -> None:
        try:
