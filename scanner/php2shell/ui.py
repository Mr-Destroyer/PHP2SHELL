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
