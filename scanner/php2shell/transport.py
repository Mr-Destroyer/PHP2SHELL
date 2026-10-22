"""
Zero-dependency HTTP/1.1 transport.

Why not `requests` / `httpx`?

  1. We must send bodies up to 20 MiB while the server is deliberately
     aborting mid-request. High-level clients raise on that, and their
     connection pools get poisoned.
  2. We must read the response CONCURRENTLY with the upload. A PHP worker can
     die right after emitting headers; a blocking recv() that starts after the
     RST loses the already-buffered response.
  3. We need byte-exact control over Content-Length (or its absence) and over
     the multipart boundary, because the probe body IS the test.
  4. Zero dependencies means this runs anywhere Python 3.9+ exists.

The transport is deliberately dumb: one request per connection, no pooling,
no retries. Retries are a policy decision made by the caller.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

# Read at most this much of a response body. We only need enough to spot a
# PHP fatal error or a version string; anything larger is wasted bandwidth.
DEFAULT_BODY_LIMIT = 1 << 20

# Send the body in slices. A single sendall() of 20 MiB blocks forever if the
# worker aborts mid-upload, because the socket buffer never drains.
SEND_CHUNK = 64 << 10

# Cap response headers so a malicious/broken server cannot exhaust our memory.
MAX_HEADER_BYTES = 256 << 10


@dataclass
class Response:
    """The outcome of one HTTP exchange."""

    status: Optional[int] = None
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: Optional[str] = None
    elapsed: float = 0.0
    bytes_sent: int = 0
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")

    def body_text(self, limit: int = 4096) -> str:
        return self.body[:limit].decode("utf-8", errors="replace")


class Transport:
    """A single-shot HTTP/1.1 client over raw sockets."""

    def __init__(
        self,
        timeout: float = 60.0,
        connect_timeout: float = 10.0,
        verify_ssl: bool = True,
        user_agent: str = "php2shell-scanner/1.0",
        body_limit: int = DEFAULT_BODY_LIMIT,
    ) -> None:
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent
        self.body_limit = body_limit

    # -- connection ------------------------------------------------------

    def _connect(self, scheme: str, host: str, port: int) -> socket.socket:
        sock = socket.create_connection((host, port), timeout=self.connect_timeout)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        if scheme == "https":
            ctx = ssl.create_default_context()
            if not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        return sock

    # -- request ---------------------------------------------------------

    def request(
        self,
        url: str,
        method: str = "GET",
        body: bytes = b"",
        headers: Optional[dict[str, str]] = None,
        read_response: bool = True,
    ) -> Response:
        """
        Perform one HTTP exchange.

        The response is read on a background thread so that we capture headers
        and any partial body even when the server aborts mid-request.
        """
        started = time.monotonic()
        result = Response(bytes_sent=len(body))

        try:
            parts = urlsplit(url)
        except ValueError as exc:
            result.error = f"invalid URL: {exc}"
            return result

        scheme = (parts.scheme or "http").lower()
        if scheme not in ("http", "https"):
            result.error = f"unsupported scheme: {scheme}"
            return result

        host = parts.hostname
        if not host:
            result.error = "URL has no host"
            return result

        port = parts.port or (443 if scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        # Build headers. Host must include the port when it is non-default.
        hdrs: dict[str, str] = {
            "Host": host if port in (80, 443) else f"{host}:{port}",
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        for key, value in (headers or {}).items():
            # Caller-supplied headers win, but never let them set Host twice.
            if key.lower() == "host":
                hdrs["Host"] = value
            else:
                hdrs[key] = value

        if body or method in ("POST", "PUT", "PATCH"):
            hdrs.setdefault("Content-Length", str(len(body)))

        head = f"{method} {path} HTTP/1.1\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
        head += "\r\n"
        head_bytes = head.encode("latin-1", errors="replace")

        sock: Optional[socket.socket] = None
        try:
            sock = self._connect(scheme, host, port)
            sock.settimeout(self.timeout)

            if not read_response:
                sock.sendall(head_bytes)
                if body:
                    self._send_body(sock, body)
                result.status = 0
                return result

            # Reader thread: start before sending so nothing is missed.
            raw = bytearray()
            read_error: list[str] = []

            def _reader() -> None:
                try:
                    while len(raw) < MAX_HEADER_BYTES + self.body_limit:
                        chunk = sock.recv(65536)
                        if not chunk:
                            break
                        raw.extend(chunk)
                except (OSError, ssl.SSLError) as exc:
                    read_error.append(str(exc))

            reader = threading.Thread(target=_reader, daemon=True)
            reader.start()

            try:
                sock.sendall(head_bytes)
                if body:
                    self._send_body(sock, body)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                # Expected: the worker died while we were still uploading.
                # Whatever the reader captured is still valid evidence.
                pass
            except OSError as exc:
                result.error = f"send failed: {exc}"

            reader.join(timeout=self.timeout + 2.0)

            self._parse(raw, result)

            if result.error is None and read_error and not raw:
                result.error = f"read failed: {read_error[0]}"

        except socket.timeout:
            result.error = "timed out"
        except ssl.SSLError as exc:
            result.error = f"TLS error: {exc}"
        except OSError as exc:
            result.error = f"connection error: {exc}"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            result.elapsed = time.monotonic() - started
