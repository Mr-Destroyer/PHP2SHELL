"""
Scan orchestration: control request, progressive probes, verdict.

The decision flow, in order of authority:

  1. Control request. If it fails or returns 5xx, the target is broken or
     blocking us -> INCONCLUSIVE. We never probe a target we cannot baseline,
     because every differential signal depends on that baseline.

  2. Progressive probes (1 MiB -> 8 MiB -> 20 MiB). After each probe:
       a. If the request was rejected before PHP parsed it -> stop, INCONCLUSIVE.
       b. If a crash signal fired -> VULNERABLE, HIGH confidence. Stop.
       c. If the advertised version is patched -> FIXED. Stop.
     Escalation exists so a low-memory_limit target is caught cheaply, and so
     we do not send 20 MiB to a host that already answered.

  3. Fallback to version data, explicitly labelled MEDIUM confidence, because
     distro backports make version strings unreliable in both directions.

  4. Otherwise NOT_VULNERABLE with NONE confidence -- which is NOT the same as
     "safe". We say so in the output.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import probe as probe_mod
from .probe import (
    Confidence,
    ProbeResult,
    Signal,
    Verdict,
    build_control_body,
    build_oversize_body,
    build_probe_body,
    detect_signal,
    is_rejected,
    parse_post_max_size,
    CONTROL_BOUNDARY,
    DEFAULT_POST_MAX_SIZE,
    MEMORY_AMPLIFICATION,
    PROBE_BOUNDARY,
    PROBE_LADDER,
)
from .transport import Response, Transport, normalize_url
from .version import PatchStatus, VersionInfo, extract_from_body, extract_from_headers


@dataclass
class ScanResult:
    """Everything we learned about one target."""

    target: str
    tested_url: str = ""
    verdict: Verdict = Verdict.ERROR
    confidence: Confidence = Confidence.NONE
    reason: str = ""
    signal: Signal = Signal.NONE
    sapi: str = "unknown"
    version: Optional[VersionInfo] = None
    control: Optional[Response] = None
    probes: list[ProbeResult] = field(default_factory=list)
    error: Optional[str] = None
    elapsed: float = 0.0
    bytes_sent: int = 0
    post_max_size: Optional[int] = None

    @property
    def is_vulnerable(self) -> bool:
        return self.verdict in (Verdict.VULNERABLE, Verdict.LIKELY_VULNERABLE)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "tested_url": self.tested_url,
            "verdict": self.verdict.value,
            "confidence": self.confidence.value,
            "reason": self.reason,
            "signal": self.signal.value,
            "sapi": self.sapi,
            "version": self.version.describe() if self.version else None,
            "version_status": (self.version.status.value
                               if self.version else None),
            "error": self.error,
            "elapsed_seconds": round(self.elapsed, 2),
            "bytes_sent": self.bytes_sent,
            "post_max_size": self.post_max_size,
            "probes": [
                {
                    "index": p.index,
                    "size_mib": p.size_mib,
                    "parts": p.parts,
                    "status": p.response.status,
                    "body_bytes": len(p.response.body),
                    "signal": p.signal.value if p.signal else None,
                    "detail": p.detail,
                    "error": p.response.error,
                }
                for p in self.probes
            ],
        }


class Scanner:
    """Scans targets for php2shell exposure."""

    def __init__(
        self,
        timeout: float = 60.0,
        connect_timeout: float = 10.0,
        verify_ssl: bool = True,
        sapi: str = "auto",
        headers: Optional[dict[str, str]] = None,
        user_agent: str = "php2shell-scanner/1.0",
        max_probe_mib: int = 20,
        on_progress: Optional[Callable[[str], None]] = None,
        on_event: Optional[Callable[[dict], None]] = None,
    ) -> None:
        self.transport = Transport(
            timeout=timeout,
            connect_timeout=connect_timeout,
            verify_ssl=verify_ssl,
            user_agent=user_agent,
        )
        self.sapi = sapi
        self.headers = headers or {}
        self.max_probe_mib = max_probe_mib
        self.on_progress = on_progress or (lambda _msg: None)
        # Structured sibling of on_progress, for consumers that want to render
        # state rather than print lines (the browser UI). Every event is a
        # plain dict with a "type" key. See ui.py for the consumer.
        self.on_event = on_event or (lambda _event: None)

    # -- helpers ---------------------------------------------------------

    def _log(self, message: str) -> None:
        self.on_progress(message)

    def _emit(self, event: str, **fields) -> None:
        self.on_event({"type": event, **fields})

    def _multipart_headers(self, boundary: str) -> dict[str, str]:
        headers = dict(self.headers)
        # Never let a caller-supplied Content-Length or Transfer-Encoding
        # desync the body we are about to send.
        for key in list(headers):
            if key.lower() in ("content-length", "transfer-encoding"):
                del headers[key]
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        return headers

    def _ladder(self) -> tuple[tuple[int, int], ...]:
        """The probe ladder, capped by max_probe_mib."""
        return tuple(p for p in PROBE_LADDER if p[0] <= self.max_probe_mib)

    def _discover_post_max_size(
        self, url: str, result: ScanResult
    ) -> Optional[int]:
        """
        Learn the target's post_max_size by deliberately exceeding it.

        PHP emits "POST Content-Length of N bytes exceeds the limit of M bytes"
        during request startup when the body is too large, and that warning
        names M. One oversized request therefore converts a hard limit into a
        known quantity.

        This matters because a probe above post_max_size is discarded before
        the multipart parser runs: it cannot crash, cannot signal, and would
        otherwise be reported as "no signal" on a host that is in fact
        vulnerable. Discovering the limit is what stops the scanner from
        silently testing nothing.

        Returns None when the limit could not be determined (display_errors
        off, a WAF swallowed the warning, or the body was accepted).
        """
        probe_size = DEFAULT_POST_MAX_SIZE + (1 << 20)
        body = build_oversize_body(probe_size)
        self._log(f"discovering post_max_size with a {probe_size:,}-byte body")

        response = self.transport.request(
            url,
            method="POST",
            body=body,
            headers=self._multipart_headers(PROBE_BOUNDARY),
        )
        result.bytes_sent += len(body)

        limit = parse_post_max_size(response.body or b"")
        if limit is None:
            self._log("post_max_size not disclosed; assuming the default")
            return None
        return limit

    # -- main entry point ------------------------------------------------

    def scan(self, target: str) -> ScanResult:
        started = time.monotonic()
        result = ScanResult(target=target)

        try:
            url = normalize_url(target)
        except ValueError as exc:
            result.error = str(exc)
            result.reason = str(exc)
            result.verdict = Verdict.ERROR
            return result

        result.tested_url = url
        self._log(f"control request -> {url}")
        self._emit("start", target=target, url=url)

        # ---- 1. Control request ----------------------------------------
        self._emit("control_start", url=url)
        control = self.transport.request(
            url,
            method="POST",
            body=build_control_body(),
            headers=self._multipart_headers(CONTROL_BOUNDARY),
        )
        result.control = control
        result.bytes_sent += len(build_control_body())

        self._emit(
            "control",
            status=control.status,
            body_bytes=len(control.body),
            error=control.error,
            elapsed=round(control.elapsed, 2),
        )

        if control.error:
            result.verdict = Verdict.INCONCLUSIVE
            result.error = f"control request failed: {control.error}"
            result.reason = result.error
            result.elapsed = time.monotonic() - started
            self._emit("result", result=result.to_dict())
            return result

        if control.status is not None and control.status >= 500:
            result.verdict = Verdict.INCONCLUSIVE
            result.error = f"control request returned HTTP {control.status}"
            result.reason = (
                f"{result.error} -- cannot establish a baseline, so no "
                f"differential signal is meaningful"
            )
            result.elapsed = time.monotonic() - started
            self._emit("result", result=result.to_dict())
            return result

        # Record whatever version the control response advertised.
        version = extract_from_headers(control.headers)
        if version is None:
            version = extract_from_body(control.body)
        result.version = version

        # ---- 1b. Discover post_max_size ---------------------------------
        # A probe larger than post_max_size is discarded by PHP before the
        # multipart parser runs, so it can never produce a signal. Sending one
        # is not merely wasteful, it is a guaranteed false negative. Ask the
        # target for its limit first, then never exceed it.
        post_max = self._discover_post_max_size(url, result)
        if post_max is not None:
            result.post_max_size = post_max
            self._log(f"post_max_size = {post_max:,} bytes")

        # ---- 2. Progressive probes -------------------------------------
        rejected_reason: Optional[str] = None

        for index, (size_mib, parts) in enumerate(self._ladder(), start=1):
            # Skip rungs that PHP would discard unparsed.
            if post_max is not None and (size_mib << 20) >= post_max:
                self._log(
                    f"probe {index} skipped: {size_mib} MiB exceeds "
                    f"post_max_size ({post_max:,} bytes)"
                )
                continue

            self._log(f"probe {index}: {size_mib} MiB, {parts} parts")
            self._emit(
                "probe_start",
                index=index,
                size_mib=size_mib,
                parts=parts,
                total=len(self._ladder()),
            )

            try:
                body = build_probe_body(size_mib, parts)
            except ValueError as exc:
                self._log(f"probe {index} skipped: {exc}")
                continue

            response = self.transport.request(
                url,
                method="POST",
                body=body,
                headers=self._multipart_headers(PROBE_BOUNDARY),
            )
            result.bytes_sent += len(body)

            probe_result = ProbeResult(
                index=index, size_mib=size_mib, parts=parts, response=response
            )
            result.probes.append(probe_result)

            # A transport error mid-probe is itself informative: the worker
            # may have died before we finished uploading. But we cannot
            # distinguish that from a network fault, so we do not treat it
            # as a signal on its own.
            if response.error:
                probe_result.detail = f"transport error: {response.error}"
                self._log(f"probe {index}: {probe_result.detail}")
                self._emit(
                    "probe",
                    index=index,
                    size_mib=size_mib,
                    status=response.status,
                    body_bytes=len(response.body),
                    error=response.error,
                    signal=None,
                    detail=probe_result.detail,
                    bytes_total=result.bytes_sent,
                )
                continue

            # Rejected before PHP parsed the body -> stop escalating.
            if is_rejected(response):
                rejected_reason = (
                    f"probe {index} was rejected with HTTP {response.status} "
                    f"before PHP parsed the body (WAF, proxy limit, or "
                    f"web-server rule)"
                )
                probe_result.detail = rejected_reason
                self._log(f"probe {index}: {rejected_reason}")
                self._emit(
                    "probe",
                    index=index,
                    size_mib=size_mib,
                    status=response.status,
                    body_bytes=len(response.body),
                    error=None,
                    signal=None,
                    detail=rejected_reason,
                    bytes_total=result.bytes_sent,
                )
                break

            # Update version if this response advertised one.
            probe_version = extract_from_headers(response.headers)
            if probe_version is not None:
                result.version = probe_version
                version = probe_version

            # ---- crash signal? ----
            signal, detail = detect_signal(control, response, self.sapi)
            if signal is not None:
                probe_result.signal = signal
                probe_result.detail = detail
                result.signal = signal
                result.verdict = Verdict.VULNERABLE
                result.confidence = Confidence.HIGH
                result.sapi = self._infer_sapi(signal)
                result.reason = (
                    f"probe {index} ({size_mib} MiB, {parts} parts) produced a "
                    f"crash signal: {detail}"
                )
                result.elapsed = time.monotonic() - started
                self._log(f"probe {index}: VULNERABLE -- {detail}")
                self._emit(
                    "probe",
                    index=index,
                    size_mib=size_mib,
                    status=response.status,
                    body_bytes=len(response.body),
                    error=None,
                    signal=signal.value,
                    detail=detail,
                    bytes_total=result.bytes_sent,
                )
                self._emit("result", result=result.to_dict())
                return result

            # ---- version says patched? stop early ----
            if version is not None and version.status is PatchStatus.FIXED:
                result.verdict = Verdict.FIXED
                result.confidence = Confidence.MEDIUM
                result.reason = (
                    f"no crash observed and the target advertises a patched "
                    f"release: {version.describe()}"
                )
                result.elapsed = time.monotonic() - started
                self._log(f"probe {index}: FIXED -- {version.describe()}")
                self._emit(
                    "probe",
                    index=index,
                    size_mib=size_mib,
                    status=response.status,
                    body_bytes=len(response.body),
                    error=None,
                    signal=None,
                    detail=probe_result.detail,
                    bytes_total=result.bytes_sent,
                )
                self._emit("result", result=result.to_dict())
                return result

            self._log(f"probe {index}: no signal")
            self._emit(
                "probe",
                index=index,
                size_mib=size_mib,
                status=response.status,
                body_bytes=len(response.body),
                error=None,
                signal=None,
                detail=probe_result.detail,
                bytes_total=result.bytes_sent,
            )

        # ---- 3. Fall back to version data ------------------------------
        if version is not None:
            if version.status is PatchStatus.FIXED:
                result.verdict = Verdict.FIXED
                result.confidence = Confidence.MEDIUM
                result.reason = (
                    f"no crash observed and the target advertises a patched "
                    f"release: {version.describe()}"
                )
            elif version.is_vulnerable:
                result.verdict = Verdict.LIKELY_VULNERABLE
                result.confidence = Confidence.MEDIUM
                result.reason = (
                    f"no crash observed, but the target advertises an "
                    f"unpatched release: {version.describe()}. Version data "
                    f"alone is not proof -- distro backports can carry the fix "
                    f"under the original version number."
                )
            else:
                result.verdict = Verdict.NOT_VULNERABLE
                result.confidence = Confidence.LOW
                result.reason = (
                    f"no crash observed; version data inconclusive: "
                    f"{version.describe()}"
                )
        elif rejected_reason:
            result.verdict = Verdict.INCONCLUSIVE
            result.confidence = Confidence.NONE
            result.reason = rejected_reason
        else:
            result.verdict = Verdict.NOT_VULNERABLE
            result.confidence = Confidence.NONE
            result.reason = (
                "no crash signal observed and the target does not advertise a "
                "PHP version. This is NOT proof of safety: a WAF, a proxy "
                "limit, or a hardened configuration can suppress the signal."
            )

        # ---- honesty check: could our probes even reach memory_limit? ----
        # If post_max_size caps the body below what is needed to exhaust
        # memory_limit, then no probe we are allowed to send can ever fire.
        # Reporting that as "no signal" would be a false negative dressed up
        # as a clean result, so say plainly that the test was inconclusive.
        if result.verdict is Verdict.NOT_VULNERABLE and result.post_max_size:
            ceiling_mib = (result.post_max_size - 1) / (1 << 20)
            reachable = int(ceiling_mib * MEMORY_AMPLIFICATION)
            if reachable < 1024:
                result.verdict = Verdict.INCONCLUSIVE
                result.confidence = Confidence.NONE
                result.reason = (
                    f"post_max_size is {result.post_max_size:,} bytes, so the "
                    f"largest body PHP will parse is ~{ceiling_mib:.1f} MiB. At "
                    f"the measured ~{MEMORY_AMPLIFICATION}x amplification that "
                    f"forces at most ~{reachable} MB of memory, which may be "
                    f"below this host's memory_limit. The probes cannot "
                    f"reliably reach the exhaustion condition, so absence of a "
                    f"signal proves nothing here. Verify the PHP version "
                    f"directly."
                )

        result.elapsed = time.monotonic() - started
        self._emit("result", result=result.to_dict())
        return result

    @staticmethod
    def _infer_sapi(signal: Signal) -> str:
        if signal is Signal.UPSTREAM_DEAD:
            return "php-fpm"
        if signal is Signal.EMPTY_200:
            return "php-fpm"
        if signal is Signal.IN_BAND_FATAL:
            return "mod_php or php-fpm"
        if signal is Signal.EMPTY_500:
            return "mod_php or php-fpm"
        return "unknown"
