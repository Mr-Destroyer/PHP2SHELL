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
