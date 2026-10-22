"""php2shell scanner — behavioural detection for CVE-2026-109618 / CVE-2026-109619."""

from .scanner import Scanner, ScanResult
from .probe import Verdict, Confidence, Signal
from .version import parse_version, VersionInfo, PatchStatus

__version__ = "1.0.0"

__all__ = [
    "Scanner", "ScanResult",
    "Verdict", "Confidence", "Signal",
    "parse_version", "VersionInfo", "PatchStatus",
]
