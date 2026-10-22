"""
Command-line interface.

Design goals:
  - Default to a safe, read-only-ish posture: warn before probing, require
    explicit acknowledgement for large scans.
  - Never print a bare "safe" verdict. Absence of signal is reported as
    absence of signal, with the caveats spelled out.
  - Machine-readable JSON for pipelines, human-readable for terminals.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from .probe import Confidence, Verdict
from .scanner import ScanResult, Scanner

VERSION = "1.1.0"

# ANSI colors, disabled when not a TTY or when --no-color is passed.
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    MAGENTA = "\033[1;35m"
    CYAN = "\033[1;36m"
    GREY = "\033[0;90m"

    enabled = True

    @classmethod
    def disable(cls) -> None:
        for name in dir(cls):
            if name.isupper() and isinstance(getattr(cls, name), str):
                setattr(cls, name, "")


def colorize(text: str, color: str) -> str:
    if not C.enabled:
        return text
    return f"{color}{text}{C.RESET}"


VERDICT_STYLE = {
    Verdict.VULNERABLE: (C.RED, "VULNERABLE"),
    Verdict.LIKELY_VULNERABLE: (C.YELLOW, "LIKELY VULNERABLE"),
    Verdict.FIXED: (C.GREEN, "FIXED"),
    Verdict.NOT_VULNERABLE: (C.CYAN, "NO SIGNAL"),
    Verdict.INCONCLUSIVE: (C.MAGENTA, "INCONCLUSIVE"),
    Verdict.ERROR: (C.GREY, "ERROR"),
}


def banner() -> None:
    print(colorize(
        "\n  php2shell scanner " + VERSION + "\n"
        "  CVE-2026-109618 / CVE-2026-109619\n", C.BOLD))
    print(colorize(
        "  Behavioural detection: triggers a memory-exhaustion condition during\n"
        "  request parsing and observes how the target fails. This sends up to\n"
        "  ~29 MiB per path and may crash a PHP worker.\n", C.GREY))
    print(colorize(
        "  Only scan systems you own or have written permission to test.\n", C.YELLOW))


def print_result(result: ScanResult, verbose: bool = False) -> None:
    color, label = VERDICT_STYLE.get(result.verdict, (C.GREY, result.verdict.value))

    print()
    print(colorize("─" * 78, C.GREY))
    print(f"  {colorize(label, color)}  {colorize(result.target, C.BOLD)}")
    print(colorize("─" * 78, C.GREY))

    print(f"  confidence : {result.confidence.value}")
    if result.version is not None:
        print(f"  version    : {result.version.describe()}")
    if result.sapi != "unknown":
        print(f"  sapi       : {result.sapi}")
    if result.signal.value != "none":
        print(f"  signal     : {result.signal.value}")
    print(f"  elapsed    : {result.elapsed:.2f}s")
    print(f"  sent       : {result.bytes_sent:,} bytes")

    print()
    print(colorize("  reason:", C.BOLD))
    for line in _wrap(result.reason, 72):
        print(f"    {line}")
