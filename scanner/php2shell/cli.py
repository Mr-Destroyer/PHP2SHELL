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

    if verbose and result.probes:
        print()
        print(colorize("  probes:", C.BOLD))
        for p in result.probes:
            status = p.response.status if p.response.status is not None else "---"
            sig = f" -> {p.signal.value}" if p.signal else ""
            err = f" ({p.response.error})" if p.response.error else ""
            print(f"    [{p.index}] {p.size_mib:>2} MiB / {p.parts:>4} parts  "
                  f"HTTP {status}  {len(p.response.body):>6} bytes{sig}{err}")
            if p.detail:
                for line in _wrap(p.detail, 66):
                    print(f"        {colorize(line, C.GREY)}")

    if result.error:
        print()
        print(colorize(f"  error: {result.error}", C.RED))


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def print_summary(results: list[ScanResult]) -> None:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict.value] = counts.get(r.verdict.value, 0) + 1

    print()
    print(colorize("═" * 78, C.GREY))
    print(colorize("  SUMMARY", C.BOLD))
    print(colorize("═" * 78, C.GREY))

    order = [
        (Verdict.VULNERABLE, C.RED),
        (Verdict.LIKELY_VULNERABLE, C.YELLOW),
        (Verdict.FIXED, C.GREEN),
        (Verdict.NOT_VULNERABLE, C.CYAN),
        (Verdict.INCONCLUSIVE, C.MAGENTA),
        (Verdict.ERROR, C.GREY),
    ]
    for verdict, color in order:
        count = counts.get(verdict.value, 0)
        if count:
            print(f"  {colorize(f'{count:>4}', color)}  {verdict.value}")

    vulnerable = [r for r in results if r.is_vulnerable]
    if vulnerable:
        print()
        print(colorize("  Vulnerable targets:", C.RED))
        for r in vulnerable:
            conf = r.confidence.value
            print(f"    - {r.target}  ({conf} confidence)")

    no_signal = [r for r in results
                 if r.verdict is Verdict.NOT_VULNERABLE
                 and r.confidence is Confidence.NONE]
    if no_signal:
        print()
        print(colorize(
            "  Note: 'NO SIGNAL' is not proof of safety. A WAF, proxy limit,\n"
            "  or hardened configuration can suppress the crash signal. Verify\n"
            "  the installed PHP version directly where you can.", C.GREY))
    print()


def load_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = []
    if args.url:
        targets.extend(args.url)
    if args.list:
        try:
            with open(args.list, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except OSError as exc:
            print(colorize(f"error: cannot read {args.list}: {exc}", C.RED),
                  file=sys.stderr)
            sys.exit(2)

    # Deduplicate while preserving order.
    seen: set[str] = set()
