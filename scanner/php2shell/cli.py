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
    unique: list[str] = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique.append(target)
    return unique


def run_ui_mode(args: argparse.Namespace, targets: list[str]) -> int:
    """Serve the browser UI. Every scan is started explicitly by the user."""
    from .ui import run_ui  # imported lazily: the CLI works without it

    banner()
    if targets:
        print(colorize(
            f"  UI mode: {len(targets)} target(s) queued. Each scan still sends "
            f"up to {args.max_probe_mib} MiB per probe.\n", C.YELLOW))
    else:
        print(colorize(
            "  UI mode: enter a target in the browser to begin.\n", C.YELLOW))

    return run_ui(
        targets=targets,
        timeout=args.timeout,
        connect_timeout=args.connect_timeout,
        verify_ssl=not args.insecure,
        sapi=args.sapi,
        headers=parse_headers(args.header),
        max_probe_mib=args.max_probe_mib,
        port=args.port,
        open_browser=not args.no_open,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="php2shell-scan",
        description="Detect php2shell (CVE-2026-109618 / CVE-2026-109619) exposure.",
        epilog=(
            "The scanner triggers a memory-exhaustion condition to detect the "
            "vulnerability behaviourally. This may crash a PHP worker. Only "
            "scan systems you are authorised to test."
        ),
    )
    parser.add_argument("-u", "--url", action="append", metavar="URL",
                        help="target URL (repeatable)")
    parser.add_argument("-l", "--list", metavar="FILE",
                        help="file of targets, one per line")
    parser.add_argument("-t", "--threads", type=int, default=5, metavar="N",
                        help="concurrent scans (default: 5)")
    parser.add_argument("--timeout", type=float, default=60.0, metavar="SEC",
                        help="per-request timeout (default: 60)")
    parser.add_argument("--connect-timeout", type=float, default=10.0,
                        metavar="SEC", help="connect timeout (default: 10)")
    parser.add_argument("--max-probe-mib", type=int, default=20, metavar="N",
                        help="largest probe to send, in MiB (default: 20)")
    parser.add_argument("--sapi", choices=("auto", "mod_php", "fpm"),
                        default="auto", help="restrict verdict rules to one SAPI")
    parser.add_argument("-H", "--header", action="append", metavar="K:V",
                        help="extra request header (repeatable)")
    parser.add_argument("-k", "--insecure", action="store_true",
                        help="skip TLS certificate verification")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="write JSON results to FILE")
    parser.add_argument("--all-results", action="store_true",
                        help="include non-vulnerable results in JSON output")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show per-probe detail")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="only print vulnerable targets")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colors")
    parser.add_argument("--yes", action="store_true",
                        help="skip the interactive confirmation prompt")
    parser.add_argument("--ui", action="store_true",
                        help="launch the interactive browser UI")
    parser.add_argument("--port", type=int, default=0, metavar="N",
                        help="UI port (default: pick a free port)")
    parser.add_argument("--no-open", action="store_true",
                        help="do not open a browser automatically")
    parser.add_argument("--version", action="version",
                        version=f"php2shell-scanner {VERSION}")
    return parser


def parse_headers(raw: Optional[list[str]]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in raw or []:
        name, sep, value = item.partition(":")
        if not sep:
            print(colorize(f"warning: ignoring malformed header {item!r}", C.YELLOW),
                  file=sys.stderr)
            continue
        headers[name.strip()] = value.strip()
    return headers


