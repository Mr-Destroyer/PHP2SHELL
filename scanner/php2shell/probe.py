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
