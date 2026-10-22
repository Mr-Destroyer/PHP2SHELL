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
