"""
PHP version parsing and patch-status classification.

The single most important accuracy decision in this scanner: a version string
is NOT proof of vulnerability, and its absence is NOT proof of safety.

Distribution vendors routinely backport security fixes WITHOUT bumping the
upstream version number. Debian's php8.2 package can report "8.2.29" and still
contain the php2shell fix. So a version check alone produces false positives.

We therefore treat version data as a *fallback signal* only, and label it as
such in the output. The authoritative signal is behavioural (see probe.py).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

# First release of each branch that contains the php2shell fix.
# Source: PHP October 2026 Security Release (php.net/archive/2026.php)
FIXED_VERSIONS: dict[tuple[int, int], int] = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}

# Branches that are end-of-life and will never receive an upstream fix.
# 8.1 and older: source backports exist for 7.4/8.0/8.1 but no binaries.
EOL_BRANCHES: set[tuple[int, int]] = {
    (5, 4), (5, 5), (5, 6),
    (7, 0), (7, 1), (7, 2), (7, 3), (7, 4),
    (8, 0), (8, 1),
}

# The earliest affected release. The vulnerable code dates to PHP 5.4.0.
EARLIEST_AFFECTED = (5, 4, 0)

# Matches "PHP/8.4.26", "PHP 8.4.26", "php/8.4.26".
#
# The "PHP" prefix is REQUIRED. Without it, "nginx/1.24.0" or "OpenSSL/3.0.11"
# parse as PHP 1.24.0 / 3.0.11 -- a real false-positive source, since those
# strings appear in Server and X-Powered-By headers all the time.
_VERSION_RE = re.compile(r"PHP[/ ](\d+)\.(\d+)\.(\d+)", re.IGNORECASE)

# A bare version is only accepted when the caller explicitly wants one (e.g.
# the user typed "8.4.26" on the command line). It is never used for header
# or body scraping.
_BARE_VERSION_RE = re.compile(r"^\s*(\d+)\.(\d+)\.(\d+)\s*$")


class PatchStatus(str, Enum):
    """Classification of a version string against the php2shell fix."""

    VULNERABLE = "VULNERABLE"      # below the fixed release for its branch
    FIXED = "FIXED"                # at or above the fixed release
    EOL = "EOL"                    # end-of-life branch, no upstream fix
    UNKNOWN_BRANCH = "UNKNOWN"     # branch we have no data for (e.g. 8.6)
    TOO_OLD = "TOO_OLD"            # older than 5.4.0, not affected
    UNPARSEABLE = "UNPARSEABLE"    # no version found


@dataclass(frozen=True)
class VersionInfo:
    """A parsed PHP version plus its patch classification."""

    raw: str
    major: int
    minor: int
    patch: int
    status: PatchStatus
    fixed_in: Optional[str] = None

    @property
    def tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    @property
    def branch(self) -> str:
        return f"{self.major}.{self.minor}"

    @property
    def is_vulnerable(self) -> bool:
        return self.status in (PatchStatus.VULNERABLE, PatchStatus.EOL)

    def describe(self) -> str:
        if self.status is PatchStatus.FIXED:
            return f"PHP {self.major}.{self.minor}.{self.patch} (patched)"
        if self.status is PatchStatus.VULNERABLE:
            return (f"PHP {self.major}.{self.minor}.{self.patch} "
                    f"(unpatched, fixed in {self.fixed_in})")
        if self.status is PatchStatus.EOL:
            return (f"PHP {self.major}.{self.minor}.{self.patch} "
                    f"(end-of-life, no upstream fix)")
        if self.status is PatchStatus.TOO_OLD:
            return f"PHP {self.major}.{self.minor}.{self.patch} (predates 5.4.0)"
        if self.status is PatchStatus.UNKNOWN_BRANCH:
            return f"PHP {self.major}.{self.minor}.{self.patch} (branch not in advisory)"
        return f"unparseable version: {self.raw!r}"


def parse_version(raw: str, allow_bare: bool = False) -> Optional[VersionInfo]:
    """
    Parse a version string and classify it.

    Returns None if no PHP version is present.

    `allow_bare` permits a string that is nothing but "x.y.z". Use it for
    user-supplied input, never for scraping headers or bodies -- otherwise
    "nginx/1.24.0" becomes PHP 1.24.0.
    """
    if not raw:
        return None

    match = _VERSION_RE.search(raw)
    if not match and allow_bare:
        match = _BARE_VERSION_RE.match(raw)
    if not match:
        return None

    major, minor, patch = (int(g) for g in match.groups())
    branch = (major, minor)
