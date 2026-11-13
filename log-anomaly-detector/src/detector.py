"""Authentication-log anomaly detection.

Pure-stdlib. The detector consumes an iterable of ``AuthEvent`` records and
emits ``Finding`` objects. Parsing (from raw log lines) is kept separate from
detection so each can be tested in isolation and so new log formats can be
plugged in without touching the detection logic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional


@dataclass(frozen=True)
class AuthEvent:
    """A single authentication attempt, normalised across log formats."""

    timestamp: datetime
    user: str
    source_ip: str
    success: bool


@dataclass(frozen=True)
class Finding:
    """Something worth a human's attention."""

    kind: str          # e.g. "brute_force", "impossible_travel"
    severity: str      # "low" | "medium" | "high"
    user: str
    source_ip: str
    detail: str
    at: datetime


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

# Matches the common OpenSSH auth.log lines, e.g.:
#   "Mar 10 13:58:01 host sshd[1123]: Failed password for root from 10.0.0.9 port 22 ssh2"
#   "Mar 10 13:58:04 host sshd[1123]: Accepted password for alice from 10.0.0.9 port 22 ssh2"
_SSH_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"sshd\[\d+\]:\s+(?P<result>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_ssh_line(line: str, *, year: int = 2026) -> Optional[AuthEvent]:
    """Parse a single OpenSSH auth log line into an :class:`AuthEvent`.

    Returns ``None`` for lines that are not login attempts. ``year`` is needed
    because the syslog timestamp format omits the year.
    """
    match = _SSH_RE.search(line)
    if not match:
        return None
    g = match.groupdict()
    hour, minute, second = (int(part) for part in g["time"].split(":"))
    ts = datetime(year, _MONTHS[g["month"]], int(g["day"]), hour, minute, second)
    return AuthEvent(
        timestamp=ts,
        user=g["user"],
        source_ip=g["ip"],
        success=g["result"] == "Accepted",
    )


def parse_log(lines: Iterable[str], *, year: int = 2026) -> list[AuthEvent]:
    """Parse many lines, silently skipping those that aren't auth attempts."""
    events = []
    for line in lines:
        event = parse_ssh_line(line, year=year)
        if event is not None:
            events.append(event)
    return events


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def detect_brute_force(
    events: Iterable[AuthEvent],
    *,
    threshold: int = 5,
    window: timedelta = timedelta(minutes=1),
) -> list[Finding]:
    """Flag >= ``threshold`` failed logins from one IP within ``window``.

    Uses a sliding window per source IP. A burst of failures in a short time
    is the classic signature of a password-guessing attack.
    """
    by_ip: dict[str, list[AuthEvent]] = {}
    for event in events:
        if not event.success:
            by_ip.setdefault(event.source_ip, []).append(event)

    findings: list[Finding] = []
    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda e: e.timestamp)
        start = 0
        reported = False
        for end in range(len(attempts)):
            while attempts[end].timestamp - attempts[start].timestamp > window:
                start += 1
            count = end - start + 1
            if count >= threshold and not reported:
                users = sorted({a.user for a in attempts[start : end + 1]})
                findings.append(
                    Finding(
                        kind="brute_force",
                        severity="high",
                        user=",".join(users),
                        source_ip=ip,
                        detail=(
                            f"{count} failed logins within "
                            f"{int(window.total_seconds())}s "
                            f"(users tried: {', '.join(users)})"
                        ),
                        at=attempts[end].timestamp,
                    )
                )
                reported = True
    return findings


def detect_impossible_travel(
    events: Iterable[AuthEvent],
    ip_locations: dict[str, tuple[float, float]],
    *,
    max_kmh: float = 900.0,
) -> list[Finding]:
    """Flag successful logins for one user from two places too far apart, too fast.

    ``ip_locations`` maps an IP to a ``(latitude, longitude)``. Consecutive
    successful logins are compared: if the implied travel speed exceeds
    ``max_kmh`` (roughly a passenger jet), it's physically implausible and the
    account may be compromised.
    """
    by_user: dict[str, list[AuthEvent]] = {}
    for event in events:
        if event.success and event.source_ip in ip_locations:
            by_user.setdefault(event.user, []).append(event)

    findings: list[Finding] = []
    for user, logins in by_user.items():
        logins.sort(key=lambda e: e.timestamp)
        for prev, curr in zip(logins, logins[1:]):
            if prev.source_ip == curr.source_ip:
                continue
            km = _haversine_km(ip_locations[prev.source_ip], ip_locations[curr.source_ip])
            hours = (curr.timestamp - prev.timestamp).total_seconds() / 3600.0
            if hours <= 0:
                speed = float("inf")
            else:
                speed = km / hours
            if speed > max_kmh:
                findings.append(
                    Finding(
                        kind="impossible_travel",
                        severity="high",
                        user=user,
                        source_ip=curr.source_ip,
                        detail=(
                            f"{km:.0f} km in {hours * 60:.0f} min "
                            f"(~{speed:.0f} km/h) from {prev.source_ip} to {curr.source_ip}"
                        ),
                        at=curr.timestamp,
                    )
                )
    return findings


def _haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Great-circle distance between two (lat, lon) points, in kilometres."""
    import math

    lat1, lon1 = map(math.radians, a)
    lat2, lon2 = map(math.radians, b)
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(h))


def analyse(
    events: Iterable[AuthEvent],
    *,
    ip_locations: Optional[dict[str, tuple[float, float]]] = None,
    brute_threshold: int = 5,
) -> list[Finding]:
    """Run every detector and return all findings, newest first."""
    events = list(events)
    findings = detect_brute_force(events, threshold=brute_threshold)
    if ip_locations:
        findings += detect_impossible_travel(events, ip_locations)
    findings.sort(key=lambda f: f.at, reverse=True)
    return findings
