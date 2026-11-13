"""Unit tests for the log anomaly detector."""

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detector import (  # noqa: E402
    AuthEvent,
    analyse,
    detect_brute_force,
    detect_impossible_travel,
    parse_ssh_line,
)


def test_parse_failed_line():
    line = "Mar 10 13:58:01 web01 sshd[1123]: Failed password for root from 203.0.113.7 port 51022 ssh2"
    event = parse_ssh_line(line, year=2026)
    assert event is not None
    assert event.user == "root"
    assert event.source_ip == "203.0.113.7"
    assert event.success is False
    assert event.timestamp == datetime(2026, 3, 10, 13, 58, 1)


def test_parse_accepted_line_with_invalid_user_prefix():
    line = "Mar 10 13:58:05 web01 sshd[1125]: Failed password for invalid user admin from 203.0.113.7 port 51026 ssh2"
    event = parse_ssh_line(line)
    assert event is not None
    assert event.user == "admin"
    assert event.success is False


def test_parse_non_auth_line_returns_none():
    assert parse_ssh_line("Mar 10 13:00:00 web01 systemd[1]: Started Daily apt timer.") is None


def _fail(ip, second, user="root"):
    return AuthEvent(datetime(2026, 3, 10, 13, 58, second), user, ip, False)


def test_brute_force_triggers_at_threshold():
    events = [_fail("10.0.0.1", s) for s in range(0, 10, 2)]  # 5 fails in 8s
    findings = detect_brute_force(events, threshold=5, window=timedelta(minutes=1))
    assert len(findings) == 1
    assert findings[0].kind == "brute_force"
    assert findings[0].source_ip == "10.0.0.1"


def test_brute_force_respects_window():
    # 5 failures but spread over 5 minutes -> no single 1-min window has 5
    events = [
        AuthEvent(datetime(2026, 3, 10, 13, 0 + m, 0), "root", "10.0.0.2", False)
        for m in range(5)
    ]
    assert detect_brute_force(events, threshold=5, window=timedelta(minutes=1)) == []


def test_brute_force_ignores_successful_logins():
    events = [AuthEvent(datetime(2026, 3, 10, 13, 0, s), "alice", "10.0.0.3", True) for s in range(6)]
    assert detect_brute_force(events, threshold=5) == []


def test_impossible_travel_flagged():
    events = [
        AuthEvent(datetime(2026, 3, 10, 14, 0, 0), "alice", "1.1.1.1", True),
        AuthEvent(datetime(2026, 3, 10, 14, 30, 0), "alice", "2.2.2.2", True),
    ]
    geo = {"1.1.1.1": (51.5, -0.12), "2.2.2.2": (-33.87, 151.21)}  # London -> Sydney
    findings = detect_impossible_travel(events, geo)
    assert len(findings) == 1
    assert findings[0].kind == "impossible_travel"


def test_possible_travel_not_flagged():
    events = [
        AuthEvent(datetime(2026, 3, 10, 14, 0, 0), "alice", "1.1.1.1", True),
        AuthEvent(datetime(2026, 3, 11, 14, 0, 0), "alice", "2.2.2.2", True),  # 24h later
    ]
    geo = {"1.1.1.1": (51.5, -0.12), "2.2.2.2": (48.85, 2.35)}  # London -> Paris, a day apart
    assert detect_impossible_travel(events, geo) == []


def test_analyse_sorts_newest_first():
    events = [_fail("10.0.0.1", s) for s in range(0, 12, 2)]
    findings = analyse(events, brute_threshold=5)
    assert findings
    assert all(findings[i].at >= findings[i + 1].at for i in range(len(findings) - 1))
