"""Unit tests for the password auditor.

The breach check is tested against the k-anonymity *parser* with a synthetic
response, so the tests are fully offline and deterministic.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.auditor import (  # noqa: E402
    AuditResult,
    _parse_breach_response,
    audit,
    estimate_entropy,
    find_issues,
)


def test_entropy_empty_password():
    assert estimate_entropy("") == (0.0, 0)


def test_entropy_grows_with_charset():
    digits, _ = estimate_entropy("12345678")
    mixed, _ = estimate_entropy("1234Ab!x")
    assert mixed > digits


def test_charset_size_detects_all_classes():
    _, charset = estimate_entropy("aA1!")
    assert charset == 26 + 26 + 10 + 33


def test_common_password_flagged():
    assert "Appears in the common-password list" in find_issues("password")


def test_repeated_chars_flagged():
    assert any("repeated" in issue for issue in find_issues("aaaab1234567"))


def test_sequence_flagged():
    assert any("sequence" in issue for issue in find_issues("abcd!Xy9012"))


def test_digits_only_flagged():
    assert "Digits only" in find_issues("019283746501")


def test_strong_password_has_no_issues():
    assert find_issues("Tr0ub4dour&3xplod3") == []


@pytest.mark.parametrize(
    "password,expected",
    [
        ("password", "WEAK"),
        ("短い1!", "WEAK"),
        ("Gx7#mQ2!pL9vZ4", "STRONG"),
    ],
)
def test_verdicts(password, expected):
    assert audit(password).verdict == expected


def test_compromised_overrides_everything():
    result = AuditResult(length=18, entropy_bits=90, charset_size=95, breached_count=42)
    assert result.verdict == "COMPROMISED"
    assert result.score == 0


def test_parse_breach_response_found():
    # suffix -> count ; the API returns suffixes of the SHA-1 hash
    body = "AAAA1:3\r\nBBBB2:57\r\nCCCC3:0"
    assert _parse_breach_response(body, "BBBB2") == 57


def test_parse_breach_response_not_found():
    body = "AAAA1:3\r\nBBBB2:57"
    assert _parse_breach_response(body, "ZZZZ9") == 0


def test_score_bounds():
    weak = audit("123456")
    assert 0 <= weak.score <= 100
