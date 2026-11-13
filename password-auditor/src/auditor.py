"""Core auditing logic for password strength.

Everything here is pure and side-effect free (except the optional breach
check, which makes a single HTTPS request using k-anonymity). Keeping the
logic pure makes it trivial to unit test.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Optional

try:  # requests is optional; the offline checks work without it.
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore


# Character-class sizes used for the entropy estimate.
_CLASSES = (
    (re.compile(r"[a-z]"), 26),
    (re.compile(r"[A-Z]"), 26),
    (re.compile(r"[0-9]"), 10),
    (re.compile(r"[^a-zA-Z0-9]"), 33),  # printable ASCII symbols
)

# A tiny sample of the most common passwords. In a real deployment you would
# load a full list (e.g. rockyou). Kept short here so the repo stays small.
_COMMON = {
    "123456", "password", "123456789", "12345678", "qwerty", "abc123",
    "football", "monkey", "letmein", "111111", "iloveyou", "admin",
    "welcome", "login", "princess", "dragon", "passw0rd", "master",
}

_SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop")


@dataclass
class AuditResult:
    """The outcome of auditing a single password."""

    length: int
    entropy_bits: float
    charset_size: int
    issues: list[str] = field(default_factory=list)
    breached_count: Optional[int] = None  # None => not checked

    @property
    def verdict(self) -> str:
        if self.breached_count:
            return "COMPROMISED"
        if self.entropy_bits < 28 or self.issues:
            return "WEAK"
        if self.entropy_bits < 60:
            return "MODERATE"
        return "STRONG"

    @property
    def score(self) -> int:
        """A 0-100 convenience score for dashboards/UI."""
        if self.breached_count:
            return 0
        base = min(self.entropy_bits / 80.0, 1.0) * 100
        base -= len(self.issues) * 10
        return max(0, min(100, round(base)))


def estimate_entropy(password: str) -> tuple[float, int]:
    """Estimate entropy in bits and the effective character-set size.

    Uses the standard ``length * log2(charset)`` model. This is an *upper
    bound* on strength; the pattern checks below catch cases where the real
    guessability is far lower than the entropy suggests.
    """
    if not password:
        return 0.0, 0
    charset = sum(size for pattern, size in _CLASSES if pattern.search(password))
    charset = charset or 1
    entropy = len(password) * math.log2(charset)
    return round(entropy, 2), charset


def find_issues(password: str) -> list[str]:
    """Return a list of human-readable weaknesses."""
    issues: list[str] = []
    lower = password.lower()

    if len(password) < 12:
        issues.append("Shorter than 12 characters")
    if lower in _COMMON:
        issues.append("Appears in the common-password list")
    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains a character repeated 3+ times in a row")
    for seq in _SEQUENCES:
        for i in range(len(seq) - 3):
            chunk = seq[i : i + 4]
            if chunk in lower or chunk[::-1] in lower:
                issues.append("Contains a keyboard/alphabet sequence")
                break
        else:
            continue
        break
    if re.fullmatch(r"\d+", password):
        issues.append("Digits only")
    if re.fullmatch(r"[a-zA-Z]+", password):
        issues.append("Letters only")
    return issues


def check_breach(password: str, *, timeout: float = 6.0) -> int:
    """Return how many times the password appears in known breaches.

    Uses the HaveIBeenPwned range API with k-anonymity: only the first five
    characters of the SHA-1 hash are ever sent. The full hash — and therefore
    the password — never leaves this machine.
    """
    if requests is None:  # pragma: no cover
        raise RuntimeError("The 'requests' package is required for breach checks")

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    resp = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        timeout=timeout,
        headers={"Add-Padding": "true"},
    )
    resp.raise_for_status()
    return _parse_breach_response(resp.text, suffix)


def _parse_breach_response(body: str, suffix: str) -> int:
    """Parse the HIBP range response body and return the count for ``suffix``."""
    for line in body.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix.strip().upper() == suffix:
            try:
                return int(count)
            except ValueError:
                return 0
    return 0


def audit(password: str, *, check_breaches: bool = False) -> AuditResult:
    """Run the full audit on a single password."""
    entropy, charset = estimate_entropy(password)
    result = AuditResult(
        length=len(password),
        entropy_bits=entropy,
        charset_size=charset,
        issues=find_issues(password),
    )
    if check_breaches:
        result.breached_count = check_breach(password)
    return result
