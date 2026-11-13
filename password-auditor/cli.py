#!/usr/bin/env python3
"""Command-line interface for the password auditor.

Examples
--------
    # Audit a single password (prompted, so it never lands in shell history)
    python cli.py

    # Audit a password passed inline, and check it against breach data
    python cli.py --password "correct horse battery staple" --check-breaches

    # Audit a file of passwords, one per line
    python cli.py --file passwords.txt --check-breaches
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.auditor import audit  # noqa: E402

_COLORS = {
    "STRONG": "\033[92m",
    "MODERATE": "\033[93m",
    "WEAK": "\033[91m",
    "COMPROMISED": "\033[91m",
}
_RESET = "\033[0m"


def _fmt(verdict: str, use_colour: bool) -> str:
    if not use_colour:
        return verdict
    return f"{_COLORS.get(verdict, '')}{verdict}{_RESET}"


def _report(label: str, password: str, check_breaches: bool, use_colour: bool) -> str:
    result = audit(password, check_breaches=check_breaches)
    lines = [
        f"[{label}]",
        f"  verdict      : {_fmt(result.verdict, use_colour)}  (score {result.score}/100)",
        f"  length       : {result.length}",
        f"  entropy      : {result.entropy_bits} bits (charset {result.charset_size})",
    ]
    if result.breached_count is not None:
        if result.breached_count:
            lines.append(f"  breaches     : seen {result.breached_count:,} times — DO NOT USE")
        else:
            lines.append("  breaches     : not found in known breach data")
    if result.issues:
        lines.append("  issues       :")
        lines.extend(f"    - {issue}" for issue in result.issues)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit password strength (defensive).")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--password", help="password to audit (avoid on shared machines)")
    group.add_argument("--file", type=Path, help="file of passwords, one per line")
    parser.add_argument(
        "--check-breaches",
        action="store_true",
        help="check against HaveIBeenPwned using k-anonymity (needs network)",
    )
    parser.add_argument("--no-colour", action="store_true", help="disable coloured output")
    args = parser.parse_args(argv)

    use_colour = sys.stdout.isatty() and not args.no_colour

    try:
        if args.file:
            passwords = [
                line.rstrip("\n")
                for line in args.file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            for i, pw in enumerate(passwords, 1):
                print(_report(f"line {i}", pw, args.check_breaches, use_colour))
                print()
        else:
            pw = args.password or getpass.getpass("Password to audit (hidden): ")
            print(_report("password", pw, args.check_breaches, use_colour))
    except KeyboardInterrupt:  # pragma: no cover
        print("\nCancelled.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
