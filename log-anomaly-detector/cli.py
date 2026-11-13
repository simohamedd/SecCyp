#!/usr/bin/env python3
"""Command-line interface for the log anomaly detector.

Examples
--------
    # Scan an SSH auth log for brute-force attempts
    python cli.py --file samples/auth.log

    # Also run impossible-travel detection using an IP geolocation map
    python cli.py --file samples/auth.log --geo samples/geo.json

    # Emit findings as JSON (for piping into other tools)
    python cli.py --file samples/auth.log --json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.detector import analyse, parse_log  # noqa: E402


def _load_geo(path: Path) -> dict[str, tuple[float, float]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {ip: (float(coords[0]), float(coords[1])) for ip, coords in raw.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect anomalies in auth logs (defensive).")
    parser.add_argument("--file", type=Path, required=True, help="auth log file to scan")
    parser.add_argument("--geo", type=Path, help="JSON map of IP -> [lat, lon] for travel checks")
    parser.add_argument("--year", type=int, default=2026, help="year for syslog timestamps")
    parser.add_argument("--threshold", type=int, default=5, help="failed logins to flag as brute force")
    parser.add_argument("--json", action="store_true", help="output findings as JSON")
    args = parser.parse_args(argv)

    lines = args.file.read_text(encoding="utf-8", errors="replace").splitlines()
    events = parse_log(lines, year=args.year)
    ip_locations = _load_geo(args.geo) if args.geo else None
    findings = analyse(events, ip_locations=ip_locations, brute_threshold=args.threshold)

    if args.json:
        payload = []
        for f in findings:
            row = asdict(f)
            row["at"] = f.at.isoformat()
            payload.append(row)
        print(json.dumps(payload, indent=2))
        return 1 if findings else 0

    print(f"Parsed {len(events)} auth events from {args.file}")
    if not findings:
        print("No anomalies detected.")
        return 0

    print(f"\n{len(findings)} finding(s):\n")
    for f in findings:
        marker = {"high": "!!", "medium": "! ", "low": "  "}.get(f.severity, "  ")
        print(f"{marker} [{f.severity.upper()}] {f.kind} — {f.user} from {f.source_ip}")
        print(f"     {f.detail}")
        print(f"     at {f.at.isoformat()}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
