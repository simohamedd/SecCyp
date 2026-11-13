#!/usr/bin/env python3
"""Command-line interface for the file integrity monitor.

Workflow
--------
    # 1. Take a baseline of a directory you trust right now
    python cli.py baseline /etc --out etc.baseline.json

    # 2. Later, check for tampering against that baseline
    python cli.py check /etc --baseline etc.baseline.json

``check`` exits 0 when nothing changed and 1 when it finds changes, so it
drops straight into cron or a CI pipeline.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.fim import diff, load_baseline, save_baseline, scan_tree  # noqa: E402


def _cmd_baseline(args: argparse.Namespace) -> int:
    root = Path(args.path)
    baseline = scan_tree(root)
    save_baseline(baseline, Path(args.out), root=root)
    print(f"Baseline written to {args.out} ({len(baseline)} files hashed).")
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    root = Path(args.path)
    baseline = load_baseline(Path(args.baseline))
    current = scan_tree(root)
    changes = diff(baseline, current)

    if changes.clean:
        print(f"OK — no changes against {args.baseline} ({len(current)} files).")
        return 0

    print(f"CHANGES DETECTED against {args.baseline}:\n")
    for label, items in (
        ("created", changes.created),
        ("modified", changes.modified),
        ("deleted", changes.deleted),
    ):
        for item in items:
            symbol = {"created": "+", "modified": "~", "deleted": "-"}[label]
            print(f"  {symbol} {label:<8} {item}")
    print(
        f"\n{len(changes.created)} created, "
        f"{len(changes.modified)} modified, "
        f"{len(changes.deleted)} deleted."
    )
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="File integrity monitor (defensive).")
    sub = parser.add_subparsers(dest="command", required=True)

    p_base = sub.add_parser("baseline", help="record a baseline of a directory")
    p_base.add_argument("path", help="directory to baseline")
    p_base.add_argument("--out", default="fim.baseline.json", help="where to write the baseline")
    p_base.set_defaults(func=_cmd_baseline)

    p_check = sub.add_parser("check", help="check a directory against a baseline")
    p_check.add_argument("path", help="directory to check")
    p_check.add_argument("--baseline", required=True, help="baseline file to compare against")
    p_check.set_defaults(func=_cmd_check)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
