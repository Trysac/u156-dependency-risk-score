"""CLI entry point for dependency-risk-score."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from dependency_risk_score import RiskError, load_facts, score_all

LEVEL_SEVERITY = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def main(argv: list[str] | None = None) -> int:
    """CLI entry point returning exit code (0: ok, 1: fail threshold reached, 2: error)."""
    parser = argparse.ArgumentParser(
        prog="dependency-risk-score",
        description="Score dependency risk from offline facts file.",
    )
    parser.add_argument("facts_path", help="Path to facts JSON file")
    parser.add_argument("--as-of", required=True, help="Reference date (YYYY-MM-DD)")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Fail if any package reaches or exceeds this risk level",
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code != 0 else 0

    # Parse --as-of date strictly
    as_of_raw = args.as_of
    if len(as_of_raw) != 10 or as_of_raw[4] != "-" or as_of_raw[7] != "-":
        sys.stderr.write(f"Error: Invalid --as-of date format: {as_of_raw[:200]}\n")
        return 2
    try:
        as_of_date = date.fromisoformat(as_of_raw)
    except ValueError:
        sys.stderr.write(f"Error: Invalid --as-of date: {as_of_raw[:200]}\n")
        return 2

    facts_file = Path(args.facts_path)
    if not facts_file.is_file():
        sys.stderr.write(f"Error: Facts file not found: {args.facts_path[:200]}\n")
        return 2

    try:
        content = facts_file.read_text(encoding="utf-8")
        packages = load_facts(content)
        reports = score_all(packages, as_of=as_of_date)
    except RiskError as exc:
        sys.stderr.write(f"Error [{exc.code}]: {str(exc)[:200]}\n")
        return 2
    except Exception as exc:
        sys.stderr.write(f"Error reading facts: {str(exc)[:200]}\n")
        return 2

    if args.format == "json":
        payload = [
            {
                "name": r.name,
                "version": r.version,
                "score": r.score,
                "level": r.level,
                "reasons": list(r.reasons),
            }
            for r in reports
        ]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        for r in reports:
            reasons_str = ",".join(r.reasons)
            sys.stdout.write(f"{r.score} {r.level} {r.name}@{r.version} {reasons_str}\n")

    if args.fail_on is not None:
        threshold = LEVEL_SEVERITY[args.fail_on]
        if any(LEVEL_SEVERITY[r.level] >= threshold for r in reports):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
