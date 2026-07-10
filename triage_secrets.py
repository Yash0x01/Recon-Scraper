#!/usr/bin/env python3
"""
Triage helper: pulls high-confidence, deduplicated secret findings out of a
recon-scraper JSON report so you're not manually scanning hundreds of rows.

Usage:
    python triage_secrets.py reports/chess.com_20260703_100134.json
    python triage_secrets.py reports/chess.com_20260703_100134.json --confidence medium
"""

import argparse
import json
import sys
from collections import defaultdict


def main():
    p = argparse.ArgumentParser()
    p.add_argument("report", help="Path to a recon-scraper JSON report")
    p.add_argument("--confidence", choices=["high", "medium", "all"], default="high",
                    help="Minimum confidence to show (default: high)")
    args = p.parse_args()

    with open(args.report, encoding="utf-8") as f:
        data = json.load(f)

    secrets = data["findings"]["secrets"]

    if args.confidence != "all":
        secrets = [s for s in secrets if s["confidence"] == args.confidence]

    # Dedupe by (type, value_preview) — the same masked token often shows up
    # across many pages/JS files that all load the same bundle.
    grouped = defaultdict(list)
    for s in secrets:
        key = (s["type"], s["value_preview"])
        grouped[key].append(s["source"])

    if not grouped:
        print(f"No '{args.confidence}' confidence secrets found.")
        return

    print(f"{len(grouped)} unique finding(s) at '{args.confidence}' confidence "
          f"(from {len(secrets)} raw hits):\n")

    for (secret_type, preview), sources in sorted(grouped.items()):
        print(f"[{secret_type}] {preview}")
        print(f"  seen in {len(sources)} location(s), e.g.:")
        for src in sources[:3]:
            print(f"    - {src}")
        if len(sources) > 3:
            print(f"    ... and {len(sources) - 3} more")
        print()


if __name__ == "__main__":
    main()
