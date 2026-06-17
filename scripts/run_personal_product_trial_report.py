#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a personal IC Copilot product trial report from local web labels.")
    parser.add_argument("--db", default=".ic_copilot/web.sqlite3")
    parser.add_argument("--output-md", default=".ic_copilot/personal_trial/product_trial_report.md")
    parser.add_argument("--output-json", default=".ic_copilot/personal_trial/product_trial_report.json")
    args = parser.parse_args()

    from ic_copilot.product_trial import write_product_trial_report

    report = write_product_trial_report(args.db, args.output_md, args.output_json)
    print(f"recommendation={report.recommendation}")
    print(f"labeled_snippets={report.labeled_snippets}")
    print(f"report={args.output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
