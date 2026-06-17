#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    from ic_copilot.repo_audit import apply_safe_cleanup, format_repo_audit_markdown, run_repo_audit, save_repo_audit

    parser = argparse.ArgumentParser(description="Audit IC Copilot repo for stale/conflicting runtime paths.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--fail-on-warning", action="store_true")
    parser.add_argument("--include-tests", action="store_true")
    parser.add_argument("--apply-safe-cleanup", action="store_true")
    args = parser.parse_args()

    removed = apply_safe_cleanup(args.root) if args.apply_safe_cleanup else []
    result = run_repo_audit(args.root, include_tests=args.include_tests)
    save_repo_audit(result, args.output_json, args.output_md)
    print(format_repo_audit_markdown(result))
    if removed:
        print(json.dumps({"safe_cleanup_removed": removed}, indent=2))
    if not result.passed:
        return 1
    if args.fail_on_warning and any(finding.severity == "warning" for finding in result.findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
