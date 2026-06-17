#!/usr/bin/env python
from __future__ import annotations

import argparse

from ic_copilot.knowledge_bundle_batch import (
    DEFAULT_REGISTRY_PATH,
    DEFAULT_REPORT_DIR,
    apply_extracted_knowledge_delta,
    format_delta_apply,
    safe_batch_error,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply new approved IC Copilot knowledge bundle deltas.")
    parser.add_argument("extracted_root", help="Directory containing extracted incident bundle folders.")
    parser.add_argument("--knowledge", "--knowledge-dir", dest="knowledge_dir", default="local_knowledge")
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY_PATH))
    parser.add_argument("--report-dir", default=str(DEFAULT_REPORT_DIR))
    parser.add_argument("--dry-run", action="store_true", help="Preview without mutating local_knowledge, registry, or bundle applied/.")
    parser.add_argument("--no-report", action="store_true", help="Do not write batch report files.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    try:
        report = apply_extracted_knowledge_delta(
            args.extracted_root,
            knowledge_dir=args.knowledge_dir,
            registry_path=args.registry,
            report_dir=args.report_dir,
            dry_run=args.dry_run,
            write_report=not args.no_report,
        )
    except Exception as exc:
        print(f"Knowledge bundle delta apply failed: {safe_batch_error(exc)}")
        return 1

    if args.json:
        import json

        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_delta_apply(report))

    counts = report["counts"]
    blocked = counts["blocked_changed_bundles"] + counts["invalid_bundles"]
    return 0 if blocked == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
