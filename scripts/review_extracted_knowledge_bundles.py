#!/usr/bin/env python
from __future__ import annotations

import argparse

from ic_copilot.knowledge_bundle_batch import (
    DEFAULT_REPORT_DIR,
    format_batch_review,
    review_extracted_knowledge_bundles,
    safe_batch_error,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Review all extracted IC Copilot knowledge bundles.")
    parser.add_argument("extracted_root", help="Directory containing extracted incident bundle folders.")
    parser.add_argument("--knowledge", "--knowledge-dir", dest="knowledge_dir", default="local_knowledge")
    parser.add_argument("--report-dir", default=str(DEFAULT_REPORT_DIR))
    parser.add_argument("--no-report", action="store_true", help="Do not write batch report files.")
    parser.add_argument("--require-review-approved", action="store_true")
    parser.add_argument(
        "--compile",
        action="store_true",
        help="Compile untrusted extracted/proposed notes into codex_review/ and reviewed/ records before validating.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    try:
        report = review_extracted_knowledge_bundles(
            args.extracted_root,
            knowledge_dir=args.knowledge_dir,
            require_review_approved=args.require_review_approved,
            compile_before_review=args.compile,
            report_dir=args.report_dir,
            write_report=not args.no_report,
        )
    except Exception as exc:
        print(f"Knowledge bundle batch review failed: {safe_batch_error(exc)}")
        return 1

    if args.json:
        import json

        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_batch_review(report))
    return 0 if report["counts"]["invalid_bundles"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
