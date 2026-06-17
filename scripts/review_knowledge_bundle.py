#!/usr/bin/env python
from __future__ import annotations

import argparse

from ic_copilot.knowledge_bundle import format_bundle_validation, validate_knowledge_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an untrusted IC Copilot knowledge bundle.")
    parser.add_argument("bundle", help="Path to .ic_copilot/knowledge_intake/extracted/<incident_slug>/")
    parser.add_argument("--knowledge-dir", default="local_knowledge", help="Runtime local_knowledge folder for duplicate checks.")
    parser.add_argument("--require-review-approved", action="store_true", help="Require reviewed/review.yaml to be approved.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    result = validate_knowledge_bundle(
        args.bundle,
        knowledge_dir=args.knowledge_dir,
        require_review_approved=args.require_review_approved,
    )
    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        print(format_bundle_validation(result))
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
