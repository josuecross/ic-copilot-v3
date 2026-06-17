#!/usr/bin/env python
from __future__ import annotations

import argparse

from ic_copilot.knowledge_bundle import apply_approved_knowledge_bundle, format_apply_result


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply reviewed IC Copilot knowledge bundle records.")
    parser.add_argument("bundle", help="Path to .ic_copilot/knowledge_intake/extracted/<incident_slug>/")
    parser.add_argument("--knowledge-dir", default="local_knowledge", help="Runtime local_knowledge folder to update.")
    parser.add_argument("--dry-run", action="store_true", help="Validate and stage the apply without writing local_knowledge.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    result = apply_approved_knowledge_bundle(args.bundle, knowledge_dir=args.knowledge_dir, dry_run=args.dry_run)
    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        print(format_apply_result(result))
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
