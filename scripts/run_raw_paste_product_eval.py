#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    from ic_copilot.raw_paste_product_eval import (
        DEFAULT_FULL_AUDIT_JSON,
        DEFAULT_FULL_AUDIT_MD,
        DEFAULT_RAW_PASTE_FIXTURE_PATH,
        DEFAULT_RAW_PASTE_OUTPUT_JSON,
        DEFAULT_RAW_PASTE_OUTPUT_MD,
        format_full_product_audit_markdown,
        format_raw_paste_product_eval_markdown,
        full_audit_report,
        load_raw_paste_product_eval_fixtures,
        run_raw_paste_product_eval,
    )

    parser = argparse.ArgumentParser(description="Run the raw Slack paste product reliability eval.")
    parser.add_argument("--fixtures", "--cases", dest="fixtures", default=str(DEFAULT_RAW_PASTE_FIXTURE_PATH))
    parser.add_argument("--output-json", default=str(DEFAULT_RAW_PASTE_OUTPUT_JSON))
    parser.add_argument("--output-md", default=str(DEFAULT_RAW_PASTE_OUTPUT_MD))
    parser.add_argument("--audit-json", default=str(DEFAULT_FULL_AUDIT_JSON))
    parser.add_argument("--audit-md", default=str(DEFAULT_FULL_AUDIT_MD))
    parser.add_argument("--catalog-path", default="local_knowledge/service_catalog.yaml")
    parser.add_argument("--command-registry-path", default="local_knowledge/command_registry.yaml")
    parser.add_argument("--memory-path", default="local_knowledge/decision_moments.jsonl")
    args = parser.parse_args()

    fixtures = load_raw_paste_product_eval_fixtures(args.fixtures)
    report = run_raw_paste_product_eval(
        fixtures,
        catalog_path=args.catalog_path,
        command_registry_path=args.command_registry_path,
        memory_path=args.memory_path,
    )

    output_json = Path(args.output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, indent=2, sort_keys=True))

    output_md = Path(args.output_md)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(format_raw_paste_product_eval_markdown(report))

    audit = full_audit_report(report)
    audit_json = Path(args.audit_json)
    audit_json.parent.mkdir(parents=True, exist_ok=True)
    audit_json.write_text(json.dumps(audit, indent=2, sort_keys=True))

    audit_md = Path(args.audit_md)
    audit_md.parent.mkdir(parents=True, exist_ok=True)
    audit_md.write_text(format_full_product_audit_markdown(audit))

    print(
        "Raw paste product eval: "
        f"{report['useful_pass_count']}/{report['total_cases']} useful, "
        f"fallbacks={report['fallback_count']}, "
        f"wrong_target_class={report['wrong_target_class_count']}, "
        f"diagnostic_dropped={report['diagnostic_evidence_dropped_count']}"
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
