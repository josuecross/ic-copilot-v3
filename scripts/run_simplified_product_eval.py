#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    from ic_copilot.simplified_product_eval import (
        DEFAULT_FIXTURE_PATH,
        DEFAULT_OUTPUT_JSON,
        DEFAULT_OUTPUT_MD,
        format_simplified_product_eval_markdown,
        load_simplified_product_eval_fixtures,
        run_simplified_product_eval,
    )

    parser = argparse.ArgumentParser(description="Run the simplified IncidentReadAndWhisper product eval gate.")
    parser.add_argument(
        "--fixtures",
        "--cases",
        dest="fixtures",
        default=str(DEFAULT_FIXTURE_PATH),
        help="JSONL simplified product eval fixtures.",
    )
    parser.add_argument("--output-json", default=str(DEFAULT_OUTPUT_JSON))
    parser.add_argument("--output-md", default=str(DEFAULT_OUTPUT_MD))
    parser.add_argument("--live", action="store_true", help="Use configured product provider instead of scripted eval reads.")
    parser.add_argument("--catalog-path", default="data/contract/service_catalog.yaml")
    parser.add_argument("--command-registry-path", default="data/contract/command_registry.yaml")
    parser.add_argument("--memory-path", default="data/contract/decision_moments.jsonl")
    args = parser.parse_args()

    fixtures = load_simplified_product_eval_fixtures(args.fixtures)
    report = run_simplified_product_eval(
        fixtures,
        live=args.live,
        catalog_path=args.catalog_path,
        command_registry_path=args.command_registry_path,
        memory_path=args.memory_path,
    )

    output_json = Path(args.output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, indent=2, sort_keys=True))

    output_md = Path(args.output_md)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(format_simplified_product_eval_markdown(report))

    print(
        "Simplified product eval: "
        f"{report['useful_pass_count']}/{report['total_cases']} useful, "
        f"fallbacks={report['fallback_count']}, wrong_owner={report['wrong_owner_count']}, "
        f"mode={report['mode']}"
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
