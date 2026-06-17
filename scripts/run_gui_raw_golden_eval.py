#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    from ic_copilot.gui_raw_golden_eval import (
        DEFAULT_GUI_RAW_GOLDEN_CASES,
        DEFAULT_GUI_RAW_GOLDEN_OUTPUT_JSON,
        DEFAULT_GUI_RAW_GOLDEN_OUTPUT_MD,
        format_gui_raw_golden_markdown,
        load_gui_raw_golden_cases,
        run_gui_raw_golden_eval,
    )

    parser = argparse.ArgumentParser(description="Run GUI raw Slack paste golden evals for the V2 state-first path.")
    parser.add_argument("--cases", default=str(DEFAULT_GUI_RAW_GOLDEN_CASES))
    parser.add_argument("--output-json", default=str(DEFAULT_GUI_RAW_GOLDEN_OUTPUT_JSON))
    parser.add_argument("--output-md", default=str(DEFAULT_GUI_RAW_GOLDEN_OUTPUT_MD))
    parser.add_argument("--catalog-path", default="local_knowledge/service_catalog.yaml")
    parser.add_argument("--command-registry-path", default="local_knowledge/command_registry.yaml")
    parser.add_argument("--memory-path", default="local_knowledge/decision_moments.jsonl")
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args()

    cases = load_gui_raw_golden_cases(args.cases, root=ROOT)
    report = run_gui_raw_golden_eval(
        cases,
        catalog_path=args.catalog_path,
        command_registry_path=args.command_registry_path,
        memory_path=args.memory_path,
        repeat=args.repeat,
    )

    output_json = Path(args.output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, indent=2, sort_keys=True))

    output_md = Path(args.output_md)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(format_gui_raw_golden_markdown(report))

    print(
        "GUI raw golden eval: "
        f"{report['useful_pass_count']}/{report['total_cases']} useful, "
        f"fallbacks={report['fallback_count']}, "
        f"ask_the_asker={report['ask_the_asker_count']}, "
        f"pseudo_targets={report['pseudo_author_target_count']}"
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
