#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    from ic_copilot.holdout_soak import (
        aggregate_live_holdout_soak,
        filter_soak_fixtures,
        format_live_holdout_soak_markdown,
        write_release_readiness_summary,
    )
    from ic_copilot.simplified_product_eval import load_simplified_product_eval_fixtures, run_simplified_product_eval

    parser = argparse.ArgumentParser(description="Run optional live-provider holdout soak evaluation.")
    parser.add_argument("--runs", type=int, default=3, help="Number of live holdout runs to attempt.")
    parser.add_argument("--cases", default="data/holdout/incident_read_holdout_cases.jsonl")
    parser.add_argument("--case-id", help="Optional focused holdout fixture id to run.")
    parser.add_argument("--catalog-path", default="local_knowledge/service_catalog.yaml")
    parser.add_argument("--command-registry-path", default="local_knowledge/command_registry.yaml")
    parser.add_argument("--memory-path", default="local_knowledge/decision_moments.jsonl")
    parser.add_argument("--scripted-report", default=".ic_copilot/knowledge_intake/reports/holdout_scripted_eval.json")
    parser.add_argument("--output-json", default=".ic_copilot/knowledge_intake/reports/latest_live_holdout_soak.json")
    parser.add_argument("--output-md", default=".ic_copilot/knowledge_intake/reports/latest_live_holdout_soak.md")
    parser.add_argument("--release-json", default=".ic_copilot/knowledge_intake/reports/latest_release_readiness.json")
    args = parser.parse_args()

    if args.runs < 1:
        raise SystemExit("--runs must be at least 1")

    fixtures = filter_soak_fixtures(load_simplified_product_eval_fixtures(args.cases), args.case_id)
    reports: list[dict[str, Any]] = []
    run_errors: list[dict[str, Any]] = []
    for run_index in range(1, args.runs + 1):
        print(f"Live holdout soak run {run_index}/{args.runs}...")
        try:
            report = run_simplified_product_eval(
                fixtures,
                live=True,
                catalog_path=args.catalog_path,
                command_registry_path=args.command_registry_path,
                memory_path=args.memory_path,
            )
        except Exception as exc:  # pragma: no cover - network/provider failures are environment-specific.
            run_errors.append({"run_index": run_index, "error": f"{type(exc).__name__}: {exc}"})
            print(f"Live holdout soak run {run_index} failed: {type(exc).__name__}: {exc}")
            continue
        report["_soak_run_index"] = run_index
        reports.append(report)
        print(
            "  useful={}/{} fallbacks={} wrong_owner={} unsafe={}".format(
                report.get("useful_pass_count", 0),
                report.get("total_cases", 0),
                report.get("fallback_count", 0),
                report.get("wrong_owner_count", 0),
                int(report.get("unsafe_action_wording_count", 0)) + int(report.get("fake_entity_count", 0)),
            )
        )

    scripted_report = _load_optional_json(args.scripted_report)
    soak = aggregate_live_holdout_soak(
        reports,
        scripted_report=scripted_report,
        runs_attempted=args.runs,
        run_errors=run_errors,
    )
    if args.case_id:
        soak["focused_case_id"] = args.case_id

    output_json = _default_focused_output(Path(args.output_json), args.case_id, "json")
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(soak, indent=2, sort_keys=True))

    output_md = _default_focused_output(Path(args.output_md), args.case_id, "md")
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(format_live_holdout_soak_markdown(soak))

    release_json = _default_focused_output(Path(args.release_json), args.case_id, "json")
    write_release_readiness_summary(soak, release_json)

    summary = soak["summary"]
    readiness = soak["release_readiness"]
    print(
        "Live holdout soak: completed={}/{} median={} min={} max={} release={}".format(
            soak["runs_completed"],
            soak["runs_attempted"],
            summary["live_useful_median"],
            summary["live_useful_min"],
            summary["live_useful_max"],
            readiness["color"],
        )
    )
    return 0 if soak["runs_completed"] > 0 else 1


def _load_optional_json(path: str) -> dict[str, Any] | None:
    source = Path(path)
    if not source.exists():
        return None
    return json.loads(source.read_text())


def _default_focused_output(path: Path, case_id: str | None, suffix: str) -> Path:
    if not case_id:
        return path
    default_name = f"latest_live_holdout_soak.{suffix}"
    if path.name != default_name:
        return path
    safe_case_id = "".join(char if char.isalnum() or char in {"_", "-"} else "_" for char in case_id)
    return path.with_name(f"latest_live_holdout_soak_{safe_case_id}.{suffix}")


if __name__ == "__main__":
    raise SystemExit(main())
