#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    from ic_copilot.catalog import load_command_registry, load_service_catalog
    from ic_copilot.evals import load_eval_cases
    from ic_copilot.memory import load_decision_moments
    from ic_copilot.simplified_product_eval import load_simplified_product_eval_fixtures

    contract = ROOT / "data" / "contract"
    required = [
        contract / "service_catalog.yaml",
        contract / "command_registry.yaml",
        contract / "decision_moments.jsonl",
        contract / "replay_cases.jsonl",
        contract / "incidents",
        contract / "expected",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        print("Missing contract fixture paths:")
        for path in missing:
            print(f"  {path}")
        return 1

    catalog = load_service_catalog(contract / "service_catalog.yaml")
    registry = load_command_registry(contract / "command_registry.yaml", catalog)
    moments = load_decision_moments(contract / "decision_moments.jsonl")
    cases = load_eval_cases(contract / "replay_cases.jsonl")
    simplified_cases = load_simplified_product_eval_fixtures(ROOT / "data/sample/simplified_product_eval_cases.jsonl")

    for case in cases:
        if case.incident_file and not Path(case.incident_file).exists():
            raise AssertionError(f"{case.case_id} missing incident file: {case.incident_file}")
        if case.expected_state_file and not Path(case.expected_state_file).exists():
            raise AssertionError(f"{case.case_id} missing expected state file: {case.expected_state_file}")
        if case.expected_decision_file and not Path(case.expected_decision_file).exists():
            raise AssertionError(f"{case.case_id} missing expected decision file: {case.expected_decision_file}")

    for expected in sorted((contract / "expected").glob("*.json")):
        json.loads(expected.read_text())

    print(
        "OK: "
        f"{len(catalog)} catalog entries, "
        f"{len(registry)} command registry entries, "
        f"{len(moments)} decision moments, "
        f"{len(cases)} replay cases, "
        f"{len(simplified_cases)} simplified product eval cases"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
