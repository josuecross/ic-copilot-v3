#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    from ic_copilot.evals import format_eval_report, run_eval_suite

    contract = ROOT / "data" / "contract"
    results = run_eval_suite(
        contract / "replay_cases.jsonl",
        catalog_path=contract / "service_catalog.yaml",
        memory_dir=contract / "decision_moments.jsonl",
        command_registry_path=contract / "command_registry.yaml",
    )
    print(format_eval_report(results))
    return 0 if all(result.passed for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
