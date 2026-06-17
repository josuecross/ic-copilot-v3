from pathlib import Path

from ic_copilot.evals import load_eval_cases, run_eval_suite


CONTRACT = Path("data/contract")


def test_contract_replay_cases_load_from_jsonl():
    cases = load_eval_cases(CONTRACT / "replay_cases.jsonl")
    assert len(cases) >= 8
    assert all(case.incident_file for case in cases)
    assert all(case.expected.phase for case in cases)


def test_contract_replay_suite_passes():
    results = run_eval_suite(
        CONTRACT / "replay_cases.jsonl",
        catalog_path=CONTRACT / "service_catalog.yaml",
        memory_dir=CONTRACT / "decision_moments.jsonl",
        command_registry_path=CONTRACT / "command_registry.yaml",
    )
    assert all(result.passed for result in results), [
        (result.case_id, result.state_scores, result.decision_scores, result.safety_scores, result.final_output)
        for result in results
        if not result.passed
    ]

