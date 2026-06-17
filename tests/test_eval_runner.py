from pathlib import Path

from ic_copilot.evals import load_eval_cases, run_eval_suite, score_eval_result
from ic_copilot.schemas import ICDecision, ICMove, IncidentPhase, ReplayEvalCase, VerifierResult


def test_loads_eval_cases():
    cases = load_eval_cases(Path("data/sample/eval_cases"))
    assert {case.case_id for case in cases} >= {"revpro_early_engage", "fake_atlassian_customer"}


def test_loads_contract_fixture_root():
    cases = load_eval_cases(Path("data/contract"))
    assert len(cases) >= 8
    assert all(case.incident_file for case in cases)


def test_eval_suite_produces_pass_fail_report_objects():
    results = run_eval_suite(Path("data/sample/eval_cases"))
    assert results
    assert all(result.case_id for result in results)


def test_safety_failures_fail_eval():
    case = ReplayEvalCase(
        case_id="bad",
        incident_id="bad",
        title="bad",
        expected={
            "phase": "triage",
            "blocker_type": "missing_impact",
            "acceptable_moves": ["ask_impact"],
            "forbidden_entities": ["Atlassian"],
        },
    )
    decision = ICDecision(
        decision_id="d1",
        incident_id="bad",
        move=ICMove.ASK_IMPACT,
        phase=IncidentPhase.TRIAGE,
        output={"say_this": "Atlassian customer is impacted."},
    )
    scored = score_eval_result(
        case,
        {
            "state": type("S", (), {"phase": "triage", "current_blocker": "missing_impact"})(),
            "decision": decision,
            "final_output": "Atlassian customer is impacted.",
            "verifier_result": VerifierResult(
                passed=False,
                final_status="fallback_required",
                blocked_claims=["fake customer"],
            ),
        },
    )
    assert not scored.passed
