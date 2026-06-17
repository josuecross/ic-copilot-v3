from __future__ import annotations

from types import SimpleNamespace

from ic_copilot.gui_raw_golden_eval import GuiRawGoldenCase, score_gui_raw_golden_result
from ic_copilot.schemas import ICDecision, ICMove, IncidentPhase, VerifierResult


def test_gui_raw_golden_fails_when_expected_memory_is_not_accepted() -> None:
    case = GuiRawGoldenCase(
        case_id="knowledge-noop",
        raw_paste="Support asks owner to engage.",
        expected_blocker_types=[],
        expected_target_classes=[],
        allowed_targets=[],
        forbidden_targets=[],
        expected_move_families=["engage_owner"],
        must_include_terms=[],
        must_include_any_terms=[],
        must_not_include_terms=[],
        expected_accepted_memory_ids=["DM_expected_memory"],
        allow_no_safe=False,
        manual_acceptance_notes="Knowledge should apply.",
        expected_read={"selected_move": "engage_owner"},
    )
    decision = ICDecision(
        decision_id="d1",
        incident_id="i1",
        move=ICMove.ENGAGE_OWNER,
        phase=IncidentPhase.TRIAGE,
        output={"say_this": "@Owner, can you confirm ownership?"},
    )
    result = {
        "decision": decision,
        "verifier_result": VerifierResult(passed=True, final_status="pass"),
        "trace": SimpleNamespace(safety_summary={}, run_diagnosis={}, accepted_memory_ids=[]),
    }

    scored = score_gui_raw_golden_result(case, result, latency_ms=1)

    assert not scored["passed"]
    assert "missing_accepted_memory:DM_expected_memory" in scored["reasons"]
    assert "missing_accepted_memory_behavior_contracts" in scored["reasons"]


def test_gui_raw_golden_fails_when_model_payload_is_over_cap() -> None:
    case = GuiRawGoldenCase(
        case_id="over-cap",
        raw_paste="Owner shares current status.",
        expected_blocker_types=[],
        expected_target_classes=[],
        allowed_targets=[],
        forbidden_targets=[],
        expected_move_families=["ask_next_validation"],
        must_include_terms=[],
        must_include_any_terms=[],
        must_not_include_terms=[],
        expected_accepted_memory_ids=[],
        allow_no_safe=False,
        manual_acceptance_notes="Payload cap must be enforced before provider call.",
        expected_read={"selected_move": "ask_next_validation"},
    )
    decision = ICDecision(
        decision_id="d1",
        incident_id="i1",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase=IncidentPhase.TRIAGE,
        output={"say_this": "@Owner, can you confirm validation?"},
    )
    result = {
        "decision": decision,
        "verifier_result": VerifierResult(passed=True, final_status="pass"),
        "trace": SimpleNamespace(
            safety_summary={"model_payload_over_cap": True},
            run_diagnosis={},
            accepted_memory_ids=[],
        ),
    }

    scored = score_gui_raw_golden_result(case, result, latency_ms=1)

    assert not scored["passed"]
    assert "model_payload_over_cap" in scored["reasons"]


def test_gui_raw_golden_matches_hyphenated_diagnostic_terms() -> None:
    case = GuiRawGoldenCase(
        case_id="hyphenated-diagnostic",
        raw_paste="Owner shares current RIA signal.",
        expected_blocker_types=[],
        expected_target_classes=[],
        allowed_targets=[],
        forbidden_targets=[],
        expected_move_families=["ask_next_validation"],
        must_include_terms=["connection limit"],
        must_include_any_terms=["Revenue API"],
        must_not_include_terms=[],
        expected_accepted_memory_ids=[],
        allow_no_safe=False,
        manual_acceptance_notes="Hyphenated diagnostics should satisfy spaced eval terms.",
        expected_read={"selected_move": "ask_next_validation"},
    )
    decision = ICDecision(
        decision_id="d1",
        incident_id="i1",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase=IncidentPhase.TRIAGE,
        output={
            "say_this": "@Revenue Integration API, can you confirm the RIA connection-limit signal for Revenue API?"
        },
    )
    result = {
        "decision": decision,
        "verifier_result": VerifierResult(passed=True, final_status="pass"),
        "trace": SimpleNamespace(safety_summary={}, run_diagnosis={}, accepted_memory_ids=[]),
    }

    scored = score_gui_raw_golden_result(case, result, latency_ms=1)

    assert scored["passed"]
