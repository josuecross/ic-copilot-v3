from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from ic_copilot.clean_context import extract_clean_incident_context
from ic_copilot.decision_repair import repair_blocked_decision
from ic_copilot.incident_loader import load_incident_events
from ic_copilot.input_processing import assess_input_size
from ic_copilot.llm.fixture_client import FixtureLLMClient
from ic_copilot.pipeline import run_pipeline
from ic_copilot.planner import plan_ic_decision
from ic_copilot.schemas import (
    CleanIncidentContext,
    CurrentIncidentState,
    EntityRef,
    EntityType,
    EvidenceBackedFact,
    EvidenceRef,
    ICDecision,
    ICMove,
    IncidentPhase,
    RoleCandidate,
    SharpBlockerAssessment,
    SlackConversationTurn,
    SlackTurnReconstruction,
)
from ic_copilot.slack_turns import reconstruct_slack_turns, should_reconstruct_turns
from ic_copilot.verifier import verify_ic_decision


API_504_FIXTURE = "data/personal_regression/incidents/p3_api_504_revenue_timeout_static.txt"


def _collapsed_long_paste() -> str:
    turns = [
        "Reporter 10:00 AM - customer is seeing errors in the application",
        "Engineer 10:01 AM - I am checking logs now",
        "Engineer 10:02 AM - logs show connection limit errors",
        "Reporter 10:03 AM - validation is still running",
        "zsrebot APP 10:04 AM - created channel lifecycle message",
        "Engineer 10:05 AM - task restarted after health checks failed",
        "Reporter 10:06 AM - still validating customer result",
        "IC 10:07 AM - please keep updates coming",
    ]
    return "\n".join(turns * 55)


class _TurnClient:
    def __init__(self) -> None:
        self.clean_payload = None

    def generate_json(self, prompt_name: str, input_payload: dict, response_model: type[BaseModel]):
        if response_model is SlackTurnReconstruction or response_model.__name__ == "SlackTurnReconstruction":
            return SlackTurnReconstruction(
                incident_id=input_payload["incident_id"],
                source_event_ids=[event["event_id"] for event in input_payload["events"]],
                turns=[
                    SlackConversationTurn(
                        turn_id="t001",
                        speaker="Engineer",
                        speaker_type="human",
                        text="I am checking logs now.",
                        source_event_ids=[input_payload["events"][0]["event_id"]],
                        confidence=0.8,
                    )
                ],
            )
        if response_model is CleanIncidentContext or response_model.__name__ == "CleanIncidentContext":
            self.clean_payload = input_payload
            return CleanIncidentContext(
                incident_id=input_payload["incident_id"],
                based_on_event_ids=[event["event_id"] for event in input_payload["events"]],
                clean_summary="clean",
            )
        raise NotImplementedError


def test_turn_reconstruction_triggers_for_collapsed_long_paste() -> None:
    raw_text = _collapsed_long_paste()
    events = load_incident_events(Path(API_504_FIXTURE), incident_id="normal_reference")[:1]
    assessment = assess_input_size(raw_text, events)
    assert should_reconstruct_turns(raw_text, events, assessment)
    reconstruction, warnings = reconstruct_slack_turns(
        raw_text=raw_text,
        events=events,
        assessment=assessment,
        incident_id="collapsed",
        llm_client=_TurnClient(),
    )
    assert not warnings
    assert reconstruction is not None
    assert reconstruction.turns[0].speaker == "Engineer"


def test_turn_reconstruction_not_triggered_for_normal_small_paste() -> None:
    raw_text = Path(API_504_FIXTURE).read_text()
    events = load_incident_events(API_504_FIXTURE)
    assessment = assess_input_size(raw_text, events)
    assert not should_reconstruct_turns(raw_text, events, assessment)


def test_clean_context_receives_reconstructed_turns() -> None:
    client = _TurnClient()
    events = load_incident_events(API_504_FIXTURE)[:1]
    reconstruction = SlackTurnReconstruction(
        incident_id="i",
        source_event_ids=["m001"],
        turns=[
            SlackConversationTurn(
                turn_id="t001",
                speaker="Engineer",
                speaker_type="human",
                text="checking logs",
                source_event_ids=["m001"],
            )
        ],
    )
    extract_clean_incident_context(
        "Engineer 10:01 AM - checking logs",
        events,
        CurrentIncidentState(incident_id="i"),
        client,
        reconstructed_turns=reconstruction,
        input_size_assessment=assess_input_size("Engineer 10:01 AM - checking logs", events),
    )
    assert client.clean_payload is not None
    assert client.clean_payload["reconstructed_turns"]["turns"][0]["speaker"] == "Engineer"


def test_api_504_role_assessment_and_pipeline_output() -> None:
    result = run_pipeline(
        API_504_FIXTURE,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=FixtureLLMClient(),
    )
    sharp = result["sharp_blocker_assessment"]
    assert sharp is None
    assert result["trace"].processing_strategy in {"incident_read_and_whisper", "incident_read_and_whisper_v2"}
    output = result["final_output"]
    output_lower = output.lower()
    assert "sriram" in output_lower
    assert "monitoring signal" in output_lower
    assert "504" in output_lower
    assert "root cause" not in output_lower
    assert "page team revenue" not in output_lower
    assert "9863631" not in output_lower
    assert "fix status" not in output_lower or output_lower.index("sriram") < output_lower.index("fix status")


def test_premature_rca_and_wrong_reporter_target_are_blocked_and_repaired() -> None:
    state = CurrentIncidentState(
        incident_id="role",
        phase=IncidentPhase.MONITORING,
        current_blocker="waiting_on_monitoring",
        severity=EvidenceBackedFact(value="P3", evidence=[EvidenceRef(event_id="m001")]),
        engaged_entities=[
            EntityRef(entity_type=EntityType.PERSON, display_name="Sriram", status="actively_working", evidence=[EvidenceRef(event_id="m010", quote="checking logs")]),
            EntityRef(entity_type=EntityType.PERSON, display_name="Aditya", status="asked", evidence=[EvidenceRef(event_id="m020", quote="can you validate now")]),
        ],
        monitoring_signals=[
            EvidenceBackedFact(value="application validation and system stability", evidence=[EvidenceRef(event_id="m021")])
        ],
        compact_summary="Technical investigator is checking logs; reporter is validating application result.",
    )
    sharp = SharpBlockerAssessment(
        incident_id="role",
        phase=IncidentPhase.MONITORING,
        blocker_type="waiting_on_monitoring",
        blocker_summary="Validation/status after technical investigation is unresolved.",
        confidence=0.8,
        technical_status_targets=["Sriram"],
        customer_or_reporter_validation_targets=["Aditya"],
        should_not_target_for_fix_status=["Aditya"],
        role_candidates=[
            RoleCandidate(name="Sriram", role_type="technical_investigator", status="actively_working", evidence_ids=["m010"]),
            RoleCandidate(name="Aditya", role_type="reporter_validator", status="validating", evidence_ids=["m020"]),
        ],
        recommended_move_families=[ICMove.ASK_NEXT_VALIDATION],
        recommended_ask_slots=["system stability", "application validation"],
    )
    bad = ICDecision(
        decision_id="bad",
        incident_id="role",
        move=ICMove.REQUEST_STATUS_OR_ETA,
        phase=IncidentPhase.MONITORING,
        output={
            "say_this": "Aditya, can you provide the current fix status and root cause analysis?",
        },
        grounding=[EvidenceRef(event_id="m020")],
    )
    verifier = verify_ic_decision(bad, state, [], [], sharp_blocker_assessment=sharp)
    assert not verifier.checks["no_premature_rca"]
    assert not verifier.checks["role_target_aligned"]
    repaired = repair_blocked_decision(bad, verifier, state, [], [], [], sharp)
    assert repaired is not None
    repaired_text = " ".join(str(value) for value in repaired.output.values()).lower()
    assert "sriram" in repaired_text
    assert "aditya" in repaired_text
    assert "root cause" not in repaired_text
    assert verify_ic_decision(repaired, state, [], [], sharp_blocker_assessment=sharp).passed


def test_generic_no_clear_output_with_role_targets_is_repaired() -> None:
    state = CurrentIncidentState(
        incident_id="role",
        phase=IncidentPhase.MONITORING,
        current_blocker="waiting_on_monitoring",
        engaged_entities=[
            EntityRef(entity_type=EntityType.PERSON, display_name="Engineer", status="actively_working", evidence=[EvidenceRef(event_id="m010")]),
            EntityRef(entity_type=EntityType.PERSON, display_name="Validator", status="asked", evidence=[EvidenceRef(event_id="m020")]),
        ],
        monitoring_signals=[
            EvidenceBackedFact(value="service stability and application validation", evidence=[EvidenceRef(event_id="m021")])
        ],
        stale_question_intents=["validate_customer_application"],
        compact_summary="Engineer is checking service stability; validator is checking application result.",
    )
    sharp = SharpBlockerAssessment(
        incident_id="role",
        phase=IncidentPhase.MONITORING,
        blocker_type="waiting_on_monitoring",
        blocker_summary="Validation/status after technical investigation is unresolved.",
        confidence=0.8,
        technical_status_targets=["Engineer"],
        customer_or_reporter_validation_targets=["Validator"],
        should_not_target_for_fix_status=["Validator"],
        role_candidates=[
            RoleCandidate(name="Engineer", role_type="technical_investigator", status="actively_working", evidence_ids=["m010"]),
            RoleCandidate(name="Validator", role_type="reporter_validator", status="validating", evidence_ids=["m020"]),
        ],
        recommended_move_families=[ICMove.REQUEST_MONITORING_SIGNAL],
        recommended_ask_slots=["system stability", "application validation"],
    )
    bad = ICDecision(
        decision_id="bad-generic",
        incident_id="role",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase=IncidentPhase.MONITORING,
        output={
            "say_this": "We have no clear next validation or status question at this time. No new validation or status questions are needed.",
        },
        grounding=[EvidenceRef(event_id="m021")],
    )
    verifier = verify_ic_decision(bad, state, [], [], sharp_blocker_assessment=sharp)
    assert not verifier.checks["not_too_generic"]
    assert any("missing actionable next line" in claim for claim in verifier.blocked_claims)
    repaired = repair_blocked_decision(bad, verifier, state, [], [], [], sharp)
    assert repaired is not None
    repaired_text = " ".join(str(value) for value in repaired.output.values()).lower()
    assert "engineer" in repaired_text
    assert "validator" in repaired_text
    assert "no clear" not in repaired_text
    assert verify_ic_decision(repaired, state, [], [], sharp_blocker_assessment=sharp).passed


def test_generic_role_targeting_planner_cases() -> None:
    fixtures = [
        "data/personal_regression/incidents/generic_technical_owner_and_reporter_split.txt",
        "data/personal_regression/incidents/generic_reporter_only_validation.txt",
        "data/personal_regression/incidents/generic_owner_active_no_repage.txt",
    ]
    for fixture in fixtures:
        assert Path(fixture).exists()

    state = CurrentIncidentState(
        incident_id="generic",
        phase=IncidentPhase.MONITORING,
        current_blocker="waiting_on_monitoring",
        engaged_entities=[
            EntityRef(entity_type=EntityType.PERSON, display_name="Engineer", status="actively_working", evidence=[EvidenceRef(event_id="m002", quote="checking logs")]),
            EntityRef(entity_type=EntityType.PERSON, display_name="Reporter", status="asked", evidence=[EvidenceRef(event_id="m004", quote="validation still running")]),
        ],
        monitoring_signals=[EvidenceBackedFact(value="error rate and application validation", evidence=[EvidenceRef(event_id="m003")])],
    )
    sharp = SharpBlockerAssessment(
        incident_id="generic",
        phase=IncidentPhase.MONITORING,
        blocker_type="waiting_on_monitoring",
        blocker_summary="Need technical stability and reporter validation.",
        technical_status_targets=["Engineer"],
        customer_or_reporter_validation_targets=["Reporter"],
        should_not_target_for_fix_status=["Reporter"],
        role_candidates=[
            RoleCandidate(name="Engineer", role_type="technical_investigator", status="actively_working"),
            RoleCandidate(name="Reporter", role_type="reporter_validator", status="validating"),
        ],
        recommended_move_families=[ICMove.ASK_NEXT_VALIDATION],
        recommended_ask_slots=["system stability", "application validation"],
    )
    decision = plan_ic_decision(state, [], [], llm_client=None, sharp_blocker_assessment=sharp)
    text = " ".join(str(value) for value in decision.output.values()).lower()
    assert "engineer" in text and "reporter" in text
    assert "root cause" not in text and "page" not in text


def test_phase131_no_regression_specific_branching_in_product_modules() -> None:
    terms = (
        "sriram",
        "aditya",
        "trimble",
        "semrush",
        "srerev-1864",
        "ria-sandbox-rest",
        "elb health",
        "504 gateway",
        "revenue engineering",
        "revpro support",
    )
    product_paths = [
        "src/ic_copilot/clean_context.py",
        "src/ic_copilot/extractor.py",
        "src/ic_copilot/planner.py",
        "src/ic_copilot/verifier.py",
        "src/ic_copilot/semantic_intent.py",
        "src/ic_copilot/sharp_blocker.py",
        "src/ic_copilot/pipeline.py",
        "src/ic_copilot/llm/prompts.py",
    ]
    offenders: list[str] = []
    for path in product_paths:
        text = Path(path).read_text(errors="replace").lower()
        offenders.extend(f"{path}:{term}" for term in terms if term in text)
    assert offenders == []
