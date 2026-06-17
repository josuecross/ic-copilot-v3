from __future__ import annotations

from pathlib import Path

from ic_copilot.clean_context import extract_clean_incident_context
from ic_copilot.decision_repair import repair_blocked_decision
from ic_copilot.incident_loader import load_incident_events
from ic_copilot.llm.fixture_client import FixtureLLMClient
from ic_copilot.pipeline import run_pipeline
from ic_copilot.schemas import (
    CurrentIncidentState,
    EvidenceRef,
    GroundedOwnerCandidate,
    ICDecision,
    ICMove,
    IncidentPhase,
    SharpBlockerAssessment,
    VisibleWorkstream,
)
from ic_copilot.sharp_blocker import assess_sharp_blocker
from ic_copilot.verifier import verify_ic_decision


RPCAPD_FIXTURE = "data/personal_regression/incidents/p3_rpcapd_billing_disk_full_static.txt"
HOTFIX_FIXTURE = "data/personal_regression/incidents/generic_hotfix_eta_visible.txt"
QUEUE_FIXTURE = "data/personal_regression/incidents/generic_queue_isolation_no_improvement.txt"
TRUST_FIXTURE = "data/personal_regression/incidents/generic_trust_post_answered_no_need.txt"


class _CaptureSharpBlockerClient(FixtureLLMClient):
    def __init__(self) -> None:
        self.payload = None

    def generate_json(self, prompt_name, input_payload, response_model):
        if prompt_name == "sharp_blocker_assessment":
            self.payload = input_payload
            return {
                "incident_id": input_payload["incident_id"],
                "based_on_event_ids": ["m001"],
                "phase": "investigation",
                "blocker_type": "mitigation_status_or_validation",
                "blocker_summary": "Mitigation status needs confirmation.",
                "confidence": 0.8,
                "evidence_ids": ["m001"],
                "visible_workstreams": [
                    {
                        "workstream_type": "mitigation",
                        "summary": "Mitigation work is visible.",
                        "status": "in_progress",
                        "owner_candidates": ["Engineer"],
                        "evidence_ids": ["m001"],
                        "unsafe_to_execute": True,
                    }
                ],
                "recommended_move_families": ["request_status_or_eta", "ask_next_validation"],
                "recommended_ask_slots": ["mitigation status", "validation signal"],
                "no_invention_constraints": ["do not invent owners"],
            }
        return super().generate_json(prompt_name, input_payload, response_model)


def _run_fixture(path: str):
    return run_pipeline(
        path,
        catalog_path="data/product_knowledge_example/service_catalog.yaml",
        command_registry_path="data/product_knowledge_example/command_registry.yaml",
        memory_path="data/product_knowledge_example/decision_moments.jsonl",
        save_trace=False,
        llm_client=FixtureLLMClient(),
    )


def test_sharp_blocker_schema_validates_general_workstream() -> None:
    assessment = SharpBlockerAssessment(
        incident_id="i1",
        based_on_event_ids=["m001"],
        phase=IncidentPhase.INVESTIGATION,
        blocker_type="rollback_or_disable_status",
        blocker_summary="Rollback was requested and validation is not confirmed.",
        evidence_ids=["m001"],
        visible_workstreams=[
            VisibleWorkstream(
                workstream_type="rollback_or_disable",
                summary="Rollback requested.",
                status="requested_not_confirmed",
                evidence_ids=["m001"],
                unsafe_to_execute=True,
            )
        ],
        recommended_move_families=[ICMove.REQUEST_STATUS_OR_ETA, ICMove.ASK_NEXT_VALIDATION],
        recommended_ask_slots=["rollback status", "validation signal"],
    )
    assert assessment.blocker_type == "rollback_or_disable_status"
    assert assessment.visible_workstreams[0].unsafe_to_execute


def test_sharp_blocker_prompt_payload_includes_clean_context_and_state() -> None:
    events = load_incident_events(RPCAPD_FIXTURE, incident_id="p3_rpcapd")
    client = _CaptureSharpBlockerClient()
    state = CurrentIncidentState(incident_id="p3_rpcapd", current_blocker="missing_validation")
    context = extract_clean_incident_context(Path(RPCAPD_FIXTURE).read_text(), events, state, client)
    assessment = assess_sharp_blocker(context, state, [], client)
    assert assessment.blocker_type == "mitigation_status_or_validation"
    assert client.payload is not None
    assert "clean_context" in client.payload
    assert "current_state" in client.payload


def test_rpcapd_fixture_uses_operational_blocker_not_customer_comms() -> None:
    result = _run_fixture(RPCAPD_FIXTURE)
    output = result["final_output"].lower()
    sharp = result["trace"].sharp_blocker_assessment
    assert sharp is None
    assert result["trace"].processing_strategy in {"incident_read_and_whisper", "incident_read_and_whisper_v2"}
    assert result["verifier_result"].passed
    assert result["decision"].move in {
        ICMove.REQUEST_STATUS_OR_ETA,
        ICMove.REQUEST_MITIGATION_OPTION,
        ICMove.ASK_NEXT_VALIDATION,
    }
    assert "customer communications" not in output
    assert "trust post" not in output
    assert any(term in output for term in ("rollback", "disable", "mitigation", "validation", "affected scope"))
    assert "truncate" not in output
    assert "ssh " not in output


def test_verifier_blocks_customer_comms_when_sharp_blocker_is_mitigation() -> None:
    assessment = SharpBlockerAssessment(
        incident_id="i1",
        blocker_type="mitigation_status_or_validation",
        blocker_summary="Mitigation status and validation are visible.",
        recommended_move_families=[ICMove.REQUEST_STATUS_OR_ETA],
    )
    decision = ICDecision(
        decision_id="d1",
        incident_id="i1",
        move=ICMove.CONFIRM_CUSTOMER_COMMS,
        phase=IncidentPhase.INVESTIGATION,
        output={
            "say_this": "Please confirm the current status of customer communications for this issue.",
            "next_line": "Do we need a customer-facing update?",
        },
        grounding=[EvidenceRef(event_id="m001", quote="mitigation is being checked")],
    )
    result = verify_ic_decision(
        decision,
        CurrentIncidentState(incident_id="i1", phase=IncidentPhase.INVESTIGATION, current_blocker="missing_validation"),
        catalog=[],
        accepted_memories=[],
        command_registry=[],
        sharp_blocker_assessment=assessment,
    )
    assert not result.passed
    assert not result.checks["sharp_blocker_aligned"]
    assert any("output_asks_wrong_blocker" in claim for claim in result.blocked_claims)


def test_verifier_allows_confirming_rollback_status_but_blocks_execution_wording() -> None:
    assessment = SharpBlockerAssessment(
        incident_id="i1",
        blocker_type="rollback_or_disable_status",
        blocker_summary="Rollback status needs confirmation.",
        recommended_move_families=[ICMove.REQUEST_STATUS_OR_ETA],
    )
    state = CurrentIncidentState(incident_id="i1", phase=IncidentPhase.INVESTIGATION, current_blocker="missing_validation")
    allowed = ICDecision(
        decision_id="d-ok",
        incident_id="i1",
        move=ICMove.REQUEST_STATUS_OR_ETA,
        phase=IncidentPhase.INVESTIGATION,
        output={"say_this": "Active owner, can you confirm rollback status and validation signal?"},
    )
    assert verify_ic_decision(allowed, state, [], [], [], sharp_blocker_assessment=assessment).passed
    blocked = ICDecision(
        decision_id="d-block",
        incident_id="i1",
        move=ICMove.REQUEST_MITIGATION_OPTION,
        phase=IncidentPhase.INVESTIGATION,
        output={"say_this": "Please truncate /var/log/messages and rollback the change now."},
    )
    result = verify_ic_decision(blocked, state, [], [], [], sharp_blocker_assessment=assessment)
    assert not result.passed
    assert any("unsafe executable action wording" in claim for claim in result.blocked_claims)


def test_generic_hotfix_eta_asks_release_blocker_not_customer_comms() -> None:
    result = _run_fixture(HOTFIX_FIXTURE)
    output = result["final_output"].lower()
    assert result["verifier_result"].passed
    assert "hotfix eta" in output or "hotfix" in output
    assert "release blocker" in output
    assert "customer communications" not in output


def test_no_safe_with_clear_sharp_blocker_repairs_to_useful_eta_ask() -> None:
    state = CurrentIncidentState(
        incident_id="i1",
        phase=IncidentPhase.INVESTIGATION,
        current_blocker="waiting_on_code_fix",
        compact_summary="Code fix/hotfix is in progress; ETA and release blockers are not confirmed.",
    )
    assessment = SharpBlockerAssessment(
        incident_id="i1",
        blocker_type="waiting_on_code_fix",
        blocker_summary="Hotfix ETA and release blockers need confirmation.",
        active_owner_candidates=[
            GroundedOwnerCandidate(
                name="Engineer",
                entity_type="person",
                source="current_evidence",
                status="actively_working",
                evidence_ids=["m001"],
            )
        ],
        recommended_move_families=[ICMove.REQUEST_STATUS_OR_ETA],
        recommended_ask_slots=["code-fix status", "ETA", "release blockers"],
    )
    original = ICDecision(
        decision_id="d-no-safe",
        incident_id="i1",
        move=ICMove.NO_SAFE_RECOMMENDATION,
        phase=IncidentPhase.INVESTIGATION,
        output={"say_this": "I do not have a safe, grounded next move yet."},
    )
    verifier_result = verify_ic_decision(original, state, [], [], [], sharp_blocker_assessment=assessment)
    repaired = repair_blocked_decision(original, verifier_result, state, [], [], [], assessment)
    assert repaired is not None
    output = " ".join(str(value) for value in repaired.output.values()).lower()
    assert repaired.move == ICMove.REQUEST_STATUS_OR_ETA
    assert "eta" in output
    assert "release blocker" in output
    assert verify_ic_decision(repaired, state, [], [], [], sharp_blocker_assessment=assessment).passed


def test_generic_queue_isolation_asks_next_mitigation_or_validation_signal() -> None:
    result = _run_fixture(QUEUE_FIXTURE)
    output = result["final_output"].lower()
    assert result["verifier_result"].passed
    assert result["decision"].move in {ICMove.REQUEST_STATUS_OR_ETA, ICMove.REQUEST_MITIGATION_OPTION, ICMove.ASK_NEXT_VALIDATION}
    assert "queue" in output
    assert "validation" in output or "mitigation" in output
    assert "customer communications" not in output


def test_generic_trust_post_answered_no_need_does_not_ask_trust_post_again() -> None:
    result = _run_fixture(TRUST_FIXTURE)
    output = result["final_output"].lower()
    assert result["verifier_result"].passed
    assert "trust post" not in output or "no need" in output or "not needed" in output
    assert "validation" in output or "mitigation" in output


def test_product_runtime_does_not_branch_on_rpcapd_regression_terms() -> None:
    forbidden = ("rpcapd", "extrahop", "billing tomcat", "balaji", "vinod", "csbx0001", "cm-31348")
    product_paths = [
        Path("src/ic_copilot/clean_context.py"),
        Path("src/ic_copilot/extractor.py"),
        Path("src/ic_copilot/planner.py"),
        Path("src/ic_copilot/verifier.py"),
        Path("src/ic_copilot/semantic_intent.py"),
        Path("src/ic_copilot/sharp_blocker.py"),
        Path("src/ic_copilot/pipeline.py"),
        Path("src/ic_copilot/llm/prompts.py"),
    ]
    offenders = []
    for path in product_paths:
        text = path.read_text().lower()
        offenders.extend(f"{path}:{term}" for term in forbidden if term in text)
    assert offenders == []
