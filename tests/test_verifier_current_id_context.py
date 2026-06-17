from ic_copilot.schemas import (
    CurrentIncidentState,
    EntityRef,
    EntityType,
    EvidenceBackedFact,
    EvidenceRef,
    ICDecision,
    ICMove,
    IncidentPhase,
)
from ic_copilot.verifier import verify_ic_decision


def _ref(text: str) -> EvidenceRef:
    return EvidenceRef(event_id="m001", quote=text)


def _decision(text: str, move: ICMove = ICMove.ASK_NEXT_VALIDATION) -> ICDecision:
    return ICDecision(
        decision_id="d1",
        incident_id="INC",
        move=move,
        phase=IncidentPhase.MITIGATION,
        output={"say_this": text},
        grounding=[_ref(text)],
        targets=[],
    )


def test_current_job_id_allowed_in_job_context() -> None:
    state = CurrentIncidentState(
        incident_id="INC",
        phase=IncidentPhase.MITIGATION,
        current_blocker="waiting_on_monitoring",
        monitoring_signals=[
            EvidenceBackedFact(
                value="Transfer Accounting batch 10112 completion",
                evidence=[_ref("Transfer Accounting batch 10112 completed")],
            )
        ],
        compact_summary="Transfer Accounting batch 10112 completed",
    )

    result = verify_ic_decision(
        _decision("Confirm batch 10112 completed cleanly."),
        state,
        catalog=[],
        accepted_memories=[],
        command_registry=[],
    )

    assert result.passed


def test_current_change_id_allowed_as_change_not_tenant() -> None:
    state = CurrentIncidentState(
        incident_id="INC",
        phase=IncidentPhase.ENGAGEMENT,
        current_blocker="waiting_on_deploy",
        monitoring_signals=[EvidenceBackedFact(value="CM 123456 deployment approval", evidence=[_ref("CM 123456 approved")])],
        compact_summary="CM 123456 approved; waiting on deployment",
    )

    result = verify_ic_decision(
        _decision("Engineering, confirm CM 123456 deployment status."),
        state,
        catalog=[],
        accepted_memories=[],
        command_registry=[],
    )

    assert result.passed


def test_url_path_number_called_tenant_is_blocked() -> None:
    state = CurrentIncidentState(
        incident_id="INC",
        rejected_entities=[
            EntityRef(
                entity_type=EntityType.TENANT,
                display_name="123456",
                status="rejected:url_path_number",
                evidence=[_ref("https://jira.local/browse/123456")],
            )
        ],
        links_seen=[],
        compact_summary="Jira link path includes 123456",
    )

    result = verify_ic_decision(
        _decision("Tenant 123456 is impacted."),
        state,
        catalog=[],
        accepted_memories=[],
        command_registry=[],
    )

    assert not result.passed
    assert result.checks["no_fake_tenant"] is False


def test_historical_tenant_leakage_still_blocked() -> None:
    state = CurrentIncidentState(incident_id="INC", compact_summary="Current incident has no tenant ID")
    memory = ICDecision(
        decision_id="d2",
        incident_id="INC",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase=IncidentPhase.INVESTIGATION,
        output={"say_this": "Check tenant 10005051."},
        grounding=[],
        targets=[],
    )

    result = verify_ic_decision(
        memory,
        state,
        catalog=[],
        accepted_memories=[],
        command_registry=[],
    )

    assert not result.passed
    assert result.checks["no_fake_tenant"] is False
