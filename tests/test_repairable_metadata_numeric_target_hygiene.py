from __future__ import annotations

from ic_copilot.blocker_reselection import select_authoritative_blocker
from ic_copilot.decision_metadata import normalize_decision_expiration, only_expiration_failed
from ic_copilot.evidence_quality import classify_events_quality
from ic_copilot.incident_brief import build_allowed_targets
from ic_copilot.normalizers.slack_paste import normalize_slack_paste
from ic_copilot.schemas import (
    AllowedTarget,
    BriefQualityResult,
    CleanTurn,
    CleanTurnLedger,
    CurrentIncidentState,
    EvidenceBackedFact,
    EvidenceRef,
    ICDecision,
    ICMove,
    ImpactState,
    IncidentBrief,
    IncidentBriefBlocker,
    IncidentBriefFocus,
    IncidentBriefValue,
    IncidentEvent,
    IncidentPhase,
    SemanticQuality,
)
from ic_copilot.semantic_read import ParallelSemanticReadResult
from ic_copilot.verifier import verify_ic_decision


def _event(event_id: str, author: str, message: str, *, sequence: int = 1, is_bot: bool = False) -> IncidentEvent:
    return IncidentEvent(
        event_id=event_id,
        incident_id="repairable-metadata",
        sequence=sequence,
        author=author,
        message=message,
        extracted_tokens={"is_bot": is_bot},
        hash=event_id,
    )


def test_expiration_only_failure_is_deterministically_repairable() -> None:
    event = _event("m001", "Jose", "Monitoring DB load and worker pod metrics now.")
    allowed = [
        AllowedTarget(
            target_id="t001",
            display_name="Jose",
            target_type="person",
            source="slack_author",
            role_hint="technical_investigator",
            targetable=True,
            target_quality="high",
            evidence_ids=["m001"],
            source_event_kind="human_validation_or_monitoring",
        )
    ]
    brief = IncidentBrief(
        incident_id="repairable-metadata",
        based_on_event_ids=["m001"],
        latest_window_event_ids=["m001"],
        current_summary="Monitoring is active on DB load and pod metrics.",
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, confidence=0.8, evidence_ids=["m001"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="monitoring_needed",
            summary="Need latest monitoring signal for DB load and pod metrics.",
            evidence_ids=["m001"],
            confidence=0.8,
        ),
        recommended_ic_focus=IncidentBriefFocus(
            summary="Ask Jose for latest monitoring signal.",
            preferred_target_ids=["t001"],
            acceptable_move_types=[ICMove.REQUEST_MONITORING_SIGNAL],
            evidence_ids=["m001"],
        ),
    )
    decision = ICDecision(
        decision_id="d",
        incident_id="repairable-metadata",
        move=ICMove.REQUEST_MONITORING_SIGNAL,
        phase=IncidentPhase.INVESTIGATION,
        target_ids=["t001"],
        output={
            "say_this": "Monitoring is active; we need the latest signal.",
            "next_line": "Jose, can you share the latest DB load and worker pod metrics?",
        },
        grounding=[EvidenceRef(event_id="m001", quote=event.message)],
        expiration="2024-12-31T23:59:59Z",
    )

    first = verify_ic_decision(
        decision,
        CurrentIncidentState(incident_id="repairable-metadata"),
        [],
        [],
        incident_brief=brief,
        allowed_targets=allowed,
        semantic_quality=SemanticQuality(status="sufficient", can_plan=True, can_render_normal_recommendation=True),
        incident_brief_quality=BriefQualityResult(passed=True, status="high"),
        event_quality=classify_events_quality([event]),
    )
    assert only_expiration_failed(first.checks)

    repaired, changed, reason = normalize_decision_expiration(decision)
    assert changed
    assert reason == "past_expiration"
    assert repaired.output == decision.output
    assert repaired.move == decision.move
    assert repaired.target_ids == decision.target_ids

    second = verify_ic_decision(
        repaired,
        CurrentIncidentState(incident_id="repairable-metadata"),
        [],
        [],
        incident_brief=brief,
        allowed_targets=allowed,
        semantic_quality=SemanticQuality(status="sufficient", can_plan=True, can_render_normal_recommendation=True),
        incident_brief_quality=BriefQualityResult(passed=True, status="high"),
        event_quality=classify_events_quality([event]),
    )
    assert second.passed


def test_numeric_evidence_classifies_ticket_tenant_url_and_metric_contexts() -> None:
    events = normalize_slack_paste(
        "Adrian: Zendesk proactive outreach ticket #585592 created.\n"
        "tenant id 30000080 is confirmed in current evidence.\n"
        "Docs link https://wiki.example.test/pages/9863631/details\n"
        "ORA-06512 line 14637\n",
        incident_id="numeric-contexts",
    )
    numbers = {
        item["value"]: item["numeric_evidence_kind"]
        for event in events
        for item in (event.extracted_tokens or {}).get("numbers", [])
    }
    assert numbers["585592"] == "ticket_id"
    assert numbers["30000080"] == "tenant_id"
    assert numbers["9863631"] == "url_path_number"
    assert numbers["14637"] == "metric_count_version"

    state = CurrentIncidentState(
        incident_id="numeric-contexts",
        compact_summary="Zendesk proactive outreach ticket #585592 created. ORA-06512 line 14637.",
        impact=ImpactState(
            affected_tenants=[
                EvidenceBackedFact(
                    value="30000080",
                    evidence=[EvidenceRef(event_id="m001", quote="tenant id 30000080 is confirmed")],
                )
            ]
        ),
    )
    ticket_decision = ICDecision(
        decision_id="ticket",
        incident_id="numeric-contexts",
        move=ICMove.REQUEST_STATUS_OR_ETA,
        phase=IncidentPhase.INVESTIGATION,
        output={"say_this": "Zendesk ticket #585592 is created.", "next_line": "Can the active owner share the next status?"},
        grounding=[EvidenceRef(event_id="m001", quote="Zendesk proactive outreach ticket #585592 created.")],
    )
    ticket_result = verify_ic_decision(ticket_decision, state, [], [])
    assert not any("585592" in claim and "tenant/account" in claim for claim in ticket_result.blocked_claims)

    ora_decision = ticket_decision.model_copy(
        update={
            "decision_id": "ora",
            "output": {"say_this": "ORA-06512 line 14637 is visible.", "next_line": "Can the active owner share status?"},
            "grounding": [EvidenceRef(event_id="m001", quote="ORA-06512 line 14637")],
        }
    )
    ora_result = verify_ic_decision(ora_decision, state, [], [])
    assert not any("14637" in claim and "tenant/account" in claim for claim in ora_result.blocked_claims)

    url_decision = ticket_decision.model_copy(
        update={
            "decision_id": "url",
            "output": {"say_this": "Tenant 9863631 appears impacted.", "next_line": "Can the active owner share status?"},
            "grounding": [EvidenceRef(event_id="m001", quote="Docs link https://wiki.example.test/pages/9863631/details")],
        }
    )
    url_result = verify_ic_decision(url_decision, state, [], [])
    assert any("9863631" in claim and "tenant/account" in claim for claim in url_result.blocked_claims)


def test_section_headers_environment_labels_and_broadcasts_are_not_targets() -> None:
    events = normalize_slack_paste(
        "Jose\n"
        "10:00 AM\n"
        "Checking DB load now.\n"
        "Current Status:\n"
        "Heavy Database Load:\n"
        "Next Actions:\n"
        "Issue:\n"
        "Actions Taken:\n"
        "ERROR:\n"
        "AP PROD:\n"
        "Prod05:\n"
        "CSBX0003:\n"
        "@here please note the status update.\n",
        incident_id="target-hygiene",
    )
    targets = build_allowed_targets(events, [], [])
    targetable_names = {target.display_name for target in targets if target.targetable}
    rejected_names = {target.display_name for target in targets if not target.targetable}

    assert "Jose" in targetable_names
    assert "here" not in targetable_names
    assert "here" in rejected_names
    forbidden = {
        "Current Status",
        "Heavy Database Load",
        "Next Actions",
        "Issue",
        "Actions Taken",
        "ERROR",
        "AP PROD",
        "Prod05",
        "CSBX0003",
    }
    assert forbidden.isdisjoint(targetable_names)


def test_later_human_confirmation_supersedes_waiting_customer_confirmation() -> None:
    events = [
        _event("m001", "Default_Agent", "Awaiting customer confirmation from the affected customer.", sequence=1, is_bot=True),
        _event(
            "m002",
            "Utsav",
            "Got reply from the customer: they are deleting account data this week, asking if we can stop the process.",
            sequence=2,
        ),
    ]
    targets = build_allowed_targets(events, [], [])
    semantic_read = ParallelSemanticReadResult(
        clean_turn_ledger=CleanTurnLedger(
            incident_id="supersession",
            clean_turns=[
                CleanTurn(
                    turn_id="turn-002",
                    speaker="Utsav",
                    speaker_type="human",
                    event_ids=["m002"],
                    message_type="answer",
                    summary="Got reply from the customer that they are deleting account data; asking if we can stop the process.",
                )
            ],
        ),
        errors={},
    )
    brief = IncidentBrief(
        incident_id="supersession",
        based_on_event_ids=["m001", "m002"],
        latest_window_event_ids=["m001", "m002"],
        current_summary="Awaiting customer confirmation from the affected customer.",
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, confidence=0.7, evidence_ids=["m001"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="validation_needed",
            summary="Awaiting customer confirmation from the affected customer.",
            evidence_ids=["m001"],
            confidence=0.8,
        ),
        recommended_ic_focus=IncidentBriefFocus(summary="Ask for customer confirmation.", evidence_ids=["m001"]),
    )

    selection, repaired, repaired_quality = select_authoritative_blocker(
        brief=brief,
        brief_quality=BriefQualityResult(passed=True, status="high"),
        semantic_quality=SemanticQuality(status="sufficient", can_plan=True, can_render_normal_recommendation=True),
        semantic_read=semantic_read,
        events=events,
        event_quality=classify_events_quality(events),
        allowed_targets=targets,
    )

    assert selection.status == "repaired"
    assert selection.selected_evidence_ids == ["m002"]
    assert repaired.latest_blocker.blocker_type == "mitigation_status_needed"
    assert "Awaiting customer confirmation" not in repaired.latest_blocker.summary
    assert any(item.intent == "ask_customer_confirmation" for item in repaired.do_not_ask)
    assert repaired_quality.passed
