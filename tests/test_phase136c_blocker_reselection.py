from __future__ import annotations

from ic_copilot.blocker_reselection import select_authoritative_blocker
from ic_copilot.evidence_quality import assess_semantic_quality, classify_events_quality, validate_incident_brief_quality
from ic_copilot.incident_brief import build_allowed_targets
from ic_copilot.normalizers.slack_paste import normalize_slack_paste
from ic_copilot.schemas import (
    ActorLedgerItem,
    ActorWorkstreamLedger,
    BriefQualityResult,
    CurrentIncidentState,
    ICDecision,
    ICMove,
    IncidentBrief,
    IncidentBriefBlocker,
    IncidentBriefFocus,
    IncidentBriefValue,
    IncidentEvent,
    IncidentPhase,
    SemanticQuality,
    WorkstreamLedgerItem,
)
from ic_copilot.semantic_read import ParallelSemanticReadResult
from ic_copilot.verifier import verify_ic_decision


def _event(event_id: str, author: str, message: str, *, is_bot: bool = False, sequence: int = 1) -> IncidentEvent:
    return IncidentEvent(
        event_id=event_id,
        incident_id="phase136c",
        sequence=sequence,
        author=author,
        message=message,
        extracted_tokens={"is_bot": is_bot},
        hash=event_id,
    )


def test_bad_preview_blocker_repairs_from_active_workstream() -> None:
    events = [
        _event("m001", "Rajesh", "I am checking duplicate line failures now.", sequence=1),
        _event("m002", "PagerDuty", "Incident in PagerDuty Preview in Slack\nStatus Triggered\nRefresh", is_bot=True, sequence=2),
    ]
    targets = build_allowed_targets(events, [], [])
    semantic = ParallelSemanticReadResult(
        actor_workstream_ledger=ActorWorkstreamLedger(
            incident_id="phase136c",
            actors=[
                ActorLedgerItem(
                    name="Rajesh",
                    actor_type="person",
                    role_hint="technical_investigator",
                    current_status="actively_working",
                    evidence_ids=["m001"],
                    targetable=True,
                )
            ],
            workstreams=[
                WorkstreamLedgerItem(
                    type="investigation",
                    status="in_progress",
                    owner_or_actor_names=["Rajesh"],
                    summary="Rajesh is actively checking the current duplicate line failure.",
                    evidence_ids=["m001"],
                )
            ],
        ),
        errors={},
    )
    semantic_quality = assess_semantic_quality(semantic, events, targets)
    brief = IncidentBrief(
        incident_id="phase136c",
        based_on_event_ids=["m001", "m002"],
        latest_window_event_ids=["m001", "m002"],
        current_summary="Duplicate line failure investigation is active.",
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, confidence=0.7, evidence_ids=["m001"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="status_eta_needed",
            summary="Incident in PagerDuty Preview in Slack Status Triggered Refresh",
            evidence_ids=["m002"],
            confidence=0.8,
        ),
        recommended_ic_focus=IncidentBriefFocus(summary="Ask for status", evidence_ids=["m002"]),
    )
    original_quality = validate_incident_brief_quality(brief, events, targets, semantic_quality)

    selection, repaired, repaired_quality = select_authoritative_blocker(
        brief=brief,
        brief_quality=original_quality,
        semantic_quality=semantic_quality,
        semantic_read=semantic,
        events=events,
        event_quality=classify_events_quality(events),
        allowed_targets=targets,
    )

    assert original_quality.passed is False
    assert selection.status == "repaired"
    assert selection.source == "actor_workstream_ledger"
    assert repaired.latest_blocker.evidence_ids == ["m001"]
    assert repaired_quality.passed
    assert repaired.recommended_ic_focus.preferred_target_ids


def test_no_safe_fallback_fails_after_valid_blocker_repair() -> None:
    events = [
        _event("m001", "Rajesh", "I am checking duplicate line failures now.", sequence=1),
        _event("m002", "PagerDuty", "Incident in PagerDuty Preview in Slack\nStatus Triggered\nRefresh", is_bot=True, sequence=2),
    ]
    targets = build_allowed_targets(events, [], [])
    semantic = ParallelSemanticReadResult(
        actor_workstream_ledger=ActorWorkstreamLedger(
            incident_id="phase136c",
            workstreams=[
                WorkstreamLedgerItem(
                    type="investigation",
                    status="in_progress",
                    owner_or_actor_names=["Rajesh"],
                    summary="Rajesh is actively checking the current duplicate line failure.",
                    evidence_ids=["m001"],
                )
            ],
        ),
        errors={},
    )
    semantic_quality = assess_semantic_quality(semantic, events, targets)
    brief = IncidentBrief(
        incident_id="phase136c",
        based_on_event_ids=["m001", "m002"],
        latest_window_event_ids=["m001", "m002"],
        current_summary="Duplicate line failure investigation is active.",
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, confidence=0.7, evidence_ids=["m001"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="status_eta_needed",
            summary="Incident in PagerDuty Preview in Slack Status Triggered Refresh",
            evidence_ids=["m002"],
            confidence=0.8,
        ),
    )
    original_quality = validate_incident_brief_quality(brief, events, targets, semantic_quality)

    selection, repaired, repaired_quality = select_authoritative_blocker(
        brief=brief,
        brief_quality=original_quality,
        semantic_quality=semantic_quality,
        semantic_read=semantic,
        events=events,
        event_quality=classify_events_quality(events),
        allowed_targets=targets,
    )
    decision = ICDecision(
        decision_id="fallback",
        incident_id="phase136c",
        move=ICMove.NO_SAFE_RECOMMENDATION,
        phase=IncidentPhase.INVESTIGATION,
        output={"say_this": "I do not have a safe, grounded next move yet."},
        confidence=0.2,
    )
    result = verify_ic_decision(
        decision=decision,
        current_state=CurrentIncidentState(incident_id="phase136c"),
        catalog=[],
        accepted_memories=[],
        incident_brief=repaired,
        allowed_targets=targets,
        semantic_quality=semantic_quality,
        incident_brief_quality=repaired_quality,
        event_quality=classify_events_quality(events),
    )

    assert selection.status == "repaired"
    assert repaired_quality.passed
    assert result.passed is False
    assert result.checks["not_too_generic"] is False


def test_preview_only_cannot_repair_and_no_safe_fallback_passes() -> None:
    events = [_event("m001", "PagerDuty", "Incident in PagerDuty Preview in Slack\nStatus Triggered", is_bot=True)]
    targets = build_allowed_targets(events, [], [])
    semantic = ParallelSemanticReadResult(
        actor_workstream_ledger=ActorWorkstreamLedger(incident_id="phase136c"),
        errors={},
    )
    semantic_quality = SemanticQuality(status="insufficient", can_plan=False, can_render_normal_recommendation=False)
    brief = IncidentBrief(
        incident_id="phase136c",
        based_on_event_ids=["m001"],
        latest_window_event_ids=["m001"],
        current_summary="Incident in PagerDuty Preview in Slack",
        phase=IncidentBriefValue(primary=IncidentPhase.UNKNOWN, confidence=0.0),
        latest_blocker=IncidentBriefBlocker(blocker_type="unknown"),
    )
    original_quality = BriefQualityResult(passed=False, status="invalid", blocked_reasons=["latest blocker is unknown"])

    selection, repaired, repaired_quality = select_authoritative_blocker(
        brief=brief,
        brief_quality=original_quality,
        semantic_quality=semantic_quality,
        semantic_read=semantic,
        events=events,
        event_quality=classify_events_quality(events),
        allowed_targets=targets,
    )
    decision = ICDecision(
        decision_id="fallback",
        incident_id="phase136c",
        move=ICMove.NO_SAFE_RECOMMENDATION,
        phase=IncidentPhase.UNKNOWN,
        output={"say_this": "I do not have a safe, grounded next move yet."},
        confidence=0.2,
    )
    result = verify_ic_decision(
        decision=decision,
        current_state=CurrentIncidentState(incident_id="phase136c"),
        catalog=[],
        accepted_memories=[],
        incident_brief=repaired,
        allowed_targets=targets,
        semantic_quality=semantic_quality,
        incident_brief_quality=repaired_quality,
        event_quality=classify_events_quality(events),
    )

    assert selection.status == "insufficient"
    assert repaired_quality.passed is False
    assert result.passed


def test_policy_id_team_name_normalizes_and_policy_option_rejected() -> None:
    events = normalize_slack_paste(
        "Rajesh\n"
        "10:01 AM\n"
        "Please route this to P0YZCXI Zuora Revenue Engineering.\n"
        "zsrebot\n"
        "10:02 AM\n"
        "- PP7TK37 Revenue Reporting (Legacy): Escalation Policy\n",
        incident_id="policy-normalize",
    )
    targets = build_allowed_targets(events, [], [])
    names = {target.display_name: target for target in targets}

    assert "P0YZCXI Zuora Revenue Engineering" not in names
    assert "Zuora Revenue Engineering" in names
    assert names["Zuora Revenue Engineering"].targetable
    assert all("PP7TK37" not in target.display_name or not target.targetable for target in targets)


def test_lifecycle_only_actor_is_not_high_quality_target() -> None:
    events = normalize_slack_paste(
        "Srinidhi was added to the channel by zsrebot\n"
        "Rajesh\n"
        "10:03 AM\n"
        "Checking the current failure now.\n",
        incident_id="lifecycle-only",
    )
    targets = build_allowed_targets(events, [], [])
    srinidhi = [target for target in targets if target.display_name == "Srinidhi"]
    assert not srinidhi or all(target.target_quality != "high" for target in srinidhi)
