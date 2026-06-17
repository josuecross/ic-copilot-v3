from __future__ import annotations

from ic_copilot.blocker_reselection import select_authoritative_blocker
from ic_copilot.decision_output import lint_manual_copy_output
from ic_copilot.evidence_quality import classify_events_quality
from ic_copilot.incident_brief import build_allowed_targets, build_target_shortlist, state_delta_from_incident_brief
from ic_copilot.normalizers.slack_paste import normalize_slack_paste
from ic_copilot.schemas import (
    AllowedTarget,
    BriefQualityResult,
    ICDecision,
    ICMove,
    IncidentBrief,
    IncidentBriefBlocker,
    IncidentBriefFocus,
    IncidentBriefRejectedOrNoise,
    IncidentBriefValue,
    IncidentBriefWorkstream,
    IncidentEvent,
    IncidentPhase,
    SemanticQuality,
)
from ic_copilot.semantic_read import ParallelSemanticReadResult, build_fallback_workstream_ledger


def _event(event_id: str, author: str, message: str, *, sequence: int = 1, is_bot: bool = False) -> IncidentEvent:
    return IncidentEvent(
        event_id=event_id,
        incident_id="latest-human-supersession",
        sequence=sequence,
        author=author,
        message=message,
        extracted_tokens={"is_bot": is_bot, "is_system": False},
        hash=event_id,
    )


def test_latest_human_supersedes_summary_blocker_without_clean_turn_ledger() -> None:
    events = [
        _event("m001", "Default_Agent", "Next Actions: Awaiting customer confirmation from customer operations.", sequence=1, is_bot=True),
        _event(
            "m002",
            "Utsav",
            "Got reply from the customer; they have been deleting account data this week. Asking if we can stop the process.",
            sequence=2,
        ),
    ]
    targets = build_allowed_targets(events, [], [])
    brief = IncidentBrief(
        incident_id="latest-human-supersession",
        based_on_event_ids=["m001", "m002"],
        latest_window_event_ids=["m001", "m002"],
        current_summary="Awaiting customer confirmation from customer operations.",
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, confidence=0.7, evidence_ids=["m001"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="validation_needed",
            summary="Awaiting customer confirmation from customer operations.",
            evidence_ids=["m001"],
            confidence=0.8,
        ),
        recommended_ic_focus=IncidentBriefFocus(summary="Ask for customer confirmation.", evidence_ids=["m001"]),
    )

    selection, repaired, repaired_quality = select_authoritative_blocker(
        brief=brief,
        brief_quality=BriefQualityResult(passed=True, status="high"),
        semantic_quality=SemanticQuality(status="sufficient", can_plan=True, can_render_normal_recommendation=True),
        semantic_read=ParallelSemanticReadResult(errors={}),
        events=events,
        event_quality=classify_events_quality(events),
        allowed_targets=targets,
    )

    assert selection.status == "repaired"
    assert selection.stale_blocker_superseded is True
    assert selection.superseding_event_ids == ["m002"]
    assert repaired.latest_blocker.blocker_type == "mitigation_status_needed"
    assert "Awaiting customer confirmation" not in repaired.latest_blocker.summary
    assert any(item.intent == "ask_customer_confirmation" for item in repaired.do_not_ask)
    assert repaired_quality.passed


def test_latest_stop_pause_action_reselects_even_when_summary_says_monitoring() -> None:
    events = [
        _event("m001", "Coordinator", "Teams continue monitoring cluster and event latency.", sequence=1),
        _event("m002", "Utsav", "Got reply from the customer; asking if we can stop the process.", sequence=2),
    ]
    targets = build_allowed_targets(events, [], [])
    brief = IncidentBrief(
        incident_id="latest-stop-pause",
        based_on_event_ids=["m001", "m002"],
        latest_window_event_ids=["m001", "m002"],
        current_summary="Teams continue monitoring cluster and event latency.",
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, confidence=0.7, evidence_ids=["m001"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="monitoring_needed",
            summary="Teams continue monitoring cluster and event latency.",
            evidence_ids=["m001"],
            confidence=0.8,
        ),
        recommended_ic_focus=IncidentBriefFocus(summary="Ask for monitoring status.", evidence_ids=["m001"]),
    )

    selection, repaired, repaired_quality = select_authoritative_blocker(
        brief=brief,
        brief_quality=BriefQualityResult(passed=True, status="high"),
        semantic_quality=SemanticQuality(status="sufficient", can_plan=True, can_render_normal_recommendation=True),
        semantic_read=ParallelSemanticReadResult(errors={}),
        events=events,
        event_quality=classify_events_quality(events),
        allowed_targets=targets,
    )

    assert selection.status == "repaired"
    assert selection.superseding_event_ids == ["m002"]
    assert repaired.latest_blocker.blocker_type == "mitigation_status_needed"
    assert repaired.recommended_ic_focus.preferred_target_ids
    assert repaired_quality.passed


def test_fallback_workstream_builder_when_actor_reader_fails() -> None:
    events = normalize_slack_paste(
        "Utsav\n"
        "8:09 PM\n"
        "Got reply from the customer; they have been deleting customer account data. Asking if we can stop the process.\n"
        "Hajime Watanabe\n"
        "8:11 PM\n"
        "Are they doing same activity on sandboxes as well?\n",
        incident_id="fallback-workstreams",
    )
    targets = build_allowed_targets(events, [], [])

    ledger = build_fallback_workstream_ledger("fallback-workstreams", events, targets)

    assert any(workstream.type == "mitigation" for workstream in ledger.workstreams)
    assert any(workstream.type == "validation" for workstream in ledger.workstreams)
    assert {name for workstream in ledger.workstreams for name in workstream.owner_or_actor_names} >= {
        "Utsav",
        "Hajime Watanabe",
    }
    assert [event_id for workstream in ledger.workstreams for event_id in workstream.evidence_ids]


def test_target_ranking_prefers_latest_human_for_mitigation_over_catalog_summary_team() -> None:
    events = [
        _event("m001", "IC", "Henry is contacting Data Pipeline team for monitoring.", sequence=1),
        _event("m002", "Utsav", "Got reply from the customer; asking if we can stop the process.", sequence=2),
    ]
    allowed = [
        AllowedTarget(
            target_id="t001",
            display_name="Data Pipeline Team",
            target_type="team",
            source="catalog",
            role_hint="owner_team",
            targetable=True,
            target_quality="medium",
        ),
        AllowedTarget(
            target_id="t002",
            display_name="Utsav",
            target_type="person",
            source="slack_author",
            role_hint="reporter_or_validator",
            targetable=True,
            target_quality="high",
            evidence_ids=["m002"],
            source_event_kind="human_operator_message",
        ),
    ]
    brief = IncidentBrief(
        incident_id="rank-mitigation",
        based_on_event_ids=["m001", "m002"],
        latest_window_event_ids=["m001", "m002"],
        current_summary="Customer activity is confirmed and a pause decision is needed.",
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, confidence=0.8, evidence_ids=["m002"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="mitigation_status_needed",
            summary="Got reply from the customer; asking if we can stop the process.",
            evidence_ids=["m002"],
            confidence=0.82,
        ),
        active_workstreams=[
            IncidentBriefWorkstream(
                workstream_type="mitigation",
                status="active",
                summary="Pause decision is being handled by latest human evidence.",
                owner_target_ids=["t002"],
                evidence_ids=["m002"],
            )
        ],
        recommended_ic_focus=IncidentBriefFocus(
            summary="Ask for pause decision.",
            preferred_target_ids=["t001", "t002"],
            acceptable_move_types=[ICMove.REQUEST_MITIGATION_OPTION],
            evidence_ids=["m002"],
        ),
    )

    shortlist = build_target_shortlist(allowed, brief, events)

    assert shortlist[0].display_name == "Utsav"
    assert "catalog/team target demoted behind latest human actor" in shortlist[-1].target_penalties


def test_catalog_team_not_selected_from_old_summary_only_when_human_coordinator_exists() -> None:
    events = [
        _event("m001", "IC", "Henry is contacting Data Pipeline team for monitoring.", sequence=1),
        _event("m002", "Henry", "I am reviewing the event-latency monitoring status now.", sequence=2),
    ]
    allowed = [
        AllowedTarget(
            target_id="t001",
            display_name="Data Pipeline Team",
            target_type="team",
            source="catalog",
            role_hint="owner_team",
            targetable=True,
            target_quality="medium",
        ),
        AllowedTarget(
            target_id="t002",
            display_name="Henry",
            target_type="person",
            source="slack_author",
            role_hint="technical_investigator",
            targetable=True,
            target_quality="high",
            evidence_ids=["m002"],
            source_event_kind="human_validation_or_monitoring",
        ),
    ]
    brief = IncidentBrief(
        incident_id="rank-monitoring",
        based_on_event_ids=["m001", "m002"],
        latest_window_event_ids=["m001", "m002"],
        current_summary="Monitoring review is active.",
        phase=IncidentBriefValue(primary=IncidentPhase.MONITORING, confidence=0.8, evidence_ids=["m002"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="monitoring_needed",
            summary="Event-latency monitoring status is being reviewed.",
            evidence_ids=["m002"],
            confidence=0.82,
        ),
        active_workstreams=[
            IncidentBriefWorkstream(
                workstream_type="monitoring",
                status="active",
                summary="Henry is coordinating the monitoring status.",
                owner_target_ids=["t002"],
                evidence_ids=["m002"],
            )
        ],
        recommended_ic_focus=IncidentBriefFocus(
            summary="Ask for monitoring status.",
            preferred_target_ids=["t001", "t002"],
            acceptable_move_types=[ICMove.REQUEST_MONITORING_SIGNAL],
            evidence_ids=["m002"],
        ),
    )

    shortlist = build_target_shortlist(allowed, brief, events)

    assert shortlist[0].display_name == "Henry"


def test_multi_word_slack_author_targetable_and_bot_mentions_not_high_quality() -> None:
    events = normalize_slack_paste(
        "zsrebot\n"
        "8:08 PM\n"
        "Hi Support team @Salim please acknowledge.\n"
        "Hajime Watanabe\n"
        "8:09 PM\n"
        "Got reply from the customer and checking whether the process can stop.\n"
        "@here please follow the update.\n"
        "Salim\n"
        "8:10 PM\n"
        "I am checking customer validation now.\n",
        incident_id="author-recovery",
    )
    targets = build_allowed_targets(events, [], [])
    by_name = {target.display_name: target for target in targets}

    assert by_name["Hajime Watanabe"].targetable
    assert by_name["Hajime Watanabe"].target_quality == "high"
    assert by_name["Salim"].targetable
    assert by_name["Salim"].target_quality == "high"
    bot_salim_mentions = [
        target
        for target in targets
        if target.display_name == "Salim" and target.source == "explicit_mention"
    ]
    assert bot_salim_mentions and all(target.target_quality != "high" for target in bot_salim_mentions)
    assert all(target.display_name != "here" or not target.targetable for target in targets)


def test_numeric_classification_no_aggregate_rejected_entity() -> None:
    brief = IncidentBrief(
        incident_id="numeric-aggregate",
        based_on_event_ids=["m001"],
        latest_window_event_ids=["m001"],
        current_summary="Tenant evidence and ticket evidence are visible.",
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, confidence=0.7, evidence_ids=["m001"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="validation_needed",
            summary="Confirm the current validation signal.",
            evidence_ids=["m001"],
            confidence=0.7,
        ),
        rejected_or_noise=[
            IncidentBriefRejectedOrNoise(
                text="Numeric operational IDs such as 91410842835, 30000080, 585592, 9863631",
                reason="url_path_number",
                evidence_ids=["m001"],
            ),
            IncidentBriefRejectedOrNoise(text="9863631", reason="url_path_number", evidence_ids=["m001"]),
        ],
    )

    delta = state_delta_from_incident_brief(brief, [])
    rejected_names = {entity.display_name for entity in delta.rejected_entities}

    assert "Numeric operational IDs such as 91410842835, 30000080, 585592, 9863631" not in rejected_names
    assert "9863631" in rejected_names


def test_duplicate_say_this_next_line_is_collapsed() -> None:
    decision = ICDecision(
        decision_id="duplicate",
        incident_id="dup",
        move=ICMove.REQUEST_MONITORING_SIGNAL,
        phase=IncidentPhase.INVESTIGATION,
        output={
            "say_this": "Active owner, please provide latest monitoring signals and status updates on cluster latency.",
            "next_line": "Active owner, can you confirm the current monitoring signals and cluster latency status?",
        },
    )

    linted, changed, reason = lint_manual_copy_output(decision)

    assert changed
    assert reason == "duplicate_next_line_removed"
    assert "next_line" not in linted.output
    assert linted.move == decision.move
