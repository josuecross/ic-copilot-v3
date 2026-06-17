from __future__ import annotations

from pathlib import Path

import pytest

from ic_copilot.evidence_quality import (
    assess_semantic_quality,
    classify_event_quality,
    validate_incident_brief_quality,
)
from ic_copilot.incident_brief import build_allowed_targets
from ic_copilot.incident_read_v2 import incident_read_v2_from_v1_fixture
from ic_copilot.llm.config import LLMConfig, LLMMode, LLMProvider
from ic_copilot.normalizers.slack_paste import normalize_slack_paste
from ic_copilot.pipeline import run_pipeline
from ic_copilot.schemas import (
    AllowedTarget,
    CleanTurn,
    CleanTurnLedger,
    CurrentIncidentState,
    EvidenceRef,
    EventQuality,
    ICDecision,
    ICMove,
    IncidentBrief,
    IncidentBriefBlocker,
    IncidentBriefFocus,
    IncidentBriefValue,
    IncidentReadAndWhisperV2,
    IncidentEvent,
    IncidentPhase,
    QuestionIntentLedger,
    SemanticQuality,
    IncidentReadAndWhisper,
    WhisperEvidenceRef,
)
from ic_copilot.semantic_read import ParallelSemanticReadResult, reduce_ledgers_to_incident_brief
from ic_copilot.verifier import verify_ic_decision


DB_FIXTURE = Path("data/personal_regression/incidents/db_high_cpu_subscription_order_processed_static.txt")
PREVIEW_ONLY_FIXTURE = Path("data/personal_regression/incidents/preview_card_only_static.txt")
L3_CONVERTED_FIXTURE = Path("data/personal_regression/incidents/l3_converted_duplicate_line_static.txt")


def _event(
    event_id: str,
    author: str,
    message: str,
    *,
    is_bot: bool = False,
    is_system: bool = False,
    sequence: int = 1,
) -> IncidentEvent:
    return IncidentEvent(
        event_id=event_id,
        incident_id="quality-test",
        sequence=sequence,
        author=author,
        message=message,
        extracted_tokens={"is_bot": is_bot, "is_system": is_system},
        hash=event_id,
    )


def test_event_quality_classifies_preview_cards_and_human_operator_evidence() -> None:
    preview = _event("m001", "PagerDuty", "Incident in PagerDuty Preview in Slack\nStatus: triggered", is_bot=True)
    status_label = _event("m002", "Status", "Status: running")
    human = _event("m003", "Rajesh", "Can you confirm the current validation signal?", sequence=3)

    assert classify_event_quality(preview).event_kind == "pagerduty_card"
    assert classify_event_quality(preview).is_planner_grounding_allowed is False
    assert classify_event_quality(status_label).is_target_source_allowed is False
    assert classify_event_quality(human).event_kind == "human_question"
    assert classify_event_quality(human).is_blocker_evidence_allowed is True


def test_semantic_quality_rejects_question_only_reader_success() -> None:
    events = [_event("m001", "dcruz", "Can you confirm if the validation is done?")]
    result = ParallelSemanticReadResult(
        question_intent_ledger=QuestionIntentLedger(incident_id="quality-test"),
        errors={
            "clean_turn_ledger": "schema failure",
            "actor_workstream_ledger": "schema failure",
            "incident_fact_ledger": "schema failure",
        },
    )

    quality = assess_semantic_quality(result, events, [])

    assert quality.status == "insufficient"
    assert quality.question_only_success is True
    assert quality.can_render_normal_recommendation is False


def test_incident_brief_quality_rejects_preview_card_blocker() -> None:
    events = [_event("m001", "PagerDuty", "Incident in PagerDuty Preview in Slack", is_bot=True)]
    brief = IncidentBrief(
        incident_id="quality-test",
        based_on_event_ids=["m001"],
        latest_window_event_ids=["m001"],
        current_summary="Incident in PagerDuty Preview in Slack",
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, confidence=0.8, evidence_ids=["m001"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="status_eta_needed",
            summary="PagerDuty incident status is open.",
            evidence_ids=["m001"],
            confidence=0.8,
        ),
        recommended_ic_focus=IncidentBriefFocus(
            summary="Ask for status",
            acceptable_move_types=[ICMove.REQUEST_STATUS_OR_ETA],
            evidence_ids=["m001"],
        ),
    )

    quality = validate_incident_brief_quality(
        brief,
        events,
        [],
        SemanticQuality(status="sufficient", can_plan=True, can_render_normal_recommendation=True),
    )

    assert not quality.passed
    assert any("preview" in reason or "human/operator" in reason for reason in quality.blocked_reasons)


def test_normalizer_keeps_table_labels_as_continuation_not_authors() -> None:
    events = normalize_slack_paste(
        "dcruz\n"
        "10:01 AM\n"
        "Sai, can you confirm the queue contributor?\n"
        "Customer ID: 17474\n"
        "Status: running\n"
        "| cluster_host | cpu |\n"
        "🚀 Problematic Query Check by Database-Agent\n"
        "tid: 17474\n"
        "Database-Agent\n"
        "10:02 AM\n"
        "Total Queries Running: 27\n"
        "Sai Krishna K\n"
        "10:03 AM\n"
        "Checking now\n",
        incident_id="db-static",
    )

    authors = [event.author for event in events]
    assert "Customer ID" not in authors
    assert "Status" not in authors
    assert "tid" not in authors
    assert "🚀 Problematic Query Check by Database-Agent" not in authors
    assert "dcruz" in authors
    assert "Sai Krishna K" in authors
    assert any("Customer ID: 17474" in event.message for event in events)
    assert sum(int(event.raw_metadata.get("non_author_continuation_lines", 0)) for event in events) >= 4


def test_allowed_targets_rejects_diagnostic_fragments_and_keeps_human_team_targets() -> None:
    events = normalize_slack_paste(DB_FIXTURE.read_text(), incident_id="db-static")
    targets = build_allowed_targets(events, [], [])
    by_name = {target.display_name: target for target in targets}

    assert by_name["dcruz"].targetable
    assert by_name["Sai Krishna K"].targetable
    assert "Database-Agent" not in by_name or by_name["Database-Agent"].targetable is False
    assert "Docs" not in by_name or by_name["Docs"].targetable is False
    assert "Summary" not in by_name or by_name["Summary"].targetable is False
    assert "Status" not in by_name or by_name["Status"].targetable is False
    assert "Total Queries Running" not in by_name or by_name["Total Queries Running"].targetable is False
    assert "tid" not in by_name or by_name["tid"].targetable is False


def test_preview_card_only_fixture_has_no_card_targets() -> None:
    events = normalize_slack_paste(PREVIEW_ONLY_FIXTURE.read_text(), incident_id="preview-only")
    targets = build_allowed_targets(events, [], [])
    targetable_names = {target.display_name.lower() for target in targets if target.targetable}

    assert "pagerduty" not in targetable_names
    assert "zoom" not in targetable_names
    assert "refresh" not in targetable_names
    assert "p0yzcxi" not in targetable_names
    assert all(target.target_quality in {"low", "rejected"} for target in targets if target.display_name in {"PagerDuty APP", "Zoom APP Call"})


def test_l3_converted_fixture_keeps_human_question_not_pagerduty_card() -> None:
    events = normalize_slack_paste(L3_CONVERTED_FIXTURE.read_text(), incident_id="l3-converted")
    qualities = {quality.event_id: quality for quality in [classify_event_quality(event) for event in events]}
    pagerduty_events = [event for event in events if "PagerDuty" in (event.author or "")]
    human_question_events = [event for event in events if "Rajesh, please check" in event.message]

    assert pagerduty_events
    assert all(not qualities[event.event_id].is_planner_grounding_allowed for event in pagerduty_events)
    assert human_question_events
    assert any(qualities[event.event_id].is_blocker_evidence_allowed for event in human_question_events)


def test_reducer_uses_visible_operator_question_instead_of_unknown_brief() -> None:
    events = normalize_slack_paste(DB_FIXTURE.read_text(), incident_id="db-static")
    targets = build_allowed_targets(events, [], [])
    clean = CleanTurnLedger(
        incident_id="db-static",
        clean_turns=[
            CleanTurn(
                turn_id="turn-001",
                speaker="dcruz",
                speaker_type="human",
                event_ids=[events[-1].event_id],
                message_type="question",
                summary="Sai, can you confirm whether SubscriptionOrderProcessed or tenant 17474 is the primary contributor?",
            )
        ],
    )
    brief = reduce_ledgers_to_incident_brief(
        incident_id="db-static",
        events=events,
        allowed_targets=targets,
        semantic_read=ParallelSemanticReadResult(clean_turn_ledger=clean, question_intent_ledger=QuestionIntentLedger(incident_id="db-static"), errors={}),
    )

    assert brief.phase.primary == IncidentPhase.INVESTIGATION
    assert brief.latest_blocker.blocker_type in {"validation_needed", "mitigation_status_needed", "status_eta_needed", "monitoring_needed"}
    assert "unclear" not in brief.latest_blocker.summary.lower()


def test_verifier_blocks_named_target_without_target_id_and_generated_evidence() -> None:
    allowed = [
        AllowedTarget(target_id="t001", display_name="DBA team", target_type="team", source="current_evidence", evidence_ids=["m001"]),
    ]
    brief = IncidentBrief(
        incident_id="i",
        based_on_event_ids=["m001"],
        latest_window_event_ids=["m001"],
        current_summary="DBA validation is pending.",
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, evidence_ids=["m001"], confidence=0.8),
        latest_blocker=IncidentBriefBlocker(blocker_type="validation_needed", summary="DBA validation is pending.", evidence_ids=["m001"], confidence=0.8),
        recommended_ic_focus=IncidentBriefFocus(summary="Ask DBA for validation.", preferred_target_ids=["t001"], acceptable_move_types=[ICMove.ASK_NEXT_VALIDATION], evidence_ids=["m001"]),
    )
    decision = ICDecision(
        decision_id="d",
        incident_id="i",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase=IncidentPhase.INVESTIGATION,
        output={"say_this": "DBA team, can you confirm the latest validation signal?"},
        grounding=[EvidenceRef(event_id="m001", quote="Latest blocker is unclear from semantic ledgers", source="generated")],
    )

    result = verify_ic_decision(decision, CurrentIncidentState(incident_id="i"), [], [], incident_brief=brief, allowed_targets=allowed)
    assert not result.checks["named_target_requires_target_id"]
    assert not result.checks["generated_summary_as_evidence"]


def test_verifier_blocks_normal_recommendation_when_semantic_quality_insufficient() -> None:
    allowed = [
        AllowedTarget(
            target_id="t001",
            display_name="Rajesh",
            target_type="person",
            source="slack_author",
            target_quality="high",
            evidence_ids=["m001"],
        )
    ]
    brief = IncidentBrief(
        incident_id="i",
        based_on_event_ids=["m001"],
        latest_window_event_ids=["m001"],
        current_summary="Validation is pending.",
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, evidence_ids=["m001"], confidence=0.8),
        latest_blocker=IncidentBriefBlocker(blocker_type="validation_needed", summary="Validation is pending.", evidence_ids=["m001"], confidence=0.8),
        recommended_ic_focus=IncidentBriefFocus(summary="Ask for validation.", preferred_target_ids=["t001"], acceptable_move_types=[ICMove.ASK_NEXT_VALIDATION], evidence_ids=["m001"]),
    )
    decision = ICDecision(
        decision_id="d",
        incident_id="i",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase=IncidentPhase.INVESTIGATION,
        target_ids=["t001"],
        output={"say_this": "Rajesh, can you confirm the validation signal?"},
        grounding=[EvidenceRef(event_id="m001", quote="Rajesh: validation pending")],
    )

    result = verify_ic_decision(
        decision,
        CurrentIncidentState(incident_id="i"),
        [],
        [],
        incident_brief=brief,
        allowed_targets=allowed,
        semantic_quality=SemanticQuality(
            status="insufficient",
            can_plan=False,
            can_render_normal_recommendation=False,
            question_only_success=True,
        ),
        event_quality=[classify_event_quality(_event("m001", "Rajesh", "validation pending"))],
    )

    assert not result.checks["semantic_quality_sufficient"]
    assert not result.checks["no_question_only_semantic_recommendation"]


def test_verifier_blocks_low_quality_selected_target_and_stale_expiration() -> None:
    allowed = [
        AllowedTarget(
            target_id="t001",
            display_name="Status",
            target_type="non_targetable_noise",
            source="current_evidence",
            targetable=True,
            target_quality="low",
            source_event_kind="table_header",
            evidence_ids=["m001"],
        )
    ]
    decision = ICDecision(
        decision_id="d",
        incident_id="i",
        move=ICMove.REQUEST_STATUS_OR_ETA,
        phase=IncidentPhase.INVESTIGATION,
        target_ids=["t001"],
        output={"say_this": "Status, can you provide the update?"},
        grounding=[EvidenceRef(event_id="m001", quote="Status: running")],
        expiration="2020-01-01T00:00:00Z",
    )

    result = verify_ic_decision(
        decision,
        CurrentIncidentState(incident_id="i"),
        [],
        [],
        allowed_targets=allowed,
        semantic_quality=SemanticQuality(status="sufficient", can_plan=True, can_render_normal_recommendation=True),
        incident_brief_quality=None,
        event_quality=[
            EventQuality(
                event_id="m001",
                event_kind="table_header",
                evidence_quality="low",
                target_source_quality="invalid",
                is_target_source_allowed=False,
                is_blocker_evidence_allowed=False,
                is_planner_grounding_allowed=False,
            )
        ],
    )

    assert not result.checks["selected_target_quality"]
    assert not result.checks["no_preview_card_grounding"]
    assert not result.checks["expires_correctly"]


class _CleanOnlyClient:
    config = LLMConfig(provider=LLMProvider.LOCAL_HTTP, mode=LLMMode.PRODUCT, enabled=True, timeout_seconds=1)

    def generate_json(self, prompt_name, input_payload, response_model):
        if response_model in {IncidentReadAndWhisper, IncidentReadAndWhisperV2} or response_model.__name__ in {
            "IncidentReadAndWhisper",
            "IncidentReadAndWhisperV2",
        }:
            target = next(
                (candidate for candidate in input_payload.get("candidate_targets", []) if candidate.get("display_name") == "Sai Krishna K"),
                (input_payload.get("candidate_targets") or [{}])[0],
            )
            selected_event = next(
                (
                    event
                    for event in input_payload.get("latest_window_events", [])
                    if "SubscriptionOrderProcessed" in event.get("text", "")
                    and "primary contributor" in event.get("text", "")
                ),
                (input_payload.get("latest_window_events") or [{"event_id": "m001", "text": ""}])[-1],
            )
            event_id = selected_event.get("event_id", "m001")
            quote = selected_event.get("text") or "SubscriptionOrderProcessed validation is pending."
            read = IncidentReadAndWhisper(
                incident_id=input_payload["incident_id"],
                current_read="SubscriptionOrderProcessed and tenant/workload validation are visible in current evidence.",
                latest_open_loop="confirm whether SubscriptionOrderProcessed or tenant/workload remains the primary contributor",
                selected_move=ICMove.ASK_NEXT_VALIDATION,
                selected_target_id=target.get("target_id"),
                selected_target_display_name=target.get("display_name"),
                say_this=(
                    "Sai Krishna K, can you confirm whether SubscriptionOrderProcessed or tenant/workload "
                    "is still the primary CPU/queue contributor before we choose the next mitigation?"
                ),
                evidence=[
                    WhisperEvidenceRef(
                        event_id=event_id,
                        quote=quote,
                        confidence=0.8,
                    )
                ],
                confidence=0.8,
            )
            if response_model is IncidentReadAndWhisper or response_model.__name__ == "IncidentReadAndWhisper":
                return read
            return incident_read_v2_from_v1_fixture(read=read, context_pack=input_payload)
        if response_model is CleanTurnLedger or response_model.__name__ == "CleanTurnLedger":
            return CleanTurnLedger(
                incident_id=input_payload["incident_id"],
                clean_turns=[
                    CleanTurn(
                        turn_id="turn-001",
                        speaker="Sai Krishna K",
                        speaker_type="human",
                        event_ids=[input_payload["event_ids"][-1]],
                        message_type="question",
                        summary="Sai, can you confirm whether SubscriptionOrderProcessed is the primary contributor?",
                    )
                ],
            )
        if response_model is QuestionIntentLedger or response_model.__name__ == "QuestionIntentLedger":
            return QuestionIntentLedger(incident_id=input_payload["incident_id"])
        if response_model is ICDecision or response_model.__name__ == "ICDecision":
            raise NotImplementedError("planner omitted")
        raise ValueError("schema failure")


class _AllSemanticFailClient(_CleanOnlyClient):
    def generate_json(self, prompt_name, input_payload, response_model):
        raise TimeoutError("read operation timed out")


def test_semantic_gating_derives_conservative_ledgers_from_clean_turns() -> None:
    result = run_pipeline(
        DB_FIXTURE,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_CleanOnlyClient(),
    )

    assert result["decision"].move != ICMove.NO_SAFE_RECOMMENDATION
    assert result["trace"].clean_turn_ledger is None
    assert result["trace"].incident_read_and_whisper is not None
    assert result["trace"].processing_strategy in {"incident_read_and_whisper", "incident_read_and_whisper_v2"}


def test_semantic_gating_blocks_normal_planning_without_clean_turns() -> None:
    with pytest.raises(TimeoutError, match="read operation timed out"):
        run_pipeline(
            DB_FIXTURE,
            catalog_path="data/contract/service_catalog.yaml",
            command_registry_path="data/contract/command_registry.yaml",
            memory_path="data/contract/decision_moments.jsonl",
            save_trace=False,
            llm_client=_AllSemanticFailClient(),
        )


def test_db_high_cpu_minimized_regression_with_fixture_client_is_grounded() -> None:
    result = run_pipeline(
        DB_FIXTURE,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_CleanOnlyClient(),
    )

    output = result["final_output"].lower()
    assert result["verifier_result"].passed
    assert "latest blocker is unclear" not in output
    assert "subscriptionorderprocessed" in output or "tenant/workload" in output or "17474" in output
    targetable = {target.display_name for target in result["allowed_targets"] if target.targetable}
    assert "Database-Agent" not in targetable
