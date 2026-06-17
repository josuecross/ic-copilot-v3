from __future__ import annotations

from ic_copilot.action_state import infer_action_state_transitions
from ic_copilot.run_diagnosis import build_run_diagnosis, stale_output_risks_for_output
from ic_copilot.schemas import (
    EventQuality,
    ICDecision,
    ICMove,
    IncidentEvent,
    MemoryApplicabilityResult,
    VerifierResult,
)
from ic_copilot.web.app import _debug_summary_from_run


def _event(event_id: str, sequence: int, author: str, message: str) -> IncidentEvent:
    return IncidentEvent(
        event_id=event_id,
        incident_id="INC-DIAG",
        sequence=sequence,
        author=author,
        message=message,
        hash=f"hash-{event_id}",
    )


def _quality(event: IncidentEvent, kind: str = "human_status_update") -> EventQuality:
    return EventQuality(
        event_id=event.event_id,
        sequence=event.sequence,
        author=event.author,
        author_type="human",
        event_kind=kind,
        evidence_quality="high",
    )


def test_scope_answer_supersedence_detects_stale_repeated_ask() -> None:
    events = [
        _event("m020", 20, "Navneeth", "This should be P1 since the customer is blocked."),
        _event("m021", 21, "Kenneth", "Are multiple customers impacted or only Toast?"),
        _event(
            "m022",
            22,
            "Zeenie Louis",
            "Only Toast has reported impact. No other customer has reported it.",
        ),
    ]
    quality = [_quality(events[0]), _quality(events[1], "human_question"), _quality(events[2])]

    risks = stale_output_risks_for_output(
        "@Navneeth, can you confirm whether this is isolated to one customer or if more production customers are affected?",
        events,
        quality,
    )

    assert risks
    assert risks[0]["risk_type"] == "scope_question_after_scope_answer"
    assert risks[0]["answered_by_event_id"] == "m022"
    assert risks[0]["severity"] == "error"


def test_operational_page_action_answers_earlier_page_request() -> None:
    events = [
        _event("m010", 10, "Sriram", "@Vignesh could you page engineering?"),
        _event("m011", 11, "Irfan", "Vignesh is on the way home. Let me page."),
        _event("m012", 12, "Irfan", "@zsrebot page team revenue"),
        _event("m013", 13, "zsrebot", "Done."),
        _event("m014", 14, "Sriram", "RIA connection limit warning is showing in logs."),
    ]
    quality = [
        _quality(events[0], "human_question"),
        _quality(events[1]),
        EventQuality(
            event_id=events[2].event_id,
            sequence=events[2].sequence,
            author=events[2].author,
            author_type="human",
            event_kind="human_operator_message",
            evidence_quality="high",
        ),
        EventQuality(
            event_id=events[3].event_id,
            sequence=events[3].sequence,
            author=events[3].author,
            author_type="bot",
            event_kind="bot_system_message",
            evidence_quality="medium",
        ),
        _quality(events[4], "human_diagnostic_evidence"),
    ]

    action_state = infer_action_state_transitions(events, quality)

    assert action_state["action_loops"][0]["final_state"] == "completed"
    assert action_state["answered_questions"][0]["question_event_id"] == "m010"
    assert any("Revenue" in item or "Engineering" in item for item in action_state["do_not_ask"])

    diagnosis = build_run_diagnosis(
        incident_id="INC-DIAG",
        events=events,
        event_quality=quality,
        final_output="@Vignesh, can you confirm if you paged engineering?",
    )

    assert any(
        item["event_id"] == "m010"
        for item in diagnosis["open_loop_diagnosis"]["answered_open_loops"]
    )
    assert diagnosis["open_loop_diagnosis"]["action_state_transitions"][0]["final_state"] == "completed"
    assert diagnosis["open_loop_diagnosis"]["stale_output_risks"][0]["risk_type"] == "asks_already_answered_question"


def test_diagnosis_marks_megastore_scope_answer_and_schema_failure() -> None:
    events = [
        _event("m020", 20, "Navneeth", "This should be P1 since the customer is blocked from running reports."),
        _event("m021", 21, "Kenneth", "Why do you say it should be a P1? How many customers are impacted?"),
        _event(
            "m022",
            22,
            "Zeenie Louis",
            "The issue reported is only for Toast. No other customer has reported it. We only have 2 live customers on this pipeline: Toast and Okta. Row count mismatch exists on the Iceberg side.",
        ),
    ]
    quality = [_quality(events[0]), _quality(events[1], "human_question"), _quality(events[2])]
    decision = ICDecision(
        decision_id="fallback-schema-invalid",
        incident_id="INC-DIAG",
        move=ICMove.NO_SAFE_RECOMMENDATION,
        phase="investigation",
        output={"say_this": "I do not have a safe, grounded next move yet."},
        model_metadata={
            "planning_failure": {
                "provider_output_was_invalid": True,
                "planning_failure_category": "planning_model_schema_invalid",
                "provider_output_invalid_reason": "Model output did not match the required schema.",
            }
        },
    )
    verifier = VerifierResult(
        passed=False,
        final_status="blocked",
        checks={"no_safe_despite_accepted_memory": False},
        blocked_claims=["no_safe_recommendation came from planning/model schema failure"],
    )

    diagnosis = build_run_diagnosis(
        incident_id="INC-DIAG",
        events=events,
        event_quality=quality,
        retrieved_memory_ids=[
            "DM_scope_before_priority_escalation",
            "DM_pipeline_health_signals_for_report_failures",
        ],
        accepted_memory_ids=["DM_pipeline_health_signals_for_report_failures"],
        decision=decision,
        verifier_result=verifier,
        final_output="SAY THIS:\nI do not have a safe, grounded next move yet.",
        fallback_used=True,
        planning_failure=decision.model_metadata["planning_failure"],
    )

    open_loop = diagnosis["open_loop_diagnosis"]
    assert any(item["question_intent"] == "impact_scope" for item in open_loop["answered_open_loops"])
    assert open_loop["later_answer_candidates"][0]["answer_event_id"] == "m022"
    assert any(item["question_intent"] == "technical_validation" for item in open_loop["unresolved_open_loops"])
    quality = diagnosis["final_output_quality"]
    assert quality["provider_output_was_invalid"] is True
    assert quality["likely_failure_category"] == "planning_model_schema_invalid"
    assert quality["likely_failure_category"] != "none"


def test_diagnosis_schema_and_memory_semantic_gap() -> None:
    events = [
        _event("m001", 1, "Zeenie Louis", "Reports are erroring out and teams are not able to run reports."),
        _event(
            "m002",
            2,
            "Zeenie Louis",
            "Current findings show row-count mismatch on the Iceberg side; pipeline validation remains next.",
        ),
    ]
    quality = [_quality(event) for event in events]
    memory_result = MemoryApplicabilityResult(
        decision_id="DM_pipeline_health_signals_for_report_failures",
        accepted=False,
        score=0.4,
        reasons=["missing required current evidence"],
        required_current_evidence_missing=["report failure"],
    )
    decision = ICDecision(
        decision_id="d1",
        incident_id="INC-DIAG",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase="mitigation",
        output={
            "say_this": "@Zeenie Louis, can you confirm the next validation for the Iceberg row-count mismatch?",
        },
        grounding=[],
    )
    verifier = VerifierResult(
        passed=True,
        final_status="pass",
        checks={"no_stale_question": True, "stale_answered_open_loop": True},
    )

    diagnosis = build_run_diagnosis(
        incident_id="INC-DIAG",
        events=events,
        event_quality=quality,
        loaded_memory_count=1,
        retrieved_memory_ids=["DM_pipeline_health_signals_for_report_failures"],
        applicability_results=[memory_result],
        accepted_memory_ids=[],
        decision=decision,
        verifier_result=verifier,
        final_output="SAY THIS:\n@Zeenie Louis, can you confirm the next validation?",
    )

    assert diagnosis["schema_version"] == "1.0"
    assert "selected_output" in diagnosis
    assert "evidence_chain" in diagnosis
    assert "open_loop_diagnosis" in diagnosis
    assert "memory_funnel" in diagnosis
    assert "final_output_quality" in diagnosis
    assert "verifier_summary" in diagnosis
    quality = diagnosis["final_output_quality"]
    assert "direct_ask" in quality
    assert "passive_owner_statement" in quality
    assert "low_quality_named_owner_terms" in quality
    assert "move_visible_intent_mismatch" in quality
    assert "actionability_failure_category" in quality
    assert "no_safe_wording_quality" in quality
    assert "target_dedup_applied" in quality
    assert "move_normalized_from" in quality
    assert "move_normalized_to" in quality
    gaps = diagnosis["memory_funnel"]["possible_semantic_gaps"]
    assert gaps
    assert gaps[0]["decision_id"] == "DM_pipeline_health_signals_for_report_failures"
    assert "reports are erroring out" in gaps[0]["nearby_current_evidence"]


def test_web_debug_summary_exposes_run_diagnosis_fields() -> None:
    run = {
        "run_id": "run-1",
        "status": "succeeded",
        "result_json": {
            "events": [],
            "state": {},
            "verifier_result": {"final_status": "pass", "checks": {}},
            "trace": {
                "run_diagnosis": {
                    "open_loop_diagnosis": {
                        "answered_open_loops": [{"event_id": "m021"}],
                        "unresolved_open_loops": [{"event_id": "derived:technical_validation"}],
                        "stale_output_risks": [],
                    },
                    "memory_funnel": {
                        "accepted": [{"decision_id": "DM_example"}],
                        "rejected": [{"decision_id": "DM_rejected", "reasons": ["missing evidence"]}],
                        "possible_semantic_gaps": [{"decision_id": "DM_gap"}],
                    },
                    "final_output_quality": {
                        "safe_but_weak": False,
                        "likely_failure_category": "none",
                        "direct_ask": True,
                        "passive_owner_statement": False,
                        "low_quality_named_owner_terms": [],
                        "move_visible_intent_mismatch": False,
                        "actionability_failure_category": "none",
                        "no_safe_wording_quality": "not_applicable",
                        "target_dedup_applied": False,
                        "move_normalized_from": None,
                        "move_normalized_to": None,
                    },
                    "verifier_summary": {"status": "pass", "meaningful_checks": []},
                },
            },
        },
    }

    summary = _debug_summary_from_run(run)

    assert summary["answered_open_loop_count"] == 1
    assert summary["unresolved_open_loop_count"] == 1
    assert summary["safe_but_weak"] is False
    assert summary["likely_failure_category"] == "none"
    assert summary["direct_ask"] is True
    assert summary["passive_owner_statement"] is False
    assert summary["low_quality_named_owner_terms"] == []
    assert summary["move_visible_intent_mismatch"] is False
    assert summary["actionability_failure_category"] == "none"
    assert summary["no_safe_wording_quality"] == "not_applicable"
    assert summary["target_dedup_applied"] is False
    assert summary["move_normalized_from"] is None
    assert summary["move_normalized_to"] is None
    assert summary["rejected_memory_ids_with_reasons"][0]["decision_id"] == "DM_rejected"
    assert summary["possible_semantic_gaps"][0]["decision_id"] == "DM_gap"


def test_diagnosis_flags_compact_timestamp_parse_loss_instead_of_none() -> None:
    events = [
        _event(
            "m001",
            1,
            "APP",
            "Incident created card only; compact human diagnostic evidence was not recovered.",
        )
    ]
    quality = [
        EventQuality(
            event_id="m001",
            sequence=1,
            author="APP",
            author_type="bot",
            event_kind="pagerduty_card",
            evidence_quality="low",
            is_target_source_allowed=False,
            is_planner_grounding_allowed=False,
            is_blocker_evidence_allowed=False,
        )
    ]
    decision = ICDecision(
        decision_id="fallback",
        incident_id="INC-DIAG",
        move=ICMove.NO_SAFE_RECOMMENDATION,
        phase="triage",
        output={"say_this": "I do not have a safe, grounded next move yet."},
    )
    verifier = VerifierResult(
        passed=True,
        final_status="pass",
        checks={"schema_valid": True},
    )

    diagnosis = build_run_diagnosis(
        incident_id="INC-DIAG",
        events=events,
        event_quality=quality,
        retrieved_memory_ids=["DM_kafka_connection_error_check_service_config_drift"],
        accepted_memory_ids=[],
        decision=decision,
        verifier_result=verifier,
        final_output="SAY THIS:\nI do not have a safe, grounded next move yet.",
        fallback_used=True,
    )
    summary = _debug_summary_from_run(
        {
            "run_id": "run-parse-loss",
            "status": "succeeded",
            "result_json": {"trace": {"run_diagnosis": diagnosis}},
        }
    )

    assert diagnosis["final_output_quality"]["likely_failure_category"] == "normalization_compact_timestamp_parse_failed"
    assert diagnosis["parsing_quality"]["normalized_event_count"] == 1
    assert diagnosis["parsing_quality"]["human_operator_event_count"] == 0
    assert summary["parsing_quality"]["likely_failure_category"] == "normalization_compact_timestamp_parse_failed"


def test_run_diagnosis_dedupes_duplicate_target_display_names() -> None:
    decision = ICDecision(
        decision_id="d-dupe",
        incident_id="INC-DIAG",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase="triage",
        output={"say_this": "DACO, can you confirm topic ownership?"},
        targets=[
            {"entity_type": "team", "display_name": "DACO", "status": "targeted"},
            {"entity_type": "team", "display_name": "DACO", "status": "targeted"},
        ],
        target_ids=["t-daco-1", "t-daco-2"],
    )
    verifier = VerifierResult(passed=True, final_status="pass", checks={})

    diagnosis = build_run_diagnosis(
        incident_id="INC-DIAG",
        events=[_event("m001", 1, "Dharani", "DACO owns topic validation.")],
        event_quality=[],
        decision=decision,
        verifier_result=verifier,
        final_output="SAY THIS:\nDACO, can you confirm topic ownership?",
    )

    assert diagnosis["selected_output"]["target_display_names"] == ["DACO"]
    assert diagnosis["selected_output"]["target_dedup_applied"] is True
    assert diagnosis["final_output_quality"]["target_dedup_applied"] is True
