from __future__ import annotations

from ic_copilot.incident_brief import build_allowed_targets
from ic_copilot.incident_read_v2 import (
    build_incident_read_v2_context_pack,
    evaluate_incident_read_v2_quality,
    extract_incident_read_and_whisper_v2,
    incident_read_v2_to_incident_read,
    is_pseudo_target_name,
)
from ic_copilot.schema_repair import validate_with_repair
from ic_copilot.normalizers.slack_paste import normalize_slack_paste
from ic_copilot.schemas import (
    IncidentEvent,
    IncidentReadAndWhisperV2,
    IncidentStateV2,
    AnsweredQuestionV2,
    NextBlockerV2,
    OpenQuestionV2,
    WhisperEvidenceRef,
    WhisperV2,
)


def _event(event_id: str = "m001", message: str = "Navneeth: current update") -> IncidentEvent:
    return IncidentEvent(
        event_id=event_id,
        incident_id="v2-test",
        sequence=1,
        author="Navneeth",
        message=message,
        hash="hash-m001",
    )


def _read_v2(
    *,
    target: str | None = "Salim Thakkar",
    say_this: str = "@Salim Thakkar, can you confirm impacted customer scope?",
    blocker_type: str = "missing_impact_scope",
) -> IncidentReadAndWhisperV2:
    return IncidentReadAndWhisperV2(
        incident_id="v2-test",
        incident_state=IncidentStateV2(
            incident_id="v2-test",
            reporters=["Salim Thakkar"],
            active_humans=["Vignesh S S", "Salim Thakkar"],
            open_questions=[
                OpenQuestionV2(
                    event_id="m001",
                    asked_by="Vignesh S S",
                    asked_to=["Salim Thakkar"],
                    question_text="All three impacted customers from same region?",
                    question_type="impact_scope",
                    answered=False,
                )
            ],
        ),
        next_blocker=NextBlockerV2(
            blocker_type=blocker_type,  # type: ignore[arg-type]
            blocker_summary="Need impact scope.",
            best_target_display_name=target,
            best_target_type="person" if target else "none",
            best_target_reason="Reporter/support path can answer the scope question.",
            evidence_event_ids=["m001"],
        ),
        whisper=WhisperV2(
            selected_move="ask_impact_scope",
            selected_target_display_name=target,
            say_this=say_this,
            evidence=[WhisperEvidenceRef(event_id="m001", quote="All three impacted customers from same region?")],
        ),
        evidence=[WhisperEvidenceRef(event_id="m001", quote="All three impacted customers from same region?")],
    )


def test_v2_pseudo_author_names_are_rejected_from_targets() -> None:
    raw = "\n".join(
        [
            "Just to confirm: this should continue the previous message",
            "2 files Salim Thakkar",
            "Phase Update",
            "set the channel topic: customer slowness",
            "SREBotjinhui.zhao",
            "@Vignesh S S As reported here",
            "Salim Thakkar  [10:03 AM]",
            "Three customers reported slowness.",
        ]
    )
    events = normalize_slack_paste(raw, incident_id="v2-test")
    targets = build_allowed_targets(events, [], [])
    targetable_names = {target.display_name for target in targets if target.targetable}
    assert "Salim Thakkar" in targetable_names
    for name in [
        "Just to confirm",
        "2 files Salim Thakkar",
        "Phase Update",
        "set the channel topic",
        "SREBotjinhui.zhao",
        "@Vignesh S S As reported here",
    ]:
        assert is_pseudo_target_name(name)
        assert name not in targetable_names


def test_v2_quality_blocks_asking_asker_same_question() -> None:
    read_v2 = _read_v2(
        target="Vignesh S S",
        say_this="@Vignesh S S, can you confirm if all three impacted customers are from the same region?",
    )
    quality = evaluate_incident_read_v2_quality(read_v2=read_v2, diagnosis_summary={"likely_failure_category": "none"})
    assert quality["usefulness_status"] == "fail"
    assert "ask_the_asker_repeated_question" in quality["failed_reasons"]


def test_v2_quality_blocks_trust_post_after_no_need_answer() -> None:
    read_v2 = _read_v2(
        target="Jose Amey",
        say_this="@Jose Amey, can you confirm whether we need a Trust Post?",
        blocker_type="trust_post_decision",
    ).model_copy(
        update={
            "incident_state": IncidentStateV2(
                incident_id="v2-test",
                active_humans=["Jose Amey"],
                do_not_ask=["Trust Post No Need"],
            )
        }
    )
    quality = evaluate_incident_read_v2_quality(read_v2=read_v2, diagnosis_summary={"likely_failure_category": "none"})
    assert quality["usefulness_status"] == "fail"
    assert "trust_post_ask_after_answer" in quality["failed_reasons"]


def test_v2_quality_allows_owner_routing_answer_to_become_owner_status_ask() -> None:
    read_v2 = _read_v2(
        target="RevPro Support",
        say_this="@RevPro Support, please start the version mismatch check and provide your status update.",
        blocker_type="awaiting_service_owner_status",
    ).model_copy(
        update={
            "incident_state": IncidentStateV2(
                incident_id="v2-test",
                active_humans=["Support Coordinator", "Raghunandan"],
                active_teams=["RevPro Support"],
                answered_questions=[
                    AnsweredQuestionV2(
                        question_text=(
                            "Raghunandan, could you please confirm if this is RevPro and whether we should "
                            "engage RevPro Support to own the mismatch check?"
                        ),
                        answer_summary=(
                            "This looks like a Zuora Revenue / RevPro deployment version mismatch. "
                            "Please engage RevPro Support to own the mismatch check."
                        ),
                        question_type="owner_routing",
                        asked_by="Support Coordinator",
                        answered_by="Raghunandan",
                        evidence_event_ids=["m001", "m002"],
                    )
                ],
            )
        }
    )

    quality = evaluate_incident_read_v2_quality(read_v2=read_v2, diagnosis_summary={"likely_failure_category": "none"})

    assert quality["usefulness_status"] == "pass"
    assert "visible_output_repeats_answered_question" not in quality["failed_reasons"]


def test_v2_target_punctuation_canonicalizes_to_allowed_target() -> None:
    read_v2 = _read_v2(target="Navneeth.", say_this="@Navneeth, can you confirm impacted tenant count?")
    read_v1 = incident_read_v2_to_incident_read(
        read_v2,
        context_pack={"candidate_targets": [{"target_id": "t001", "display_name": "Navneeth", "target_type": "person"}]},
        latest_window_events=[_event(message="Navneeth asked about impacted tenant count.")],
    )
    assert read_v1.selected_target_display_name == "Navneeth"
    assert read_v1.selected_target_id == "t001"


def test_v2_quality_degrades_when_diagnosis_has_failure_category() -> None:
    read_v2 = _read_v2()
    quality = evaluate_incident_read_v2_quality(
        read_v2=read_v2,
        diagnosis_summary={"likely_failure_category": "context_pack_lost_high_signal_diagnostic_evidence"},
    )
    assert quality["parser_quality_status"] == "degraded"
    assert quality["usefulness_status"] == "degraded"


def test_v2_state_and_blocker_schema_capture_open_questions() -> None:
    read_v2 = _read_v2()
    assert read_v2.incident_state.open_questions[0].question_type == "impact_scope"
    assert read_v2.next_blocker.blocker_type == "missing_impact_scope"
    assert read_v2.whisper.say_this.startswith("@Salim Thakkar")


def test_v2_context_pack_enforces_payload_budget_after_wrapper_fields() -> None:
    base_context_pack = {
        "incident_id": "large-v2",
        "context_pack_variant": "compact",
        "latest_window_events": [
            {
                "event_id": f"m{idx:03d}",
                "sequence": idx,
                "author": f"Human {idx}",
                "author_type": "human",
                "event_kind": "human_status_update",
                "planner_grounding_allowed": True,
                "text": "latest human update " + ("with repeated diagnostic context " * 80),
                "slack_mentions": [],
            }
            for idx in range(30)
        ],
        "candidate_targets": [
            {
                "target_id": f"t{idx:03d}",
                "display_name": f"Owner Team {idx}",
                "target_type": "team",
                "target_class": "service_owner",
                "role_hint": "owner_team",
                "source": "current_evidence",
                "latest_evidence_ids": [f"m{idx:03d}"],
                "why_visible": "visible owner " * 40,
            }
            for idx in range(30)
        ],
        "current_work_items": [{"work_item_label": "Validation", "status_or_action": "validate " * 90}],
        "retained_diagnostic_facts": [
            {"fact_id": f"fact_{idx}", "event_id": f"m{idx:03d}", "excerpt": "diagnostic " * 80}
            for idx in range(20)
        ],
        "detected_diagnostic_facts": [
            {"fact_id": f"detected_{idx}", "event_id": f"m{idx:03d}", "excerpt": "detected " * 80}
            for idx in range(20)
        ],
        "dropped_diagnostic_facts": [
            {"fact_id": f"dropped_{idx}", "event_id": f"m{idx:03d}", "excerpt": "dropped " * 80}
            for idx in range(20)
        ],
        "diagnostic_fact_classifications": [
            {"fact_id": f"fact_{idx}", "classification": "diagnostic " * 80}
            for idx in range(20)
        ],
        "accepted_memory_behavior_contracts": [
            {"decision_id": f"DM_{idx}", "behavior_hint": "hint " * 90}
            for idx in range(8)
        ],
        "action_state_transitions": [
            {"action_id": "a1", "final_state": "completed", "transitions": [{"quote": "quote " * 60}]}
        ],
        "answered_questions_from_actions": [
            {"question_event_id": "m001", "answer_summary": "completed " * 60}
        ],
        "do_not_ask_from_actions": ["confirm whether engineering was paged"],
        "do_not_target": [{"display_name": f"Noise {idx}", "reason": "noise " * 60} for idx in range(20)],
        "latest_window_selection": {"event_ids": [f"m{idx:03d}" for idx in range(30)]},
    }

    pack = build_incident_read_v2_context_pack(base_context_pack=base_context_pack, allowed_targets=[])

    assert pack["model_payload_over_cap"] is False
    assert pack["provider_payload_char_count"] <= pack["model_payload_hard_cap"]
    assert pack["context_budget_repacked"] is True
    assert pack["action_state_transitions"]


def test_v2_owner_routing_blocker_synonym_recovers_without_no_safe() -> None:
    payload = _read_v2(target="RevPro Support", say_this="@RevPro Support, can you confirm ownership?").model_dump(
        mode="json"
    )
    payload["next_blocker"]["blocker_type"] = "owner_routing"

    read_v2 = validate_with_repair(payload, IncidentReadAndWhisperV2, context="test_v2_owner_routing")

    assert read_v2.next_blocker.blocker_type == "missing_owner"
    assert read_v2.whisper.selected_move != "no_safe_recommendation"
    assert any("recovered_schema_synonym" in note for note in read_v2.safety_notes)


def test_v2_awaiting_owner_routing_blocker_synonym_recovers_without_no_safe() -> None:
    payload = _read_v2(target="Revenue Engineering", say_this="@Revenue Engineering, can you confirm ownership?").model_dump(
        mode="json"
    )
    payload["next_blocker"]["blocker_type"] = "awaiting_owner_routing"

    read_v2 = validate_with_repair(payload, IncidentReadAndWhisperV2, context="test_v2_awaiting_owner_routing")

    assert read_v2.next_blocker.blocker_type == "missing_owner"
    assert read_v2.whisper.selected_move != "no_safe_recommendation"
    assert any("recovered_schema_synonym" in note for note in read_v2.safety_notes)


def test_v2_extract_uses_schema_synonym_repair_from_client_dict() -> None:
    class Client:
        def generate_json(self, prompt_name, input_payload, response_model):
            del prompt_name, input_payload, response_model
            payload = _read_v2(
                target="RevPro Support",
                say_this="@RevPro Support, can you confirm ownership for the version mismatch?",
            ).model_dump(mode="json")
            payload["next_blocker"]["blocker_type"] = "owner_routing"
            return payload

    read_v2 = extract_incident_read_and_whisper_v2({"incident_id": "v2-test"}, Client())

    assert read_v2.next_blocker.blocker_type == "missing_owner"
    assert read_v2.whisper.selected_move != "no_safe_recommendation"
