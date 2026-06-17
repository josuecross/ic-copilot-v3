from __future__ import annotations

from pathlib import Path

from ic_copilot.extractor import extract_state_delta
from ic_copilot.incident_loader import load_incident_events
from ic_copilot.catalog import load_service_catalog
from ic_copilot.normalizers.slack_paste import normalize_slack_paste
from ic_copilot.pipeline import run_pipeline
from ic_copilot.planner import plan_ic_decision
from ic_copilot.decision_repair import repair_blocked_decision
from ic_copilot.schema_repair import ModelOutputValidationError, normalize_move, validate_with_repair
from ic_copilot.schemas import CurrentIncidentState, ICDecision, ICMove
from ic_copilot.state_merge import merge_state_delta
from ic_copilot.verifier import detect_stale_question, detect_stale_question_findings, verify_ic_decision
from ic_copilot.web.app import _debug_summary_from_run


SECURITY_FIXTURE = "data/personal_regression/incidents/p3_security_workflow_vulnerability_static.txt"


class _SecurityStateClient:
    def generate_json(self, prompt_name, input_payload, _response_model):
        if prompt_name in {"clean_incident_context_extractor", "semantic_intent_assessment"}:
            raise NotImplementedError
        if prompt_name == "state_delta_extractor":
            return {
                "incident_id": input_payload["incident_id"],
                "phase": "acknowledgement",
                "compact_summary": "P3 security vulnerability in Workflow product.",
            }
        return {
            "decision_id": "security-details",
            "incident_id": input_payload["current_state"]["incident_id"],
            "move": "request_details_from_researcher",
            "phase": "investigation",
            "output": {
                "say_this": "The reporter details are already linked; keep the bridge on ownership and validation.",
                "next_line": "Security/Workflow DRI, please confirm owner, exposure scope, containment, and next validation step.",
            },
        }


class _UnknownMoveClient(_SecurityStateClient):
    def generate_json(self, prompt_name, input_payload, response_model):
        if prompt_name in {"state_delta_extractor", "clean_incident_context_extractor", "semantic_intent_assessment"}:
            return super().generate_json(prompt_name, input_payload, response_model)
        return {
            "decision_id": "unknown-move",
            "incident_id": input_payload["current_state"]["incident_id"],
            "move": "totally_new_security_move",
            "phase": "investigation",
            "output": {"say_this": "This invented move should not fail the whole run."},
        }


class _StaleDetailsDecisionClient(_SecurityStateClient):
    def generate_json(self, prompt_name, input_payload, response_model):
        if prompt_name in {"state_delta_extractor", "clean_incident_context_extractor", "semantic_intent_assessment"}:
            return super().generate_json(prompt_name, input_payload, response_model)
        return {
            "decision_id": "stale-details",
            "incident_id": input_payload["current_state"]["incident_id"],
            "move": "request_details_from_researcher",
            "phase": "engagement",
            "output": {
                "say_this": "Bimodh, can you share more details from the researcher?",
                "next_line": "Please provide the vulnerability details.",
            },
        }


class _ObservationStaleDecisionClient(_SecurityStateClient):
    def generate_json(self, prompt_name, input_payload, response_model):
        if prompt_name in {"state_delta_extractor", "clean_incident_context_extractor", "semantic_intent_assessment"}:
            return super().generate_json(prompt_name, input_payload, response_model)
        return {
            "decision_id": "stale-observations",
            "incident_id": input_payload["current_state"]["incident_id"],
            "move": "ask_next_validation",
            "phase": "engagement",
            "output": {
                "say_this": (
                    "Hi Bimodh, could you please provide your observations and the next proposed actions "
                    "regarding the reported vulnerability?"
                )
            },
        }


class _PollutedSecurityStateClient(_SecurityStateClient):
    def generate_json(self, prompt_name, input_payload, response_model):
        if prompt_name in {"clean_incident_context_extractor", "semantic_intent_assessment"}:
            return super().generate_json(prompt_name, input_payload, response_model)
        if prompt_name != "state_delta_extractor":
            return super().generate_json(prompt_name, input_payload, response_model)
        return {
            "incident_id": input_payload["incident_id"],
            "phase": "engagement",
            "compact_summary": "P3 security vulnerability in Workflow product.",
            "engaged_entities": [
                {"entity_type": "person", "display_name": "APP", "status": "active"},
                {"entity_type": "person", "display_name": "Phase Update", "status": "active"},
                {"entity_type": "person", "display_name": "Bimodh", "status": "active"},
            ],
        }


def _security_state() -> CurrentIncidentState:
    events = load_incident_events(SECURITY_FIXTURE, incident_id="p3_security_workflow")
    delta = extract_state_delta(events, CurrentIncidentState(incident_id="p3_security_workflow"), _SecurityStateClient())
    return merge_state_delta(CurrentIncidentState(incident_id="p3_security_workflow"), delta)


def test_request_details_from_researcher_repairs_and_preserves_domain_intent() -> None:
    assert normalize_move("request_details_from_researcher") == "ask_next_validation"
    decision = validate_with_repair(
        {
            "decision_id": "d1",
            "incident_id": "security",
            "move": "request_details_from_researcher",
            "phase": "investigation",
            "output": {"say_this": "Keep the IC focused on the next validation step."},
        },
        ICDecision,
        context="test",
    )
    assert decision.move == ICMove.ASK_NEXT_VALIDATION
    assert decision.domain_intent == "request_details_from_researcher"
    assert decision.model_metadata["original_move"] == "request_details_from_researcher"


def test_security_move_aliases_map_to_canonical_ic_moves() -> None:
    assert normalize_move("request_vulnerability_scope") == "ask_impact"
    assert normalize_move("request_containment_plan") == "request_mitigation_option"
    assert normalize_move("confirm_security_owner") == "confirm_ownership"
    assert normalize_move("engage_security_owner") == "engage_owner"


def test_unknown_move_raises_controlled_model_output_error() -> None:
    try:
        validate_with_repair(
            {
                "decision_id": "d2",
                "incident_id": "security",
                "move": "unknown_weird_move",
                "phase": "investigation",
                "output": {"say_this": "No raw pydantic traceback should be product-facing."},
            },
            ICDecision,
            context="test",
        )
    except ModelOutputValidationError as exc:
        assert exc.original_move == "unknown_weird_move"
    else:
        raise AssertionError("unsupported move should raise controlled validation error")


def test_planner_unknown_move_uses_deterministic_fallback_not_failure() -> None:
    decision = plan_ic_decision(
        CurrentIncidentState(incident_id="security", phase="investigation"),
        [],
        [],
        llm_client=_UnknownMoveClient(),
        command_registry=[],
    )
    assert decision.move == ICMove.NO_SAFE_RECOMMENDATION
    assert decision.domain_intent == "totally_new_security_move"
    assert decision.model_metadata["planner_fallback_used"] is True
    assert "totally_new_security_move" in decision.model_metadata["planner_validation_error"]


def test_security_static_fixture_marks_details_ask_stale_and_rejects_noise() -> None:
    events = load_incident_events(SECURITY_FIXTURE, incident_id="p3_security_workflow")
    delta = extract_state_delta(events, CurrentIncidentState(incident_id="p3_security_workflow"), _SecurityStateClient())
    state = merge_state_delta(CurrentIncidentState(incident_id="p3_security_workflow"), delta)
    rejected = {entity.display_name for entity in state.rejected_entities}
    rejected_status = {entity.display_name: entity.status for entity in state.rejected_entities}
    candidates = {entity.display_name for entity in state.candidate_services}
    assert "request_details_from_researcher" in state.stale_question_intents
    assert "request_observations" in state.stale_question_intents
    assert "request_next_actions_from_reporter" in state.stale_question_intents
    assert any(question.intent == "request_details_from_researcher" for question in state.answered_questions)
    assert {"Workflow", "Security"}.issubset(candidates)
    assert "9863631" in rejected
    assert "Default_Agent" in rejected
    assert rejected_status["9863631"] == "rejected:url_path_number"
    assert rejected_status["10846"] == "rejected:jira_issue_number_not_tenant"
    assert state.current_blocker == "missing_validation"


def test_semantic_stale_details_detector_blocks_paraphrases_after_link() -> None:
    state = _security_state()
    blocked_phrases = [
        "Hi Bimodh, could you please provide your observations and the next proposed actions regarding the reported vulnerability?",
        "Can you share more details from the researcher report?",
        "What are your observations on the reported vulnerability?",
        "Please provide the vulnerability details.",
    ]
    for phrase in blocked_phrases:
        findings = detect_stale_question_findings(phrase, state)
        assert findings, phrase
        assert findings[0]["matched_family"] == "details_request"
    assert not detect_stale_question("Can we confirm exposure scope?", state)
    assert not detect_stale_question("Can we confirm the containment plan?", state)
    assert not detect_stale_question("Can we confirm the next validation step?", state)
    assert not detect_stale_question("Can we confirm the Workflow/Security owner?", state)


def test_verifier_blocks_stale_researcher_details_after_link() -> None:
    events = load_incident_events(SECURITY_FIXTURE, incident_id="p3_security_workflow")
    delta = extract_state_delta(events, CurrentIncidentState(incident_id="p3_security_workflow"), _SecurityStateClient())
    state = merge_state_delta(CurrentIncidentState(incident_id="p3_security_workflow"), delta)
    decision = ICDecision(
        decision_id="d-stale-details",
        incident_id="p3_security_workflow",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase="investigation",
        output={"say_this": "Bimodh, can you share more details from the researcher?"},
    )
    result = verify_ic_decision(decision, state, catalog=[], accepted_memories=[], command_registry=[])
    assert not result.passed
    assert any("request_details_from_researcher" in claim for claim in result.blocked_claims)


def test_verifier_blocks_exact_bimodh_observations_next_actions_output() -> None:
    state = _security_state()
    decision = ICDecision(
        decision_id="d-stale-observations",
        incident_id="p3_security_workflow",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase="engagement",
        output={
            "say_this": (
                "Hi Bimodh, could you please provide your observations and the next proposed actions "
                "regarding the reported vulnerability?"
            )
        },
    )
    result = verify_ic_decision(decision, state, catalog=[], accepted_memories=[], command_registry=[])
    assert not result.passed
    assert result.final_status == "fallback_required"
    assert any("details_request" in claim for claim in result.blocked_claims)
    assert any("provide your observations" in claim for claim in result.blocked_claims)


def test_verifier_blocks_mixed_validation_and_additional_details_ask_after_link() -> None:
    events = load_incident_events(SECURITY_FIXTURE, incident_id="p3_security_workflow")
    delta = extract_state_delta(events, CurrentIncidentState(incident_id="p3_security_workflow"), _SecurityStateClient())
    state = merge_state_delta(CurrentIncidentState(incident_id="p3_security_workflow"), delta)
    decision = ICDecision(
        decision_id="d-mixed-stale-details",
        incident_id="p3_security_workflow",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase="engagement",
        output={
            "say_this": (
                "Bimodh, please provide the next validation steps or additional details from the researcher report."
            )
        },
    )
    result = verify_ic_decision(decision, state, catalog=[], accepted_memories=[], command_registry=[])
    assert not result.passed
    assert any("request_details_from_researcher" in claim for claim in result.blocked_claims)


def test_security_details_ask_allowed_when_details_are_missing() -> None:
    state = CurrentIncidentState(incident_id="security", phase="investigation")
    decision = ICDecision(
        decision_id="d-details-ok",
        incident_id="security",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase="investigation",
        output={"say_this": "Security reporter, can you share more details from the vulnerability report?"},
    )
    result = verify_ic_decision(decision, state, catalog=[], accepted_memories=[], command_registry=[])
    assert result.checks["no_stale_question"]


def test_verifier_guided_repair_turns_stale_details_into_useful_next_move() -> None:
    events = load_incident_events(SECURITY_FIXTURE, incident_id="p3_security_workflow")
    delta = extract_state_delta(events, CurrentIncidentState(incident_id="p3_security_workflow"), _SecurityStateClient())
    state = merge_state_delta(CurrentIncidentState(incident_id="p3_security_workflow"), delta)
    original = ICDecision(
        decision_id="d-stale",
        incident_id="p3_security_workflow",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase="engagement",
        domain_intent="request_details_from_researcher",
        output={"say_this": "Bimodh, can you share more details from the researcher?"},
    )
    blocked = verify_ic_decision(original, state, catalog=[], accepted_memories=[], command_registry=[])
    repaired = repair_blocked_decision(original, blocked, state, [], [], [])
    assert repaired is not None
    assert repaired.move == ICMove.ASK_NEXT_VALIDATION
    assert "details link has already been provided" in repaired.output["say_this"]
    assert "exposure scope" in repaired.output["next_line"]
    assert "containment or validation" in repaired.output["next_line"]
    repaired_verifier = verify_ic_decision(repaired, state, catalog=[], accepted_memories=[], command_registry=[])
    assert repaired_verifier.passed


def test_verifier_guided_repair_turns_observations_next_actions_into_security_next_step() -> None:
    state = _security_state()
    original = ICDecision(
        decision_id="d-stale-observations",
        incident_id="p3_security_workflow",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase="engagement",
        output={
            "say_this": (
                "Hi Bimodh, could you please provide your observations and the next proposed actions "
                "regarding the reported vulnerability?"
            )
        },
    )
    blocked = verify_ic_decision(original, state, catalog=[], accepted_memories=[], command_registry=[])
    repaired = repair_blocked_decision(original, blocked, state, [], [], [])
    assert repaired is not None
    assert repaired.move == ICMove.ASK_NEXT_VALIDATION
    output = f"{repaired.output['say_this']} {repaired.output['next_line']}".lower()
    assert "details link has already been provided" in output
    assert "owner" in output
    assert "exposure scope" in output
    assert "containment or validation" in output
    assert "observations" not in output
    assert "proposed actions" not in output
    assert verify_ic_decision(repaired, state, catalog=[], accepted_memories=[], command_registry=[]).passed


def test_verifier_guided_repair_replaces_ungrounded_catalog_service_drift() -> None:
    events = load_incident_events(SECURITY_FIXTURE, incident_id="p3_security_workflow")
    delta = extract_state_delta(events, CurrentIncidentState(incident_id="p3_security_workflow"), _SecurityStateClient())
    state = merge_state_delta(CurrentIncidentState(incident_id="p3_security_workflow"), delta)
    catalog = load_service_catalog("local_knowledge/service_catalog.yaml")
    original = ICDecision(
        decision_id="d-service-drift",
        incident_id="p3_security_workflow",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase="engagement",
        output={
            "say_this": "Looks like OCM/commerce-catalog is already engaged.",
            "next_line": "Praneeth or OCM owner, can you confirm deployment validation?",
        },
    )
    blocked = verify_ic_decision(original, state, catalog=catalog, accepted_memories=[], command_registry=[])
    assert not blocked.passed
    assert any("ungrounded catalog service claim" in claim for claim in blocked.blocked_claims)
    repaired = repair_blocked_decision(original, blocked, state, [], [], [])
    assert repaired is not None
    assert repaired.model_metadata["repair_reason"] == "ungrounded_service_repair"
    assert "Workflow" in repaired.output["say_this"]
    assert "OCM" not in repaired.output["say_this"]
    repaired_verifier = verify_ic_decision(repaired, state, catalog=catalog, accepted_memories=[], command_registry=[])
    assert repaired_verifier.passed


def test_verifier_guided_repair_handles_blocked_security_owner_confirmation() -> None:
    events = load_incident_events(SECURITY_FIXTURE, incident_id="p3_security_workflow")
    delta = extract_state_delta(events, CurrentIncidentState(incident_id="p3_security_workflow"), _SecurityStateClient())
    state = merge_state_delta(CurrentIncidentState(incident_id="p3_security_workflow"), delta)
    original = ICDecision(
        decision_id="d-owner-blocked",
        incident_id="p3_security_workflow",
        move=ICMove.CONFIRM_OWNERSHIP,
        phase="engagement",
        output={
            "say_this": (
                "Workflow/Security DRI, please confirm the exposure scope, containment status, and next "
                "validation steps."
            )
        },
        targets=[state.engaged_entities[-1]],
    )
    blocked = verify_ic_decision(original, state, catalog=[], accepted_memories=[], command_registry=[])
    assert not blocked.passed
    repaired = repair_blocked_decision(original, blocked, state, [], [], [])
    assert repaired is not None
    assert repaired.model_metadata["repair_reason"] == "blocked_security_next_move_repair"
    assert "details link has already been provided" in repaired.output["say_this"]
    assert verify_ic_decision(repaired, state, catalog=[], accepted_memories=[], command_registry=[]).passed


def test_empty_unknown_state_allows_no_safe_recommendation() -> None:
    state = CurrentIncidentState(incident_id="empty")
    original = ICDecision(
        decision_id="d-empty",
        incident_id="empty",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase="unknown",
        output={"say_this": "Can you share more details?"},
    )
    blocked = verify_ic_decision(original, state, catalog=[], accepted_memories=[], command_registry=[])
    assert repair_blocked_decision(original, blocked, state, [], [], []) is None


def test_security_static_pipeline_uses_fallback_for_unknown_move_without_crashing() -> None:
    result = run_pipeline(
        SECURITY_FIXTURE,
        catalog_path="data/product_knowledge_example/service_catalog.yaml",
        command_registry_path="data/product_knowledge_example/command_registry.yaml",
        memory_path="data/product_knowledge_example/decision_moments.jsonl",
        save_trace=False,
        llm_client=_UnknownMoveClient(),
    )
    assert result["final_output"]
    assert result["trace"].processing_strategy in {"incident_read_and_whisper", "incident_read_and_whisper_v2"}
    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert result["trace"].safety_summary["repair_used"] is False
    assert result["trace"].safety_summary["why_no_safe_recommendation"]
    assert result["trace"].safety_summary["processing_warnings"]


def test_security_static_pipeline_repairs_stale_details_instead_of_no_safe() -> None:
    result = run_pipeline(
        SECURITY_FIXTURE,
        catalog_path="data/product_knowledge_example/service_catalog.yaml",
        command_registry_path="data/product_knowledge_example/command_registry.yaml",
        memory_path="data/product_knowledge_example/decision_moments.jsonl",
        save_trace=False,
        llm_client=_StaleDetailsDecisionClient(),
    )
    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert result["verifier_result"].passed
    assert result["trace"].safety_summary["repair_used"] is False
    assert result["trace"].safety_summary["processing_warnings"]
    assert "model output did not validate cleanly" in result["final_output"].lower()


def test_security_static_pipeline_repairs_observations_next_actions_instead_of_no_safe() -> None:
    result = run_pipeline(
        SECURITY_FIXTURE,
        catalog_path="data/product_knowledge_example/service_catalog.yaml",
        command_registry_path="data/product_knowledge_example/command_registry.yaml",
        memory_path="data/product_knowledge_example/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ObservationStaleDecisionClient(),
    )
    output = result["final_output"].lower()
    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert result["verifier_result"].passed
    assert result["trace"].safety_summary["repair_used"] is False
    assert "model output did not validate cleanly" in output


def test_security_static_filters_system_labels_from_engaged_entities() -> None:
    events = load_incident_events(SECURITY_FIXTURE, incident_id="p3_security_workflow")
    delta = extract_state_delta(
        events,
        CurrentIncidentState(incident_id="p3_security_workflow"),
        _PollutedSecurityStateClient(),
    )
    state = merge_state_delta(CurrentIncidentState(incident_id="p3_security_workflow"), delta)
    engaged = {entity.display_name for entity in state.engaged_entities}
    assert "APP" not in engaged
    assert "Phase Update" not in engaged
    assert "Bimodh" in engaged


def test_debug_summary_includes_rejected_entity_reason() -> None:
    result = run_pipeline(
        SECURITY_FIXTURE,
        catalog_path="data/product_knowledge_example/service_catalog.yaml",
        command_registry_path="data/product_knowledge_example/command_registry.yaml",
        memory_path="data/product_knowledge_example/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ObservationStaleDecisionClient(),
    )
    trace = result["trace"].model_dump(mode="json")
    summary = _debug_summary_from_run(
        {
            "run_id": "debug-security",
            "status": "completed",
            "result_json": {
                "trace": trace,
                "state": result["state"].model_dump(mode="json"),
                "verifier_result": result["verifier_result"].model_dump(mode="json"),
                "decision": result["decision"].model_dump(mode="json"),
                "raw_decision": result["raw_decision"].model_dump(mode="json"),
            },
        }
    )
    rejected = {item["display_name"] for item in summary["rejected_targets"]}
    assert "9863631" in rejected
    assert "Default_Agent" in rejected


def test_security_static_normalizer_does_not_treat_bot_lifecycle_as_command() -> None:
    text = Path(SECURITY_FIXTURE).read_text()
    events = normalize_slack_paste(text, incident_id="p3_security_workflow")
    assert len(events) >= 6
    assert events[0].source == "slack_system"
    assert events[0].extracted_tokens["command_candidates"] == []
    assert events[1].source == "slack_system"
    assert events[1].extracted_tokens["command_candidates"] == []
    assert any("could you please share more details" in event.message for event in events)
    assert any("WF-10846" in event.message for event in events)
    assert any("Default_Agent" in event.message for event in events)


def test_slack_copy_author_time_split_becomes_separate_events() -> None:
    events = normalize_slack_paste(
        "IC Bot APP 10:01 AM\n"
        "created this channel\n"
        "Bimodh\n"
        "10:06 AM\n"
        "Details are in WF issue WF-10846: https://jira.example.invalid/browse/WF-10846\n"
        "Leo APP 10:08 AM\n"
        "I can help coordinate owner confirmation.",
        incident_id="split_security",
    )
    assert [event.author for event in events] == ["IC Bot", "Bimodh", "Leo"]
    assert events[0].source == "slack_system"
    assert events[1].message.startswith("Details are in WF issue")
