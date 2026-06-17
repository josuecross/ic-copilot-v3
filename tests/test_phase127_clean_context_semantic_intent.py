from __future__ import annotations

from pathlib import Path

from ic_copilot.clean_context import extract_clean_incident_context
from ic_copilot.extractor import extract_state_delta
from ic_copilot.incident_loader import load_incident_events
from ic_copilot.pipeline import run_pipeline
from ic_copilot.schemas import CurrentIncidentState, ICDecision, ICMove
from ic_copilot.semantic_intent import assess_output_intent, high_confidence_stale_matches
from ic_copilot.state_merge import merge_state_delta


SECURITY_FIXTURE = "data/personal_regression/incidents/p3_security_workflow_vulnerability_static.txt"


class _MinimalCleanContextClient:
    def generate_json(self, prompt_name, input_payload, response_model):
        if prompt_name in {"clean_incident_context_extractor", "semantic_intent_assessment"}:
            raise NotImplementedError
        if prompt_name == "state_delta_extractor":
            return {"incident_id": input_payload["incident_id"], "phase": "acknowledgement"}
        raise NotImplementedError


class _ObservationStalePlannerClient(_MinimalCleanContextClient):
    def generate_json(self, prompt_name, input_payload, response_model):
        if prompt_name in {
            "clean_incident_context_extractor",
            "semantic_intent_assessment",
            "state_delta_extractor",
        }:
            return super().generate_json(prompt_name, input_payload, response_model)
        return {
            "decision_id": "stale-observations-phase127",
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


def test_clean_context_extracts_security_incident_view_from_slack_paste() -> None:
    events = load_incident_events(SECURITY_FIXTURE, incident_id="p3_security_workflow")
    raw_text = Path(SECURITY_FIXTURE).read_text()
    context = extract_clean_incident_context(
        raw_text,
        events,
        CurrentIncidentState(incident_id="p3_security_workflow"),
        _MinimalCleanContextClient(),
    )
    assert context.phase.value == "engagement"
    assert context.current_blocker.blocker_type == "missing_validation"
    assert "request_details_from_researcher" in context.question_ledger.stale_question_intents
    assert any(entity.name == "Workflow" for entity in context.candidate_services)
    assert any(entity.text == "9863631" and entity.reason == "url_path_number" for entity in context.rejected_entities)
    assert any(entity.text == "Default_Agent" for entity in context.rejected_entities)


def test_state_delta_uses_clean_context_without_inventing_runtime_facts() -> None:
    events = load_incident_events(SECURITY_FIXTURE, incident_id="p3_security_workflow")
    base_state = CurrentIncidentState(incident_id="p3_security_workflow")
    client = _MinimalCleanContextClient()
    context = extract_clean_incident_context(Path(SECURITY_FIXTURE).read_text(), events, base_state, client)
    delta = extract_state_delta(events, base_state, client, clean_context=context)
    state = merge_state_delta(base_state, delta)
    assert state.phase == "engagement"
    assert state.current_blocker == "missing_validation"
    assert "request_details_from_researcher" in state.stale_question_intents
    assert {entity.display_name for entity in state.candidate_services}.issuperset({"Workflow", "Security"})
    assert "9863631" not in {fact.value for fact in state.impact.affected_tenants}


def test_semantic_intent_assessment_catches_stale_observations_paraphrase() -> None:
    events = load_incident_events(SECURITY_FIXTURE, incident_id="p3_security_workflow")
    base_state = CurrentIncidentState(incident_id="p3_security_workflow")
    client = _MinimalCleanContextClient()
    context = extract_clean_incident_context(Path(SECURITY_FIXTURE).read_text(), events, base_state, client)
    state = merge_state_delta(base_state, extract_state_delta(events, base_state, client, clean_context=context))
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
    assessment = assess_output_intent(decision, state, context, client)
    matches = high_confidence_stale_matches(assessment)
    assert matches
    assert matches[0].matched_stale_intent in context.question_ledger.stale_question_intents


def test_pipeline_records_clean_context_semantic_assessment_and_repair() -> None:
    result = run_pipeline(
        SECURITY_FIXTURE,
        catalog_path="data/product_knowledge_example/service_catalog.yaml",
        command_registry_path="data/product_knowledge_example/command_registry.yaml",
        memory_path="data/product_knowledge_example/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ObservationStalePlannerClient(),
    )
    assert result["trace"].processing_strategy in {"incident_read_and_whisper", "incident_read_and_whisper_v2"}
    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert result["trace"].clean_context is None
    assert result["trace"].semantic_intent_assessment is None
    assert result["trace"].safety_summary["legacy_debug_only"]
    assert result["trace"].repair_result["repair_used"] is False
    output = result["final_output"].lower()
    assert "model output did not validate cleanly" in output
