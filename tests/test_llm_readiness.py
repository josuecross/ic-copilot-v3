from __future__ import annotations

import pytest
from pydantic import ValidationError

from ic_copilot.extractor import extract_state_delta
from ic_copilot.llm import prompts
from ic_copilot.llm.fixture_client import FixtureLLMClient
from ic_copilot.normalizers.slack_paste import normalize_slack_paste_file
from ic_copilot.schemas import CurrentIncidentState, StateDelta


def test_fixture_llm_client_returns_pydantic_model_instance():
    events = normalize_slack_paste_file("data/sample/incidents/revpro_early_engage.txt")
    delta = extract_state_delta(events, CurrentIncidentState(incident_id="revpro"), FixtureLLMClient())
    assert isinstance(delta, StateDelta)
    assert delta.current_blocker == "missing_owner"


def test_generate_json_dict_output_must_validate_to_requested_model():
    class DictClient:
        def generate_json(self, prompt_name, input_payload, response_model):
            return {"incident_id": input_payload["incident_id"], "phase": "triage"}

    delta = extract_state_delta([], CurrentIncidentState(incident_id="i"), DictClient())
    assert isinstance(delta, StateDelta)
    assert delta.phase == "triage"


def test_invalid_llm_output_is_rejected():
    class BadClient:
        def generate_json(self, prompt_name, input_payload, response_model):
            return {"incident_id": input_payload["incident_id"], "phase": "not_a_phase"}

    with pytest.raises(ValidationError):
        extract_state_delta([], CurrentIncidentState(incident_id="i"), BadClient())


def test_prompt_contract_snapshots_keep_safety_language():
    assert "Every fact must have evidence" in prompts.STATE_DELTA_EXTRACTOR_PROMPT
    assert "Historical incidents provide behavior patterns, not current facts" in prompts.IC_PLANNER_PROMPT
    assert "Allowed move values" in prompts.IC_PLANNER_PROMPT
    assert "Do not invent a new move value" in prompts.IC_PLANNER_PROMPT
    assert "domain_intent" in prompts.IC_PLANNER_PROMPT
    assert "Do not invent facts" in prompts.VERIFIER_REPAIR_PROMPT


def test_fixture_client_has_no_network_provider_behavior():
    client = FixtureLLMClient()
    with pytest.raises(NotImplementedError):
        client.generate_json("unknown", {}, CurrentIncidentState)
