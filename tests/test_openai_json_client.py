from __future__ import annotations

import json

import pytest

from ic_copilot.llm.config import LLMConfig
from ic_copilot.llm.providers.base_json import ProviderJSONError
from ic_copilot.llm.providers.openai_json import DEFAULT_OPENAI_SHADOW_MODEL, OpenAIJSONClient
from ic_copilot.schemas import ICDecision, StateDelta


def test_openai_client_uses_structured_messages_for_state_delta():
    captured = {}

    def transport(request):
        captured.update(request)
        return {
            "output": {"incident_id": "revpro_early_engage", "phase": "triage"},
            "id": "resp_123",
            "model": "fake-model",
            "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        }

    client = OpenAIJSONClient(LLMConfig(provider="openai", model="fake-model"), transport=transport)
    delta = client.generate_json("state_delta_extractor", {"api_key": "secret"}, StateDelta)
    assert delta.incident_id == "revpro_early_engage"
    assert captured["model"] == "fake-model"
    assert isinstance(captured["input"], list)
    assert "Every fact must have evidence" in captured["input"][0]["content"]
    assert "Do not infer customers from URLs" in captured["input"][0]["content"]
    assert "secret" not in json.dumps(captured)
    assert captured["text"]["format"]["type"] == "json_schema"
    assert client.last_response_metadata["provider_response_id"] == "resp_123"
    assert client.last_response_metadata["total_tokens"] == 15


def test_openai_client_defaults_model_and_validates_ic_decision():
    def transport(request):
        assert request["model"] == DEFAULT_OPENAI_SHADOW_MODEL
        assert "historical incidents provide behavior patterns" in request["input"][0]["content"].lower()
        return {
            "output": {
                "decision_id": "d1",
                "incident_id": "i1",
                "move": "no_safe_recommendation",
                "phase": "triage",
                "output": {"say_this": "I do not have a safe, grounded next move yet."},
            }
        }

    client = OpenAIJSONClient(LLMConfig(provider="openai"), transport=transport)
    decision = client.generate_json("ic_planner", {"current_state": {"incident_id": "i1"}}, ICDecision)
    assert decision.decision_id == "d1"
    assert decision.move == "no_safe_recommendation"


def test_openai_invalid_json_and_schema_errors_are_clear():
    invalid_json_client = OpenAIJSONClient(
        LLMConfig(provider="openai"),
        transport=lambda _request: "not-json",
    )
    with pytest.raises(ProviderJSONError, match="invalid JSON"):
        invalid_json_client.generate_json("state_delta_extractor", {}, StateDelta)

    invalid_schema_client = OpenAIJSONClient(
        LLMConfig(provider="openai"),
        transport=lambda _request: {"output": {"incident_id": "i", "phase": "bad_phase"}},
    )
    with pytest.raises(Exception, match="phase"):
        invalid_schema_client.generate_json("state_delta_extractor", {}, StateDelta)


def test_openai_messages_do_not_include_api_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-very-secret")
    captured = {}

    def transport(request):
        captured.update(request)
        return {"output": {"incident_id": "i"}}

    client = OpenAIJSONClient(LLMConfig(provider="openai", api_key_env="OPENAI_API_KEY"), transport=transport)
    client.generate_json("state_delta_extractor", {"authorization": "Bearer sk-very-secret"}, StateDelta)
    text = json.dumps(captured)
    assert "sk-very-secret" not in text
    assert "[REDACTED]" in text
