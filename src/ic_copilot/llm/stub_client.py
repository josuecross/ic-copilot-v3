from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from pydantic import BaseModel

from ic_copilot.llm.fixture_client import FixtureLLMClient
from ic_copilot.schemas import ICDecision, ICMove, IncidentPhase


ModelT = TypeVar("ModelT", bound=BaseModel)
StubResponse = dict[str, Any] | BaseModel | Callable[[str, dict[str, Any], type[BaseModel]], Any]


class ConfigurableStubLLMClient:
    """Deterministic test client for shadow mode.

    When no response is configured for a prompt, it delegates to FixtureLLMClient so CLI smoke
    tests can exercise the full shadow path without network or API keys.
    """

    def __init__(
        self,
        responses: dict[str, StubResponse] | None = None,
        *,
        fallback_to_fixture: bool = True,
    ) -> None:
        self.responses = responses or {}
        self.fallback_to_fixture = fallback_to_fixture
        self.fixture = FixtureLLMClient()
        self.calls: list[dict[str, Any]] = []

    def generate_json(
        self,
        prompt_name: str,
        input_payload: dict,
        response_model: type[ModelT],
    ) -> ModelT:
        self.calls.append(
            {
                "prompt_name": prompt_name,
                "input_payload": input_payload,
                "response_model": response_model.__name__,
            }
        )
        if prompt_name not in self.responses:
            if self.fallback_to_fixture:
                try:
                    return self.fixture.generate_json(prompt_name, input_payload, response_model)
                except NotImplementedError:
                    if response_model is ICDecision or response_model.__name__ == "ICDecision":
                        state = input_payload.get("current_state", {})
                        return response_model.model_validate(
                            {
                                "decision_id": "stub-no-safe-recommendation",
                                "incident_id": state.get("incident_id", "shadow-stub"),
                                "move": ICMove.NO_SAFE_RECOMMENDATION,
                                "phase": state.get("phase", IncidentPhase.UNKNOWN),
                                "output": {"say_this": "I do not have a safe, grounded next move yet."},
                                "targets": [],
                                "rationale": ["Stub fallback used for shadow-only planning."],
                                "confidence": 0.2,
                            }
                        )
                    raise
            raise RuntimeError(f"No stub response configured for prompt={prompt_name}")

        response = self.responses[prompt_name]
        if callable(response):
            response = response(prompt_name, input_payload, response_model)
        if isinstance(response, BaseModel):
            return response_model.model_validate(response.model_dump())
        return response_model.model_validate(response)
