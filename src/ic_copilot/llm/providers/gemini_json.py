from __future__ import annotations

import importlib
import os
from typing import TypeVar

from pydantic import BaseModel

from ic_copilot.llm.config import LLMConfig
from ic_copilot.llm.providers.base_json import BaseJSONProviderClient


ModelT = TypeVar("ModelT", bound=BaseModel)


class GeminiJSONClient(BaseJSONProviderClient):
    def __init__(self, config: LLMConfig, transport=None) -> None:
        super().__init__(config, transport)
        if config.api_key_env and not os.environ.get(config.api_key_env):
            raise RuntimeError(f"Missing API key environment variable: {config.api_key_env}")

    def generate_json(self, prompt_name: str, input_payload: dict, response_model: type[ModelT]) -> ModelT:
        request = self._request_payload(prompt_name, input_payload, response_model)
        if self.transport is not None:
            return self._validate(self.transport(request), response_model)
        try:
            genai = importlib.import_module("google.generativeai")
        except ImportError as exc:
            raise RuntimeError("Gemini SDK is not installed. Install optional provider dependencies first.") from exc
        genai.configure(api_key=os.environ.get(self.config.api_key_env or "GEMINI_API_KEY"))
        model = genai.GenerativeModel(self.config.model)
        response = model.generate_content(str(request))
        return self._validate(response.text, response_model)
