from __future__ import annotations

import json
import urllib.request
from typing import TypeVar

from pydantic import BaseModel

from ic_copilot.llm.config import LLMConfig
from ic_copilot.llm.providers.base_json import BaseJSONProviderClient


ModelT = TypeVar("ModelT", bound=BaseModel)


class LocalHTTPJSONClient(BaseJSONProviderClient):
    def __init__(self, config: LLMConfig, transport=None) -> None:
        super().__init__(config, transport)
        if not config.base_url and transport is None:
            raise RuntimeError("local_http provider requires base_url")

    def generate_json(self, prompt_name: str, input_payload: dict, response_model: type[ModelT]) -> ModelT:
        request_payload = self._request_payload(prompt_name, input_payload, response_model)
        if self.transport is not None:
            return self._validate(self.transport(request_payload), response_model)
        request = urllib.request.Request(
            self.config.base_url or "",
            data=json.dumps(request_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
            return self._validate(response.read().decode("utf-8"), response_model)
