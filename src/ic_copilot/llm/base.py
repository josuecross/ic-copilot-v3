from __future__ import annotations

from typing import Protocol, TypeVar

from pydantic import BaseModel

ModelT = TypeVar("ModelT", bound=BaseModel)


class LLMClient(Protocol):
    def generate_json(
        self,
        prompt_name: str,
        input_payload: dict,
        response_model: type[ModelT],
    ) -> ModelT:
        """Generate structured JSON compatible with ``response_model``."""

