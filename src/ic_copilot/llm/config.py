from __future__ import annotations

import os
from enum import Enum

from pydantic import Field

from ic_copilot.env import maybe_load_local_env
from ic_copilot.schemas import StrictBaseModel


class LLMProvider(str, Enum):
    FIXTURE = "fixture"
    STUB = "stub"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    LOCAL_HTTP = "local_http"


class LLMMode(str, Enum):
    PRIMARY_DISABLED = "primary_disabled"
    SHADOW = "shadow"
    PRODUCT = "product"


class LLMConfig(StrictBaseModel):
    provider: LLMProvider = LLMProvider.FIXTURE
    mode: LLMMode = LLMMode.PRIMARY_DISABLED
    model: str | None = None
    base_url: str | None = None
    api_key_env: str | None = None
    timeout_seconds: float = Field(default=30.0, ge=0.1)
    max_retries: int = Field(default=0, ge=0)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    enabled: bool = False
    redact_payload: bool = True
    fail_on_shadow_error: bool = False
    prompt_overrides: dict[str, str] = Field(default_factory=dict)
    prompt_variant_id: str | None = None
    prompt_variant_hash: str | None = None


def _bool_env(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _float_env(value: str | None, default: float) -> float:
    return default if value in {None, ""} else float(value)


def _int_env(value: str | None, default: int) -> int:
    return default if value in {None, ""} else int(value)


def load_llm_config_from_env(prefix: str = "IC_COPILOT_SHADOW_LLM_") -> LLMConfig:
    maybe_load_local_env()
    enabled = _bool_env(os.environ.get(f"{prefix}ENABLED"), False)
    provider = os.environ.get(f"{prefix}PROVIDER", "fixture")
    api_key_env = os.environ.get(f"{prefix}API_KEY_ENV") or None
    if provider == LLMProvider.OPENAI.value and api_key_env is None:
        api_key_env = "OPENAI_API_KEY"
    return LLMConfig(
        provider=provider,
        mode=LLMMode.SHADOW if enabled else LLMMode.PRIMARY_DISABLED,
        model=os.environ.get(f"{prefix}MODEL") or None,
        base_url=os.environ.get(f"{prefix}BASE_URL") or None,
        api_key_env=api_key_env,
        timeout_seconds=_float_env(os.environ.get(f"{prefix}TIMEOUT_SECONDS"), 30.0),
        max_retries=_int_env(os.environ.get(f"{prefix}MAX_RETRIES"), 0),
        temperature=_float_env(os.environ.get(f"{prefix}TEMPERATURE"), 0.0),
        enabled=enabled,
        redact_payload=_bool_env(os.environ.get(f"{prefix}REDACT_PAYLOAD"), True),
        fail_on_shadow_error=_bool_env(os.environ.get(f"{prefix}FAIL_ON_ERROR"), False),
    )
