from __future__ import annotations

import os

from ic_copilot.env import maybe_load_local_env
from ic_copilot.llm.base import LLMClient
from ic_copilot.llm.config import LLMConfig, LLMMode, LLMProvider
from ic_copilot.runtime_config import ProductRuntimeConfig


class ProductConfigurationError(RuntimeError):
    pass


def require_product_provider_ready(config: ProductRuntimeConfig) -> None:
    maybe_load_local_env()
    if config.llm.provider == "local_http":
        if not config.llm.base_url:
            raise ProductConfigurationError("local_http product runs require llm.base_url in ic_copilot.local.yaml.")
        return
    if not os.environ.get(config.llm.api_key_env):
        raise ProductConfigurationError(
            f"{config.llm.api_key_env} is required for normal IC Copilot product runs. "
            "Set it in .env or your shell. FixtureLLMClient is test/eval only."
        )


def _provider(value: str) -> LLMProvider:
    return {
        "openai": LLMProvider.OPENAI,
        "anthropic": LLMProvider.ANTHROPIC,
        "gemini": LLMProvider.GEMINI,
        "local_http": LLMProvider.LOCAL_HTTP,
    }[value]


def create_product_llm_client(config: ProductRuntimeConfig) -> LLMClient:
    require_product_provider_ready(config)
    llm_config = LLMConfig(
        provider=_provider(config.llm.provider),
        mode=LLMMode.PRODUCT,
        model=config.llm.model,
        base_url=config.llm.base_url,
        api_key_env=config.llm.api_key_env,
        timeout_seconds=config.llm.timeout_seconds,
        temperature=config.llm.temperature,
        enabled=True,
        redact_payload=config.llm.redact_payload,
        fail_on_shadow_error=False,
    )
    if config.llm.provider == "openai":
        from ic_copilot.llm.providers.openai_json import OpenAIJSONClient

        return OpenAIJSONClient(llm_config)
    if config.llm.provider == "anthropic":
        from ic_copilot.llm.providers.anthropic_json import AnthropicJSONClient

        return AnthropicJSONClient(llm_config)
    if config.llm.provider == "gemini":
        from ic_copilot.llm.providers.gemini_json import GeminiJSONClient

        return GeminiJSONClient(llm_config)
    if config.llm.provider == "local_http":
        from ic_copilot.llm.providers.local_http_json import LocalHTTPJSONClient

        return LocalHTTPJSONClient(llm_config)
    raise ProductConfigurationError(f"Unsupported product LLM provider: {config.llm.provider}")
