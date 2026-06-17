from __future__ import annotations

import os

from ic_copilot.env import maybe_load_local_env
from ic_copilot.llm.base import LLMClient
from ic_copilot.llm.config import LLMConfig, LLMProvider
from ic_copilot.llm.fixture_client import FixtureLLMClient
from ic_copilot.llm.stub_client import ConfigurableStubLLMClient


LIVE_PROVIDERS = {
    LLMProvider.OPENAI,
    LLMProvider.ANTHROPIC,
    LLMProvider.GEMINI,
}


def _require_api_key(config: LLMConfig, default_env: str) -> None:
    maybe_load_local_env()
    env_name = config.api_key_env or default_env
    if not os.environ.get(env_name):
        raise RuntimeError(f"Missing API key environment variable for {config.provider}: {env_name}")


def create_llm_client(config: LLMConfig) -> LLMClient:
    if config.provider == LLMProvider.FIXTURE:
        return FixtureLLMClient()
    if config.provider == LLMProvider.STUB:
        return ConfigurableStubLLMClient()
    if config.provider == LLMProvider.OPENAI:
        _require_api_key(config, "OPENAI_API_KEY")
        from ic_copilot.llm.providers.openai_json import OpenAIJSONClient

        return OpenAIJSONClient(config)
    if config.provider == LLMProvider.ANTHROPIC:
        _require_api_key(config, "ANTHROPIC_API_KEY")
        from ic_copilot.llm.providers.anthropic_json import AnthropicJSONClient

        return AnthropicJSONClient(config)
    if config.provider == LLMProvider.GEMINI:
        _require_api_key(config, "GEMINI_API_KEY")
        from ic_copilot.llm.providers.gemini_json import GeminiJSONClient

        return GeminiJSONClient(config)
    if config.provider == LLMProvider.LOCAL_HTTP:
        from ic_copilot.llm.providers.local_http_json import LocalHTTPJSONClient

        return LocalHTTPJSONClient(config)
    raise RuntimeError(f"Unsupported LLM provider: {config.provider}")
