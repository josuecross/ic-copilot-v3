from __future__ import annotations

import pytest

from ic_copilot.llm.fixture_client import FixtureLLMClient
from ic_copilot.llm.product_client import ProductConfigurationError, create_product_llm_client
from ic_copilot.llm.stub_client import ConfigurableStubLLMClient
from ic_copilot.runtime_config import ProductRuntimeConfig


def test_missing_openai_key_fails_closed(monkeypatch) -> None:
    monkeypatch.delenv("IC_COPILOT_MISSING_PRODUCT_KEY", raising=False)
    config = ProductRuntimeConfig.model_validate({"llm": {"api_key_env": "IC_COPILOT_MISSING_PRODUCT_KEY"}})
    with pytest.raises(ProductConfigurationError, match="IC_COPILOT_MISSING_PRODUCT_KEY is required"):
        create_product_llm_client(config)


def test_openai_product_client_created_with_key(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    client = create_product_llm_client(ProductRuntimeConfig())
    assert not isinstance(client, FixtureLLMClient)
    assert not isinstance(client, ConfigurableStubLLMClient)


def test_product_client_never_accepts_fixture_provider() -> None:
    with pytest.raises(Exception):
        ProductRuntimeConfig.model_validate({"llm": {"provider": "fixture"}})
