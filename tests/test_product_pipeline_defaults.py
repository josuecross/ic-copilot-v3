from __future__ import annotations

import pytest

from ic_copilot.llm.product_client import ProductConfigurationError
from ic_copilot.pipeline import run_pipeline
from ic_copilot.runtime_config import ProductRuntimeConfig
from tests.helpers import fixture_run_pipeline


def test_product_pipeline_without_key_fails_closed(monkeypatch) -> None:
    monkeypatch.delenv("IC_COPILOT_MISSING_PRODUCT_KEY", raising=False)
    config = ProductRuntimeConfig.model_validate({"llm": {"api_key_env": "IC_COPILOT_MISSING_PRODUCT_KEY"}})
    with pytest.raises(ProductConfigurationError, match="IC_COPILOT_MISSING_PRODUCT_KEY is required"):
        run_pipeline("data/sample/incidents/revpro_early_engage.txt", save_trace=False, runtime_config=config)


def test_fixture_pipeline_still_works_only_when_explicit() -> None:
    result = fixture_run_pipeline("data/sample/incidents/revpro_early_engage.txt", save_trace=False)
    assert result["final_output"].startswith("SAY THIS:")
    assert result["trace"].verifier_result.passed
