from __future__ import annotations

import pytest

from ic_copilot.llm.product_client import ProductConfigurationError
from ic_copilot.product_smoke import run_product_smoke
from ic_copilot.runtime_config import ProductRuntimeConfig
from tests.helpers import fixture_llm_client


def test_product_smoke_with_injected_fixture_client(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-" + "k" * 48)
    output = tmp_path / "smoke.json"
    payload = run_product_smoke(
        "data/sample/incidents/revpro_early_engage.txt",
        output_json=output,
        llm_client=fixture_llm_client(),
        knowledge_dir="data/product_knowledge_example",
    )
    assert payload["ok"] is True
    assert payload["verifier_passed"] is True
    assert output.exists()


def test_product_smoke_missing_provider_fails_closed(monkeypatch) -> None:
    monkeypatch.delenv("PHASE122_SMOKE_MISSING", raising=False)
    config = ProductRuntimeConfig.model_validate({"llm": {"api_key_env": "PHASE122_SMOKE_MISSING"}})
    with pytest.raises(ProductConfigurationError):
        from ic_copilot.pipeline import run_pipeline

        run_pipeline("data/sample/incidents/revpro_early_engage.txt", save_trace=False, runtime_config=config)
