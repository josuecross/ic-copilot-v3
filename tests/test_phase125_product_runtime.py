from __future__ import annotations

import pytest

from ic_copilot.pipeline import run_pipeline
from ic_copilot.product_knowledge import ProductKnowledgeError
from ic_copilot.runtime_config import ProductRuntimeConfig
from tests.helpers import fixture_llm_client


def test_product_run_fails_closed_when_knowledge_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("ic_copilot.pipeline.create_product_llm_client", lambda config: fixture_llm_client())
    config = ProductRuntimeConfig.model_validate(
        {"llm": {"api_key_env": "OPENAI_API_KEY"}, "product_knowledge_path": str(tmp_path / "missing")}
    )
    with pytest.raises(ProductKnowledgeError, match="Product knowledge folder is missing or invalid"):
        run_pipeline("data/sample/incidents/revpro_early_engage.txt", save_trace=False, runtime_config=config)


def test_product_run_uses_product_knowledge_when_present(monkeypatch) -> None:
    monkeypatch.setattr("ic_copilot.pipeline.create_product_llm_client", lambda config: fixture_llm_client())
    config = ProductRuntimeConfig.model_validate({"product_knowledge_path": "data/product_knowledge_example"})
    result = run_pipeline("data/sample/incidents/revpro_early_engage.txt", save_trace=False, runtime_config=config)
    assert result["final_output"].startswith("SAY THIS:")
    assert result["trace"].command_registry_size > 0


def test_explicit_paths_still_work_without_product_knowledge() -> None:
    result = run_pipeline(
        "data/sample/incidents/revpro_early_engage.txt",
        catalog_path="data/sample/service_catalog.yaml",
        memory_path="data/sample/decision_moments",
        save_trace=False,
        llm_client=fixture_llm_client(),
    )
    assert result["final_output"].startswith("SAY THIS:")
