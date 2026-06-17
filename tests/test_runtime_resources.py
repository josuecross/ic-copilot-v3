from __future__ import annotations

import pytest

from ic_copilot.product_knowledge import ProductKnowledgeError
from ic_copilot.runtime_config import ProductRuntimeConfig
from ic_copilot.runtime_resources import (
    load_product_catalog,
    load_product_command_registry,
    load_product_decision_moments,
)


def test_product_resources_load_product_knowledge_example() -> None:
    config = ProductRuntimeConfig.model_validate({"product_knowledge_path": "data/product_knowledge_example"})
    catalog = load_product_catalog(config)
    registry = load_product_command_registry(config, catalog)
    moments = load_product_decision_moments(config)
    assert {entry.service_id for entry in catalog}
    assert all(entry.requires_human_approval for entry in registry)
    assert {moment.decision_id for moment in moments}


def test_product_resources_fail_closed_when_local_knowledge_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = ProductRuntimeConfig()
    with pytest.raises(ProductKnowledgeError, match="Product knowledge folder is missing or invalid"):
        load_product_catalog(config)


def test_product_runtime_rejects_forbidden_knowledge_paths() -> None:
    for forbidden in (
        ".ic_copilot/personal_corpus",
        ".ic_copilot/artifact_staging",
        "data/generated",
        "data/corpus",
        "data/prompt_variants",
        "ic_copilot_previous_incidents_" + "_fake",
    ):
        with pytest.raises(ValueError):
            ProductRuntimeConfig.model_validate({"product_knowledge_path": forbidden})
