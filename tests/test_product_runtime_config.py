from __future__ import annotations

import pytest
import yaml

from ic_copilot.runtime_config import ProductRuntimeConfig, load_product_runtime_config


def test_builtin_product_config_defaults_are_real_ai_and_safe() -> None:
    config = ProductRuntimeConfig()
    assert config.llm.provider == "openai"
    assert config.llm.api_key_env == "OPENAI_API_KEY"
    assert config.runtime.command_execution_enabled is False
    assert config.runtime.slack_posting_enabled is False
    assert config.runtime.paging_enabled is False
    assert config.timeouts.total_run_timeout_seconds == 60
    assert config.timeouts.latest_window_brief_timeout_seconds == 20
    assert config.timeouts.latest_window_retry_timeout_seconds == 25
    assert config.timeouts.full_context_enrichment_timeout_seconds == 20
    assert config.timeouts.planner_timeout_seconds == 15
    payload = config.model_dump()
    assert "enabled" not in payload["llm"]
    assert "shadow" not in payload["llm"]
    assert "primary_disabled" not in payload["llm"]


def test_explicit_product_config_loads(tmp_path) -> None:
    path = tmp_path / "ic_copilot.local.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "llm": {"provider": "local_http", "model": "local", "api_key_env": "NONE", "base_url": "http://127.0.0.1:11434"},
                "runtime": {"command_execution_enabled": False, "slack_posting_enabled": False, "paging_enabled": False},
            }
        )
    )
    assert load_product_runtime_config(path).llm.provider == "local_http"


def test_invalid_provider_and_draft_runtime_path_rejected(tmp_path) -> None:
    bad_provider = tmp_path / "bad_provider.yaml"
    bad_provider.write_text("llm:\n  provider: fixture\n")
    with pytest.raises(Exception):
        load_product_runtime_config(bad_provider)

    draft_path = tmp_path / "draft.yaml"
    draft_path.write_text("product_knowledge_path: .ic_copilot/corrections/drafts\n")
    with pytest.raises(ValueError):
        load_product_runtime_config(draft_path)
