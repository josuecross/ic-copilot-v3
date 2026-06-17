from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, model_validator

from ic_copilot.env import maybe_load_local_env
from ic_copilot.schemas import StrictBaseModel


class ProductLLMSettings(StrictBaseModel):
    provider: Literal["openai", "anthropic", "gemini", "local_http"] = "openai"
    model: str = "gpt-4.1-mini"
    api_key_env: str = "OPENAI_API_KEY"
    base_url: str | None = None
    timeout_seconds: float = Field(default=30.0, ge=0.1)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    redact_payload: bool = True


class RuntimeSafetySettings(StrictBaseModel):
    require_verifier_pass: bool = True
    fail_closed: bool = True
    command_execution_enabled: bool = False
    slack_posting_enabled: bool = False
    paging_enabled: bool = False


class RuntimeTimeoutSettings(StrictBaseModel):
    total_run_timeout_seconds: float = Field(default=60.0, ge=1.0)
    latest_window_brief_timeout_seconds: float = Field(default=20.0, ge=0.1)
    latest_window_retry_timeout_seconds: float = Field(default=25.0, ge=0.1)
    full_context_enrichment_timeout_seconds: float = Field(default=20.0, ge=0.1)
    clean_context_timeout_seconds: float = Field(default=20.0, ge=0.1)
    state_delta_timeout_seconds: float = Field(default=25.0, ge=0.1)
    sharp_blocker_timeout_seconds: float = Field(default=15.0, ge=0.1)
    planner_timeout_seconds: float = Field(default=15.0, ge=0.1)
    semantic_intent_timeout_seconds: float = Field(default=10.0, ge=0.1)
    repair_timeout_seconds: float = Field(default=10.0, ge=0.1)
    total_pipeline_soft_timeout_seconds: float = Field(default=60.0, ge=1.0)
    total_pipeline_hard_timeout_seconds: float = Field(default=75.0, ge=1.0)


class RuntimePaths(StrictBaseModel):
    catalog: str = "local_knowledge/service_catalog.yaml"
    command_registry: str = "local_knowledge/command_registry.yaml"
    memory: str = "local_knowledge/decision_moments.jsonl"


class ProductRuntimeConfig(StrictBaseModel):
    llm: ProductLLMSettings = Field(default_factory=ProductLLMSettings)
    runtime: RuntimeSafetySettings = Field(default_factory=RuntimeSafetySettings)
    timeouts: RuntimeTimeoutSettings = Field(default_factory=RuntimeTimeoutSettings)
    paths: RuntimePaths = Field(default_factory=RuntimePaths)
    product_knowledge_path: str = "local_knowledge"

    @model_validator(mode="after")
    def validate_runtime_safety(self) -> "ProductRuntimeConfig":
        validate_product_runtime_config(self)
        return self


def default_config_paths() -> list[Path]:
    paths: list[Path] = []
    env_path = os.environ.get("IC_COPILOT_CONFIG")
    if env_path:
        paths.append(Path(env_path))
    paths.append(Path("ic_copilot.local.yaml"))
    return paths


def load_product_runtime_config(path: str | Path | None = None) -> ProductRuntimeConfig:
    maybe_load_local_env()
    if path is not None:
        data = yaml.safe_load(Path(path).read_text()) or {}
        config = ProductRuntimeConfig.model_validate(data)
        validate_product_runtime_config(config)
        return config
    for candidate in default_config_paths():
        if candidate.exists():
            data = yaml.safe_load(candidate.read_text()) or {}
            config = ProductRuntimeConfig.model_validate(data)
            validate_product_runtime_config(config)
            return config
    config = ProductRuntimeConfig()
    validate_product_runtime_config(config)
    return config


def write_example_product_config(path: str | Path = "ic_copilot.local.example.yaml") -> Path:
    output = Path(path)
    config = ProductRuntimeConfig()
    output.write_text(yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False))
    return output


def validate_product_runtime_config(config: ProductRuntimeConfig) -> None:
    if config.runtime.command_execution_enabled:
        raise ValueError("command_execution_enabled must remain false for local personal product runs")
    if config.runtime.slack_posting_enabled:
        raise ValueError("slack_posting_enabled must remain false for local personal product runs")
    if config.runtime.paging_enabled:
        raise ValueError("paging_enabled must remain false for local personal product runs")
    for value in (
        config.product_knowledge_path,
        config.paths.catalog,
        config.paths.command_registry,
        config.paths.memory,
    ):
        normalized = Path(value).as_posix()
        if (
            "artifact_staging" in normalized
            or "corrections/drafts" in normalized
            or "personal_corpus" in normalized
            or "data/generated" in normalized
            or "data/dev_eval" in normalized
            or "data/corpus" in normalized
            or "data/prompt_variants" in normalized
            or "ic_copilot_previous_incidents__" in normalized
            or ".draft" in normalized
        ):
            raise ValueError(f"runtime paths may not load draft/staging/dev knowledge: {value}")


def product_provider_is_configured(config: ProductRuntimeConfig) -> bool:
    maybe_load_local_env()
    if config.llm.provider == "local_http":
        return bool(config.llm.base_url)
    return bool(os.environ.get(config.llm.api_key_env))
