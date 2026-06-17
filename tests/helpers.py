from __future__ import annotations

from pathlib import Path
from typing import Any

from ic_copilot.llm.fixture_client import FixtureLLMClient
from ic_copilot.pipeline import run_pipeline


def fixture_llm_client() -> FixtureLLMClient:
    return FixtureLLMClient()


def fixture_run_pipeline(
    incident_file: str | Path,
    catalog_path: str | Path = "data/sample/service_catalog.yaml",
    memory_dir: str | Path = "data/sample/decision_moments",
    command_registry_path: str | Path | None = None,
    save_trace: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    return run_pipeline(
        incident_file=incident_file,
        catalog_path=catalog_path,
        memory_path=memory_dir,
        command_registry_path=command_registry_path,
        save_trace=save_trace,
        llm_client=fixture_llm_client(),
        **kwargs,
    )
