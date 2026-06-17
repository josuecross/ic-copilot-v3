from __future__ import annotations

import pytest

from ic_copilot.web.pipeline_events import STEP_ORDER, run_pipeline_with_progress
from tests.helpers import fixture_llm_client


def test_run_pipeline_with_progress_emits_core_steps(tmp_path):
    events = []
    result = run_pipeline_with_progress(
        incident_file="data/sample/incidents/revpro_early_engage.txt",
        catalog_path="data/contract/service_catalog.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        command_registry_path="data/contract/command_registry.yaml",
        save_trace=False,
        on_event=events.append,
        run_id="run-test",
        llm_client=fixture_llm_client(),
    )

    terminal = {event.step: event for event in events if event.status in {"succeeded", "skipped"}}
    for step in STEP_ORDER:
        assert step in terminal
    assert result["trace"].trace_id
    assert terminal["complete"].status == "succeeded"
    assert terminal["normalize_input"].elapsed_ms is not None


def test_run_pipeline_with_progress_failed_step_emits_failed(tmp_path):
    events = []
    missing = tmp_path / "missing.txt"

    with pytest.raises(FileNotFoundError):
        run_pipeline_with_progress(
            incident_file=missing,
            catalog_path="data/contract/service_catalog.yaml",
            memory_path="data/contract/decision_moments.jsonl",
            command_registry_path="data/contract/command_registry.yaml",
            save_trace=False,
            on_event=events.append,
            run_id="run-failed",
            llm_client=fixture_llm_client(),
        )

    assert any(event.step == "normalize_input" and event.status == "failed" for event in events)
    assert any(event.step == "complete" and event.status == "failed" for event in events)


def test_verifier_fallback_is_not_pipeline_crash():
    events = []
    result = run_pipeline_with_progress(
        incident_file="data/sample/incidents/revpro_early_engage.txt",
        catalog_path="data/contract/service_catalog.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        command_registry_path="data/contract/command_registry.yaml",
        save_trace=False,
        on_event=events.append,
        run_id="run-safe",
        llm_client=fixture_llm_client(),
    )

    assert result["verifier_result"].final_status in {"pass", "rewrite_required", "fallback_required", "blocked"}
    assert any(event.step == "complete" and event.status == "succeeded" for event in events)
