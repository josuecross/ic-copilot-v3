from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from ic_copilot.input_processing import (
    assess_input_size,
    merge_clean_contexts,
    select_latest_window,
    select_chunks,
    split_event_chunks,
)
from ic_copilot.incident_loader import load_incident_events
from ic_copilot.llm.fixture_client import FixtureLLMClient
from ic_copilot.pipeline import run_pipeline
from ic_copilot.schemas import CleanIncidentContext, IncidentBrief, IncidentEvent, StateDelta
from ic_copilot.web.app import create_app
from ic_copilot.web.pipeline_events import STEP_ORDER
from ic_copilot.web.run_store import list_step_events


API_504_FIXTURE = "data/personal_regression/incidents/p3_api_504_revenue_timeout_static.txt"


def _long_text() -> str:
    base = Path(API_504_FIXTURE).read_text()
    boilerplate = "\n".join(f"zsrebot APP 9:{i:02d} AM\nTrust Post reminder boilerplate {i}" for i in range(55))
    logs = "\n".join(f"Sriram 10:{i:02d} AM\nlog line {i}: open connection limit error timeout" for i in range(32, 52))
    return f"{boilerplate}\n\n{base}\n\n{logs}"


class _ChunkAndStateRetryClient(FixtureLLMClient):
    def __init__(self) -> None:
        self.brief_calls = 0
        self.state_calls = 0

    def generate_json(self, prompt_name, input_payload, response_model):
        if prompt_name == "incident_brief_extractor" or response_model is IncidentBrief or response_model.__name__ == "IncidentBrief":
            self.brief_calls += 1
            if self.brief_calls == 1:
                raise TimeoutError("The read operation timed out")
        if response_model is StateDelta or response_model.__name__ == "StateDelta":
            self.state_calls += 1
            if len(input_payload.get("events") or []) > 35 and self.state_calls == 1:
                raise TimeoutError("The read operation timed out")
        return super().generate_json(prompt_name, input_payload, response_model)


class _AlwaysTimeoutIncidentBriefClient(FixtureLLMClient):
    def generate_json(self, prompt_name, input_payload, response_model):
        if prompt_name == "incident_brief_extractor" or response_model is IncidentBrief or response_model.__name__ == "IncidentBrief":
            raise TimeoutError("The read operation timed out")
        return super().generate_json(prompt_name, input_payload, response_model)


class _AlwaysTimeoutSemanticReadClient(FixtureLLMClient):
    reader_prompts = {
        "incident_read_and_whisper",
        "incident_read_and_whisper_v2",
        "clean_turn_ledger",
        "actor_workstream_ledger",
        "incident_fact_ledger",
        "question_intent_ledger",
    }

    def generate_json(self, prompt_name, input_payload, response_model):
        if prompt_name in self.reader_prompts:
            raise TimeoutError("The read operation timed out")
        return super().generate_json(prompt_name, input_payload, response_model)


class _StateDeltaAlwaysTimeoutClient(FixtureLLMClient):
    def generate_json(self, prompt_name, input_payload, response_model):
        if response_model is StateDelta or response_model.__name__ == "StateDelta":
            raise TimeoutError("The read operation timed out")
        return super().generate_json(prompt_name, input_payload, response_model)


def _event(sequence: int, author: str, message: str) -> IncidentEvent:
    return IncidentEvent(
        incident_id="latest",
        event_id=f"m{sequence:03d}",
        sequence=sequence,
        author=author,
        message=message,
        hash=f"h{sequence:03d}",
    )


def test_latest_window_selector_keeps_latest_human_validation_and_drops_bot_noise() -> None:
    events = [_event(i, "zsrebot APP", f"Trust Post reminder boilerplate {i}") for i in range(1, 31)]
    events.extend(_event(i, "Engineer", f"log line {i}: timeout error connection limit") for i in range(31, 61))
    events.extend(
        [
            _event(61, "IC", "P3 API errors are under investigation."),
            _event(62, "Owner", "Task restarted and health check is improving."),
            _event(63, "Validator", "Customer application validation is still running."),
            _event(64, "Owner", "Please confirm monitoring signal is stable."),
            _event(65, "Validator", "Still seeing one sandbox running; will validate completion."),
        ]
    )
    selection = select_latest_window(events, max_events=25, min_latest_events=15)
    selected = set(selection.event_ids)
    assert "m065" in selected
    assert "m063" in selected
    assert sum(1 for event_id in selected if int(event_id[1:]) <= 30) < 5
    assert selection.contains_latest_human_evidence
    assert selection.contains_latest_validation_or_monitoring


def test_input_assessment_and_chunk_selection_for_long_slack_paste(tmp_path) -> None:
    incident = tmp_path / "long_api_504.txt"
    incident.write_text(_long_text())
    events = load_incident_events(incident, incident_id="p3_api_504")
    assessment = assess_input_size(incident.read_text(), events)
    chunks = split_event_chunks(events, max_chunk_chars=4000, max_events_per_chunk=20)
    selected = select_chunks(chunks, max_chunks=4)
    assert assessment.recommended_strategy in {"chunked_clean_context", "latest_window_only_with_summary"}
    assert len(chunks) > len(selected)
    assert selected[-1].events[-1].event_id == chunks[-1].events[-1].event_id
    assert any("Trimble sandbox 5" in event.message for chunk in selected for event in chunk.events)


def test_chunked_clean_context_and_state_latest_window_retry_pass(tmp_path) -> None:
    incident = tmp_path / "long_api_504.txt"
    incident.write_text(_long_text())
    client = _ChunkAndStateRetryClient()
    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=client,
    )
    trace = result["trace"]
    assert trace.input_size_assessment is not None
    assert trace.processing_strategy in {"incident_read_and_whisper", "incident_read_and_whisper_v2"}
    assert trace.latest_window_selection is not None
    assert trace.latest_window_selection.kept_event_count <= 35
    assert trace.incident_brief is None
    assert trace.incident_read_and_whisper is not None
    assert trace.retry_attempted is False
    assert trace.safety_summary["state_delta_status"] == "legacy_debug_only_not_run"
    assert trace.safety_summary["full_context_enrichment_status"] == "skipped"
    assert result["verifier_result"].passed
    output = result["final_output"].lower()
    assert output.startswith("say this:")
    assert "page team revenue" not in output
    assert "9863631" not in output


def test_incident_brief_success_state_delta_timeout_still_succeeds(tmp_path) -> None:
    incident = tmp_path / "long_api_504.txt"
    incident.write_text(_long_text())
    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_StateDeltaAlwaysTimeoutClient(),
    )
    trace = result["trace"]
    assert result["verifier_result"].passed
    assert trace.incident_brief is None
    assert trace.incident_read_and_whisper is not None
    assert trace.safety_summary["state_delta_status"] == "legacy_debug_only_not_run"
    assert trace.safety_summary["full_context_enrichment_status"] == "skipped"
    assert trace.provider_timeout_stage is None
    assert result["final_output"].startswith("SAY THIS:")


def test_merge_clean_contexts_preserves_evidence_and_dedupes_entities() -> None:
    one = CleanIncidentContext(
        incident_id="i1",
        based_on_event_ids=["m001"],
        clean_summary="first",
    )
    two = CleanIncidentContext(
        incident_id="i1",
        based_on_event_ids=["m001", "m002"],
        clean_summary="second",
    )
    merged = merge_clean_contexts([one, two], "i1")
    assert merged.based_on_event_ids == ["m001", "m002"]
    assert "first" in merged.clean_summary and "second" in merged.clean_summary


def test_web_timeout_failure_is_terminal_and_debug_keeps_normalized_events(tmp_path) -> None:
    client = TestClient(
            create_app(
                db_path=tmp_path / "web.sqlite3",
                input_dir=tmp_path / "inputs",
                llm_client=_AlwaysTimeoutSemanticReadClient(),
            )
        )
    response = client.post("/api/runs", json={"pasted_text": _long_text(), "save_trace": False})
    run_id = response.json()["run_id"]
    for _ in range(120):
        data = client.get(f"/api/runs/{run_id}").json()
        if data["run"]["status"] in {"succeeded", "failed"}:
            break
        time.sleep(0.05)
    assert data["run"]["status"] == "failed"
    assert "Provider timed out" in data["run"]["error"]
    debug = client.get(f"/api/runs/{run_id}/debug-summary").json()
    assert debug["normalized_event_count"] > 0
    assert debug["first_event_id"] == "m001"
    events = list_step_events(run_id, tmp_path / "web.sqlite3")
    latest_by_step = {event["step"]: event["status"] for event in events}
    assert latest_by_step["complete"] == "failed"
    assert all(latest_by_step.get(step) in {"succeeded", "failed", "skipped"} for step in STEP_ORDER)
