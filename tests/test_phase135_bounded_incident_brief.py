from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from ic_copilot.incident_brief import build_allowed_targets, build_incident_brief_payload, incident_brief_payload_stats
from ic_copilot.incident_loader import load_incident_events
from ic_copilot.input_processing import assess_input_size, select_latest_window
from ic_copilot.llm.fixture_client import FixtureLLMClient
from ic_copilot.pipeline import run_pipeline
from ic_copilot.schema_repair import validate_with_repair
from ic_copilot.schemas import CurrentIncidentState, IncidentBrief
from ic_copilot.web.app import create_app
from ic_copilot.web.pipeline_events import STEP_ORDER
from ic_copilot.web.run_store import list_step_events


def _medium_paste() -> str:
    lines: list[str] = [
        "[09:00] IC Bot: P2 incident created. Reference https://docs.example.invalid/pages/9863631/runbook",
        "[09:01] IM-Agent: Default_Agent joined the channel.",
    ]
    lines.extend(f"[09:{i:02d}] zsrebot APP: Trust Post reminder boilerplate {i}." for i in range(2, 12))
    lines.extend(
        f"[09:{i:02d}] Engineer: diagnostic table row {i} error timeout health check status={i % 3} owner update pending."
        for i in range(12, 24)
    )
    lines.extend(
        [
            "[09:24] Support: Zendesk ticket is visible and customer validation is pending.",
            "[09:25] Engineer: dashboard shows lag still growing for tenant id 30000091.",
            "[09:26] IC: Can the active owner confirm status, ETA, and validation signal?",
            "[09:27] Engineer: latest metrics still above threshold; checking mitigation status.",
            "[09:28] Validator: customer validation is still running.",
            "[09:29] Engineer: next update will confirm whether recovery signal is green.",
        ]
    )
    return "\n".join(lines)


class _FirstBriefTimeoutClient(FixtureLLMClient):
    def __init__(self) -> None:
        self.brief_calls = 0
        self.brief_payloads: list[dict] = []

    def generate_json(self, prompt_name, input_payload, response_model):
        if response_model is IncidentBrief or response_model.__name__ == "IncidentBrief":
            self.brief_calls += 1
            self.brief_payloads.append(input_payload)
            if self.brief_calls == 1:
                raise TimeoutError("The read operation timed out")
        return super().generate_json(prompt_name, input_payload, response_model)


class _AlwaysBriefTimeoutClient(FixtureLLMClient):
    def __init__(self) -> None:
        self.brief_calls = 0
        self.brief_payloads: list[dict] = []

    def generate_json(self, prompt_name, input_payload, response_model):
        if response_model is IncidentBrief or response_model.__name__ == "IncidentBrief":
            self.brief_calls += 1
            self.brief_payloads.append(input_payload)
            raise TimeoutError("The read operation timed out")
        return super().generate_json(prompt_name, input_payload, response_model)


def test_medium_paste_incident_brief_timeout_retries_ultra_compact_and_succeeds(tmp_path) -> None:
    incident = tmp_path / "medium.txt"
    incident.write_text(_medium_paste())
    client = _FirstBriefTimeoutClient()
    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=client,
    )
    trace = result["trace"]
    assert result["verifier_result"].passed
    assert trace.latest_window_selection is not None
    assert trace.processing_strategy in {"incident_read_and_whisper", "incident_read_and_whisper_v2"}
    assert trace.retry_attempted is False
    assert trace.incident_brief_attempt_count == 0
    assert trace.incident_read_and_whisper is not None
    assert client.brief_payloads == []


def test_both_incident_brief_attempts_timeout_terminal_web_failure_has_debug_metadata(tmp_path) -> None:
    web = TestClient(
        create_app(
            db_path=tmp_path / "web.sqlite3",
            input_dir=tmp_path / "inputs",
            llm_client=_AlwaysBriefTimeoutClient(),
        )
    )
    response = web.post("/api/runs", json={"pasted_text": _medium_paste(), "save_trace": False})
    run_id = response.json()["run_id"]
    for _ in range(160):
        data = web.get(f"/api/runs/{run_id}").json()
        if data["run"]["status"] in {"succeeded", "failed"}:
            break
        time.sleep(0.05)
    assert data["run"]["status"] == "succeeded"
    assert data["result"]["final_output"].startswith("SAY THIS:")
    debug = web.get(f"/api/runs/{run_id}/debug-summary").json()
    assert debug["normalized_event_count"] >= 20
    assert debug["latest_window_selection"]["event_ids"]
    assert debug["incident_brief_attempt_count"] == 0
    assert debug["retry_attempted"] is False
    assert debug["incident_read_and_whisper"]
    events = list_step_events(run_id, tmp_path / "web.sqlite3")
    latest_by_step = {event["step"]: event["status"] for event in events}
    assert latest_by_step["complete"] == "succeeded"
    assert all(latest_by_step.get(step) in {"succeeded", "failed", "skipped"} for step in STEP_ORDER)


def test_compact_incident_brief_payload_preserves_ids_and_filters_url_numbers() -> None:
    incident_text = _medium_paste()
    events = load_incident_events(Path("data/personal_regression/incidents/p3_ocs_lag_trust_post_static.txt"))
    assessment = assess_input_size(incident_text, events)
    selection = select_latest_window(events, max_events=18, min_latest_events=12)
    selected = [event for event in events if event.event_id in set(selection.event_ids)]
    targets = build_allowed_targets(selected, [], [])
    payload = build_incident_brief_payload(
        incident_text,
        selected,
        current_state=CurrentIncidentState(incident_id="compact"),
        allowed_targets=targets,
        input_size_assessment=assessment,
        attempt_name="ultra_compact_incident_brief",
        max_chars_per_event=500,
        max_targets=24,
    )
    stats = incident_brief_payload_stats(payload)
    assert stats["event_count"] == len(selected)
    assert all(event["event_id"] for event in payload["events"])
    payload_text = " ".join(event["message"] for event in payload["events"])
    assert "tenant id 30000091" in payload_text
    assert "9863631" not in payload_text
    target_by_name = {target["display_name"]: target for target in payload["allowed_targets"]}
    assert target_by_name["Default_Agent"]["targetable"] is False
    assert target_by_name["9863631"]["targetable"] is False


def test_incident_brief_blocker_alias_repaired_before_schema_failure() -> None:
    brief = validate_with_repair(
        {
            "incident_id": "alias",
            "based_on_event_ids": ["m001"],
            "current_summary": "Owner confirmation is the current blocker.",
            "phase": {"primary": "investigating", "confidence": 0.8, "evidence_ids": ["m001"]},
            "latest_blocker": {
                "blocker_type": "confirm_ownership",
                "summary": "Need ownership confirmation.",
                "confidence": 0.8,
                "evidence_ids": ["m001"],
            },
            "recommended_ic_focus": {
                "summary": "Ask the owner to confirm ownership.",
                "preferred_target_ids": [],
                "acceptable_move_types": ["confirm_ownership"],
                "evidence_ids": ["m001"],
            },
        },
        IncidentBrief,
        context="test_incident_brief_alias",
    )
    assert brief.phase.primary == "investigation"
    assert brief.latest_blocker.blocker_type == "missing_owner"
