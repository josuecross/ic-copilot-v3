from __future__ import annotations

import time
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from ic_copilot.schemas import utc_now
from ic_copilot.web.app import create_app
from ic_copilot.web.models import RunRequest
from ic_copilot.web.run_store import create_run, init_web_db, mark_stale_running_runs


class _BadDecisionClient:
    def generate_json(self, prompt_name, input_payload, response_model):
        if prompt_name in {"clean_incident_context_extractor", "semantic_intent_assessment"}:
            raise NotImplementedError
        if prompt_name == "state_delta_extractor":
            return {"incident_id": input_payload["incident_id"], "phase": "investigation"}
        return {
            "decision_id": "bad-move",
            "incident_id": input_payload["current_state"]["incident_id"],
            "move": "totally_new_move",
            "phase": "investigation",
            "output": {"say_this": "This should fail safely."},
        }


def _wait_for_run(client: TestClient, run_id: str) -> dict:
    for _ in range(80):
        data = client.get(f"/api/runs/{run_id}").json()
        if data["run"]["status"] in {"succeeded", "failed"}:
            return data
        time.sleep(0.05)
    raise AssertionError("run did not finish")


def test_phase126_ui_is_ic_first_and_has_no_dev_overrides() -> None:
    html = Path("src/ic_copilot/web/templates/index.html").read_text()
    assert "IC Copilot" in html
    assert "Local manual-copy incident whisper" in html
    assert "ai-badge" in html
    assert "knowledge-badge" in html
    assert "verifier-badge" in html
    assert html.index("incident-text") < html.index("runtime-status")
    assert "Developer path overrides" not in html
    assert "catalog-path" not in html
    assert "memory-path" not in html
    assert "command-registry-path" not in html
    assert "Artifact Curation" not in html
    assert "Knowledge Corrections" not in html
    assert "Personal Calibration Mode" not in html
    assert 'id="copy-output" type="button" disabled' in html
    assert 'id="copy-error" type="button" disabled hidden' in html


def test_default_run_request_has_no_path_or_shadow_fields() -> None:
    assert "catalog_path" not in RunRequest.model_fields
    assert "memory_path" not in RunRequest.model_fields
    assert "command_registry_path" not in RunRequest.model_fields
    assert "openai_shadow_enabled" not in RunRequest.model_fields
    assert "openai_model" not in RunRequest.model_fields


def test_unknown_planner_move_uses_sanitized_fallback_in_web_run(tmp_path) -> None:
    client = TestClient(
        create_app(
            db_path=tmp_path / "web.sqlite3",
            input_dir=tmp_path / "inputs",
            llm_client=_BadDecisionClient(),
        )
    )
    response = client.post(
        "/api/runs",
        json={"pasted_text": "IC: P3 incident, investigation ongoing.", "save_trace": False},
    )
    run_id = response.json()["run_id"]
    data = _wait_for_run(client, run_id)
    assert data["run"]["status"] == "succeeded"
    assert data["result"]["final_output"]
    assert data["result"]["say_this"] == "I do not have a safe, grounded next move yet."
    debug = client.get(f"/api/runs/{run_id}/debug-summary").json()
    assert debug["processing_strategy"] in {"incident_read_and_whisper", "incident_read_and_whisper_v2"}
    assert debug["why_no_safe_recommendation"]
    assert "ValidationError" not in (data["run"]["error"] or "")
    assert "pydantic.dev" not in (data["run"]["error"] or "")
    events = client.get(f"/api/runs/{run_id}/events").text
    assert "ValidationError" not in events
    assert "event: complete" in events


def test_stale_running_run_is_marked_failed(tmp_path) -> None:
    db_path = tmp_path / "web.sqlite3"
    run_id = create_run("paste", "stale", None, db_path)
    stale_time = (utc_now() - timedelta(hours=2)).isoformat()
    with init_web_db(db_path) as conn:
        conn.execute("UPDATE runs SET status = 'running', updated_at = ? WHERE run_id = ?", (stale_time, run_id))
        conn.commit()
    assert mark_stale_running_runs(db_path, older_than_seconds=60) == 1
    client = TestClient(create_app(db_path=db_path, input_dir=tmp_path / "inputs"))
    run = client.get(f"/api/runs/{run_id}").json()["run"]
    assert run["status"] == "failed"
    assert "still running" in run["error"]
