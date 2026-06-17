from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from ic_copilot.web.app import create_app
from tests.helpers import fixture_llm_client


def _client(tmp_path):
    app = create_app(
        db_path=tmp_path / "web.sqlite3",
        input_dir=tmp_path / "inputs",
        correction_dir=tmp_path / "corrections",
        llm_client=fixture_llm_client(),
    )
    return TestClient(app)


def _wait_for_run(client: TestClient, run_id: str) -> dict:
    for _ in range(80):
        response = client.get(f"/api/runs/{run_id}")
        data = response.json()
        if data["run"]["status"] in {"succeeded", "failed"}:
            return data
        time.sleep(0.05)
    raise AssertionError("run did not finish")


def test_web_app_health_and_index(tmp_path):
    client = _client(tmp_path)
    assert client.get("/health").json() == {"status": "ok", "bind": "localhost-only"}
    config = client.get("/api/config").json()
    assert config["runtime"] == "verified_ai_product"
    assert config["provider"] == "openai"
    assert config["verifier_required"] is True
    assert config["runtime_knowledge_source"] == "local_knowledge"
    html = client.get("/").text
    assert "IC Copilot" in html
    assert "Local manual-copy incident whisper" in html


def test_web_run_from_paste_trace_feedback_delete(tmp_path):
    client = _client(tmp_path)
    text = Path("data/sample/incidents/revpro_early_engage.txt").read_text()
    response = client.post("/api/runs", json={"pasted_text": text, "save_trace": True})
    assert response.status_code == 200
    run_id = response.json()["run_id"]

    data = _wait_for_run(client, run_id)
    assert data["run"]["status"] == "succeeded"
    assert "SAY THIS:" in data["result"]["final_output"]

    trace = client.get(f"/api/runs/{run_id}/trace")
    assert trace.status_code == 200
    assert trace.json()["trace_id"]

    with client.stream("GET", f"/api/runs/{run_id}/events") as stream:
        body = "".join(stream.iter_text())
    assert "event: step" in body
    assert "event: complete" in body

    feedback = client.post(
        f"/api/runs/{run_id}/feedback",
        json={"usefulness": "useful_with_edit", "failure_tags": ["too_generic"], "reviewer_notes": "ok"},
    )
    assert feedback.status_code == 200
    assert feedback.json()["label_id"].startswith("label-")

    deleted = client.delete(f"/api/runs/{run_id}")
    assert deleted.status_code == 200
    assert client.get(f"/api/runs/{run_id}").status_code == 404


def test_web_upload_jsonl_run(tmp_path):
    client = _client(tmp_path)
    payload = Path("ic_copilot_previous_incidents__try_20260523_193347__fixture_package/fixtures/incidents/IN-10984.jsonl")
    if not payload.exists():
        payload = Path("data/sample/incidents/revpro_early_engage.txt")
    with payload.open("rb") as handle:
        response = client.post("/api/runs/upload", files={"file": (payload.name, handle, "text/plain")})
    assert response.status_code == 200
    data = _wait_for_run(client, response.json()["run_id"])
    assert data["run"]["status"] == "succeeded"
