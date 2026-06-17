from __future__ import annotations

import json
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
    return TestClient(app), tmp_path


def _wait_for_run(client: TestClient, run_id: str) -> dict:
    for _ in range(80):
        data = client.get(f"/api/runs/{run_id}").json()
        if data["run"]["status"] in {"succeeded", "failed"}:
            return data
        time.sleep(0.05)
    raise AssertionError("run did not finish")


def _start_sample_run(client: TestClient) -> str:
    response = client.post(
        "/api/runs",
        json={
            "sample_path": "data/sample/incidents/revpro_early_engage.txt",
            "save_trace": True,
        },
    )
    assert response.status_code == 200
    return response.json()["run_id"]


def test_recent_runs_debug_summary_and_feedback_export(tmp_path):
    client, _ = _client(tmp_path)
    run_id = _start_sample_run(client)
    data = _wait_for_run(client, run_id)
    assert data["run"]["total_elapsed_ms"] is not None

    runs = client.get("/api/runs").json()["runs"]
    assert runs[0]["run_id"] == run_id
    assert runs[0]["verifier_status"] == "pass"
    assert "SAY THIS:" in runs[0]["final_output_preview"]

    summary = client.get(f"/api/runs/{run_id}/debug-summary").json()
    assert summary["phase"]
    assert "retrieved_memory_ids" in summary
    assert summary["verifier_status"] == "pass"

    feedback = client.post(
        f"/api/runs/{run_id}/feedback",
        json={
            "usefulness": "useful_with_edit",
            "failure_tags": ["too_generic"],
            "reviewer_notes": "Bearer abc123 should redact",
        },
    )
    assert feedback.status_code == 200
    assert client.post(f"/api/runs/{run_id}/mark-reviewed", json={"reviewer_name": "reviewer"}).status_code == 404

    export = client.get("/api/feedback/export?format=jsonl").text
    assert '"run_id":' in export
    assert "abc123" not in export
    assert "[REDACTED_SECRET]" in export


def test_correction_routes_disabled_by_default(tmp_path):
    client, _ = _client(tmp_path)
    response = client.post(
        "/api/corrections/validate",
        json={
            "correction_type": "service_alias",
            "payload": {"service_id": "revpro", "alias": "RevPro", "reason": "visible"},
        },
    )
    assert response.status_code == 404
    assert client.get("/api/corrections/drafts").status_code == 404


def test_samples_include_product_samples_only(tmp_path):
    client, _ = _client(tmp_path)
    samples = client.get("/api/samples").json()["samples"]
    assert any(sample["path"] == "data/sample/incidents/revpro_early_engage.txt" for sample in samples)
    assert not any(sample["source"] == "previous_package" for sample in samples)


def test_path_safety_rejects_outside_sample_and_sanitizes_upload(tmp_path):
    client, _ = _client(tmp_path)
    rejected = client.post("/api/runs", json={"sample_path": "/etc/passwd"})
    assert rejected.status_code == 400

    response = client.post(
        "/api/runs/upload",
        files={"file": ("../../secret.txt", b"hello incident", "text/plain")},
    )
    assert response.status_code == 200
    run_id = response.json()["run_id"]
    data = _wait_for_run(client, run_id)
    assert ".." not in data["run"]["input_name"]
    assert data["run"]["input_path"].endswith("secret.txt")


def test_delete_all_runs_removes_web_inputs_not_base_files(tmp_path):
    client, _ = _client(tmp_path)
    base_file = Path("data/sample/incidents/revpro_early_engage.txt")
    before = base_file.read_text()
    run_id = _start_sample_run(client)
    _wait_for_run(client, run_id)

    deleted = client.delete("/api/runs?confirm=true").json()

    assert deleted["deleted"] >= 1
    assert client.get("/api/runs").json()["runs"] == []
    assert base_file.read_text() == before


def test_product_run_without_key_fails_closed_when_no_test_client_injected(tmp_path, monkeypatch):
    monkeypatch.delenv("IC_COPILOT_MISSING_PRODUCT_KEY", raising=False)
    config = tmp_path / "ic_copilot.local.yaml"
    config.write_text("llm:\n  api_key_env: IC_COPILOT_MISSING_PRODUCT_KEY\n")
    monkeypatch.setenv("IC_COPILOT_CONFIG", str(config))
    client = TestClient(
        create_app(
            db_path=tmp_path / "product.sqlite3",
            input_dir=tmp_path / "inputs_product",
            correction_dir=tmp_path / "corrections_product",
        )
    )
    response = client.post(
        "/api/runs",
        json={
            "sample_path": "data/sample/incidents/revpro_early_engage.txt",
            "save_trace": True,
        },
    )
    run_id = response.json()["run_id"]
    data = _wait_for_run(client, run_id)
    assert data["run"]["status"] == "failed"
    assert "IC_COPILOT_MISSING_PRODUCT_KEY is required for normal IC Copilot product runs" in data["run"]["error"]


def test_download_input_returns_redacted_local_copy(tmp_path):
    client, _ = _client(tmp_path)
    response = client.post(
        "/api/runs",
        json={"pasted_text": "incident says bearer abc123 is visible", "save_trace": True},
    )
    run_id = response.json()["run_id"]
    _wait_for_run(client, run_id)
    body = client.get(f"/api/runs/{run_id}/download-input").text
    assert "abc123" not in body
    assert "[REDACTED_SECRET]" in body


def test_debug_trace_is_json_serializable(tmp_path):
    client, _ = _client(tmp_path)
    run_id = _start_sample_run(client)
    _wait_for_run(client, run_id)
    trace = client.get(f"/api/runs/{run_id}/trace").json()
    json.dumps(trace)
