from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from ic_copilot.llm.providers.base_json import ProviderJSONError
from ic_copilot.web.app import create_app


class FailingProviderClient:
    def generate_json(self, prompt_name, input_payload, response_model):
        raise ProviderJSONError(
            "OpenAI HTTP error 401 invalid_api_key " + "sk-proj-" + "h" * 48,
            provider="openai",
        )


def _wait_for_run(client: TestClient, run_id: str) -> dict:
    for _ in range(80):
        data = client.get(f"/api/runs/{run_id}").json()
        if data["run"]["status"] in {"succeeded", "failed"}:
            return data
        time.sleep(0.05)
    raise AssertionError("run did not finish")


def test_provider_auth_error_marks_web_run_failed_and_sanitized(tmp_path) -> None:
    client = TestClient(
        create_app(
            db_path=tmp_path / "web.sqlite3",
            input_dir=tmp_path / "inputs",
            llm_client=FailingProviderClient(),
        )
    )
    response = client.post(
        "/api/runs",
        json={"pasted_text": Path("data/sample/incidents/revpro_early_engage.txt").read_text(), "save_trace": False},
    )
    run_id = response.json()["run_id"]
    data = _wait_for_run(client, run_id)
    assert data["run"]["status"] == "failed"
    assert "sk-proj" not in data["run"]["error"]
    assert "authentication failed" in data["run"]["error"].lower()
    runs = client.get("/api/runs").json()["runs"]
    assert any(run["run_id"] == run_id and run["status"] == "failed" for run in runs)
    events = client.get(f"/api/runs/{run_id}/events").text
    assert "event: error" in events
    assert "sk-proj" not in events
    debug = client.get(f"/api/runs/{run_id}/debug-summary").json()
    assert debug["status"] == "failed"
    assert "sk-proj" not in debug["error"]

    assert client.post(f"/api/runs/{run_id}/export-regression-draft").status_code == 404


def test_config_endpoint_exposes_safe_diagnostics(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-" + "i" * 48)
    client = TestClient(create_app(db_path=tmp_path / "web.sqlite3", input_dir=tmp_path / "inputs"))
    config = client.get("/api/config").json()
    assert config["api_key_present"] is True
    assert config["api_key_fingerprint"]
    assert "sk-proj" not in str(config)
    assert config["api_key_validated_status"] == "unknown"
