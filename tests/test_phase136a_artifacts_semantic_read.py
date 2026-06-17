from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from ic_copilot.incident_brief import build_allowed_targets
from ic_copilot.incident_loader import load_incident_events
from ic_copilot.catalog import build_command_registry, load_service_catalog
from ic_copilot.pipeline import run_pipeline
from ic_copilot.semantic_read import (
    ParallelSemanticReadResult,
    build_deterministic_actor_workstream_ledger,
    build_deterministic_clean_turn_ledger,
    build_deterministic_incident_fact_ledger,
    build_deterministic_question_intent_ledger,
    reduce_ledgers_to_incident_brief,
)
from ic_copilot.web.app import create_app
from ic_copilot.web.pipeline_events import STEP_ORDER, run_pipeline_with_progress
from ic_copilot.web.run_store import (
    create_run,
    get_step_artifact,
    init_web_db,
    list_step_artifacts,
    save_step_artifact,
)
from tests.helpers import fixture_llm_client


class OneReaderTimeoutClient:
    def __init__(self, failed_prompt: str) -> None:
        self.failed_prompt = failed_prompt
        self.fixture = fixture_llm_client()

    def generate_json(self, prompt_name, input_payload, response_model):
        if prompt_name == self.failed_prompt:
            raise TimeoutError("read operation timed out")
        return self.fixture.generate_json(prompt_name, input_payload, response_model)


class AllReadersTimeoutClient:
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
            raise TimeoutError("read operation timed out")
        return fixture_llm_client().generate_json(prompt_name, input_payload, response_model)


def test_step_artifact_storage_redacts_and_fetches(tmp_path):
    db_path = tmp_path / "web.sqlite3"
    init_web_db(db_path).close()
    run_id = create_run("paste", "test", None, db_path)

    artifact_id = save_step_artifact(
        run_id,
        "semantic_read",
        "clean_turn_ledger",
        {"status": "ok", "api_key": "abc"},
        {"authorization": "Bearer secret-token-value", "value": "safe"},
        warnings=["warning"],
        path=db_path,
    )

    summaries = list_step_artifacts(run_id, db_path)
    assert summaries[0]["summary_json"]["api_key"] == "[REDACTED]"
    assert "payload_json" not in summaries[0]

    full = get_step_artifact(artifact_id, db_path)
    assert full is not None
    assert full["payload_json"]["authorization"] == "[REDACTED]"
    assert full["payload_json"]["value"] == "safe"


def test_pipeline_records_semantic_artifacts_when_one_reader_fails():
    artifacts = []
    result = run_pipeline(
        "data/sample/incidents/revpro_early_engage.txt",
        catalog_path="data/contract/service_catalog.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        command_registry_path="data/contract/command_registry.yaml",
        llm_client=OneReaderTimeoutClient("incident_fact_ledger"),
        save_trace=False,
        on_artifact=artifacts.append,
        run_id="run-artifact-test",
    )

    assert result["final_output"].startswith("SAY THIS:")
    artifact_types = {artifact.artifact_type for artifact in artifacts}
    assert {
        "incident_read_context_pack_summary",
        "incident_read_v2_context_pack_summary",
    }.intersection(artifact_types)
    assert "incident_read_and_whisper_summary" in artifact_types
    assert result["trace"].clean_turn_ledger is None
    assert result["trace"].incident_read_and_whisper is not None
    assert result["trace"].step_artifacts


def test_all_semantic_reader_failures_are_terminal_with_step_metadata():
    events = []
    artifacts = []

    with pytest.raises(TimeoutError):
        run_pipeline_with_progress(
            incident_file="data/sample/incidents/revpro_early_engage.txt",
            catalog_path="data/contract/service_catalog.yaml",
            memory_path="data/contract/decision_moments.jsonl",
            command_registry_path="data/contract/command_registry.yaml",
            save_trace=False,
            on_event=events.append,
            on_artifact=artifacts.append,
            run_id="run-semantic-failed",
            llm_client=AllReadersTimeoutClient(),
        )

    terminal = {event.step: event for event in events if event.status in {"succeeded", "failed", "skipped"}}
    for step in STEP_ORDER:
        assert step in terminal
    assert terminal["semantic_read"].status == "skipped"
    assert terminal["planning"].status == "failed"
    assert terminal["complete"].status == "failed"
    assert any(
        artifact.artifact_type in {"incident_read_context_pack_summary", "incident_read_v2_context_pack_summary"}
        for artifact in artifacts
    )


def test_semantic_reducer_builds_incident_brief_and_rejects_url_path_tenants():
    events = load_incident_events(
        "data/personal_regression/incidents/generic_trust_post_answered_no_need.txt",
        incident_id="generic",
    )
    catalog = load_service_catalog("data/contract/service_catalog.yaml")
    allowed_targets = build_allowed_targets(events, catalog, build_command_registry(catalog))
    semantic_result = ParallelSemanticReadResult(
        clean_turn_ledger=build_deterministic_clean_turn_ledger("generic", events),
        actor_workstream_ledger=build_deterministic_actor_workstream_ledger(
            "generic",
            events,
            allowed_targets,
        ),
        incident_fact_ledger=build_deterministic_incident_fact_ledger("generic", events),
        question_intent_ledger=build_deterministic_question_intent_ledger("generic", events),
        errors={},
    )

    brief = reduce_ledgers_to_incident_brief(
        incident_id="generic",
        events=events,
        allowed_targets=allowed_targets,
        semantic_read=semantic_result,
    )

    assert brief.based_on_event_ids
    assert any(item.intent == "ask_trust_post_needed" for item in brief.do_not_ask)
    assert all(item.reason != "url_domain" or item.text for item in brief.rejected_or_noise)


def test_web_step_artifact_endpoints_and_ui_markup(tmp_path):
    client = TestClient(
        create_app(
            db_path=tmp_path / "web.sqlite3",
            input_dir=tmp_path / "inputs",
            llm_client=fixture_llm_client(),
        )
    )
    response = client.post(
        "/api/runs",
        json={
            "pasted_text": "09:00 IC: P3 test\n09:01 Alice: checking logs\n09:02 Bob: can validate now?",
            "save_trace": False,
        },
    )
    run_id = response.json()["run_id"]
    for _ in range(100):
        run = client.get(f"/api/runs/{run_id}").json()["run"]
        if run["status"] in {"succeeded", "failed"}:
            break
    assert run["status"] == "succeeded"

    artifacts = client.get(f"/api/runs/{run_id}/step-artifacts").json()["artifacts"]
    assert artifacts
    assert "payload_json" not in artifacts[0]
    full = client.get(f"/api/runs/{run_id}/step-artifacts/{artifacts[0]['id']}").json()["artifact"]
    assert "payload_json" in full

    html = client.get("/").text
    app_js = client.get("/static/app.js").text
    assert "View generated data" in app_js
    assert "artifact curation" not in html.lower()
