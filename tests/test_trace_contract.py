from __future__ import annotations

import json
from pathlib import Path

from ic_copilot.schemas import ICDecision, ICMove, IncidentPhase, TraceRecord
from ic_copilot.storage import init_db, iter_traces
from tests.helpers import fixture_run_pipeline


SAMPLE_INCIDENT = Path("data/sample/incidents/revpro_early_engage.txt")


def test_run_pipeline_returns_json_serializable_trace():
    result = fixture_run_pipeline(SAMPLE_INCIDENT, save_trace=False)
    trace = result["trace"]
    assert isinstance(trace, TraceRecord)
    assert trace.incident_id == "revpro_early_engage"
    assert trace.input_event_ids
    assert trace.current_state.incident_id == "revpro_early_engage"
    assert all(isinstance(item, str) for item in trace.retrieved_memory_ids)
    assert all(isinstance(item, str) for item in trace.accepted_memory_ids)
    assert trace.raw_decision.decision_id
    assert trace.verifier_result.final_status == "pass"
    assert trace.final_output == result["final_output"]
    json.dumps(trace.model_dump(mode="json"))


def test_trace_memory_retrieval_contains_ids_not_snippets():
    result = fixture_run_pipeline(SAMPLE_INCIDENT, save_trace=False)
    trace = result["trace"]
    assert trace.retrieved_memory_ids
    assert trace.hydrated_memory_ids
    assert trace.retrieved_memory_ids == trace.hydrated_memory_ids[: len(trace.retrieved_memory_ids)]
    assert all(" " not in item for item in trace.retrieved_memory_ids)


def test_trace_marks_positive_revpro_without_fallback():
    result = fixture_run_pipeline(SAMPLE_INCIDENT, save_trace=False)
    assert result["trace"].safety_summary["fallback_used"] is False
    assert result["verifier_result"].passed


def test_trace_marks_blocked_negative_with_fallback(monkeypatch):
    def unsafe_plan(*args, **kwargs):
        return ICDecision(
            decision_id="unsafe",
            incident_id="06_negative_fake_entities",
            move=ICMove.ENGAGE_OWNER,
            phase=IncidentPhase.TRIAGE,
            output={
                "say_this": "Atlassian customer tenant 9863631 appears impacted.",
                "next_line": "Default_Agent, please confirm ownership.",
                "command": "@zsrebot oncall Default_Agent",
            },
            confidence=0.5,
        )

    result = fixture_run_pipeline(
        "data/contract/incidents/06_negative_fake_entities.txt",
        "data/contract/service_catalog.yaml",
        "data/contract/decision_moments.jsonl",
        "data/contract/command_registry.yaml",
        save_trace=False,
        planner_func=unsafe_plan,
    )
    trace = result["trace"]
    assert trace.safety_summary["fallback_used"] is True
    assert trace.safety_summary["original_verifier_status"] == "fallback_required"
    assert trace.safety_summary["original_blocked_claims"]
    assert trace.verifier_result.passed
    assert "Atlassian" not in trace.final_output
    assert "9863631" not in trace.final_output


def test_trace_can_be_persisted_and_read_from_sqlite(tmp_path, monkeypatch):
    db_path = tmp_path / "traces.sqlite3"
    monkeypatch.setenv("IC_COPILOT_DB_PATH", str(db_path))
    result = fixture_run_pipeline(SAMPLE_INCIDENT, save_trace=True)
    conn = init_db(db_path)
    rows = list(iter_traces(conn, kind="run"))
    conn.close()
    assert rows
    payload = rows[-1]["payload"]
    assert payload["trace_id"] == result["trace"].trace_id
    assert payload["final_output"] == result["final_output"]
    assert payload["safety_summary"]["fallback_used"] is False
