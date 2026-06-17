from __future__ import annotations

from pathlib import Path


def test_acceptance_gate_includes_phase110_non_network_checks():
    text = Path("scripts/run_acceptance_gate.py").read_text()
    assert "IncidentBrief, allowed target, and semantic stale regression" in text
    assert "test_phase132_incident_brief.py" in text
    assert "web safety audit" in text


def test_dev_archive_and_local_knowledge_paths_ignored():
    text = Path(".gitignore").read_text()
    assert "local_knowledge/" in text
    assert ".ic_copilot/" in text
