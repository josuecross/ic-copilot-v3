from pathlib import Path

import pytest

from ic_copilot.normalizers.incident_jsonl import load_incident_jsonl


PACKAGE = Path("ic_copilot_previous_incidents__try_20260523_193347__fixture_package")
IN10984 = PACKAGE / "IN-10984/fixtures/incidents/IN-10984.jsonl"


@pytest.mark.skipif(not IN10984.exists(), reason="previous incident package not present")
def test_in10984_jsonl_loads_with_stable_tokens():
    events = load_incident_jsonl(IN10984)
    assert len(events) == 12
    assert events[0].event_id == "m001"
    assert events[-1].event_id == "m012"
    assert events[0].extracted_tokens["command_candidates"] == ["@zsrebot page user @Robert Ljungqvist"]
    assert all("tenant" not in event.extracted_tokens for event in events)


def test_jsonl_bot_lifecycle_command_not_candidate(tmp_path):
    path = tmp_path / "incident.jsonl"
    path.write_text(
        '{"event_id":"m001","sequence":1,"author":"zsrebot","text":"@zsrebot created this channel","candidate_commands":["@zsrebot created this channel"]}\n'
    )
    [event] = load_incident_jsonl(path, incident_id="i1")
    assert event.source == "slack_system"
    assert event.extracted_tokens["command_candidates"] == []
