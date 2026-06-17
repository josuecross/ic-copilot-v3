from pathlib import Path

from ic_copilot.normalizers.slack_paste import normalize_slack_text


CONTRACT = Path("data/contract")


def test_normalizer_outputs_ordered_incident_events():
    raw = (CONTRACT / "incidents/01_revpro_early_engage.txt").read_text()
    events = normalize_slack_text(raw, incident_id="INC-9001")
    assert len(events) >= 5
    assert [event.event_id for event in events] == [f"m{i:03d}" for i in range(1, len(events) + 1)]
    assert all(event.message for event in events)


def test_normalizer_extracts_urls_numbers_and_real_commands_without_promoting_semantics():
    raw = (CONTRACT / "incidents/05_db_high_cpu_queue.txt").read_text()
    events = normalize_slack_text(raw, incident_id="INC-9005")
    assert any("@zsrebot oncall dba" in event.extracted_tokens["command_candidates"] for event in events)

    negative = (CONTRACT / "incidents/06_negative_fake_entities.txt").read_text()
    negative_events = normalize_slack_text(negative, incident_id="INC-9006")
    assert any("zuora.atlassian.net" in url for event in negative_events for url in event.extracted_tokens["urls"])
    assert any(
        token["value"] == "9863631"
        for event in negative_events
        for token in event.extracted_tokens["numbers"]
    )
    assert all(
        "@zsrebot created this channel" not in " ".join(event.extracted_tokens["command_candidates"])
        for event in negative_events
    )


def test_multiline_continuation_does_not_invent_author():
    raw = "[09:00] Alex: first line\ncontinuation without author\n[09:01] MD. Please confirm this log field"
    events = normalize_slack_text(raw, incident_id="INC-MULTI")
    assert len(events) == 2
    assert "continuation without author" in events[0].message
    assert events[1].author is None
    assert "MD. Please" in events[1].message

