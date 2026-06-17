from ic_copilot.normalizers.slack_paste import normalize_slack_paste


def test_url_extraction_works():
    events = normalize_slack_paste("IC: See https://zuora.atlassian.net/browse/INC-1")
    assert events[0].extracted_tokens["urls"] == ["https://zuora.atlassian.net/browse/INC-1"]


def test_url_domain_is_not_promoted_to_customer():
    events = normalize_slack_paste("IC: See https://zuora.atlassian.net/browse/INC-1")
    tokens = events[0].extracted_tokens
    assert "customer" not in tokens
    assert "Atlassian" not in tokens.values()


def test_docs_url_number_is_not_promoted_to_tenant():
    events = normalize_slack_paste("IC: Notes https://docs.example.invalid/document/d/9863631/edit")
    assert events[0].extracted_tokens["numbers"][0]["value"] == "9863631"
    assert "tenant" not in events[0].extracted_tokens


def test_bot_system_channel_created_line_is_not_command():
    events = normalize_slack_paste("@zsrebot: @zsrebot created this channel")
    assert events[0].source == "slack_system"
    assert events[0].extracted_tokens["command_candidates"] == []


def test_multiline_continuation_appends_to_previous_event_without_author():
    events = normalize_slack_paste("Alex: first line\ncontinuation line\nBlair: second event")
    assert len(events) == 2
    assert "continuation line" in events[0].message
    assert events[0].author == "Alex"
    assert events[1].author == "Blair"
