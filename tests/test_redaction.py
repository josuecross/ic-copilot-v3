from __future__ import annotations

from ic_copilot.llm.redaction import redact_for_llm


def test_nested_secrets_are_redacted_without_mutating_original():
    payload = {
        "incident": "RevPro",
        "auth": {"api_key": "sk-test", "nested": {"password": "pw"}},
        "items": [{"token": "abc"}, {"value": "ordinary"}],
    }
    redacted = redact_for_llm(payload)
    assert redacted["auth"]["api_key"] == "[REDACTED]"
    assert redacted["auth"]["nested"]["password"] == "[REDACTED]"
    assert redacted["items"][0]["token"] == "[REDACTED]"
    assert redacted["items"][1]["value"] == "ordinary"
    assert payload["auth"]["api_key"] == "sk-test"


def test_auth_headers_and_secret_values_are_redacted():
    payload = {
        "headers": {"Authorization": "Bearer " + "abcdefghijklmnopqrstuvwxyz"},
        "aws": "AKIAABCDEFGHIJKLMNOP",
        "private": "-----BEGIN PRIVATE KEY-----\nabc",
    }
    redacted = redact_for_llm(payload)
    assert redacted["headers"]["Authorization"] == "[REDACTED]"
    assert redacted["aws"] == "[REDACTED]"
    assert redacted["private"] == "[REDACTED]"


def test_operational_incident_evidence_is_preserved():
    payload = {
        "customer": "Google Fiber",
        "tenant": "10005051",
        "service": "RevPro Support",
        "message": "P3 RevPro deployment mismatch",
    }
    assert redact_for_llm(payload) == payload
