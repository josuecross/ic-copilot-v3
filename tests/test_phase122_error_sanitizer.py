from __future__ import annotations

from ic_copilot.error_sanitizer import classify_provider_error, extract_safe_request_id, sanitize_provider_error


def test_sanitize_provider_error_removes_raw_key_and_suffix() -> None:
    key = "sk-proj-" + "c" * 48
    clean = sanitize_provider_error(f"invalid_api_key for {key}")
    assert key not in clean
    assert "sk-proj" not in clean
    assert "[REDACTED_API_KEY]" in clean


def test_sanitize_provider_error_removes_bearer_and_cookie() -> None:
    token = "abcdefghijklmnopqrstuvwxyz"
    raw = "Authorization: Bearer " + token + " " + "Cook" + "ie: sessionid=" + token
    clean = sanitize_provider_error(raw)
    assert "abcdefghijklmnopqrstuvwxyz" not in clean
    assert "[REDACTED" in clean


def test_provider_error_classification() -> None:
    assert classify_provider_error("OpenAI HTTP error 401 invalid_api_key") == "auth_error"
    assert classify_provider_error("model_not_found") == "model_error"
    assert classify_provider_error("429 rate_limit_exceeded") == "rate_limit"
    assert classify_provider_error("connection timed out") == "network_error"


def test_request_id_extraction_keeps_safe_id() -> None:
    assert extract_safe_request_id("request_id: req_123456789") == "req_123456789"
