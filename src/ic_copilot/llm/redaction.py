from __future__ import annotations

import copy
import re
from typing import Any


SECRET_KEY_PARTS = (
    "password",
    "token",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "session",
)

SECRET_VALUE_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.I),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b", re.I),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?=.*[A-Z])(?=.*[a-z])(?=.*\d)\b[A-Za-z0-9_+/=-]{32,}\b"),
)
PRIVATE_KEY_PATTERN = SECRET_VALUE_PATTERNS[5]
TOKEN_METRIC_KEYS = {
    "estimated_token_count",
    "token_count",
    "input_tokens",
    "output_tokens",
    "total_tokens",
}


def _secret_key(key: Any) -> bool:
    key_text = str(key).lower()
    if key_text == "extracted_tokens":
        return False
    normalized = key_text.replace("-", "_")
    if normalized in TOKEN_METRIC_KEYS:
        return False
    parts = {part for chunk in normalized.split(".") for part in chunk.split("_") if part}
    return any(
        normalized == secret
        or normalized.endswith(f"_{secret}")
        or normalized.startswith(f"{secret}_")
        or secret in parts
        for secret in SECRET_KEY_PARTS
    )


def _redact_string(value: str) -> str:
    if PRIVATE_KEY_PATTERN.search(value):
        return "[REDACTED]"
    redacted = value
    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _secret_key(key) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact(item) for item in value)
    if isinstance(value, str):
        return _redact_string(value)
    return value


def redact_for_llm(value: Any) -> Any:
    """Return a redacted deep copy suitable for outbound shadow LLM calls."""
    return _redact(copy.deepcopy(value))
