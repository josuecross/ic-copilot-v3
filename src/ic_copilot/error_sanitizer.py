from __future__ import annotations

import json
import re
from typing import Any


SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_-]{10,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"(Authorization\s*[:=]\s*)([^\s,;]+)", re.IGNORECASE),
    re.compile(r"(Cookie\s*[:=]\s*)([^;\n]+)", re.IGNORECASE),
    re.compile(r"([A-Za-z0-9_-]{8})[A-Za-z0-9_-]{16,}"),
)


def _stringify(error: Exception | str | dict[str, Any] | Any) -> str:
    if isinstance(error, dict):
        return json.dumps(error, default=str)
    return str(error)


def sanitize_provider_error(error: Exception | str | dict[str, Any]) -> str:
    text = _stringify(error)
    sanitized = text
    sanitized = re.sub(r"sk-[A-Za-z0-9_-]{10,}", "[REDACTED_API_KEY]", sanitized)
    sanitized = re.sub(r"Bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED_TOKEN]", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(
        r"(Authorization\s*[:=]\s*)([^\s,;]+)",
        r"\1[REDACTED_AUTHORIZATION]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(r"(Cookie\s*[:=]\s*)([^;\n]+)", r"\1[REDACTED_COOKIE]", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(
        r"([\"']?(?:api[_-]?key|access_token|refresh_token|id_token|password|secret)[\"']?\s*[:=]\s*[\"']?)([^\"'\s,}]+)",
        r"\1[REDACTED_SECRET]",
        sanitized,
        flags=re.IGNORECASE,
    )
    return sanitized


def sanitize_user_facing_error(error: Exception | str | dict[str, Any]) -> str:
    """Return a compact product-safe error string for the main UI/CLI.

    Debug traces may keep structured context, but the main product panel should not show
    Pydantic trace bodies, provider blobs, documentation URLs, or secret fragments.
    """

    text = sanitize_provider_error(error)
    lowered = text.lower()
    unsupported_move = re.search(r"input_value='([^']+)'", text) or re.search(r"input_value=([^,\s]+)", text)
    if "icdecision" in lowered and "move" in lowered and ("validation" in lowered or "input should be" in lowered):
        if unsupported_move:
            return (
                "Model output did not match the ICDecision schema. The model suggested an unsupported "
                f"move: {unsupported_move.group(1)}. A safe fallback was used when possible."
            )
        return "Model output did not match the ICDecision schema. The run was stopped safely."
    if "unsupported move:" in lowered:
        move = re.search(r"unsupported move:\s*([A-Za-z0-9_-]+)", text)
        if move:
            return (
                "Model output did not match the ICDecision schema. The model suggested an unsupported "
                f"move: {move.group(1)}. A safe fallback was used when possible."
            )
    if "large slack paste" in lowered and ("timed out" in lowered or "timeout" in lowered):
        return (
            "Provider timed out while processing a large Slack paste. Try rerun; if it repeats, "
            "paste the latest 30-50 messages around the current blocker."
        )
    if "retried with compact context" in lowered and ("timed out" in lowered or "timeout" in lowered):
        return (
            "Provider timed out while reading the incident. The app retried with compact context and still failed. "
            "Try again or paste the latest 20-30 messages around the current blocker."
        )
    if "latest incident context" in lowered and ("timed out" in lowered or "timeout" in lowered):
        return "Provider timed out while reading the latest incident context. Paste fewer latest messages or retry."
    if "read operation timed out" in lowered or "timed out" in lowered or "timeout" in lowered:
        return (
            "Provider timed out while processing the incident. Try rerun; if it repeats, paste the latest "
            "30-50 messages around the current blocker."
        )
    if "validationerror" in lowered or "validation error" in lowered:
        return "Model output did not match the required schema. The run was stopped safely."
    if "invalid_api_key" in lowered or "incorrect api key" in lowered or "401" in lowered and "openai" in lowered:
        return (
            "OpenAI authentication failed. Check OPENAI_API_KEY, .env, and ic_copilot.local.yaml, "
            "then restart the server."
        )
    cleaned = re.sub(r"https://errors\.pydantic\.dev/\S+", "", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > 360:
        cleaned = cleaned[:357].rstrip() + "..."
    return cleaned or "The run failed safely. See Debug / Trace for details."


def classify_provider_error(error: Exception | str | dict[str, Any]) -> str:
    text = sanitize_provider_error(error).lower()
    if any(term in text for term in ("invalid_api_key", "invalid api key", "incorrect api key", "401", "authentication")):
        return "auth_error"
    if any(term in text for term in ("model_not_found", "model not found", "does not exist", "unsupported model")):
        return "model_error"
    if any(term in text for term in ("rate_limit", "rate limit", "429", "quota")):
        return "rate_limit"
    if any(term in text for term in ("timed out", "timeout", "connection", "network", "urlerror")):
        return "network_error"
    if any(term in text for term in ("schema", "validation", "invalid json", "json response")):
        return "schema_error"
    return "provider_error"


def extract_safe_request_id(error: Exception | str | dict[str, Any]) -> str | None:
    text = sanitize_provider_error(error)
    patterns = (
        r"(?:request[_ -]?id|x-request-id|req[_-])[\"'\s:=]+([A-Za-z0-9._-]{6,80})",
        r"\b(req_[A-Za-z0-9._-]{6,80})\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def provider_safe_message(provider: str, error: Exception | str | dict[str, Any]) -> str:
    error_type = classify_provider_error(error)
    provider_name = provider.capitalize()
    if provider.lower() == "openai" and error_type == "auth_error":
        return (
            "OpenAI authentication failed. The configured OPENAI_API_KEY was rejected by the provider. "
            "Check `.env`, shell environment, and `ic_copilot.local.yaml`. The app may be loading a "
            "different key than your manual curl test."
        )
    if error_type == "model_error":
        return f"{provider_name} rejected the configured model. Check the model in `ic_copilot.local.yaml`."
    if error_type == "rate_limit":
        return f"{provider_name} rate limit or quota blocked this run. Try again later or check account limits."
    if error_type == "network_error":
        return f"{provider_name} network request failed. Check local network access and provider availability."
    if error_type == "schema_error":
        return f"{provider_name} returned output that did not validate against the required schema."
    return f"{provider_name} provider request failed. Check provider configuration and try again."
