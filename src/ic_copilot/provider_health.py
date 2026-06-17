from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import Field

from ic_copilot.error_sanitizer import classify_provider_error, extract_safe_request_id, sanitize_provider_error
from ic_copilot.llm.product_client import ProductConfigurationError, create_product_llm_client
from ic_copilot.llm.providers.base_json import ProviderJSONError
from ic_copilot.runtime_config import load_product_runtime_config
from ic_copilot.runtime_diagnostics import collect_provider_runtime_diagnostics
from ic_copilot.schemas import StrictBaseModel, utc_now


ProviderHealthKind = Literal[
    "unknown",
    "ok",
    "auth_error",
    "model_error",
    "rate_limit",
    "network_error",
    "provider_error",
    "schema_error",
]


class ProviderHealthStatus(StrictBaseModel):
    status: ProviderHealthKind = "unknown"
    provider: str
    model: str
    checked_at: datetime = Field(default_factory=utc_now)
    latency_ms: int | None = None
    safe_message: str
    error_type: str | None = None
    request_id: str | None = None
    fingerprint: str | None = None
    raw_error_redacted: str | None = None


class ProviderHealthProbe(StrictBaseModel):
    ok: bool
    message: str = ""


def _safe_failure_status(
    exc: Exception,
    *,
    provider: str,
    model: str,
    fingerprint: str | None,
    latency_ms: int | None,
) -> ProviderHealthStatus:
    if isinstance(exc, ProviderJSONError):
        error_type = exc.error_type or classify_provider_error(exc.raw_error_redacted or str(exc))
        request_id = exc.request_id
        raw_redacted = exc.raw_error_redacted
        safe_message = exc.safe_message
    else:
        error_type = "auth_error" if isinstance(exc, ProductConfigurationError) else classify_provider_error(exc)
        request_id = extract_safe_request_id(exc)
        raw_redacted = sanitize_provider_error(exc)
        if error_type == "auth_error" and provider == "openai":
            safe_message = (
                "OpenAI authentication failed. The configured OPENAI_API_KEY was rejected by the provider. "
                "Check `.env`, shell environment, and `ic_copilot.local.yaml`. The app may be loading a "
                "different key than your manual curl test."
            )
        else:
            safe_message = raw_redacted
    return ProviderHealthStatus(
        status=error_type,  # type: ignore[arg-type]
        provider=provider,
        model=model,
        latency_ms=latency_ms,
        safe_message=safe_message,
        error_type=error_type,
        request_id=request_id,
        fingerprint=fingerprint,
        raw_error_redacted=raw_redacted,
    )


def check_product_provider_health(
    config_path: str | Path | None = None,
    *,
    timeout_seconds: float | None = None,
) -> ProviderHealthStatus:
    diag = collect_provider_runtime_diagnostics(config_path)
    started = time.perf_counter()
    try:
        config = load_product_runtime_config(config_path)
        if timeout_seconds is not None:
            config = config.model_copy(update={"llm": config.llm.model_copy(update={"timeout_seconds": timeout_seconds})})
        client = create_product_llm_client(config)
        result = client.generate_json(
            "provider_health_check",
            {
                "task": "Return a tiny JSON health probe only.",
                "expected": {"ok": True, "message": "ok"},
            },
            ProviderHealthProbe,
        )
        latency_ms = int((time.perf_counter() - started) * 1000)
        if not result.ok:
            return ProviderHealthStatus(
                status="schema_error",
                provider=diag.provider,
                model=diag.model,
                latency_ms=latency_ms,
                safe_message="Provider health response validated but did not return ok=true.",
                error_type="schema_error",
                fingerprint=diag.effective_key_fingerprint,
            )
        return ProviderHealthStatus(
            status="ok",
            provider=diag.provider,
            model=diag.model,
            latency_ms=latency_ms,
            safe_message="Provider health check succeeded through the product adapter path.",
            fingerprint=diag.effective_key_fingerprint,
        )
    except Exception as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        return _safe_failure_status(
            exc,
            provider=diag.provider,
            model=diag.model,
            fingerprint=diag.effective_key_fingerprint,
            latency_ms=latency_ms,
        )
