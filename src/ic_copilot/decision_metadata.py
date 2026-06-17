from __future__ import annotations

import re
from datetime import datetime, timezone

from ic_copilot.schemas import ICDecision


ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")
ISO_DURATION_RE = re.compile(r"^P(?:T)?\d+[SMHD]$", re.I)


def normalize_decision_expiration(
    decision: ICDecision,
    *,
    now: datetime | None = None,
    default_duration: str = "PT15M",
) -> tuple[ICDecision, bool, str | None]:
    """Repair LLM-produced expiration metadata without changing decision content.

    The IC whisper is pipeline-local and manual-copy only. An absolute timestamp
    from the model is not allowed to decide whether otherwise grounded advice
    falls back; the runtime owns this metadata.
    """
    raw_expiration = str(decision.expiration or "").strip()
    now = now or datetime.now(timezone.utc)
    if not raw_expiration:
        reason = "missing_expiration"
    elif ISO_DURATION_RE.match(raw_expiration):
        return decision, False, None
    elif ISO_DATE_RE.match(raw_expiration):
        try:
            expires_at = datetime.fromisoformat(raw_expiration.replace("Z", "+00:00"))
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
        except ValueError:
            reason = "invalid_absolute_expiration"
        else:
            # Keep the output stable by normalizing model-owned wall-clock times
            # to the product's short relative TTL.
            reason = "past_expiration" if expires_at <= now else "absolute_expiration_normalized"
    else:
        reason = "invalid_expiration"

    metadata = dict(decision.model_metadata)
    metadata.update(
        {
            "metadata_repair_reason": reason,
            "original_expiration": raw_expiration,
            "normalized_expiration": default_duration,
        }
    )
    return decision.model_copy(update={"expiration": default_duration, "model_metadata": metadata}), True, reason


def only_expiration_failed(checks: dict[str, bool]) -> bool:
    failed = [name for name, passed in checks.items() if not passed]
    return failed == ["expires_correctly"]
