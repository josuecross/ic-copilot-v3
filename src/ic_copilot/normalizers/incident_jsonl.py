from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ic_copilot.normalizers.slack_paste import extract_slack_like_tokens
from ic_copilot.schemas import IncidentEvent


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _event_hash(incident_id: str, sequence: int, author: str | None, message: str) -> str:
    stable = f"{incident_id}|{sequence}|{author or ''}|{message}"
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def load_incident_jsonl(path: str | Path, incident_id: str | None = None) -> list[IncidentEvent]:
    source = Path(path)
    incident_id = incident_id or source.stem
    events: list[IncidentEvent] = []
    for line_number, line in enumerate(source.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{source}:{line_number}: invalid JSONL record: {exc}") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"{source}:{line_number}: expected JSON object")

        sequence = int(raw.get("sequence") or len(events) + 1)
        event_id = str(raw.get("event_id") or f"m{sequence:03d}")
        author = raw.get("author") or raw.get("user") or raw.get("display_name")
        message = raw.get("message") or raw.get("text")
        if not message:
            raise ValueError(f"{source}:{line_number}: missing message/text")
        ts = raw.get("ts") or raw.get("timestamp")
        raw_metadata = dict(raw.get("raw_metadata") or {})
        raw_metadata.setdefault("jsonl_line", line_number)
        raw_metadata.setdefault("author_type", raw.get("author_type"))
        tokens = extract_slack_like_tokens(
            str(message),
            author=str(author) if author else None,
            urls=[str(item) for item in _as_list(raw.get("urls"))],
            mentions=[str(item) for item in _as_list(raw.get("mentions"))],
            command_candidates=[str(item) for item in _as_list(raw.get("candidate_commands"))],
        )
        if raw.get("extracted_tokens") and isinstance(raw["extracted_tokens"], dict):
            provided = raw["extracted_tokens"]
            for key in ("urls", "slack_mentions", "command_candidates", "numbers"):
                if provided.get(key):
                    existing = tokens.get(key, [])
                    tokens[key] = existing + [item for item in provided[key] if item not in existing]
        source_name = "incident_jsonl"
        if tokens.get("is_system"):
            source_name = "slack_system"
        events.append(
            IncidentEvent(
                event_id=event_id,
                incident_id=incident_id,
                ts=str(ts) if ts is not None else None,
                sequence=sequence,
                source=source_name,
                author=str(author) if author else None,
                message=str(message),
                extracted_tokens=tokens,
                raw_metadata=raw_metadata,
                hash=str(raw.get("hash") or _event_hash(incident_id, sequence, str(author) if author else None, str(message))),
            )
        )
    return sorted(events, key=lambda event: event.sequence)
