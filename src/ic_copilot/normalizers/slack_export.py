from __future__ import annotations

from pathlib import Path

from ic_copilot.normalizers.slack_paste import normalize_slack_paste
from ic_copilot.schemas import IncidentEvent


def normalize_slack_export(path: str | Path, incident_id: str | None = None) -> list[IncidentEvent]:
    """Phase 1 export shim: treat a plain text export as a Slack paste."""
    return normalize_slack_paste(Path(path).read_text(), incident_id=incident_id)

