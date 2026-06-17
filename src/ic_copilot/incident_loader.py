from __future__ import annotations

from pathlib import Path

from ic_copilot.normalizers.incident_jsonl import load_incident_jsonl
from ic_copilot.normalizers.slack_paste import normalize_slack_paste_file
from ic_copilot.schemas import IncidentEvent


def incident_id_from_path(path: str | Path) -> str:
    return Path(path).stem.replace(" ", "_")


def load_incident_events(incident_file: str | Path, incident_id: str | None = None) -> list[IncidentEvent]:
    path = Path(incident_file)
    resolved_incident_id = incident_id or incident_id_from_path(path)
    if path.suffix == ".jsonl":
        return load_incident_jsonl(path, incident_id=resolved_incident_id)
    return normalize_slack_paste_file(path, incident_id=resolved_incident_id)
