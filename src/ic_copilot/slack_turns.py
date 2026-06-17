from __future__ import annotations

import re

from ic_copilot.error_sanitizer import sanitize_user_facing_error
from ic_copilot.llm.base import LLMClient
from ic_copilot.schema_repair import validate_with_repair
from ic_copilot.schemas import (
    IncidentEvent,
    InputSizeAssessment,
    SlackTurnReconstruction,
)


SPEAKER_TIME_PATTERN = re.compile(
    r"(?im)^(?:[A-Z][A-Za-z0-9 ._'@-]{0,60}\s+(?:APP\s+)?\d{1,2}:\d{2}\s?[AP]M|\d{1,2}:\d{2}\s?[AP]M\s+[A-Z][A-Za-z0-9 ._'@-]{0,60}:)"
)
AUTHOR_TIME_SPLIT_PATTERN = re.compile(
    r"(?im)^[A-Z][A-Za-z0-9 ._'@-]{0,60}\s*$\n^\d{1,2}:\d{2}\s?[AP]M\s*$"
)


def should_reconstruct_turns(raw_text: str, events: list[IncidentEvent], assessment: InputSizeAssessment) -> bool:
    if assessment.character_count <= 3000 or len(events) >= 8:
        return False
    block_count = len(SPEAKER_TIME_PATTERN.findall(raw_text)) + len(AUTHOR_TIME_SPLIT_PATTERN.findall(raw_text))
    return block_count >= 8


def reconstruct_slack_turns(
    *,
    raw_text: str,
    events: list[IncidentEvent],
    assessment: InputSizeAssessment,
    incident_id: str,
    llm_client: LLMClient,
) -> tuple[SlackTurnReconstruction | None, list[str]]:
    if not should_reconstruct_turns(raw_text, events, assessment):
        return None, []

    payload = {
        "incident_id": incident_id,
        "raw_text": raw_text,
        "events": [event.model_dump(mode="json") for event in events],
        "input_size_assessment": assessment.model_dump(mode="json"),
        "rules": [
            "Only reconstruct speaker turns; do not infer incident facts.",
            "Preserve source event IDs.",
            "Do not invent speakers.",
            "Default_Agent and bot/system labels are not real teams.",
            "URL path numbers and docs page numbers are not tenants.",
        ],
    }
    try:
        reconstruction = llm_client.generate_json(
            "slack_turn_reconstruction",
            payload,
            SlackTurnReconstruction,
        )
        return validate_with_repair(
            reconstruction,
            SlackTurnReconstruction,
            context="slack_turn_reconstruction",
        ), []
    except Exception as exc:
        return None, [f"Slack turn reconstruction skipped: {sanitize_user_facing_error(exc)}"]
