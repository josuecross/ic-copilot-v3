from __future__ import annotations

import re
from typing import Any

from ic_copilot.llm.redaction import redact_for_llm
from ic_copilot.schemas import EventQuality, IncidentEvent


ACTION_STATE_SCHEMA_VERSION = "1.0"

PAGE_REQUEST_RE = re.compile(
    r"\b(?:could you|can you|please|have we|has someone|need to|we need to)\b"
    r"[^.?!\n]{0,100}\b(?:page|engage|loop in|contact)\b"
    r"[^.?!\n]{0,100}\b(?:engineering|team|owner|oncall|on-call|support|responsible)\b",
    re.IGNORECASE,
)
PAGE_ACCEPT_RE = re.compile(
    r"\b(?:i will|i'll|let me|on it|will)\b[^.?!\n]{0,80}\b(?:page|engage|loop in|contact)\b",
    re.IGNORECASE,
)
PAGE_EXECUTION_RE = re.compile(
    r"(?:^|\s)@?zsrebot\b[^.\n]{0,120}\bpage\s+(?:team|user|oncall)\b|"
    r"\bpage\s+(?:team|user|oncall)\b[^.\n]{0,120}\b(?:revenue|engineering|owner|support|sre|ops)\b",
    re.IGNORECASE,
)
PAGE_COMPLETION_RE = re.compile(
    r"\b(?:done|paged|paging completed|page completed|successfully paged|notified)\b",
    re.IGNORECASE,
)


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _compact(value: str | None, *, limit: int = 220) -> str:
    text = " ".join(str(redact_for_llm(value or "")).split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rsplit(" ", 1)[0].rstrip() + "..."


def _quality_by_id(event_quality: list[EventQuality] | list[dict[str, Any]] | None) -> dict[str, EventQuality]:
    quality_by_id: dict[str, EventQuality] = {}
    for item in event_quality or []:
        quality = item if isinstance(item, EventQuality) else EventQuality.model_validate(item)
        quality_by_id[quality.event_id] = quality
    return quality_by_id


def _is_operator_or_bot_confirmation(event: IncidentEvent, quality_by_id: dict[str, EventQuality]) -> bool:
    quality = quality_by_id.get(event.event_id)
    if quality is None:
        tokens = event.extracted_tokens or {}
        return not bool(tokens.get("is_system"))
    return quality.event_kind not in {
        "preview_card",
        "pagerduty_card",
        "jira_card",
        "zoom_card",
        "slack_lifecycle",
        "generated_summary_fragment",
        "low_signal_noise",
    }


def _target_hint(text: str) -> str:
    lowered = _norm(text)
    if "revenue" in lowered:
        return "Revenue Engineering"
    if "engineering" in lowered:
        return "Engineering"
    if "support" in lowered:
        return "Support"
    if "owner" in lowered or "responsible" in lowered:
        return "Owner team"
    return "owner/team"


def infer_action_state_transitions(
    events: list[IncidentEvent] | list[dict[str, Any]],
    event_quality: list[EventQuality] | list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Infer closed operational action loops from current evidence.

    This is not answer generation or target routing. It only annotates that an
    earlier operational ask was accepted/executed/confirmed by later evidence so
    the one-call V2 reader can avoid repeating a stale question.
    """

    normalized_events = [
        event if isinstance(event, IncidentEvent) else IncidentEvent.model_validate(event)
        for event in events
    ]
    quality_by_id = _quality_by_id(event_quality)
    action_loops: list[dict[str, Any]] = []
    answered_questions: list[dict[str, Any]] = []
    do_not_ask: list[str] = []

    for idx, event in enumerate(normalized_events):
        if not _is_operator_or_bot_confirmation(event, quality_by_id):
            continue
        if not PAGE_REQUEST_RE.search(event.message):
            continue
        target = _target_hint(event.message)
        transitions: list[dict[str, Any]] = [
            {
                "state": "requested",
                "event_id": event.event_id,
                "author": event.author,
                "quote": _compact(event.message),
            }
        ]
        accepted_event: IncidentEvent | None = None
        executed_event: IncidentEvent | None = None
        completed_event: IncidentEvent | None = None
        for later in normalized_events[idx + 1 :]:
            if not _is_operator_or_bot_confirmation(later, quality_by_id):
                continue
            later_text = later.message or ""
            if accepted_event is None and PAGE_ACCEPT_RE.search(later_text):
                accepted_event = later
                transitions.append(
                    {
                        "state": "accepted",
                        "event_id": later.event_id,
                        "author": later.author,
                        "quote": _compact(later_text),
                    }
                )
                continue
            if executed_event is None and PAGE_EXECUTION_RE.search(later_text):
                executed_event = later
                transitions.append(
                    {
                        "state": "executed",
                        "event_id": later.event_id,
                        "author": later.author,
                        "quote": _compact(later_text),
                    }
                )
                continue
            if completed_event is None and (
                PAGE_COMPLETION_RE.search(later_text)
                and (executed_event is not None or "page" in _norm(later_text))
            ):
                completed_event = later
                transitions.append(
                    {
                        "state": "completed",
                        "event_id": later.event_id,
                        "author": later.author,
                        "quote": _compact(later_text),
                    }
                )
                break
        final_state = "completed" if completed_event else "executed" if executed_event else "accepted" if accepted_event else "requested"
        if final_state not in {"executed", "completed"}:
            continue
        if final_state == "completed":
            transitions.append(
                {
                    "state": "superseded",
                    "event_id": completed_event.event_id if completed_event else executed_event.event_id,
                    "author": completed_event.author if completed_event else executed_event.author,
                    "quote": "Earlier page/engagement ask was closed by later execution/confirmation evidence.",
                }
            )
        action_id = f"{event.event_id}:operational_page_or_engage"
        action_loops.append(
            {
                "action_id": action_id,
                "action_type": "page_or_engage_owner",
                "target_hint": target,
                "final_state": final_state,
                "requested_by": event.author,
                "accepted_by": accepted_event.author if accepted_event else None,
                "executed_by": executed_event.author if executed_event else None,
                "confirmed_by": completed_event.author if completed_event else None,
                "transitions": transitions,
                "closed": final_state in {"executed", "completed"},
                "do_not_ask_intent": "confirm_page_or_engagement_completed",
                "do_not_ask_text": f"Do not ask whether {target} was paged or engaged; current evidence already shows the action was {final_state}.",
            }
        )
        answered_questions.append(
            {
                "question_event_id": event.event_id,
                "question_intent": "owner_status",
                "question_text": _compact(event.message),
                "answer_event_id": (completed_event or executed_event).event_id,
                "answer_summary": f"{target} page/engagement was {final_state} by later current evidence.",
                "answer_reason": "operational action completion",
                "answer_confidence": 0.9 if completed_event else 0.82,
            }
        )
        do_not_ask.append(f"confirm whether {target} was paged")
        do_not_ask.append(f"ask {event.author or 'the requester'} whether {target} was paged")

    return {
        "schema_version": ACTION_STATE_SCHEMA_VERSION,
        "action_loops": action_loops,
        "answered_questions": answered_questions,
        "do_not_ask": list(dict.fromkeys(do_not_ask)),
    }
