from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from ic_copilot.schemas import (
    CleanContextBlocker,
    CleanContextValue,
    CleanIncidentContext,
    CleanQuestionLedger,
    IncidentEvent,
    InputSizeAssessment,
    LatestWindowSelection,
)


BOT_AUTHORS = {
    "app",
    "ic bot",
    "im-agent",
    "jira cloud",
    "phase update",
    "slackbot",
    "zsrebot",
}
HIGH_SIGNAL_TERMS = (
    "p1",
    "p2",
    "p3",
    "sev",
    "impact",
    "customer",
    "tenant",
    "sandbox",
    "application",
    "owner",
    "oncall",
    "page",
    "paged",
    "error",
    "exception",
    "timeout",
    "504",
    "limit",
    "failed",
    "health",
    "restart",
    "rollback",
    "disable",
    "hotfix",
    "deploy",
    "mitigation",
    "validate",
    "validation",
    "responding",
    "response",
    "still running",
    "monitor",
    "status",
    "eta",
    "?",
)
LOG_TERMS = (
    "exception",
    "traceback",
    "error",
    "failed",
    "timeout",
    "limit",
    "health check",
    "version",
    "package",
    "stdout",
    "stderr",
    "```",
)
ACTION_TERMS = (
    "rollback",
    "disable",
    "restart",
    "hotfix",
    "deploy",
    "mitigat",
    "fix",
    "checking",
    "investigating",
    "validat",
    "monitor",
)
QUESTION_TERMS = ("?", "can you", "could you", "please confirm", "status", "eta", "update")
VALIDATION_MONITORING_TERMS = (
    "validate",
    "validation",
    "monitor",
    "stable",
    "still failing",
    "still running",
    "fixed",
    "mitigated",
    "health",
    "dashboard",
)
CUSTOMER_SUPPORT_TERMS = (
    "customer",
    "tenant",
    "support",
    "sandbox",
    "ticket",
    "zendesk",
)
RELATED_INCIDENT_TERMS = (
    "related incidents found",
    "what caused the previous incident",
    "what fix/mitigation worked",
    "previous incident",
)


@dataclass(frozen=True)
class EventChunk:
    chunk_id: str
    events: list[IncidentEvent]
    raw_text: str
    score: int


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _event_text(event: IncidentEvent) -> str:
    author = f"{event.author}: " if event.author else ""
    return f"{event.event_id} {author}{event.message}"


def _event_is_bot(event: IncidentEvent) -> bool:
    author = _norm(event.author)
    return author in BOT_AUTHORS or "bot" in author or "app" == author


def _event_is_low_value_bot_noise(event: IncidentEvent) -> bool:
    text = _norm(f"{event.author or ''} {event.message}")
    if any(term in text for term in RELATED_INCIDENT_TERMS):
        return True
    if not _event_is_bot(event):
        return False
    low_value_terms = (
        "trust post reminder",
        "created channel",
        "joined channel",
        "added by",
        "preview in slack",
        "show more",
        "pinned by",
        "workflow terminated",
    )
    return any(term in text for term in low_value_terms)


def _is_code_or_log(message: str) -> bool:
    text = _norm(message)
    if any(term in text for term in LOG_TERMS):
        return True
    return bool(re.search(r"(^|\n)\s*(?:at\s+\S+|\w+=\S+|[\w./-]+:\s*\d+)", message))


def _event_score(event: IncidentEvent, index: int, total: int) -> int:
    text = _norm(f"{event.author or ''} {event.message}")
    score = 0
    if not _event_is_bot(event):
        score += 3
    if any(term in text for term in RELATED_INCIDENT_TERMS):
        score -= 12
    score += sum(2 for term in HIGH_SIGNAL_TERMS if term in text)
    score += min(len(event.extracted_tokens.get("urls", [])), 3)
    score += min(len(event.extracted_tokens.get("command_candidates", [])) * 2, 4)
    if _is_code_or_log(event.message):
        score += 3
    if "created channel" in text or "joined channel" in text or "added by" in text:
        score -= 2
    if any(term in text for term in ("next action", "next actions", "await", "please confirm", "can you confirm")):
        score += 8
    if index >= max(0, total - 10):
        score += 3
    return score


def assess_input_size(raw_text: str, events: list[IncidentEvent]) -> InputSizeAssessment:
    char_count = len(raw_text)
    event_count = len(events)
    url_count = sum(len(event.extracted_tokens.get("urls", [])) for event in events)
    long_event_count = sum(1 for event in events if len(event.message) > 1200)
    code_or_log_count = sum(1 for event in events if _is_code_or_log(event.message))
    bot_count = sum(1 for event in events if _event_is_bot(event))
    estimated_tokens = max(1, char_count // 4)
    reasons: list[str] = []
    if char_count > 18000:
        reasons.append("input has more than 18k characters")
    if event_count > 45:
        reasons.append("input has more than 45 normalized events")
    if long_event_count:
        reasons.append("input includes long pasted log/message blocks")
    if code_or_log_count >= 4:
        reasons.append("input includes multiple log or diagnostic snippets")
    if estimated_tokens > 5000:
        reasons.append("estimated token count is high for a single clean-context pass")

    if char_count > 50000 or event_count > 120:
        strategy = "latest_window_only_with_summary"
    elif char_count > 18000 or event_count > 45 or estimated_tokens > 5000 or code_or_log_count >= 4:
        strategy = "chunked_clean_context"
    elif char_count > 10000:
        strategy = "compact_then_single_pass"
    else:
        strategy = "single_pass"
    return InputSizeAssessment(
        event_count=event_count,
        character_count=char_count,
        estimated_token_count=estimated_tokens,
        long_event_count=long_event_count,
        url_count=url_count,
        code_or_log_block_count=code_or_log_count,
        bot_or_system_event_count=bot_count,
        likely_too_large_for_single_pass=strategy != "single_pass",
        recommended_strategy=strategy,
        reasons=reasons,
    )


def _make_chunk(chunk_index: int, events: list[IncidentEvent], total_events: int) -> EventChunk:
    raw = "\n\n".join(_event_text(event) for event in events)
    start = events[0].event_id if events else "none"
    end = events[-1].event_id if events else "none"
    score = sum(_event_score(event, total_events - len(events) + idx, total_events) for idx, event in enumerate(events))
    return EventChunk(chunk_id=f"chunk-{chunk_index:02d}-{start}-{end}", events=events, raw_text=raw, score=score)


def split_event_chunks(
    events: list[IncidentEvent],
    *,
    max_chunk_chars: int = 14000,
    max_events_per_chunk: int = 40,
) -> list[EventChunk]:
    chunks: list[EventChunk] = []
    current: list[IncidentEvent] = []
    current_chars = 0
    for event in events:
        event_chars = len(_event_text(event)) + 2
        if current and (len(current) >= max_events_per_chunk or current_chars + event_chars > max_chunk_chars):
            chunks.append(_make_chunk(len(chunks) + 1, current, len(events)))
            current = []
            current_chars = 0
        current.append(event)
        current_chars += event_chars
    if current:
        chunks.append(_make_chunk(len(chunks) + 1, current, len(events)))
    return chunks


def select_chunks(chunks: list[EventChunk], *, max_chunks: int = 5) -> list[EventChunk]:
    if len(chunks) <= max_chunks:
        return chunks
    selected: dict[str, EventChunk] = {}
    selected[chunks[0].chunk_id] = chunks[0]
    selected[chunks[-1].chunk_id] = chunks[-1]
    for chunk in sorted(chunks, key=lambda item: item.score, reverse=True):
        if len(selected) >= max_chunks:
            break
        selected[chunk.chunk_id] = chunk
    return sorted(selected.values(), key=lambda item: chunks.index(item))


def latest_window_events(events: list[IncidentEvent], *, max_events: int = 35) -> list[IncidentEvent]:
    selection = select_latest_window(events, max_events=max_events)
    selected = set(selection.event_ids)
    return [event for event in events if event.event_id in selected]


def select_latest_window(
    events: list[IncidentEvent],
    *,
    max_events: int = 35,
    min_latest_events: int = 20,
) -> LatestWindowSelection:
    if not events:
        return LatestWindowSelection(reason="no events available")
    has_low_value_sections = any(_event_is_low_value_bot_noise(event) for event in events)
    if len(events) <= max_events and not has_low_value_sections:
        ids = [event.event_id for event in events]
        return LatestWindowSelection(
            event_ids=ids,
            reason="input fits latest-window budget",
            dropped_event_count=0,
            kept_event_count=len(ids),
            **_latest_window_flags(events),
        )

    total = len(events)
    selected_ids: set[str] = set()

    first_candidates = events[: min(8, total)]
    summary_terms = ("incident", "summary", "p1", "p2", "p3", "severity", "title", "created")
    for event in first_candidates:
        text = _norm(f"{event.author or ''} {event.message}")
        if any(term in text for term in summary_terms):
            selected_ids.add(event.event_id)
        if len(selected_ids) >= 3:
            break

    tail = events[-max(max_events, min_latest_events):]
    selected_log_count = 0
    for event in reversed(tail):
        if len(selected_ids) >= max_events:
            break
        if _event_is_low_value_bot_noise(event):
            continue
        if _is_code_or_log(event.message) and selected_log_count >= 6:
            continue
        selected_ids.add(event.event_id)
        if _is_code_or_log(event.message):
            selected_log_count += 1
        if len([event_id for event_id in selected_ids if event_id in {tail_event.event_id for tail_event in tail}]) >= min_latest_events:
            break

    if len(selected_ids) < min_latest_events:
        for event in reversed(tail):
            if len(selected_ids) >= max_events or len(selected_ids) >= min_latest_events:
                break
            if _is_code_or_log(event.message) and selected_log_count >= 8:
                continue
            selected_ids.add(event.event_id)
            if _is_code_or_log(event.message):
                selected_log_count += 1

    remaining_slots = max_events - len(selected_ids)
    if remaining_slots > 0:
        scored = sorted(
            enumerate(events),
            key=lambda pair: (_event_score(pair[1], pair[0], total), pair[0]),
            reverse=True,
        )
        for _, event in scored:
            if remaining_slots <= 0:
                break
            if event.event_id in selected_ids or _event_is_low_value_bot_noise(event):
                continue
            if _is_code_or_log(event.message) and selected_log_count >= 8:
                continue
            if _event_score(event, events.index(event), total) < 4:
                continue
            selected_ids.add(event.event_id)
            if _is_code_or_log(event.message):
                selected_log_count += 1
            remaining_slots -= 1

    selected_events = [event for event in events if event.event_id in selected_ids]
    if len(selected_events) > max_events:
        selected_events = selected_events[-max_events:]
    ids = [event.event_id for event in selected_events]
    return LatestWindowSelection(
        event_ids=ids,
        reason="selected latest high-signal operator window",
        dropped_event_count=max(0, len(events) - len(ids)),
        kept_event_count=len(ids),
        **_latest_window_flags(selected_events),
    )


def _latest_window_flags(events: list[IncidentEvent]) -> dict[str, bool]:
    if not events:
        return {
            "contains_latest_human_evidence": False,
            "contains_latest_bot_summary": False,
            "contains_latest_actions": False,
            "contains_latest_questions": False,
            "contains_latest_validation_or_monitoring": False,
            "contains_latest_customer_or_support_update": False,
        }
    latest_slice = events[-10:]
    all_text = " ".join(_norm(f"{event.author or ''} {event.message}") for event in events)
    return {
        "contains_latest_human_evidence": any(not _event_is_bot(event) for event in latest_slice),
        "contains_latest_bot_summary": any(_event_is_bot(event) for event in latest_slice),
        "contains_latest_actions": any(term in all_text for term in ACTION_TERMS),
        "contains_latest_questions": any(term in all_text for term in QUESTION_TERMS),
        "contains_latest_validation_or_monitoring": any(term in all_text for term in VALIDATION_MONITORING_TERMS),
        "contains_latest_customer_or_support_update": any(term in all_text for term in CUSTOMER_SUPPORT_TERMS),
    }


def _dedupe_by_key(items: Iterator, key_func) -> list:
    seen: set[str] = set()
    out = []
    for item in items:
        key = key_func(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def merge_clean_contexts(
    chunk_contexts: list[CleanIncidentContext],
    incident_id: str,
) -> CleanIncidentContext:
    if not chunk_contexts:
        return CleanIncidentContext(
            incident_id=incident_id,
            clean_summary="No clean context chunks succeeded.",
            uncertainty_notes=["CleanIncidentContext could not be extracted from the available chunks."],
        )
    based_on_event_ids = _dedupe_by_key(
        (event_id for context in chunk_contexts for event_id in context.based_on_event_ids),
        lambda event_id: event_id,
    )
    phase = max((context.phase for context in chunk_contexts), key=lambda item: item.confidence, default=CleanContextValue())
    severity = max(
        (context.severity for context in chunk_contexts if context.severity.value != "unknown"),
        key=lambda item: item.confidence,
        default=CleanContextValue(),
    )
    blocker = max(
        (context.current_blocker for context in chunk_contexts if context.current_blocker.blocker_type != "unknown"),
        key=lambda item: item.confidence,
        default=CleanContextBlocker(),
    )
    summary_bits = [context.clean_summary for context in chunk_contexts if context.clean_summary]
    source_bits = [context.source_summary for context in chunk_contexts if context.source_summary]
    question_ledger = CleanQuestionLedger(
        open_questions=_dedupe_by_key(
            (question for context in chunk_contexts for question in context.question_ledger.open_questions),
            lambda question: question.question_id,
        ),
        answered_questions=_dedupe_by_key(
            (question for context in chunk_contexts for question in context.question_ledger.answered_questions),
            lambda question: question.question_id,
        ),
        stale_question_intents=sorted(
            {
                intent
                for context in chunk_contexts
                for intent in context.question_ledger.stale_question_intents
            }
        ),
    )
    return CleanIncidentContext(
        incident_id=incident_id,
        based_on_event_ids=based_on_event_ids,
        source_summary="\n".join(source_bits)[-3000:],
        clean_summary=" ".join(dict.fromkeys(summary_bits))[:1800],
        phase=phase,
        severity=severity,
        current_blocker=blocker,
        incident_kind=_dedupe_by_key(
            (fact for context in chunk_contexts for fact in context.incident_kind),
            lambda fact: f"{fact.fact_type}:{_norm(fact.value)}",
        ),
        facts=_dedupe_by_key(
            (fact for context in chunk_contexts for fact in context.facts),
            lambda fact: f"{fact.fact_type}:{_norm(fact.value)}",
        ),
        candidate_services=_dedupe_by_key(
            (entity for context in chunk_contexts for entity in context.candidate_services),
            lambda entity: f"{entity.entity_type}:{_norm(entity.name)}",
        ),
        engaged_entities=_dedupe_by_key(
            (entity for context in chunk_contexts for entity in context.engaged_entities),
            lambda entity: f"{entity.entity_type}:{_norm(entity.name)}",
        ),
        suggested_but_not_engaged=_dedupe_by_key(
            (entity for context in chunk_contexts for entity in context.suggested_but_not_engaged),
            lambda entity: f"{entity.entity_type}:{_norm(entity.name)}",
        ),
        question_ledger=question_ledger,
        actions_completed=_dedupe_by_key(
            (action for context in chunk_contexts for action in context.actions_completed),
            lambda action: action.action_id,
        ),
        monitoring_signals=_dedupe_by_key(
            (signal for context in chunk_contexts for signal in context.monitoring_signals),
            lambda signal: _norm(signal.value),
        ),
        rejected_entities=_dedupe_by_key(
            (entity for context in chunk_contexts for entity in context.rejected_entities),
            lambda entity: f"{entity.rejected_entity_type}:{_norm(entity.text)}:{entity.reason}",
        ),
        do_not_invent=sorted({item for context in chunk_contexts for item in context.do_not_invent}),
        uncertainty_notes=sorted({item for context in chunk_contexts for item in context.uncertainty_notes}),
    )
