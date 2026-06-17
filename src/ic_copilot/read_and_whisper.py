from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from ic_copilot.action_state import infer_action_state_transitions
from ic_copilot.llm.base import LLMClient
from ic_copilot.llm.redaction import redact_for_llm
from ic_copilot.raw_paste_contract import (
    db_cpu_initial_contract,
    diagnostic_fact_classifications,
    expected_memory_contracts,
    extract_diagnostic_facts,
    target_class_for_allowed_target,
)
from ic_copilot.schemas import (
    AllowedTarget,
    CommandRegistryEntry,
    DecisionMoment,
    EntityRef,
    EntityType,
    EvidenceRef,
    ICDecision,
    IncidentEvent,
    IncidentReadAndWhisper,
    InputSizeAssessment,
    LatestWindowSelection,
    ServiceCatalogEntry,
    WhisperEvidenceRef,
    utc_now,
)
from ic_copilot.work_items import extract_current_work_items


MAX_EVENT_TEXT_CHARS = 360
MAX_LOW_SIGNAL_TEXT_CHARS = 160
MAX_CANDIDATE_TARGETS = 20
MAX_REJECTED_TARGETS = 10
MAX_TARGET_ALIASES = 10
MAX_MODEL_EVENTS = 18
MAX_ULTRA_MODEL_EVENTS = 12
MAX_ULTRA_EVENT_TEXT_CHARS = 220
MAX_MODEL_PAYLOAD_TARGET_CHARS = 14_000
MAX_MODEL_PAYLOAD_HARD_CHARS = 18_000
MAX_ULTRA_MODEL_PAYLOAD_TARGET_CHARS = 8_000
NOISY_TARGET_EVENT_KINDS = {
    "bot_system_message",
    "bot_diagnostic_evidence",
    "bot_lifecycle",
    "bot_owner_request",
    "preview_card",
    "pagerduty_card",
    "jira_card",
    "zoom_card",
    "slack_lifecycle",
    "log_or_code_block",
    "table_row",
    "table_header",
    "generated_summary_fragment",
    "low_signal_noise",
}
NOISY_TARGET_NAMES = {
    "@channel",
    "@here",
    "active",
    "audit logs",
    "awaiting sre",
    "app",
    "batchcount",
    "comment",
    "current status",
    "checkpoint",
    "createdon",
    "daco-bot",
    "dedicated_topic",
    "dedicatedcluster",
    "dedicatedtopic",
    "dedicatedtopiccount",
    "envirovmentvariables",
    "expiry",
    "fix vulnerability",
    "heavy database load",
    "incident commander",
    "issue",
    "issue priority",
    "issue start time",
    "issue status",
    "meeting id",
    "monitor workers",
    "monitoring plan",
    "next action",
    "re-evaluate severity",
    "owners",
    "priority",
    "recordfromcache",
    "recordfromdb",
    "rediskeys",
    "the team",
    "trust post",
    "roles",
    "rotate credentials",
    "services impacted",
    "teams involved",
    "tenants impacted",
    "tenantid",
    "topicname",
    "topicnumber",
    "ttl",
    "updatedby",
    "updatedon",
}
NOISY_TARGET_CONTAINS = (
    "action items",
    "audit logs",
    "assignee",
    "checkpoint",
    "fix vulnerability",
    "impact summary",
    "key observations",
    "meeting id",
    "monitoring plan",
    "next action",
    "owners",
    "preview in slack",
    "please join to slack channel",
    "reasoning for escalation",
    "re-evaluate severity",
    "reference links",
    "services impacted",
    "teams involved",
    "tenants impacted",
    "ticket created",
    "rotate credentials",
    "generated summary",
    "latency_count_topic",
    "dedicated_topic",
    "recordfromdb",
    "recordfromcache",
    "rediskeys",
)
TARGET_SOURCE_RANK = {
    "slack_author": 600,
    "explicit_mention": 500,
    "current_evidence": 400,
    "catalog": 300,
    "service_alias": 240,
    "command_registry": 200,
}
TARGET_QUALITY_RANK = {"high": 80, "medium": 40, "low": -80, "rejected": -120}
STOPWORDS = {
    "about",
    "also",
    "and",
    "any",
    "are",
    "can",
    "confirm",
    "current",
    "from",
    "have",
    "latest",
    "need",
    "please",
    "provide",
    "share",
    "status",
    "that",
    "the",
    "this",
    "with",
    "you",
}
URL_IN_TEXT_RE = re.compile(r"https?://[^\s>)\]]+")
DIAGNOSTIC_EXCERPT_TERM_GROUPS = (
    ("cpubusypercent", "threshold > 90", "cpu / memory"),
    ("replication lag", "cpu & memory snapshot", "shard dune jobs"),
    ("database_agent", "database agent"),
    ("connection to node -1", "broker may not be available", "producer"),
    ("pod can connect", "connected to", "kafka broker"),
    ("runtime config", "service config", "cert", "certificate"),
    ("notary event worker",),
    ("kafka investigation", "event produce latency", "ocs lag"),
)


def _diagnostic_salient_excerpt(text: str, limit: int) -> str | None:
    lowered = text.lower()
    windows: list[str] = []
    for group in DIAGNOSTIC_EXCERPT_TERM_GROUPS:
        match: tuple[int, str] | None = None
        for term in group:
            index = lowered.find(term)
            if index >= 0:
                match = (index, term)
                break
        if match is None:
            continue
        index, term = match
        start = max(0, index - 20)
        after = 110 if term == "connection to node -1" else 60
        end = min(len(text), index + len(term) + after)
        windows.append(text[start:end].strip())
    if len(windows) < 2:
        return None
    excerpt = " ... ".join(dict.fromkeys(windows))
    if len(excerpt) <= limit:
        return excerpt
    return f"{excerpt[:limit].rstrip()} ... [truncated]"


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _target_key(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", " ", _norm(value)).strip()


def _target_entity_type(target: AllowedTarget) -> EntityType:
    if target.target_type == "team":
        return EntityType.TEAM
    if target.target_type == "service":
        return EntityType.SERVICE
    if target.target_type == "person":
        return EntityType.PERSON
    if target.target_type == "bot_system":
        return EntityType.UNKNOWN
    return EntityType.UNKNOWN


def _compact_text(text: str, *, low_signal: bool = False) -> str:
    limit = MAX_LOW_SIGNAL_TEXT_CHARS if low_signal else MAX_EVENT_TEXT_CHARS
    compacted = " ".join((text or "").split())
    compacted = URL_IN_TEXT_RE.sub(lambda match: f"[URL domain: {urlparse(match.group(0)).netloc}]", compacted)
    if len(compacted) <= limit:
        return str(redact_for_llm(compacted))
    diagnostic_excerpt = None if low_signal else _diagnostic_salient_excerpt(compacted, limit)
    if diagnostic_excerpt:
        return str(redact_for_llm(diagnostic_excerpt))
    return str(redact_for_llm(f"{compacted[:limit].rstrip()} ... [truncated]"))


def _url_context(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    return {"domain": parsed.netloc}


def _quality_for_event(event: IncidentEvent, event_quality_by_id: dict[str, Any]) -> Any | None:
    return event_quality_by_id.get(event.event_id)


def _event_row(
    event: IncidentEvent,
    event_quality_by_id: dict[str, Any],
    *,
    max_text_chars: int | None = None,
) -> dict[str, Any]:
    quality = _quality_for_event(event, event_quality_by_id)
    kind = getattr(quality, "event_kind", "unknown")
    low_signal = kind in {
        "bot_system_message",
        "bot_lifecycle",
        "bot_owner_request",
        "preview_card",
        "pagerduty_card",
        "jira_card",
        "zoom_card",
        "slack_lifecycle",
        "log_or_code_block",
        "table_row",
        "table_header",
        "generated_summary_fragment",
        "low_signal_noise",
    }
    compact_text = _compact_text(event.message, low_signal=low_signal)
    if max_text_chars is not None and len(compact_text) > max_text_chars:
        compact_text = f"{compact_text[:max_text_chars].rstrip()} ... [truncated]"
    tokens = event.extracted_tokens or {}
    return {
        "event_id": event.event_id,
        "sequence": event.sequence,
        "timestamp": event.ts,
        "author": event.author,
        "author_type": getattr(quality, "author_type", "unknown"),
        "event_kind": kind,
        "evidence_quality": getattr(quality, "evidence_quality", "medium"),
        "target_source_allowed": getattr(quality, "is_target_source_allowed", False),
        "planner_grounding_allowed": getattr(quality, "is_planner_grounding_allowed", False),
        "text": str(redact_for_llm(compact_text)),
        "urls": [_url_context(url) for url in tokens.get("urls", [])[:6]],
        "slack_mentions": redact_for_llm(tokens.get("slack_mentions", [])[:10]),
        "command_candidates": redact_for_llm(tokens.get("command_candidates", [])[:5]),
    }


def _target_candidate_rejection_reason(target: AllowedTarget) -> str | None:
    name = " ".join((target.display_name or "").split())
    name_norm = _norm(name)
    is_work_item_owner = "work-item owner" in _norm(target.reason)
    if not target.targetable or target.target_quality not in {"high", "medium"}:
        return target.rejection_reason or target.reason or "target is not high/medium quality"
    if target.target_type in {"bot_system", "non_targetable_noise"}:
        return "bot/system or noise target type"
    if target.source_event_kind in NOISY_TARGET_EVENT_KINDS and not is_work_item_owner:
        return f"source event kind is not targetable: {target.source_event_kind}"
    if not name_norm:
        return "empty target"
    if name_norm.startswith("just to confirm"):
        return "question prefix is not targetable"
    if re.match(r"^\d+\s+files?\b", name_norm):
        return "file label is not targetable"
    if "response we would see this" in name_norm:
        return "generated summary fragment is not targetable"
    if re.match(r"^@?[a-z][\w .-]{1,80}\s+as reported here\b", name_norm):
        return "quoted mention prefix is not targetable"
    if re.match(r"^srebot[a-z0-9_.-]+$", name_norm):
        return "fused bot/person string is not targetable"
    if name_norm in NOISY_TARGET_NAMES:
        return "section/header/system label is not targetable"
    if _looks_like_json_or_diagnostic_target(name):
        return "JSON/log diagnostic key is not targetable"
    if any(term in name_norm for term in NOISY_TARGET_CONTAINS):
        return "preview/ticket/generated fragment is not targetable"
    if target.source in {"catalog", "service_alias", "command_registry"} and not target.evidence_ids:
        if "visible in evidence" not in _norm(target.reason):
            return "catalog/registry target has no current evidence match"
    if re.match(r"^\d+\.\s+", name):
        return "numbered section heading is not targetable"
    if re.fullmatch(r"\d+", name):
        return "numeric ID is not targetable"
    if re.fullmatch(r"P[A-Z0-9]{5,}", name):
        return "policy/incident ID is not targetable"
    if re.fullmatch(r"[A-Z]+-\d+", name, re.I):
        return "ticket/Jira ID is not targetable"
    if re.search(r"\.(?:png|jpe?g|gif|webp|txt|log)$", name, re.I):
        return "file/image name is not targetable"
    if name.endswith("(Owner") or name.endswith("(owner"):
        return "chopped generated fragment is not targetable"
    if target.source in {"slack_author", "explicit_mention", "current_evidence"} and name_norm.endswith(
        (" investigation", " status", " impact", " update")
    ):
        if not any(term in name_norm for term in (" team", " engineering", " support", " sre", " ops")):
            return "section heading is not targetable"
    if "(owner:" in name_norm or re.match(r"^[A-Z][A-Za-z0-9 /&_.-]{2,72}:\s*\(Owner:", name):
        return "owner/action label is not targetable"
    return None


def _is_database_owner_target_row(row: dict[str, Any]) -> bool:
    target_class = str(row.get("target_class") or "")
    display = _target_key(str(row.get("display_name") or ""))
    canonical = _target_key(str(row.get("canonical_id") or ""))
    return target_class == "database_owner" or display in {"dba", "database dbe", "database engineering"} or canonical in {
        "dba",
        "database_engineering",
        "database dbe",
    }


def _is_database_owner_allowed_target(target: AllowedTarget) -> bool:
    display = _target_key(target.display_name)
    canonical = _target_key(target.canonical_id)
    return display in {"dba", "database dbe", "database engineering"} or canonical in {
        "dba",
        "database_engineering",
        "database dbe",
    }


def _add_db_cpu_diagnostic_owner_candidates(
    candidate_rows: list[dict[str, Any]],
    allowed_targets: list[AllowedTarget],
    retained_diagnostic_facts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    contract = db_cpu_initial_contract(retained_diagnostic_facts)
    if contract is None:
        return candidate_rows
    existing_keys = {_target_key(str(row.get("display_name") or "")) for row in candidate_rows}
    rows = [row for row in candidate_rows if _is_database_owner_target_row(row)]
    for target in allowed_targets:
        if not target.targetable or target.target_quality not in {"high", "medium"}:
            continue
        if not _is_database_owner_allowed_target(target):
            continue
        key = _target_key(target.display_name)
        if key in existing_keys:
            continue
        rows.append(
            _target_row(
                target,
                merged_evidence_ids=[
                    str(fact.get("event_id"))
                    for fact in retained_diagnostic_facts
                    if fact.get("event_id")
                ],
            )
        )
        existing_keys.add(key)
    if rows:
        return rows[:MAX_CANDIDATE_TARGETS]
    return candidate_rows


def _minimal_db_cpu_owner_candidate_rows(
    allowed_targets: list[AllowedTarget],
    retained_diagnostic_facts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if db_cpu_initial_contract(retained_diagnostic_facts) is None:
        return []
    evidence_ids = list(
        dict.fromkeys(
            str(fact.get("event_id"))
            for fact in retained_diagnostic_facts
            if fact.get("event_id")
        )
    )[:3]
    rows: list[dict[str, Any]] = []
    for target in allowed_targets:
        if not target.targetable or target.target_quality not in {"high", "medium"}:
            continue
        if not _is_database_owner_allowed_target(target):
            continue
        rows.append(
            {
                "target_id": target.target_id,
                "display_name": target.display_name,
                "target_type": target.target_type,
                "role_hint": target.role_hint,
                "source": target.source,
                "source_event_kind": target.source_event_kind,
                "target_class": "database_owner",
                "latest_evidence_ids": evidence_ids,
                "why_visible": "DB CPU diagnostic service owner",
                "alias_target_ids": [],
            }
        )
        if len(rows) >= 2:
            break
    return rows


JSON_DIAGNOSTIC_TARGET_RE = re.compile(
    r"""^\s*
    ["'{]*
    (?P<key>[A-Za-z_][A-Za-z0-9_.-]{1,64})
    ["'}]*
    \s*(?::.*)?$""",
    re.VERBOSE,
)
JSON_DIAGNOSTIC_TARGET_KEYS = {
    "active",
    "batchcount",
    "comment",
    "createdon",
    "dedicated_topic",
    "dedicatedcluster",
    "dedicatedtopic",
    "dedicatedtopiccount",
    "envirovmentvariables",
    "expiry",
    "key",
    "latency_count_topic",
    "locked",
    "recordfromcache",
    "recordfromdb",
    "rediskeys",
    "ttl",
    "tenantid",
    "topic_name",
    "topic_number",
    "topicname",
    "topicnumber",
    "updatedby",
    "updatedon",
}


def _looks_like_json_or_diagnostic_target(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    if stripped.startswith(("{", "[", "}", "]")) and ":" in stripped:
        return True
    match = JSON_DIAGNOSTIC_TARGET_RE.match(stripped)
    if not match:
        return False
    key = _target_key(match.group("key")).replace(" ", "_")
    if key in JSON_DIAGNOSTIC_TARGET_KEYS:
        return True
    return ":" in stripped and bool(re.search(r"[A-Z_]", match.group("key"))) and len(key.split()) == 1


def _event_quality_score(event: IncidentEvent, quality: Any | None, index: int) -> tuple[int, int]:
    kind = getattr(quality, "event_kind", "unknown")
    author_type = getattr(quality, "author_type", "unknown")
    tokens = event.extracted_tokens or {}
    text_norm = _norm(event.message)
    has_work_item = bool(extract_current_work_items([event]))
    score = index
    if kind.startswith("human_") or author_type == "human":
        score += 1000
    elif kind in {"bot_system_message", "bot_summary"}:
        score -= 200
    elif kind in NOISY_TARGET_EVENT_KINDS:
        score -= 500
    if any(term in text_norm for term in ("?", "confirm", "validate", "status", "eta", "monitor", "owner", "next action")):
        score += 180
    if tokens.get("command_candidates"):
        score += 120
    if tokens.get("slack_mentions"):
        score += 40
    if has_work_item:
        score += 260
    return score, index


SEVERITY_OR_IMPACT_CLAIM_RE = re.compile(
    r"\b(?:should\s+be|needs?\s+to\s+be|make\s+it|convert(?:ed)?\s+to)\s+(?:a\s+)?p[1-4]\b"
    r"|\b(?:escalat(?:e|ion)|priority|severity)\b"
    r"|(?:customer|tenant|user|report)\s+(?:is\s+)?(?:blocked|impacted|unable|affected)",
    re.IGNORECASE,
)
TRAILING_SCOPE_OWNER_SIGNAL_RE = re.compile(
    r"\b(?:"
    r"scope|impact(?:ed)?|blast\s+radius|only\s+(?:one|1)|single\s+customer|multiple\s+customers?|"
    r"live\s+customers?|customer\s+count|who\s+else|what\s+does\s+p[1-4]\s+mean|"
    r"row[- ]?count|mismatch|pipeline|owner|next\s+steps?|validate|validation|confirm|"
    r"findings?|current\s+status|status|monitor(?:ing)?|signal"
    r")\b",
    re.IGNORECASE,
)


def _is_human_model_event(event: IncidentEvent, quality: Any | None) -> bool:
    return (
        getattr(quality, "author_type", "unknown") == "human"
        or str(getattr(quality, "event_kind", "")).startswith("human_")
        or str(getattr(event, "author_type", "") or "").lower() == "human"
    )


def _protected_trailing_human_event_ids(
    latest_window_events: list[IncidentEvent],
    event_quality_by_id: dict[str, Any],
) -> list[str]:
    """Keep late human scope/owner evidence after severity/impact claims visible.

    This is input shaping only: it does not choose the blocker, move, or target.
    It prevents the one AI read from seeing a reporter's escalation claim while
    missing later human evidence that asks or answers scope, impact, owner, or
    validation questions.
    """
    last_claim_index = -1
    for index, event in enumerate(latest_window_events):
        if SEVERITY_OR_IMPACT_CLAIM_RE.search(f"{event.author or ''} {event.message or ''}"):
            last_claim_index = index
    if last_claim_index < 0:
        return []
    protected: list[str] = [latest_window_events[last_claim_index].event_id]
    for event in latest_window_events[last_claim_index + 1 :]:
        quality = event_quality_by_id.get(event.event_id)
        if not _is_human_model_event(event, quality):
            continue
        if TRAILING_SCOPE_OWNER_SIGNAL_RE.search(event.message or ""):
            protected.append(event.event_id)
    return protected[-6:]


def _trim_events_preserving_ids(
    events: list[IncidentEvent],
    max_events: int,
    protected_ids: set[str],
) -> list[IncidentEvent]:
    if len(events) <= max_events:
        return events
    selected = list(events)
    while len(selected) > max_events:
        remove_index = next((index for index, event in enumerate(selected) if event.event_id not in protected_ids), None)
        if remove_index is None:
            return selected[-max_events:]
        selected.pop(remove_index)
    return selected


def _trim_event_rows_preserving_ids(
    rows: list[dict[str, Any]],
    max_events: int,
    protected_ids: set[str],
) -> list[dict[str, Any]]:
    if len(rows) <= max_events:
        return rows
    selected = list(rows)
    while len(selected) > max_events:
        remove_index = next(
            (index for index, row in enumerate(selected) if str(row.get("event_id") or "") not in protected_ids),
            None,
        )
        if remove_index is None:
            return selected[-max_events:]
        selected.pop(remove_index)
    return selected


def _select_model_events(
    latest_window_events: list[IncidentEvent],
    event_quality_by_id: dict[str, Any],
    *,
    ultra_compact: bool = False,
) -> list[IncidentEvent]:
    if not latest_window_events:
        return []
    protected_ids = set(_protected_trailing_human_event_ids(latest_window_events, event_quality_by_id))
    if ultra_compact:
        human_events = [
            event
            for event in latest_window_events
            if _is_human_model_event(event, event_quality_by_id.get(event.event_id))
        ]
        selected = human_events[-MAX_ULTRA_MODEL_EVENTS:] or [
            event
            for event in latest_window_events
            if getattr(event_quality_by_id.get(event.event_id), "is_planner_grounding_allowed", False)
        ][-MAX_ULTRA_MODEL_EVENTS:]
        selected_by_id = {event.event_id: event for event in selected or latest_window_events[-MAX_ULTRA_MODEL_EVENTS:]}
        for event in latest_window_events:
            if event.event_id in protected_ids:
                selected_by_id[event.event_id] = event
        selected_events = sorted(selected_by_id.values(), key=lambda event: event.sequence)
        return _trim_events_preserving_ids(selected_events, MAX_ULTRA_MODEL_EVENTS, protected_ids)

    scored = [
        (_event_quality_score(event, event_quality_by_id.get(event.event_id), index), event)
        for index, event in enumerate(latest_window_events)
    ]
    high_signal = [
        event
        for (_score, _index), event in sorted(scored, key=lambda item: item[0], reverse=True)
        if getattr(event_quality_by_id.get(event.event_id), "is_planner_grounding_allowed", False)
        or str(getattr(event_quality_by_id.get(event.event_id), "event_kind", "")).startswith("human_")
        or extract_current_work_items([event])
    ][:MAX_MODEL_EVENTS]
    context_bots = [
        event
        for event in latest_window_events
        if str(getattr(event_quality_by_id.get(event.event_id), "event_kind", "")) in {"bot_system_message", "bot_summary"}
    ][-2:]
    selected_by_id = {event.event_id: event for event in [*high_signal, *context_bots]}
    for event in latest_window_events:
        if event.event_id in protected_ids:
            selected_by_id[event.event_id] = event
    selected = sorted(selected_by_id.values(), key=lambda event: event.sequence)
    if len(selected) > MAX_MODEL_EVENTS:
        low_ids = {
            event.event_id
            for event in selected
            if getattr(event_quality_by_id.get(event.event_id), "is_planner_grounding_allowed", False) is False
            and event.event_id not in protected_ids
        }
        while len(selected) > MAX_MODEL_EVENTS and low_ids:
            remove_id = next(event.event_id for event in selected if event.event_id in low_ids)
            selected = [event for event in selected if event.event_id != remove_id]
            low_ids.discard(remove_id)
        selected = _trim_events_preserving_ids(selected, MAX_MODEL_EVENTS, protected_ids)
    return selected or latest_window_events[-MAX_MODEL_EVENTS:]


def _latest_evidence_order(target: AllowedTarget, event_order: dict[str, int]) -> int:
    return max((event_order.get(event_id, -1) for event_id in target.evidence_ids), default=-1)


def _target_priority(
    target: AllowedTarget,
    event_order: dict[str, int],
    *,
    work_item_owner_keys: set[str] | None = None,
) -> tuple[int, int, int, int]:
    work_item_owner_keys = work_item_owner_keys or set()
    work_item_owner_bonus = 500 if _target_key(target.display_name) in work_item_owner_keys else 0
    human_source_bonus = 90 if (target.source_event_kind or "").startswith("human_") else 0
    source_rank = TARGET_SOURCE_RANK.get(target.source, 0)
    quality_rank = TARGET_QUALITY_RANK.get(target.target_quality, 0)
    latest_rank = _latest_evidence_order(target, event_order)
    return (
        source_rank + quality_rank + human_source_bonus + work_item_owner_bonus,
        latest_rank,
        len(target.evidence_ids),
        -int(target.target_id[1:] or 0),
    )


def _target_group_type(target: AllowedTarget) -> str:
    if target.target_type != "non_targetable_noise":
        return target.target_type
    if target.source in {"slack_author", "explicit_mention"}:
        return "person"
    return target.target_type


def _why_visible(target: AllowedTarget, *, work_item_owner: bool = False) -> str:
    if work_item_owner:
        return "explicit current work-item owner"
    reason = target.reason or target.source.replace("_", " ")
    return reason[:120]


def _target_row(
    target: AllowedTarget,
    *,
    merged_evidence_ids: list[str] | None = None,
    alias_target_ids: list[str] | None = None,
    work_item_owner: bool = False,
) -> dict[str, Any]:
    return {
        "target_id": target.target_id,
        "display_name": target.display_name,
        "target_type": target.target_type,
        "role_hint": target.role_hint,
        "source": target.source,
        "source_event_kind": target.source_event_kind,
        "target_class": target_class_for_allowed_target(target, work_item_owner=work_item_owner),
        "latest_evidence_ids": (merged_evidence_ids if merged_evidence_ids is not None else target.evidence_ids)[:5],
        "why_visible": _why_visible(target, work_item_owner=work_item_owner),
        "alias_target_ids": alias_target_ids or [],
    }


def _canonical_candidate_targets(
    allowed_targets: list[AllowedTarget],
    latest_window_event_ids: list[str],
    *,
    work_item_owner_names: list[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Return model-facing target candidates with duplicate/noisy IDs folded away.

    This is deterministic safety-envelope work only: it decides which IDs are
    eligible to expose, not who the IC should ask.
    """
    event_order = {event_id: index for index, event_id in enumerate(latest_window_event_ids)}
    model_event_ids = set(latest_window_event_ids)
    work_item_owner_keys = {_target_key(name) for name in (work_item_owner_names or []) if _target_key(name)}
    groups: dict[tuple[str, str], list[AllowedTarget]] = {}
    for target in allowed_targets:
        if target.evidence_ids and not model_event_ids.intersection(target.evidence_ids):
            continue
        key = (_target_key(target.display_name), _target_group_type(target))
        if not key[0]:
            continue
        groups.setdefault(key, []).append(target)

    candidates: list[tuple[tuple[int, int, int, int], dict[str, Any]]] = []
    rejected: list[dict[str, Any]] = []
    aliases: list[dict[str, Any]] = []
    for (_name_key, target_type), group in groups.items():
        valid = [target for target in group if _target_candidate_rejection_reason(target) is None]
        if not valid:
            for target in group:
                rejected.append(
                    {
                        "display_name": target.display_name,
                        "target_type": target.target_type,
                        "source": target.source,
                        "target_quality": target.target_quality,
                        "source_event_kind": target.source_event_kind,
                        "rejection_reason": _target_candidate_rejection_reason(target)
                        or target.rejection_reason
                        or target.reason,
                        "evidence_ids": target.evidence_ids,
                    }
                )
            continue
        winner = max(valid, key=lambda target: _target_priority(target, event_order, work_item_owner_keys=work_item_owner_keys))
        merged_evidence_ids = sorted(
            {event_id for target in group for event_id in target.evidence_ids},
            key=lambda event_id: event_order.get(event_id, -1),
            reverse=True,
        )
        alias_ids = [target.target_id for target in group if target.target_id != winner.target_id]
        row = _target_row(
            winner,
            merged_evidence_ids=merged_evidence_ids,
            alias_target_ids=alias_ids,
            work_item_owner=_target_key(winner.display_name) in work_item_owner_keys,
        )
        candidates.append((_target_priority(winner, event_order, work_item_owner_keys=work_item_owner_keys), row))
        if alias_ids:
            aliases.append(
                {
                    "canonical_target_id": winner.target_id,
                    "canonical_display_name": winner.display_name,
                    "target_type": target_type,
                    "alias_target_ids": alias_ids,
                    "winner_source": winner.source,
                    "winner_source_event_kind": winner.source_event_kind,
                }
            )
        for target in group:
            if target.target_id == winner.target_id:
                continue
            reason = _target_candidate_rejection_reason(target) or "duplicate canonicalized to better target evidence"
            rejected.append(
                {
                    "display_name": target.display_name,
                    "target_type": target.target_type,
                    "source": target.source,
                    "target_quality": target.target_quality,
                    "source_event_kind": target.source_event_kind,
                    "rejection_reason": reason,
                    "canonical_target_id": winner.target_id,
                    "evidence_ids": target.evidence_ids,
                }
            )
    candidates.sort(key=lambda item: item[0], reverse=True)
    candidate_rows = [row for _, row in candidates]
    target_by_id = {target.target_id: target for target in allowed_targets}
    rows_to_remove: set[str] = set()
    for row in list(candidate_rows):
        row_id = str(row.get("target_id") or "")
        target = target_by_id.get(row_id)
        if target is None or target.source != "explicit_mention":
            continue
        alias_key = _target_key(row.get("display_name"))
        if len(alias_key) < 4 or " " in alias_key:
            continue
        matching_row = next(
            (
                candidate
                for candidate in candidate_rows
                if candidate.get("target_type") == "person"
                and candidate.get("target_id") != row_id
                and _target_key(str(candidate.get("display_name") or "")).startswith(f"{alias_key} ")
                and target_by_id.get(str(candidate.get("target_id") or ""), target).source == "slack_author"
            ),
            None,
        )
        if matching_row is None:
            continue
        matching_row.setdefault("alias_target_ids", []).append(row_id)
        aliases.append(
            {
                "canonical_target_id": matching_row.get("target_id"),
                "canonical_display_name": matching_row.get("display_name"),
                "target_type": "person",
                "alias_target_ids": [row_id],
                "winner_source": matching_row.get("source"),
                "winner_source_event_kind": matching_row.get("source_event_kind"),
                "alias_reason": "short mention maps to full visible Slack author",
            }
        )
        rows_to_remove.add(row_id)
    if rows_to_remove:
        candidate_rows = [row for row in candidate_rows if str(row.get("target_id") or "") not in rows_to_remove]
    known_alias_ids = {
        str(alias_id)
        for row in candidate_rows
        for alias_id in row.get("alias_target_ids", [])
    } | {str(row.get("target_id")) for row in candidate_rows}
    for target in allowed_targets:
        if target.target_id in known_alias_ids:
            continue
        if target.targetable or target.source not in {"explicit_mention", "slack_author"}:
            continue
        alias_key = _target_key(target.display_name)
        if len(alias_key) < 4 or " " in alias_key:
            continue
        matching_row = next(
            (
                row
                for row in candidate_rows
                if row.get("target_type") == "person"
                and _target_key(str(row.get("display_name") or "")).startswith(f"{alias_key} ")
            ),
            None,
        )
        if matching_row is None:
            continue
        matching_row.setdefault("alias_target_ids", []).append(target.target_id)
        aliases.append(
            {
                "canonical_target_id": matching_row.get("target_id"),
                "canonical_display_name": matching_row.get("display_name"),
                "target_type": "person",
                "alias_target_ids": [target.target_id],
                "winner_source": matching_row.get("source"),
                "winner_source_event_kind": matching_row.get("source_event_kind"),
                "alias_reason": "short mention maps to full visible Slack author",
            }
        )
    return (
        candidate_rows[:MAX_CANDIDATE_TARGETS],
        rejected[:MAX_REJECTED_TARGETS],
        aliases[:MAX_TARGET_ALIASES],
    )


def _candidate_targets(
    allowed_targets: list[AllowedTarget],
    latest_window_event_ids: list[str],
    *,
    work_item_owner_names: list[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    return _canonical_candidate_targets(
        allowed_targets,
        latest_window_event_ids,
        work_item_owner_names=work_item_owner_names,
    )


def _candidate_target_classes(candidate_targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for target in candidate_targets:
        target_class = str(target.get("target_class") or "unknown")
        display_name = str(target.get("display_name") or "")
        key = (display_name.lower(), target_class)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "display_name": display_name,
                "target_id": target.get("target_id"),
                "target_type": target.get("target_type"),
                "target_class": target_class,
                "role_hint": target.get("role_hint"),
            }
        )
    return rows[:MAX_CANDIDATE_TARGETS]


def _service_team_owner_candidates(candidate_targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    owner_classes = {"explicit_action_owner", "service_owner", "config_owner", "database_owner", "investigating_human"}
    rows: list[dict[str, Any]] = []
    for target in candidate_targets:
        target_class = str(target.get("target_class") or "")
        if target_class not in owner_classes:
            continue
        rows.append(
            {
                "display_name": target.get("display_name"),
                "target_id": target.get("target_id"),
                "target_class": target_class,
                "why_visible": target.get("why_visible"),
                "latest_evidence_ids": target.get("latest_evidence_ids", []),
            }
        )
    return rows[:10]


def _diagnostic_actionability_rows(
    diagnostic_behavior_contracts: list[dict[str, Any]],
    candidate_targets: list[dict[str, Any]],
    retained_diagnostic_facts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    fact_ids = list(dict.fromkeys(str(fact.get("fact_id") or "") for fact in retained_diagnostic_facts if fact.get("fact_id")))
    for contract in diagnostic_behavior_contracts:
        contract_id = str(contract.get("decision_id") or "")
        if contract_id != "DIAG_db_cpu_initial_database_owner_status":
            continue
        database_targets = [
            {
                "target_id": target.get("target_id"),
                "display_name": target.get("display_name"),
                "target_class": target.get("target_class"),
            }
            for target in candidate_targets
            if target.get("target_class") == "database_owner"
        ][:3]
        if not database_targets:
            continue
        rows.append(
            {
                "contract_id": contract_id,
                "actionability": "safe_direct_ask_available",
                "target_class": "database_owner",
                "visible_candidate_targets": database_targets,
                "retained_fact_ids": fact_ids[:8],
                "safe_ask_shape": (
                    "Ask DBA/database owner for current DB CPU status and recovery signal: "
                    "CPUBusyPercent, connection count, replication lag, or DUNE jobs."
                ),
                "no_safe_guidance": (
                    "Do not choose no_safe merely because the app culprit is unknown."
                ),
            }
        )
    return rows[:3]


def _all_rejected_targets(allowed_targets: list[AllowedTarget], canonical_rejected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = {
        (
            _target_key(str(item.get("display_name") or "")),
            str(item.get("source") or ""),
            str(item.get("rejection_reason") or ""),
        )
        for item in canonical_rejected
    }
    rejected = list(canonical_rejected)
    for target in allowed_targets:
        if target.source in {"catalog", "service_alias", "command_registry"} and not target.evidence_ids:
            if "visible in evidence" not in _norm(target.reason):
                continue
        reason = _target_candidate_rejection_reason(target)
        if reason is None and target.targetable and target.target_quality in {"high", "medium"}:
            continue
        reason = reason or target.rejection_reason or target.reason
        key = (_target_key(target.display_name), target.source, reason)
        if key in seen:
            continue
        seen.add(key)
        rejected.append(
            {
                "display_name": target.display_name,
                "target_type": target.target_type,
                "source": target.source,
                "target_quality": target.target_quality,
                "source_event_kind": target.source_event_kind,
                "rejection_reason": target.rejection_reason or target.reason,
                "evidence_ids": target.evidence_ids,
            }
        )
    def rejected_priority(row: dict[str, Any]) -> tuple[int, int]:
        source = str(row.get("source") or "")
        reason = _norm(str(row.get("rejection_reason") or ""))
        display = _norm(str(row.get("display_name") or ""))
        current_evidence = 0 if source in {"slack_author", "explicit_mention", "current_evidence"} else 1
        important_noise = 0 if display in {"default_agent", "app", "zsrebot"} or "bot/system" in reason else 1
        return current_evidence, important_noise

    rejected.sort(key=rejected_priority)
    return rejected[:MAX_REJECTED_TARGETS]


def _rejected_target_buckets(
    rejected_targets: list[dict[str, Any]],
    target_aliases: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    alias_names = {_target_key(alias.get("canonical_display_name")) for alias in target_aliases}
    non_targetable_but_mentionable_facts: list[dict[str, Any]] = []
    forbidden_output_entities: list[dict[str, Any]] = []
    do_not_target_only: list[dict[str, Any]] = []
    for row in rejected_targets:
        name = str(row.get("display_name") or "")
        name_key = _target_key(name)
        reason = _norm(str(row.get("rejection_reason") or ""))
        if row.get("canonical_target_id") or (name_key and name_key in alias_names):
            continue
        if re.fullmatch(r"\d+", name) or any(
            term in reason
            for term in (
                "numeric",
                "ticket",
                "jira",
                "url path",
                "environment",
                "shard",
                "diagnostic",
                "key-value",
                "table",
                "log",
                "label",
            )
        ):
            non_targetable_but_mentionable_facts.append(row)
            do_not_target_only.append(row)
            continue
        if any(term in reason for term in ("bot/system", "placeholder", "generated", "preview")):
            forbidden_output_entities.append(row)
            continue
        do_not_target_only.append(row)
    return {
        "non_targetable_but_mentionable_facts": non_targetable_but_mentionable_facts[:MAX_REJECTED_TARGETS],
        "target_aliases_to_allowed_targets": target_aliases,
        "forbidden_output_entities": forbidden_output_entities[:MAX_REJECTED_TARGETS],
        "do_not_target_only": do_not_target_only[:MAX_REJECTED_TARGETS],
    }


def _catalog_hints(catalog: list[ServiceCatalogEntry], context_text: str) -> list[dict[str, Any]]:
    context_key = _target_key(context_text)
    rows: list[dict[str, Any]] = []
    for entry in catalog:
        names = [entry.canonical_name, *entry.aliases, entry.service_id]
        if not any(_target_key(name) and _target_key(name) in context_key for name in names):
            continue
        rows.append(
            {
                "service_id": entry.service_id,
                "canonical_name": entry.canonical_name,
                "kind": str(getattr(entry.kind, "value", entry.kind)),
                "aliases": entry.aliases[:3],
                "known_signals": entry.known_signals[:3],
            }
        )
        if len(rows) >= 5:
            break
    return rows


def _memory_hints(accepted_memories: list[DecisionMoment], context_text: str) -> list[dict[str, Any]]:
    context_terms = _tokens(context_text)
    if not context_terms:
        return []
    hints: list[dict[str, Any]] = []
    for moment in accepted_memories:
        contracts = expected_memory_contracts([moment.decision_id])
        contract = contracts[0] if contracts else {}
        hints.append(
            {
                "decision_id": moment.decision_id,
                "move": moment.move,
                "behavior_hint": moment.ic_action,
                "why_it_helped": moment.why_it_worked,
                "forbidden_fact_leakage": moment.forbidden_fact_leakage,
                "expected_target_classes": contract.get("expected_target_classes", []),
                "expected_visible_term_groups": contract.get("expected_visible_term_groups", []),
            }
        )
        if len(hints) >= 3:
            break
    return hints


def _command_rows(command_registry: list[CommandRegistryEntry], events: list[IncidentEvent]) -> list[dict[str, Any]]:
    observed = {
        str(command)
        for event in events
        for command in (event.extracted_tokens or {}).get("command_candidates", [])
    }
    if not observed:
        return []
    rows: list[dict[str, Any]] = []
    for command in command_registry:
        if command.danger_level not in {"read_only", "read_only_lookup"}:
            continue
        if not command.requires_human_approval:
            continue
        if command.exact and command.command not in observed:
            continue
        rows.append(
            {
                "command": command.command,
                "command_id": command.command_id,
                "target": command.target,
                "danger_level": command.danger_level,
                "requires_human_approval": command.requires_human_approval,
            }
        )
        if len(rows) >= 10:
            break
    return rows


def _work_item_owner_names(work_items: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for item in work_items:
        names.extend(str(name) for name in item.get("owner_names", []) if str(name).strip())
        group = str(item.get("owner_group") or "").strip()
        if group:
            names.append(group)
    return list(dict.fromkeys(names))


def _command_candidate_counts(events: list[IncidentEvent]) -> dict[str, int]:
    excluded_human_mentions = 0
    observed_bot_commands = 0
    url_slash_false_positive_count = 0
    for event in events:
        tokens = event.extracted_tokens or {}
        commands = [str(command) for command in tokens.get("command_candidates", [])]
        observed_bot_commands += sum(1 for command in commands if command.lower().startswith("@zsrebot"))
        url_domains = {urlparse(str(url)).netloc for url in tokens.get("urls", [])}
        url_slash_false_positive_count += sum(
            1
            for command in commands
            if command.startswith("/") and any(domain and domain in command for domain in url_domains)
        )
        excluded_human_mentions += sum(
            1
            for mention in tokens.get("slack_mentions", [])
            if str(mention).lower() not in {"zsrebot", "zsrebotstg", "here", "channel"}
        )
    return {
        "excluded_human_mention_count": excluded_human_mentions,
        "observed_bot_command_candidate_count": observed_bot_commands,
        "url_slash_false_positive_count": url_slash_false_positive_count,
    }


def _pack_char_count(pack: dict[str, Any]) -> int:
    return len(json.dumps(pack, default=str))


def _compact_diagnostic_fact_rows(rows: Any, *, limit: int, excerpt_limit: int = 110) -> list[dict[str, Any]]:
    compact_rows: list[dict[str, Any]] = []
    seen_fact_ids: set[str] = set()
    for row in list(rows or []):
        if len(compact_rows) >= limit:
            break
        if not isinstance(row, dict):
            continue
        fact_id = str(row.get("fact_id") or "")
        if fact_id and fact_id in seen_fact_ids:
            continue
        if fact_id:
            seen_fact_ids.add(fact_id)
        compact: dict[str, Any] = {
            "fact_id": row.get("fact_id"),
            "fact_label": row.get("fact_label"),
            "event_id": row.get("event_id"),
            "source_event_kind": row.get("source_event_kind"),
            "author_type": row.get("author_type"),
            "planner_grounding_allowed": row.get("planner_grounding_allowed"),
            "matched_term": row.get("matched_term"),
        }
        if row.get("present_terms"):
            compact["present_terms"] = list(row.get("present_terms") or [])[:6]
        if row.get("diagnostic_allowed_for"):
            compact["diagnostic_allowed_for"] = row.get("diagnostic_allowed_for")
        if excerpt_limit > 0 and row.get("excerpt"):
            compact["excerpt"] = _truncate_model_text(row.get("excerpt"), excerpt_limit)
        compact_rows.append(compact)
    return compact_rows


def _compact_diagnostic_classification_rows(rows: Any, *, limit: int) -> list[dict[str, Any]]:
    compact_rows: list[dict[str, Any]] = []
    for row in list(rows or [])[:limit]:
        if not isinstance(row, dict):
            continue
        compact_rows.append(
            {
                "fact_id": row.get("fact_id"),
                "category": row.get("category"),
                "event_id": row.get("event_id"),
                "allowed_for": row.get("allowed_for"),
            }
        )
    return compact_rows


def _diagnostic_fact_priority(fact: dict[str, Any]) -> tuple[int, int, int, str]:
    fact_id = str(fact.get("fact_id") or "")
    allowed_for = fact.get("diagnostic_allowed_for") or {}
    priority = {
        "failed_records_workload": 0,
        "database_agent_involvement": 1,
        "db_cpu_threshold": 2,
        "db_instance_or_host": 3,
        "db_connection_count": 4,
        "replication_lag_status": 5,
        "dune_or_jobs_check": 6,
        "sync_latency_topic_permission": 7,
        "producer_connection_error": 8,
        "cert_runtime_config_clue": 9,
        "megastore_scope_or_pipeline": 10,
        "ocs_lag_owner_action": 11,
        "temporal_transfer_accounting": 12,
    }
    return (
        priority.get(fact_id, 100),
        0 if allowed_for.get("target_selection") else 1,
        -len(fact.get("present_terms") or []),
        fact_id,
    )


def _truncate_model_text(value: Any, limit: int) -> str:
    compacted = " ".join(str(value or "").split())
    if len(compacted) <= limit:
        return compacted
    return f"{compacted[:limit].rstrip()} ... [truncated]"


def _enforce_model_payload_budget(pack: dict[str, Any], *, ultra_compact: bool) -> dict[str, Any]:
    hard_cap = MAX_ULTRA_MODEL_PAYLOAD_TARGET_CHARS if ultra_compact else MAX_MODEL_PAYLOAD_HARD_CHARS
    if _pack_char_count(pack) <= hard_cap:
        return pack
    pack = dict(pack)
    protected_event_ids = set(str(event_id) for event_id in pack.get("trailing_high_signal_human_event_ids", []))
    protected_event_ids.update(str(event_id) for event_id in pack.get("retained_high_signal_diagnostic_event_ids", []))
    protected_event_ids.update(
        str(fact.get("event_id"))
        for fact in pack.get("retained_diagnostic_facts", [])
        if isinstance(fact, dict) and fact.get("event_id")
    )
    pack["do_not_target"] = pack.get("do_not_target", [])[:8]
    pack["do_not_target_only"] = pack.get("do_not_target_only", [])[:8]
    pack["non_targetable_but_mentionable_facts"] = pack.get("non_targetable_but_mentionable_facts", [])[:8]
    pack["forbidden_output_entities"] = pack.get("forbidden_output_entities", [])[:8]
    pack["target_aliases"] = pack.get("target_aliases", [])[:8]
    pack["target_aliases_to_allowed_targets"] = pack.get("target_aliases_to_allowed_targets", [])[:8]
    pack["candidate_targets"] = pack.get("candidate_targets", [])[:16]
    pack["candidate_target_classes"] = pack.get("candidate_target_classes", [])[:16]
    pack["service_team_owner_candidates"] = pack.get("service_team_owner_candidates", [])[:8]
    pack["detected_diagnostic_facts"] = _compact_diagnostic_fact_rows(
        pack.get("detected_diagnostic_facts", []),
        limit=16,
    )
    pack["retained_diagnostic_facts"] = _compact_diagnostic_fact_rows(
        pack.get("retained_diagnostic_facts", []),
        limit=16,
    )
    pack["dropped_diagnostic_facts"] = _compact_diagnostic_fact_rows(
        pack.get("dropped_diagnostic_facts", []),
        limit=8,
    )
    pack["diagnostic_fact_classifications"] = pack.get("diagnostic_fact_classifications", [])[:16]
    pack["diagnostic_behavior_contracts"] = pack.get("diagnostic_behavior_contracts", [])[:2]
    pack["diagnostic_actionability"] = pack.get("diagnostic_actionability", [])[:2]
    pack["accepted_memory_behavior_contracts"] = pack.get("accepted_memory_behavior_contracts", [])[:3]
    pack["catalog_hints"] = pack.get("catalog_hints", [])[:4]
    pack["decision_moment_behavior_hints"] = pack.get("decision_moment_behavior_hints", [])[:2]
    if _pack_char_count(pack) <= hard_cap:
        return pack
    event_limit = 180 if ultra_compact else 240
    trimmed_events = []
    for row in pack.get("latest_window_events", []):
        row = dict(row)
        row_limit = max(event_limit, 440) if str(row.get("event_id") or "") in protected_event_ids else event_limit
        row["text"] = _truncate_model_text(row.get("text"), row_limit)
        row["urls"] = row.get("urls", [])[:3]
        row["slack_mentions"] = row.get("slack_mentions", [])[:5]
        row["command_candidates"] = row.get("command_candidates", [])[:3]
        row["numbers"] = row.get("numbers", [])[:4]
        trimmed_events.append(row)
    pack["latest_window_events"] = trimmed_events
    if _pack_char_count(pack) > hard_cap:
        pack["candidate_targets"] = pack.get("candidate_targets", [])[:12]
        pack["candidate_target_classes"] = pack.get("candidate_target_classes", [])[:12]
        pack["service_team_owner_candidates"] = pack.get("service_team_owner_candidates", [])[:6]
        pack["detected_diagnostic_facts"] = _compact_diagnostic_fact_rows(
            pack.get("detected_diagnostic_facts", []),
            limit=12,
            excerpt_limit=80,
        )
        pack["retained_diagnostic_facts"] = _compact_diagnostic_fact_rows(
            pack.get("retained_diagnostic_facts", []),
            limit=12,
            excerpt_limit=80,
        )
        pack["dropped_diagnostic_facts"] = _compact_diagnostic_fact_rows(
            pack.get("dropped_diagnostic_facts", []),
            limit=5,
            excerpt_limit=80,
        )
        pack["diagnostic_fact_classifications"] = pack.get("diagnostic_fact_classifications", [])[:12]
        pack["diagnostic_behavior_contracts"] = pack.get("diagnostic_behavior_contracts", [])[:1]
        pack["diagnostic_actionability"] = pack.get("diagnostic_actionability", [])[:1]
        pack["accepted_memory_behavior_contracts"] = pack.get("accepted_memory_behavior_contracts", [])[:2]
        pack["do_not_target"] = pack.get("do_not_target", [])[:5]
        pack["target_aliases"] = pack.get("target_aliases", [])[:5]
        pack["target_aliases_to_allowed_targets"] = pack.get("target_aliases_to_allowed_targets", [])[:5]
        pack["non_targetable_but_mentionable_facts"] = pack.get("non_targetable_but_mentionable_facts", [])[:5]
        pack["do_not_target_only"] = pack.get("do_not_target_only", [])[:5]
        pack["forbidden_output_entities"] = pack.get("forbidden_output_entities", [])[:5]
        tighter_events = []
        tighter_limit = 140 if not ultra_compact else 120
        for row in pack.get("latest_window_events", []):
            row = dict(row)
            row_limit = max(tighter_limit, 380) if str(row.get("event_id") or "") in protected_event_ids else tighter_limit
            row["text"] = _truncate_model_text(row.get("text"), row_limit)
            tighter_events.append(row)
        pack["latest_window_events"] = tighter_events
    if _pack_char_count(pack) > hard_cap:
        pack["safety_rules"] = [
            "Use current evidence only.",
            "Choose selected_target_id from candidate_targets.",
            "No posting, paging, execution, remediation, or invented facts.",
            "Copy evidence.quote exactly.",
        ]
        if pack.get("diagnostic_actionability"):
            pack["safety_rules"].insert(
                2,
                "If diagnostic_actionability says safe_direct_ask_available, choose one visible_candidate_target and use safe_ask_shape; do not choose no_safe solely because the app culprit is unknown.",
            )
        pack["catalog_hints"] = []
        pack["decision_moment_behavior_hints"] = pack.get("decision_moment_behavior_hints", [])[:1]
        pack["target_aliases_to_allowed_targets"] = []
        pack["accepted_memory_behavior_contracts"] = pack.get("accepted_memory_behavior_contracts", [])[:1]
        pack["diagnostic_behavior_contracts"] = pack.get("diagnostic_behavior_contracts", [])[:1]
        pack["diagnostic_actionability"] = pack.get("diagnostic_actionability", [])[:1]
        pack["dropped_diagnostic_facts"] = []
    if _pack_char_count(pack) > hard_cap:
        final_events = []
        for row in pack.get("latest_window_events", []):
            row = dict(row)
            fallback_limit = 110 if not ultra_compact else 95
            row_limit = max(fallback_limit, 340) if str(row.get("event_id") or "") in protected_event_ids else fallback_limit
            row["text"] = _truncate_model_text(row.get("text"), row_limit)
            row["urls"] = row.get("urls", [])[:2]
            row["slack_mentions"] = row.get("slack_mentions", [])[:4]
            row["command_candidates"] = row.get("command_candidates", [])[:2]
            final_events.append(row)
        pack["latest_window_events"] = _trim_event_rows_preserving_ids(
            final_events,
            14 if not ultra_compact else 10,
            protected_event_ids,
        )
    if _pack_char_count(pack) > hard_cap:
        pack["diagnostic_fact_classifications"] = _compact_diagnostic_classification_rows(
            pack.get("diagnostic_fact_classifications", []),
            limit=10,
        )
        pack["detected_diagnostic_facts"] = _compact_diagnostic_fact_rows(
            pack.get("detected_diagnostic_facts", []),
            limit=10,
            excerpt_limit=60,
        )
        pack["retained_diagnostic_facts"] = _compact_diagnostic_fact_rows(
            pack.get("retained_diagnostic_facts", []),
            limit=10,
            excerpt_limit=60,
        )
    if _pack_char_count(pack) > hard_cap:
        pack["detected_diagnostic_facts"] = _compact_diagnostic_fact_rows(
            pack.get("detected_diagnostic_facts", []),
            limit=10,
            excerpt_limit=0,
        )
        pack["retained_diagnostic_facts"] = _compact_diagnostic_fact_rows(
            pack.get("retained_diagnostic_facts", []),
            limit=10,
            excerpt_limit=80,
        )
    return pack


def _sync_model_event_debug(pack: dict[str, Any]) -> dict[str, Any]:
    rows = pack.get("latest_window_events", [])
    latest_ids = [str(row.get("event_id")) for row in rows if row.get("event_id")]
    protected = [str(event_id) for event_id in pack.get("trailing_high_signal_human_event_ids", [])]
    selection = dict(pack.get("latest_window_selection") or {})
    selection["event_ids"] = latest_ids
    selection["kept_event_count"] = len(latest_ids)
    pack["latest_window_selection"] = selection
    pack["trailing_high_signal_human_event_ids_kept"] = [
        event_id for event_id in protected if event_id in latest_ids
    ]
    pack["trailing_high_signal_human_event_ids_dropped"] = [
        event_id for event_id in protected if event_id not in latest_ids
    ]
    return pack


def _model_input_size_assessment(input_size_assessment: InputSizeAssessment) -> dict[str, Any]:
    return {
        "event_count": input_size_assessment.event_count,
        "character_count": input_size_assessment.character_count,
        "estimated_token_count": input_size_assessment.estimated_token_count,
        "url_count": input_size_assessment.url_count,
        "bot_or_system_event_count": input_size_assessment.bot_or_system_event_count,
        "recommended_strategy": input_size_assessment.recommended_strategy,
    }


def build_incident_read_context_pack(
    *,
    incident_id: str,
    latest_window_events: list[IncidentEvent],
    input_size_assessment: InputSizeAssessment,
    latest_window_selection: LatestWindowSelection,
    allowed_targets: list[AllowedTarget],
    command_registry: list[CommandRegistryEntry],
    catalog: list[ServiceCatalogEntry],
    accepted_memories: list[DecisionMoment],
    event_quality: list[Any],
    ultra_compact: bool = False,
) -> dict[str, Any]:
    event_quality_by_id = {quality.event_id: quality for quality in event_quality}
    trailing_high_signal_human_event_ids = _protected_trailing_human_event_ids(
        latest_window_events,
        event_quality_by_id,
    )
    model_events = _select_model_events(
        latest_window_events,
        event_quality_by_id,
        ultra_compact=ultra_compact,
    )
    latest_event_ids = [event.event_id for event in model_events]
    high_signal_diagnostic_event_ids = [
        event.event_id
        for event in latest_window_events
        if str(getattr(event_quality_by_id.get(event.event_id), "event_kind", "")) == "human_diagnostic_evidence"
        and getattr(event_quality_by_id.get(event.event_id), "is_planner_grounding_allowed", False)
    ]
    retained_high_signal_diagnostic_event_ids = [
        event_id for event_id in high_signal_diagnostic_event_ids if event_id in latest_event_ids
    ]
    dropped_high_signal_diagnostic_event_ids = [
        event_id for event_id in high_signal_diagnostic_event_ids if event_id not in latest_event_ids
    ]
    detected_diagnostic_facts = sorted(
        extract_diagnostic_facts(latest_window_events, event_quality_by_id),
        key=_diagnostic_fact_priority,
    )
    retained_diagnostic_facts = [
        fact for fact in detected_diagnostic_facts if str(fact.get("event_id") or "") in set(latest_event_ids)
    ]
    dropped_diagnostic_facts = [
        fact for fact in detected_diagnostic_facts if str(fact.get("event_id") or "") not in set(latest_event_ids)
    ]
    current_work_items = extract_current_work_items(model_events)
    work_item_owner_names = _work_item_owner_names(current_work_items)
    model_selection = latest_window_selection.model_copy(
        update={
            "event_ids": latest_event_ids,
            "kept_event_count": len(latest_event_ids),
            "dropped_event_count": max(0, len(latest_window_events) - len(latest_event_ids)),
            "reason": (
                "ultra-compact incident_read_and_whisper retry"
                if ultra_compact
                else "compact incident_read_and_whisper model pack"
            ),
        }
    )
    candidate_targets, canonical_rejected, target_aliases = _candidate_targets(
        allowed_targets,
        latest_event_ids,
        work_item_owner_names=work_item_owner_names,
    )
    candidate_targets = _add_db_cpu_diagnostic_owner_candidates(
        candidate_targets,
        allowed_targets,
        retained_diagnostic_facts,
    )
    rejected_targets = _all_rejected_targets(allowed_targets, canonical_rejected)
    rejected_buckets = _rejected_target_buckets(rejected_targets, target_aliases)
    max_text_chars = MAX_ULTRA_EVENT_TEXT_CHARS if ultra_compact else None
    events = [
        _event_row(event, event_quality_by_id, max_text_chars=max_text_chars)
        for event in model_events
    ]
    context_text = "\n".join(event.message for event in model_events)
    command_counts = _command_candidate_counts(model_events)
    safety_rules = [
        "Always emit valid IncidentReadAndWhisper JSON matching the schema exactly.",
        "Use current latest-window evidence as authoritative.",
        "Bot diagnostic/self-check evidence can ground technical facts; target_source_allowed=false only means the bot/card/log itself must not be selected as the target.",
        "If diagnostic_actionability contains actionability=safe_direct_ask_available, choose one of its visible_candidate_targets and write a direct ask using safe_ask_shape unless another safety rule makes every visible ask unsafe.",
        "Prefer latest human/operator evidence over older bot/system summaries.",
        "Choose selected_target_id only from candidate_targets.",
        "Do not infer customers from URL domains or tenants/accounts from URL path numbers.",
        "Do not invent people, teams, services, customers, tenants, commands, impact, mitigation, or monitoring signals.",
        "Do not suggest posting, paging, executing commands, or remediation.",
        "A single useful say_this is enough; next_line is optional.",
        "SAY THIS must be a direct manual-copy IC message, usually an explicit question to the selected target.",
        "Do not output a passive restatement of findings as the whole SAY THIS.",
        "Prefer 'can you confirm/share/provide...' over 'we need...' in visible output.",
        "Do not say 'we need X or Y to decide next steps'; ask the selected target for the next validation, owner, or monitoring signal.",
        "If no safe direct ask exists, choose no_safe_recommendation instead of a passive owner statement.",
        "For no_safe_recommendation, use wording like 'I do not have a safe, grounded next move yet.' Do not imply closure with 'no further action needed' unless evidence explicitly closes the incident.",
        "Copy evidence.quote exactly from latest_window_events.text.",
    ]
    if not ultra_compact:
        safety_rules.insert(
            2,
            "Bot summaries and preview cards are context, not primary current truth when later human evidence supersedes them.",
        )
        safety_rules.insert(
            -2,
            "Commands are optional manual-copy suggestions only and must come from command_registry.",
        )
        safety_rules.insert(
            5,
            "Use current_work_items only as explicit owner/action evidence. These may come from Owner rows or rows like 'Label: @person is checking...' / 'Label: team will monitor...'. If asking about a work item, target one of that item's explicit owners or owner group.",
        )
        safety_rules.insert(
            6,
            "already_answered must contain only questions answered by later current evidence and must not repeat latest_open_loop.",
        )
        safety_rules.insert(
            7,
            "Do not reopen an older generic status/Zoom recap ask after a later human incident update provides Current Status, Findings, or Next Steps; choose the latest unresolved owner/action instead.",
        )
        safety_rules.insert(
            8,
            "If action_state_transitions says an operational page/engagement request was accepted, executed, or completed by later current evidence, do not ask whether that page/engagement happened; move to the latest diagnostic, owner-status, validation, or monitoring blocker.",
        )
        safety_rules.insert(
            9,
            "If a later human message answers customer scope, do not ask the earlier broad customer-scope question again.",
        )
        safety_rules.insert(
            10,
            "If a later update names an owner checking latency, topic health, queue catch-up, validation, or monitoring, ask that owner for the concrete status/signal instead of no_safe_recommendation.",
        )
        safety_rules.insert(
            11,
            "If current_work_items has an owner/action for latency, topic health, queue catch-up, validation, or monitoring, select that owner/group and ask for the concrete signal/status.",
        )
        safety_rules.insert(
            12,
            "Treat phrases like 'should be P1/P2' as proposed severity, not confirmed priority in current_read, latest_open_loop, rationale, and say_this. Confirmed priority requires current bot/IC priority-change evidence.",
        )
        safety_rules.insert(
            13,
            "For permission-blocked command loops, if a separate reporter asks for exact symptoms or affected scope before grouping reports, target that reporter/validator for symptoms/scope before DACO or permission-path validation.",
        )
        safety_rules.insert(
            14,
            "If a person is only mentioned as someone to page/get paged or as a possible helper, do not name them as the visible owner unless they are the selected current target.",
        )
        safety_rules.insert(
            11,
            "If broad impact scope is already answered and the remaining open loop is technical validation, ask for concrete validation owner/signal instead of asking broad scope again.",
        )
        safety_rules.insert(
            12,
            "If broad impact scope is answered and a pipeline, table, row-count, replication, topic, queue, or data mismatch remains unresolved, prefer a safe direct ask to the active investigator, owner group, or pipeline owner for validation and the next monitoring signal over no_safe_recommendation.",
        )
        safety_rules.insert(
            13,
            "If an accepted behavior hint exists and current evidence supports a direct validation, monitoring, owner, or impact ask, do not use no_safe_recommendation.",
        )
        safety_rules.insert(
            14,
            "When behavior hints include expected_target_classes and expected_visible_term_groups, treat them as guidance for the ask shape: choose a target from the matching visible candidates and include the requested validation/status terms if current evidence supports them.",
        )
        safety_rules.insert(
            15,
            "If row-count, Iceberg, DEL-table, pipeline, topic, queue, replication, or data mismatch evidence remains after customer scope is answered, ask the current investigator or service owner for validation / next signal.",
        )
        safety_rules.insert(
            16,
            "If a catalog-supported service/team is targetable and a person mention is weak, target the latest human evidence owner or the catalog service/team, not the weak mention.",
        )
        safety_rules.insert(
            17,
            "If a DB CPU/replication/DUNE self-check alert is present but no app-specific culprit is known, ask the DBA/database owner for current CPU status and the next recovery signal. Do not return no_safe merely because the app culprit is unknown, and do not target DACO unless failed_records/DACO source evidence is present.",
        )
    diagnostic_behavior_contracts = []
    if db_cpu_contract := db_cpu_initial_contract(retained_diagnostic_facts):
        diagnostic_behavior_contracts.append(db_cpu_contract)
    action_state = infer_action_state_transitions(model_events, event_quality)
    diagnostic_actionability = _diagnostic_actionability_rows(
        diagnostic_behavior_contracts,
        candidate_targets,
        retained_diagnostic_facts,
    )
    pack = {
        "incident_id": incident_id,
        "product_path": "incident_read_and_whisper",
        "context_pack_variant": "ultra_compact" if ultra_compact else "compact",
        "input_size_assessment": _model_input_size_assessment(input_size_assessment),
        "latest_window_selection": model_selection.model_dump(mode="json"),
        "latest_window_events": events,
        "trailing_high_signal_human_event_ids": trailing_high_signal_human_event_ids,
        "retained_high_signal_diagnostic_event_ids": retained_high_signal_diagnostic_event_ids,
        "dropped_high_signal_diagnostic_event_ids": dropped_high_signal_diagnostic_event_ids,
        "detected_diagnostic_facts": detected_diagnostic_facts[:24],
        "retained_diagnostic_facts": retained_diagnostic_facts[:24],
        "dropped_diagnostic_facts": dropped_diagnostic_facts[:24],
        "diagnostic_fact_classifications": diagnostic_fact_classifications(
            detected_diagnostic_facts,
            retained_diagnostic_facts,
        ),
        "current_work_items": current_work_items,
        "action_state_transitions": action_state.get("action_loops", [])[:6],
        "answered_questions_from_actions": action_state.get("answered_questions", [])[:6],
        "do_not_ask_from_actions": action_state.get("do_not_ask", [])[:8],
        "candidate_targets": candidate_targets,
        "candidate_target_classes": _candidate_target_classes(candidate_targets),
        "service_team_owner_candidates": _service_team_owner_candidates(candidate_targets),
        "target_aliases": target_aliases,
        "do_not_target": rejected_targets,
        **rejected_buckets,
        "command_registry": _command_rows(command_registry, model_events),
        "catalog_hints": [] if ultra_compact else _catalog_hints(catalog, context_text),
        "decision_moment_behavior_hints": [] if ultra_compact else _memory_hints(accepted_memories, context_text),
        "accepted_memory_behavior_contracts": [] if ultra_compact else expected_memory_contracts(
            [memory.decision_id for memory in accepted_memories]
        )[:5],
        "diagnostic_behavior_contracts": [] if ultra_compact else diagnostic_behavior_contracts[:3],
        "diagnostic_actionability": [] if ultra_compact else diagnostic_actionability,
        "safety_rules": safety_rules,
        **command_counts,
    }
    pack["model_exposed_command_count"] = len(pack["command_registry"])
    pack["model_payload_hard_cap"] = MAX_ULTRA_MODEL_PAYLOAD_TARGET_CHARS if ultra_compact else MAX_MODEL_PAYLOAD_HARD_CHARS
    packed = redact_for_llm(_enforce_model_payload_budget(pack, ultra_compact=ultra_compact))
    packed["provider_payload_char_count"] = 0
    packed["model_payload_over_cap"] = False
    packed["provider_payload_char_count"] = _pack_char_count(packed)
    packed["model_payload_over_cap"] = packed["provider_payload_char_count"] > packed["model_payload_hard_cap"]
    if packed["model_payload_over_cap"]:
        packed = _enforce_model_payload_budget(packed, ultra_compact=ultra_compact)
        packed["provider_payload_char_count"] = _pack_char_count(packed)
        packed["model_payload_over_cap"] = packed["provider_payload_char_count"] > packed["model_payload_hard_cap"]
    if packed["model_payload_over_cap"]:
        packed["candidate_targets"] = packed.get("candidate_targets", [])[:8]
        packed["target_aliases"] = []
        packed["target_aliases_to_allowed_targets"] = []
        packed["do_not_target"] = packed.get("do_not_target", [])[:3]
        packed["do_not_target_only"] = packed.get("do_not_target_only", [])[:3]
        packed["non_targetable_but_mentionable_facts"] = []
        packed["forbidden_output_entities"] = []
        packed["command_registry"] = []
        packed["model_exposed_command_count"] = 0
        packed["catalog_hints"] = []
        packed["decision_moment_behavior_hints"] = packed.get("decision_moment_behavior_hints", [])[:1]
        packed["accepted_memory_behavior_contracts"] = packed.get("accepted_memory_behavior_contracts", [])[:1]
        compact_events = []
        protected_event_ids = set(str(event_id) for event_id in packed.get("trailing_high_signal_human_event_ids", []))
        protected_event_ids.update(str(event_id) for event_id in packed.get("retained_high_signal_diagnostic_event_ids", []))
        protected_event_ids.update(
            str(fact.get("event_id"))
            for fact in packed.get("retained_diagnostic_facts", [])
            if isinstance(fact, dict) and fact.get("event_id")
        )
        for row in _trim_event_rows_preserving_ids(
            packed.get("latest_window_events", []),
            10 if not ultra_compact else 8,
            protected_event_ids,
        ):
            row = dict(row)
            row_limit = 300 if str(row.get("event_id") or "") in protected_event_ids else 80
            row["text"] = _truncate_model_text(row.get("text"), row_limit)
            compact_events.append(row)
        packed["latest_window_events"] = compact_events
        packed["provider_payload_char_count"] = _pack_char_count(packed)
        packed["model_payload_over_cap"] = packed["provider_payload_char_count"] > packed["model_payload_hard_cap"]
    if not packed.get("candidate_targets"):
        diagnostic_owner_rows = _minimal_db_cpu_owner_candidate_rows(
            allowed_targets,
            list(packed.get("retained_diagnostic_facts") or []),
        )
        if diagnostic_owner_rows:
            packed["candidate_targets"] = diagnostic_owner_rows[:2]
            packed["candidate_target_classes"] = _candidate_target_classes(diagnostic_owner_rows[:2])
            packed["service_team_owner_candidates"] = _service_team_owner_candidates(diagnostic_owner_rows[:2])
            packed["do_not_target"] = packed.get("do_not_target", [])[:3]
            packed["do_not_target_only"] = packed.get("do_not_target_only", [])[:3]
            packed["non_targetable_but_mentionable_facts"] = packed.get(
                "non_targetable_but_mentionable_facts",
                [],
            )[:3]
            if _pack_char_count(packed) > packed["model_payload_hard_cap"]:
                packed["candidate_targets"] = diagnostic_owner_rows[:1]
                packed["candidate_target_classes"] = _candidate_target_classes(diagnostic_owner_rows[:1])
                packed["service_team_owner_candidates"] = _service_team_owner_candidates(diagnostic_owner_rows[:1])
                packed["target_aliases"] = []
                packed["target_aliases_to_allowed_targets"] = []
                packed["do_not_target"] = packed.get("do_not_target", [])[:1]
                packed["do_not_target_only"] = packed.get("do_not_target_only", [])[:1]
                packed["non_targetable_but_mentionable_facts"] = []
                packed["forbidden_output_entities"] = []
    packed["provider_payload_char_count"] = _pack_char_count(packed)
    packed["model_payload_over_cap"] = packed["provider_payload_char_count"] > packed["model_payload_hard_cap"]
    return _sync_model_event_debug(packed)


def build_ultra_compact_incident_read_context_pack(**kwargs: Any) -> dict[str, Any]:
    return build_incident_read_context_pack(**kwargs, ultra_compact=True)


def context_pack_summary(context_pack: dict[str, Any]) -> dict[str, Any]:
    char_count = len(json.dumps(context_pack, default=str))
    return {
        "strategy": context_pack.get("product_path"),
        "variant": context_pack.get("context_pack_variant"),
        "char_count": char_count,
        "model_payload_char_count": char_count,
        "provider_payload_char_count": context_pack.get("provider_payload_char_count", char_count),
        "model_payload_hard_cap": context_pack.get("model_payload_hard_cap"),
        "model_payload_over_cap": context_pack.get("model_payload_over_cap", False),
        "event_count": len(context_pack.get("latest_window_events", [])),
        "model_event_count": len(context_pack.get("latest_window_events", [])),
        "work_item_count": len(context_pack.get("current_work_items", [])),
        "work_item_labels": [
            item.get("work_item_label")
            for item in context_pack.get("current_work_items", [])[:6]
        ],
        "permission_denied_work_item_count": sum(
            1
            for item in context_pack.get("current_work_items", [])
            if item.get("work_item_type") == "permission_blocked_operational_attempt"
        ),
        "candidate_target_count": len(context_pack.get("candidate_targets", [])),
        "target_alias_count": sum(len(item.get("alias_target_ids", [])) for item in context_pack.get("target_aliases", [])),
        "rejected_target_count": len(context_pack.get("do_not_target", [])),
        "mentionable_fact_count": len(context_pack.get("non_targetable_but_mentionable_facts", [])),
        "forbidden_output_entity_count": len(context_pack.get("forbidden_output_entities", [])),
        "do_not_target_only_count": len(context_pack.get("do_not_target_only", [])),
        "command_count": len(context_pack.get("command_registry", [])),
        "model_exposed_command_count": context_pack.get("model_exposed_command_count", len(context_pack.get("command_registry", []))),
        "excluded_human_mention_count": context_pack.get("excluded_human_mention_count", 0),
        "observed_bot_command_candidate_count": context_pack.get("observed_bot_command_candidate_count", 0),
        "url_slash_false_positive_count": context_pack.get("url_slash_false_positive_count", 0),
        "latest_window_event_ids": context_pack.get("latest_window_selection", {}).get("event_ids", []),
        "trailing_high_signal_human_event_ids": context_pack.get("trailing_high_signal_human_event_ids", []),
        "trailing_high_signal_human_event_ids_kept": context_pack.get(
            "trailing_high_signal_human_event_ids_kept",
            [],
        ),
        "trailing_high_signal_human_event_ids_dropped": context_pack.get(
            "trailing_high_signal_human_event_ids_dropped",
            [],
        ),
        "retained_high_signal_diagnostic_event_ids": context_pack.get(
            "retained_high_signal_diagnostic_event_ids",
            [],
        ),
        "dropped_high_signal_diagnostic_event_ids": context_pack.get(
            "dropped_high_signal_diagnostic_event_ids",
            [],
        ),
        "detected_diagnostic_fact_ids": [
            fact.get("fact_id") for fact in context_pack.get("detected_diagnostic_facts", [])[:24]
        ],
        "retained_diagnostic_fact_ids": [
            fact.get("fact_id") for fact in context_pack.get("retained_diagnostic_facts", [])[:24]
        ],
        "dropped_diagnostic_fact_ids": [
            fact.get("fact_id") for fact in context_pack.get("dropped_diagnostic_facts", [])[:24]
        ],
        "detected_diagnostic_facts": context_pack.get("detected_diagnostic_facts", [])[:12],
        "retained_diagnostic_facts": context_pack.get("retained_diagnostic_facts", [])[:12],
        "dropped_diagnostic_facts": context_pack.get("dropped_diagnostic_facts", [])[:12],
        "diagnostic_fact_classifications": context_pack.get("diagnostic_fact_classifications", [])[:12],
        "candidate_target_classes": context_pack.get("candidate_target_classes", [])[:12],
        "service_team_owner_candidates": context_pack.get("service_team_owner_candidates", [])[:10],
        "accepted_memory_behavior_contracts": context_pack.get("accepted_memory_behavior_contracts", [])[:5],
        "action_state_transition_count": len(context_pack.get("action_state_transitions", [])),
        "answered_questions_from_actions_count": len(context_pack.get("answered_questions_from_actions", [])),
        "do_not_ask_from_actions_count": len(context_pack.get("do_not_ask_from_actions", [])),
        "diagnostic_behavior_contracts": context_pack.get("diagnostic_behavior_contracts", [])[:5],
        "diagnostic_actionability": context_pack.get("diagnostic_actionability", [])[:5],
        "candidate_targets": [
            target.get("display_name")
            for target in context_pack.get("candidate_targets", [])[:10]
        ],
        "target_aliases": context_pack.get("target_aliases", [])[:10],
        "rejected_targets": [
            target.get("display_name")
            for target in context_pack.get("do_not_target", [])[:10]
        ],
        "rejected_json_log_target_examples": [
            target.get("display_name")
            for target in context_pack.get("do_not_target", [])
            if "json" in str(target.get("rejection_reason") or "").lower()
            or "diagnostic" in str(target.get("rejection_reason") or "").lower()
        ][:8],
    }


def extract_incident_read_and_whisper(
    context_pack: dict[str, Any],
    llm_client: LLMClient,
) -> IncidentReadAndWhisper:
    raw = llm_client.generate_json(
        "incident_read_and_whisper",
        context_pack,
        IncidentReadAndWhisper,
    )
    if isinstance(raw, IncidentReadAndWhisper):
        return raw
    return IncidentReadAndWhisper.model_validate(raw)


def _candidate_by_id(context_pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(target.get("target_id")): target
        for target in context_pack.get("candidate_targets", [])
        if target.get("target_id")
    }


def _canonical_id_by_alias(context_pack: dict[str, Any]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for alias in context_pack.get("target_aliases", []):
        canonical_id = str(alias.get("canonical_target_id") or "")
        if not canonical_id:
            continue
        mapping[canonical_id] = canonical_id
        for alias_id in alias.get("alias_target_ids", []) or []:
            mapping[str(alias_id)] = canonical_id
    return mapping


def _candidate_by_display(context_pack: dict[str, Any]) -> dict[tuple[str, str | None], dict[str, Any]]:
    by_name: dict[tuple[str, str | None], dict[str, Any]] = {}
    for target in context_pack.get("candidate_targets", []):
        name_key = _target_key(str(target.get("display_name") or ""))
        target_type = target.get("target_type")
        if name_key:
            by_name[(name_key, target_type)] = target
            by_name.setdefault((name_key, None), target)
    return by_name


def _tokens(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", _norm(value))
        if token not in STOPWORDS and not token.isdigit()
    }


def _split_excerpt_units(text: str) -> list[str]:
    units: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [part.strip() for part in re.split(r"(?<=[.!?])\s+", line) if part.strip()]
        units.extend(parts or [line])
    return units or [text.strip()]


def _shorten_excerpt(text: str, *, limit: int = 240) -> str:
    compacted = " ".join(text.split())
    if len(compacted) <= limit:
        return compacted
    return f"{compacted[:limit].rstrip()}..."


def _quote_looks_truncated_mid_word(quote: str, event_text: str) -> bool:
    compact_quote = " ".join(str(quote).split()).rstrip()
    if not compact_quote or not compact_quote[-1].isalnum():
        return False
    if compact_quote.endswith("..."):
        return False
    compact_event = " ".join(str(event_text).split())
    raw_index = compact_event.find(compact_quote)
    if raw_index >= 0:
        next_index = raw_index + len(compact_quote)
        return next_index < len(compact_event) and compact_event[next_index].isalnum()
    last_word = compact_quote.rsplit(" ", 1)[-1].lower()
    if len(last_word) < 5:
        return False
    return any(
        token.startswith(last_word) and token != last_word
        for token in re.findall(r"[A-Za-z0-9_/-]+", compact_event.lower())
    )


def _best_event_excerpt(
    *,
    event_text: str,
    claim_text: str,
    selected_target_display_name: str | None,
) -> tuple[str | None, dict[str, Any]]:
    event_terms = _tokens(event_text)
    claim_terms = _tokens(claim_text)
    overlap = event_terms & claim_terms
    target_key = _target_key(selected_target_display_name)
    target_supported = bool(target_key and target_key in _target_key(event_text))
    if len(overlap) < 2 and not target_supported:
        return None, {
            "reason": "insufficient_term_overlap",
            "overlap": sorted(overlap),
            "target_supported": target_supported,
        }
    best_unit = ""
    best_score = -1
    for unit in _split_excerpt_units(event_text):
        unit_terms = _tokens(unit)
        score = len(unit_terms & claim_terms)
        if target_key and target_key in _target_key(unit):
            score += 3
        if score > best_score:
            best_unit = unit
            best_score = score
    if best_score <= 0 and not target_supported:
        return None, {"reason": "no_supporting_excerpt", "overlap": sorted(overlap)}
    return str(redact_for_llm(_shorten_excerpt(best_unit or event_text))), {
        "reason": "canonical_excerpt_selected",
        "overlap": sorted(overlap)[:12],
        "target_supported": target_supported,
        "excerpt_score": best_score,
    }


def _output_directly_addresses_target(output_text: str, display_name: str) -> bool:
    text_norm = _norm(output_text)
    name_norm = _target_key(display_name)
    if not text_norm or not name_norm:
        return False
    pattern = rf"(?<![a-z0-9])@?{re.escape(name_norm)}(?![a-z0-9])"
    match = re.search(pattern, text_norm)
    if not match:
        return False
    tail = text_norm[match.end() : match.end() + 80]
    head = text_norm[max(0, match.start() - 12) : match.start()]
    if head.rstrip().endswith("@"):
        return True
    if re.match(r"\s*(?:,|/|\band\b|\bor\b)", tail):
        return True
    return bool(re.match(r"\s+(?:can you|could you|please|confirm|provide|share)\b", tail))


def _additional_addressed_target_ids(
    *,
    read: IncidentReadAndWhisper,
    allowed_targets: list[AllowedTarget],
    selected_target_ids: list[str],
) -> list[str]:
    output_text = " ".join(piece for piece in (read.say_this, read.next_line or "") if piece)
    selected = set(selected_target_ids)
    extras: list[str] = []
    for target in allowed_targets:
        if target.target_id in selected:
            continue
        if not target.targetable or target.target_quality not in {"high", "medium"}:
            continue
        if target.target_type in {"bot_system", "non_targetable_noise"}:
            continue
        if _target_candidate_rejection_reason(target) is not None:
            continue
        if _output_directly_addresses_target(output_text, target.display_name):
            extras.append(target.target_id)
            selected.add(target.target_id)
    return extras


def normalize_incident_read_envelope(
    read: IncidentReadAndWhisper,
    *,
    context_pack: dict[str, Any],
    latest_window_events: list[IncidentEvent],
) -> tuple[IncidentReadAndWhisper, dict[str, Any]]:
    """Canonicalize repairable metadata around the AI semantic read.

    This does not choose a new move, blocker, target, or wording. It only maps
    duplicate target IDs to the canonical model-facing ID and replaces safe
    paraphrased evidence quotes with verbatim excerpts from the cited event.
    """
    metadata: dict[str, Any] = {
        "target_id_canonicalized": False,
        "target_canonicalization": None,
        "evidence_quote_canonicalized": False,
        "quote_canonicalizations": [],
        "quote_canonicalization_skipped": [],
    }
    candidate_by_id = _candidate_by_id(context_pack)
    alias_to_canonical = _canonical_id_by_alias(context_pack)
    candidate_by_display = _candidate_by_display(context_pack)

    updates: dict[str, Any] = {}
    selected_id = read.selected_target_id
    selected_display = read.selected_target_display_name
    canonical_id = alias_to_canonical.get(selected_id or "")
    if selected_id and selected_id not in candidate_by_id and canonical_id in candidate_by_id:
        canonical = candidate_by_id[canonical_id]
        updates["selected_target_id"] = canonical_id
        updates["selected_target_display_name"] = canonical.get("display_name")
        metadata["target_id_canonicalized"] = True
        metadata["target_canonicalization"] = {
            "from_target_id": selected_id,
            "to_target_id": canonical_id,
            "reason": "duplicate_target_id_alias",
            "display_name": canonical.get("display_name"),
        }
    elif selected_id and selected_id not in candidate_by_id and selected_display:
        name_key = _target_key(selected_display)
        matching = candidate_by_display.get((name_key, None))
        if matching is not None:
            updates["selected_target_id"] = matching.get("target_id")
            updates["selected_target_display_name"] = matching.get("display_name")
            metadata["target_id_canonicalized"] = True
            metadata["target_canonicalization"] = {
                "from_target_id": selected_id,
                "to_target_id": matching.get("target_id"),
                "reason": "display_name_matched_canonical_target",
                "display_name": matching.get("display_name"),
            }
    elif selected_id and selected_id in candidate_by_id:
        canonical = candidate_by_id[selected_id]
        if selected_display and _target_key(selected_display) != _target_key(str(canonical.get("display_name") or "")):
            updates["selected_target_display_name"] = canonical.get("display_name")
            metadata["target_canonicalization"] = {
                "from_display_name": selected_display,
                "to_display_name": canonical.get("display_name"),
                "reason": "selected_target_display_name_normalized",
            }
    elif not selected_id and selected_display:
        name_key = _target_key(selected_display)
        matching = candidate_by_display.get((name_key, None))
        if matching is None:
            matching = next(
                (
                    candidate
                    for candidate in context_pack.get("candidate_targets", [])
                    if name_key
                    and (
                        _target_key(str(candidate.get("display_name") or "")).endswith(f" {name_key}")
                        or _target_key(str(candidate.get("display_name") or "")).startswith(f"{name_key} ")
                    )
                ),
                None,
            )
        if matching is not None:
            updates["selected_target_id"] = matching.get("target_id")
            updates["selected_target_display_name"] = matching.get("display_name")
            metadata["target_id_canonicalized"] = True
            metadata["target_canonicalization"] = {
                "from_target_id": None,
                "to_target_id": matching.get("target_id"),
                "reason": "missing_target_id_display_name_matched",
                "display_name": matching.get("display_name"),
            }

    event_text_by_id = {event.event_id: event.message for event in latest_window_events}
    claim_text = " ".join(
        piece
        for piece in (
            read.current_read,
            read.latest_open_loop,
            read.say_this,
            read.next_line or "",
            updates.get("selected_target_display_name") or read.selected_target_display_name or "",
        )
        if piece
    )
    updated_evidence: list[WhisperEvidenceRef] = []
    for evidence in read.evidence:
        event_text = event_text_by_id.get(evidence.event_id)
        quote_norm = _norm(evidence.quote)
        event_norm = _norm(event_text)
        quote_is_supported = quote_norm in event_norm or event_norm in quote_norm
        quote_is_truncated = _quote_looks_truncated_mid_word(evidence.quote, event_text)
        if not event_text or not quote_norm or (quote_is_supported and not quote_is_truncated):
            updated_evidence.append(evidence)
            continue
        excerpt, detail = _best_event_excerpt(
            event_text=event_text,
            claim_text=f"{claim_text} {evidence.quote}",
            selected_target_display_name=updates.get("selected_target_display_name")
            or read.selected_target_display_name,
        )
        if excerpt is None:
            metadata["quote_canonicalization_skipped"].append(
                {
                    "event_id": evidence.event_id,
                    "original_quote": evidence.quote,
                    **detail,
                }
            )
            updated_evidence.append(evidence)
            continue
        metadata["evidence_quote_canonicalized"] = True
        metadata["quote_canonicalizations"].append(
            {
                "event_id": evidence.event_id,
                "original_quote": evidence.quote,
                "canonical_quote": excerpt,
                **detail,
            }
        )
        updated_evidence.append(evidence.model_copy(update={"quote": excerpt}))
    if metadata["evidence_quote_canonicalized"]:
        updates["evidence"] = updated_evidence

    if not updates:
        return read, metadata
    return read.model_copy(update=updates), metadata


def decision_from_incident_read(
    read: IncidentReadAndWhisper,
    *,
    allowed_targets: list[AllowedTarget],
    current_events: list[IncidentEvent] | None = None,
) -> ICDecision:
    allowed_by_id = {target.target_id: target for target in allowed_targets}
    event_text_by_id = {event.event_id: event.message for event in (current_events or [])}
    targets: list[EntityRef] = []
    selected_target_ids: list[str] = []
    if read.selected_target_id:
        selected_target_ids.append(read.selected_target_id)
    selected_target_ids.extend(
        _additional_addressed_target_ids(
            read=read,
            allowed_targets=allowed_targets,
            selected_target_ids=selected_target_ids,
        )
    )
    selected_target_ids = list(dict.fromkeys(selected_target_ids))
    for selected_target_id in selected_target_ids:
        target = allowed_by_id.get(selected_target_id)
        if target is not None:
            targets.append(
                EntityRef(
                    entity_type=_target_entity_type(target),
                    display_name=target.display_name,
                    canonical_id=target.canonical_id,
                    status="targeted",
                    evidence=[
                        EvidenceRef(
                            event_id=event_id,
                            quote=str(redact_for_llm(_shorten_excerpt(event_text_by_id.get(event_id, "")))),
                            confidence=0.7,
                        )
                        for event_id in target.evidence_ids[:3]
                    ],
                    source="catalog" if target.source in {"catalog", "service_alias"} else "current_evidence",
                )
            )
    output: dict[str, Any] = {"say_this": read.say_this}
    if read.next_line:
        output["next_line"] = read.next_line
    if read.command is not None:
        output["command"] = read.command.model_dump(mode="json")
    grounding = [
        EvidenceRef(
            event_id=item.event_id,
            quote=item.quote,
            confidence=item.confidence,
        )
        for item in read.evidence
    ]
    return ICDecision(
        decision_id=f"read-whisper-{read.incident_id}-{utc_now().strftime('%H%M%S')}",
        incident_id=read.incident_id,
        move=read.selected_move,
        phase="unknown",
        domain_intent=read.latest_open_loop,
        model_metadata={
            "product_path": "incident_read_and_whisper",
            "current_read": read.current_read,
            "latest_open_loop": read.latest_open_loop,
            "already_answered": read.already_answered,
            "uncertainty": read.uncertainty,
            "selected_target_display_name": read.selected_target_display_name,
        },
        output=output,
        target_ids=selected_target_ids,
        targets=targets,
        rationale=[read.current_read, read.latest_open_loop, *(read.already_answered[:5])],
        grounding=grounding,
        confidence=read.confidence,
        expiration="PT15M",
    )
