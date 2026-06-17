from __future__ import annotations

import re
from typing import Any

from ic_copilot.llm.redaction import redact_for_llm
from ic_copilot.schemas import IncidentEvent


MAX_WORK_ITEMS = 6
MAX_WORK_ITEM_ACTION_CHARS = 220

WORK_ITEM_RE = re.compile(
    r"^\s*(?:[-*•]\s*)?"
    r"(?P<label>[A-Z][A-Za-z0-9 /&_.-]{2,72}?):\s*"
    r"\(Owner:\s*(?P<owners>[^)]{1,180})\)\s*"
    r"(?:[-–—]\s*)?(?P<action>.*)$"
)
MENTION_RE = re.compile(r"@([A-Za-z][\w.-]*)")
DIRECT_OWNER_ACTION_RE = re.compile(
    r"^\s*(?:[-*•]\s*)?"
    r"(?P<label>[A-Z][A-Za-z0-9 /&_.-]{2,72}?):\s*"
    r"(?P<body>.+?)\s*$"
)
LEADING_GROUP_RE = re.compile(
    r"^(?P<group>[A-Z][A-Za-z0-9 /&_.-]{1,72}?"
    r"(?:\s+(?:team|Team|engineering|Engineering|SRE|Ops|Support)|Workflow|Security))\s+"
    r"(?P<verb>is|are|will|was|were|has|have|checking|monitoring|validating|investigating)\b"
)
RELATED_GROUP_RE = re.compile(
    r"\b(?:contacting|checking with|working with|waiting on|asked|asking|coordinating with)\s+"
    r"(?:the\s+)?(?P<group>[A-Z][A-Za-z0-9 /&_.-]{1,72}?"
    r"(?:\s+(?:team|Team|engineering|Engineering|SRE|Ops|Support)|Workflow|Security))\b"
)
ACTIVE_ACTION_VERB_RE = re.compile(
    r"\b(?:is|are|will|was|were|has|have)\s+"
    r"(?:contacting|checking|monitoring|validating|investigating|reviewing|coordinating|working|owning|driving)\b",
    re.IGNORECASE,
)
ACTION_LABEL_TERMS = {
    "audit",
    "check",
    "credential",
    "fix",
    "investigation",
    "monitor",
    "next action",
    "next step",
    "recovery",
    "rotate",
    "validation",
}
NON_WORK_ITEM_LABELS = {
    "current status",
    "impact summary",
    "issue",
    "issue status",
    "roles",
    "severity",
    "status",
    "teams involved",
    "tenants impacted",
}
PERMISSION_DENIED_TERMS = (
    "don't have required permission",
    "do not have required permission",
    "don't have the permission",
    "do not have the permission",
    "required permission",
    "permission denied",
    "lacking permission",
    "i don't have access",
    "i do not have access",
    "i don't have the permission",
    "i do not have the permission",
    "requires dedicated_topic permission",
)
DEDICATED_TOPIC_ACTION_TERMS = (
    "daco",
    "daco-bot",
    "dedicated topic",
    "dedicated_topic",
    "move",
    "topic",
    "topics for",
)
SCOPE_SYMPTOM_VALIDATION_TERMS = (
    "exact symptoms",
    "affected scope",
    "symptoms and affected scope",
    "scope for",
)
REPORT_GROUPING_TERMS = (
    "before grouping",
    "before we group",
    "grouping this",
    "same issue",
    "related",
)


def _compact(value: str, *, limit: int | None = None) -> str:
    compacted = " ".join((value or "").split()).strip()
    if limit is not None and len(compacted) > limit:
        compacted = f"{compacted[:limit].rstrip()} ... [truncated]"
    return str(redact_for_llm(compacted))


def _owner_parts(owner_text: str) -> tuple[str | None, list[str]]:
    text = " ".join(owner_text.split()).strip()
    if not text:
        return None, []
    if "@" not in text:
        return _compact(text) or None, []
    group, *mention_parts = text.split("@")
    owner_group = _compact(group.strip(" ,;:-/")) or None
    owner_names: list[str] = []
    for part in mention_parts:
        name = _compact(part.strip(" ,;:-"))
        if name and name.lower() not in {"here", "channel"}:
            owner_names.append(name)
    return owner_group, list(dict.fromkeys(owner_names))


def _label_allows_direct_owner_action(label: str, body: str) -> bool:
    label_norm = re.sub(r"\s+", " ", label.strip().lower())
    body_norm = re.sub(r"\s+", " ", body.strip().lower())
    if not label_norm or label_norm in NON_WORK_ITEM_LABELS:
        return False
    if any(term in label_norm for term in ACTION_LABEL_TERMS):
        return True
    return any(term in body_norm for term in ("check", "monitor", "validate", "investigat", "contact", "owner"))


def _direct_owner_parts(body: str) -> tuple[str | None, list[str]]:
    owner_names = [
        _compact(match.group(1).strip(" ,;:-"))
        for match in MENTION_RE.finditer(body)
        if _compact(match.group(1).strip(" ,;:-")).lower() not in {"here", "channel"}
    ]
    owner_group: str | None = None
    leading_group = LEADING_GROUP_RE.search(body)
    if leading_group:
        owner_group = _compact(leading_group.group("group").strip(" ,;:-")) or None
    related_group = RELATED_GROUP_RE.search(body)
    if related_group:
        owner_group = _compact(related_group.group("group").strip(" ,;:-")) or owner_group
    return owner_group, list(dict.fromkeys(owner_names))


def _extract_direct_work_item(line: str) -> dict[str, Any] | None:
    match = DIRECT_OWNER_ACTION_RE.match(line)
    if not match:
        return None
    label = _compact(match.group("label"), limit=80)
    body = match.group("body")
    body_norm = re.sub(r"\s+", " ", body.strip().lower())
    if "(owner:" in body_norm:
        return None
    if not _label_allows_direct_owner_action(label, body):
        return None
    owner_group, owner_names = _direct_owner_parts(body)
    has_direct_owner_action = bool(owner_names and ACTIVE_ACTION_VERB_RE.search(body)) or bool(LEADING_GROUP_RE.search(body))
    if not has_direct_owner_action:
        return None
    if not owner_group and not owner_names:
        return None
    return {
        "work_item_label": label,
        "owner_names": owner_names[:6],
        "owner_group": owner_group,
        "status_or_action": _compact(body, limit=MAX_WORK_ITEM_ACTION_CHARS),
    }


def _extract_permission_blocked_work_item(events: list[IncidentEvent]) -> dict[str, Any] | None:
    evidence_ids: list[str] = []
    combined = "\n".join(event.message or "" for event in events)
    combined_norm = re.sub(r"\s+", " ", combined.lower())
    has_permission_denial = any(term in combined_norm for term in PERMISSION_DENIED_TERMS)
    has_dedicated_topic_action = any(term in combined_norm for term in DEDICATED_TOPIC_ACTION_TERMS)
    if not (has_permission_denial and has_dedicated_topic_action):
        return None
    for event in events:
        text_norm = re.sub(r"\s+", " ", (event.message or "").lower())
        if any(term in text_norm for term in (*PERMISSION_DENIED_TERMS, *DEDICATED_TOPIC_ACTION_TERMS)):
            evidence_ids.append(event.event_id)
    if not evidence_ids:
        return None
    return {
        "work_item_label": "Dedicated topic permission path",
        "owner_names": [],
        "owner_group": "DACO",
        "status_or_action": _compact(
            "Dedicated-topic move attempt is permission-blocked; validate the correct DACO or "
            "incident-manager owner and confirm scope/topic evidence before the next safe path.",
            limit=MAX_WORK_ITEM_ACTION_CHARS,
        ),
        "evidence_id": evidence_ids[-1],
        "evidence_ids": list(dict.fromkeys(evidence_ids))[:6],
        "work_item_type": "permission_blocked_operational_attempt",
        "unsafe_next_moves": [
            "ask permission-denied users to perform the move",
            "ask anyone to execute the command",
            "expose tenant IDs",
        ],
    }


def _has_permission_loop(events: list[IncidentEvent]) -> bool:
    combined = "\n".join(event.message or "" for event in events)
    combined_norm = re.sub(r"\s+", " ", combined.lower())
    return any(term in combined_norm for term in PERMISSION_DENIED_TERMS) and any(
        term in combined_norm for term in DEDICATED_TOPIC_ACTION_TERMS
    )


def _extract_scope_symptom_validation_work_item(events: list[IncidentEvent]) -> dict[str, Any] | None:
    if not _has_permission_loop(events):
        return None
    for event in reversed(events):
        text = event.message or ""
        text_norm = re.sub(r"\s+", " ", text.lower())
        asks_scope_or_symptoms = any(term in text_norm for term in SCOPE_SYMPTOM_VALIDATION_TERMS)
        asks_before_grouping = any(term in text_norm for term in REPORT_GROUPING_TERMS)
        if not (asks_scope_or_symptoms and asks_before_grouping):
            continue
        tokens = event.extracted_tokens or {}
        if tokens.get("is_bot") or tokens.get("is_system") or not event.author:
            continue
        owner_names = [
            _compact(match.group(1).strip(" ,;:-"), limit=80)
            for match in MENTION_RE.finditer(text)
            if _compact(match.group(1).strip(" ,;:-")).lower()
            not in {"here", "channel", "daco-bot", "zsrebot", "incident-managers"}
        ]
        return {
            "work_item_label": "Scope/symptom validation before grouping reports",
            "owner_names": list(dict.fromkeys(owner_names)) or [_compact(event.author, limit=80)],
            "owner_group": None,
            "status_or_action": _compact(text, limit=MAX_WORK_ITEM_ACTION_CHARS),
            "evidence_id": event.event_id,
            "work_item_type": "scope_symptom_validation",
        }
    return None


def extract_current_work_items(events: list[IncidentEvent]) -> list[dict[str, Any]]:
    """Extract explicit owner/action rows without inferring the active blocker.

    Rows such as ``Fix Vulnerability: (Owner: Workflow @person) - ...`` are
    product input structure: they tell the AI and verifier who the current text
    explicitly says owns that work item. This helper does not decide which item
    is sharpest or whether it is the final IC move.
    """
    items: list[dict[str, Any]] = []
    scope_symptom_item = _extract_scope_symptom_validation_work_item(events)
    if scope_symptom_item:
        items.append(scope_symptom_item)
    permission_item = _extract_permission_blocked_work_item(events)
    if permission_item:
        items.append(permission_item)
    for event in events:
        for line in (event.message or "").splitlines():
            match = WORK_ITEM_RE.match(line)
            if not match:
                direct_item = _extract_direct_work_item(line)
                if not direct_item:
                    continue
                direct_item["evidence_id"] = event.event_id
                items.append(direct_item)
                if len(items) >= MAX_WORK_ITEMS:
                    return items
                continue
            owner_group, owner_names = _owner_parts(match.group("owners"))
            action = _compact(match.group("action"), limit=MAX_WORK_ITEM_ACTION_CHARS)
            label = _compact(match.group("label"), limit=80)
            if not label or (not owner_group and not owner_names):
                continue
            items.append(
                {
                    "work_item_label": label,
                    "owner_names": owner_names[:6],
                    "owner_group": owner_group,
                    "status_or_action": action,
                    "evidence_id": event.event_id,
                }
            )
            if len(items) >= MAX_WORK_ITEMS:
                return items
    return items
