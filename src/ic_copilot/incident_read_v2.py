from __future__ import annotations

import json
import re
from typing import Any

from ic_copilot.llm.base import LLMClient
from ic_copilot.llm.redaction import redact_for_llm
from ic_copilot.read_and_whisper import decision_from_incident_read
from ic_copilot.schema_repair import validate_with_repair
from ic_copilot.schemas import (
    AllowedTarget,
    AnsweredQuestionV2,
    ICMove,
    IncidentEvent,
    IncidentReadAndWhisper,
    IncidentReadAndWhisperV2,
    IncidentStateV2,
    NextBlockerV2,
    OpenQuestionV2,
    RejectedTargetV2,
    WhisperEvidenceRef,
    WhisperV2,
)


MAX_V2_EVENTS = 18
MAX_V2_TARGETS = 16
MAX_V2_REJECTED = 8
MAX_V2_MEMORY_HINTS = 4
MAX_V2_WORK_ITEMS = 8
MAX_V2_DIAGNOSTIC_FACTS = 12
V2_MODEL_PAYLOAD_HARD_CAP = 18_000
PSEUDO_TARGET_PATTERNS = (
    re.compile(r"^just to confirm\b", re.I),
    re.compile(r"^\d+\s+files?\b", re.I),
    re.compile(r"^phase update\b", re.I),
    re.compile(r"^set the channel topic\b", re.I),
    re.compile(r"^srebot[a-z0-9_.-]+", re.I),
    re.compile(r"\bresponse we would see this\b", re.I),
    re.compile(r"^@?[A-Z][\w .-]{1,80}\s+as reported here\b", re.I),
)
V2_MOVE_TO_V1: dict[str, ICMove] = {
    "engage_owner": ICMove.ENGAGE_OWNER,
    "confirm_ownership": ICMove.CONFIRM_OWNERSHIP,
    "ask_next_validation": ICMove.ASK_NEXT_VALIDATION,
    "request_status_or_eta": ICMove.REQUEST_STATUS_OR_ETA,
    "request_mitigation_option": ICMove.REQUEST_MITIGATION_OPTION,
    "request_monitoring_signal": ICMove.REQUEST_MONITORING_SIGNAL,
    "summarize_current_state": ICMove.SUMMARIZE_CURRENT_STATE,
    "prevent_stale_question": ICMove.PREVENT_STALE_QUESTION,
    "escalate_severity_or_owner": ICMove.ESCALATE_SEVERITY_OR_OWNER,
    "handoff_or_assign_dri": ICMove.HANDOFF_OR_ASSIGN_DRI,
    "wait_for_active_work": ICMove.WAIT_FOR_ACTIVE_WORK,
    "ask_code_fix_status": ICMove.ASK_CODE_FIX_STATUS,
    "ask_status_eta": ICMove.ASK_STATUS_ETA,
    "ask_impact": ICMove.ASK_IMPACT,
    "confirm_deployment_related": ICMove.CONFIRM_DEPLOYMENT_RELATED,
    "confirm_customer_comms": ICMove.CONFIRM_CUSTOMER_COMMS,
    "monitor_next": ICMove.MONITOR_NEXT,
    "ask_impact_scope": ICMove.ASK_IMPACT,
    "ask_escalation_type": ICMove.ESCALATE_SEVERITY_OR_OWNER,
    "ask_owner_routing": ICMove.CONFIRM_OWNERSHIP,
    "ask_status_or_eta": ICMove.ASK_STATUS_ETA,
    "ask_validation_signal": ICMove.ASK_NEXT_VALIDATION,
    "ask_customer_confirmation": ICMove.ASK_NEXT_VALIDATION,
    "ask_trust_post_decision": ICMove.CONFIRM_CUSTOMER_COMMS,
    "no_safe_recommendation": ICMove.NO_SAFE_RECOMMENDATION,
}


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _key(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", " ", _norm(value)).strip()


def _tokens(value: str | None) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", _norm(value))
        if token
        not in {
            "and",
            "are",
            "can",
            "confirm",
            "could",
            "for",
            "from",
            "please",
            "provide",
            "share",
            "that",
            "the",
            "this",
            "you",
        }
    }


def _answered_question_repeat_allowed(
    question: AnsweredQuestionV2,
    *,
    say_this: str,
    selected_target: str | None,
) -> bool:
    if question.question_type != "owner_routing":
        return False
    answer = _key(question.answer_summary)
    target = _key(selected_target)
    if not target or target not in answer:
        return False
    text = _key(say_this)
    return bool(
        re.search(
            r"\b(status|update|ownership|owner|start|starting|checking|mismatch check|validation|next signal)\b",
            text,
        )
    )


def _compact_text(value: str | None, limit: int = 260) -> str:
    text = " ".join(str(redact_for_llm(value or "")).split())
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0].rstrip() + " ..."


def is_pseudo_target_name(value: str | None) -> bool:
    text = " ".join(str(value or "").split()).strip()
    if not text:
        return False
    normalized = _norm(text.strip(" .,:;"))
    if normalized in {
        "app",
        "phase update",
        "set the channel topic",
        "just to confirm",
        "pinned by",
        "thread reply",
    }:
        return True
    return any(pattern.search(text) for pattern in PSEUDO_TARGET_PATTERNS)


def _canonical_display_name(value: str | None, candidate_targets: list[dict[str, Any]]) -> str | None:
    if not value:
        return None
    stripped = " ".join(value.split()).strip()
    stripped = stripped.strip(" \t\r\n")
    key = _key(stripped.rstrip(".,:;"))
    if not key:
        return None
    for target in candidate_targets:
        if _key(str(target.get("display_name") or "")) == key:
            return str(target.get("display_name"))
    return stripped.rstrip(".,:;")


def _target_id_for_display(display_name: str | None, candidate_targets: list[dict[str, Any]]) -> str | None:
    display_key = _key(display_name)
    if not display_key:
        return None
    for target in candidate_targets:
        if _key(str(target.get("display_name") or "")) == display_key:
            return str(target.get("target_id"))
    for target in candidate_targets:
        candidate_key = _key(str(target.get("display_name") or ""))
        if candidate_key and (candidate_key in display_key or display_key in candidate_key):
            return str(target.get("target_id"))
    return None


def _target_rows_for_v2(base_context_pack: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in base_context_pack.get("candidate_targets", []):
        display = str(row.get("display_name") or "")
        if is_pseudo_target_name(display):
            continue
        rows.append(
            {
                "target_id": row.get("target_id"),
                "display_name": display,
                "target_type": row.get("target_type"),
                "target_class": row.get("target_class"),
                "role_hint": row.get("role_hint"),
                "source": row.get("source"),
                "latest_evidence_ids": row.get("latest_evidence_ids", [])[:3],
                "why_visible": _compact_text(row.get("why_visible") or row.get("reason"), 120),
            }
        )
        if len(rows) >= MAX_V2_TARGETS:
            break
    return rows


def _event_rows_for_v2(base_context_pack: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in base_context_pack.get("latest_window_events", []):
        event_kind = str(event.get("event_kind") or "")
        text_limit = 440 if "diagnostic" in event_kind else 360
        rows.append(
            {
                "event_id": event.get("event_id"),
                "sequence": event.get("sequence"),
                "timestamp": event.get("timestamp"),
                "author": event.get("author"),
                "author_type": event.get("author_type"),
                "event_kind": event.get("event_kind"),
                "planner_grounding_allowed": event.get("planner_grounding_allowed"),
                "text": _compact_text(event.get("text"), text_limit),
                "mentions": event.get("slack_mentions", [])[:8],
            }
        )
        if len(rows) >= MAX_V2_EVENTS:
            break
    return rows


def _compact_rows(rows: list[dict[str, Any]] | None, limit: int) -> list[dict[str, Any]]:
    compacted: list[dict[str, Any]] = []
    for row in rows or []:
        item: dict[str, Any] = {}
        for key, value in row.items():
            if isinstance(value, str):
                item[key] = _compact_text(value, 180)
            elif isinstance(value, list):
                item[key] = value[:6]
            elif isinstance(value, dict):
                item[key] = {
                    str(child_key): _compact_text(child_value, 120) if isinstance(child_value, str) else child_value
                    for child_key, child_value in list(value.items())[:8]
                }
            else:
                item[key] = value
        compacted.append(item)
        if len(compacted) >= limit:
            break
    return compacted


def _compact_target_aliases(base_context_pack: dict[str, Any]) -> list[dict[str, Any]]:
    aliases: list[dict[str, Any]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for row in base_context_pack.get("target_aliases", []) or []:
        alias_ids = tuple(str(item) for item in (row.get("alias_target_ids") or [])[:6])
        key = (str(row.get("canonical_target_id") or ""), alias_ids)
        if key in seen:
            continue
        seen.add(key)
        aliases.append(
            {
                "canonical_target_id": row.get("canonical_target_id"),
                "canonical_display_name": row.get("canonical_display_name"),
                "alias_target_ids": list(alias_ids),
                "alias_reason": row.get("alias_reason"),
            }
        )
        if len(aliases) >= 10:
            break
    return aliases


def _v2_pack_char_count(pack: dict[str, Any]) -> int:
    return len(json.dumps(pack, default=str, sort_keys=True))


def _trim_v2_text(value: Any, limit: int) -> Any:
    if not isinstance(value, str):
        return value
    return _compact_text(value, limit)


def _trim_v2_rows(
    rows: list[dict[str, Any]],
    *,
    limit: int,
    text_limit: int,
    protected_event_ids: set[str] | None = None,
    protected_text_limit: int | None = None,
) -> list[dict[str, Any]]:
    trimmed = []
    protected = protected_event_ids or set()
    for row in rows[:limit]:
        item = {}
        row_text_limit = (
            max(text_limit, protected_text_limit or text_limit)
            if str(row.get("event_id") or "") in protected
            else text_limit
        )
        for key, value in row.items():
            if isinstance(value, str):
                item[key] = _compact_text(value, row_text_limit)
            elif isinstance(value, list):
                item[key] = value[:4]
            elif isinstance(value, dict):
                item[key] = {
                    str(child_key): _trim_v2_text(child_value, max(80, row_text_limit // 2))
                    for child_key, child_value in list(value.items())[:6]
                }
            else:
                item[key] = value
        trimmed.append(item)
    return trimmed


def _enforce_v2_model_payload_budget(pack: dict[str, Any]) -> dict[str, Any]:
    hard_cap = int(pack.get("model_payload_hard_cap") or V2_MODEL_PAYLOAD_HARD_CAP)
    if _v2_pack_char_count(pack) <= hard_cap:
        return pack

    protected_event_ids = {
        str(fact.get("event_id"))
        for fact in pack.get("retained_diagnostic_facts", [])
        if isinstance(fact, dict) and fact.get("event_id")
    }
    protected_event_ids.update(str(event_id) for event_id in pack.get("retained_high_signal_diagnostic_event_ids", []))
    compacted = dict(pack)
    compacted["context_budget_repacked"] = True
    compacted["context_budget_repack_reason"] = "v2_wrapper_payload_over_cap"
    compacted["latest_window_events"] = _trim_v2_rows(
        list(compacted.get("latest_window_events", [])),
        limit=14,
        text_limit=260,
        protected_event_ids=protected_event_ids,
        protected_text_limit=440,
    )
    compacted["candidate_targets"] = _trim_v2_rows(
        list(compacted.get("candidate_targets", [])),
        limit=12,
        text_limit=120,
    )
    compacted["current_work_items"] = _trim_v2_rows(
        list(compacted.get("current_work_items", [])),
        limit=6,
        text_limit=160,
    )
    compacted["diagnostic_facts"] = _trim_v2_rows(
        list(compacted.get("diagnostic_facts", [])),
        limit=8,
        text_limit=140,
    )
    compacted["detected_diagnostic_facts"] = _trim_v2_rows(
        list(compacted.get("detected_diagnostic_facts", [])),
        limit=8,
        text_limit=120,
    )
    compacted["retained_diagnostic_facts"] = _trim_v2_rows(
        list(compacted.get("retained_diagnostic_facts", [])),
        limit=8,
        text_limit=120,
    )
    compacted["dropped_diagnostic_facts"] = []
    compacted["diagnostic_fact_classifications"] = _trim_v2_rows(
        list(compacted.get("diagnostic_fact_classifications", [])),
        limit=8,
        text_limit=100,
    )
    compacted["accepted_behavior_hints"] = _trim_v2_rows(
        list(compacted.get("accepted_behavior_hints", [])),
        limit=3,
        text_limit=180,
    )
    compacted["decision_moment_behavior_hints"] = _trim_v2_rows(
        list(compacted.get("decision_moment_behavior_hints", [])),
        limit=3,
        text_limit=180,
    )
    compacted["accepted_memory_behavior_contracts"] = _trim_v2_rows(
        list(compacted.get("accepted_memory_behavior_contracts", [])),
        limit=3,
        text_limit=160,
    )
    compacted["action_state_transitions"] = _trim_v2_rows(
        list(compacted.get("action_state_transitions", [])),
        limit=4,
        text_limit=160,
    )
    compacted["answered_questions_from_actions"] = _trim_v2_rows(
        list(compacted.get("answered_questions_from_actions", [])),
        limit=4,
        text_limit=160,
    )
    compacted["do_not_ask_from_actions"] = list(compacted.get("do_not_ask_from_actions", []))[:6]
    compacted["do_not_target_examples"] = _trim_v2_rows(
        list(compacted.get("do_not_target_examples", [])),
        limit=5,
        text_limit=100,
    )
    compacted["do_not_target"] = compacted["do_not_target_examples"]
    compacted["non_targetable_but_mentionable_facts"] = _trim_v2_rows(
        list(compacted.get("non_targetable_but_mentionable_facts", [])),
        limit=5,
        text_limit=100,
    )
    compacted["do_not_target_only"] = []
    compacted["forbidden_output_entities"] = _trim_v2_rows(
        list(compacted.get("forbidden_output_entities", [])),
        limit=5,
        text_limit=100,
    )
    compacted["target_aliases"] = list(compacted.get("target_aliases", []))[:4]
    compacted["candidate_target_classes"] = _trim_v2_rows(
        list(compacted.get("candidate_target_classes", [])),
        limit=8,
        text_limit=80,
    )
    compacted["service_team_owner_candidates"] = _trim_v2_rows(
        list(compacted.get("service_team_owner_candidates", [])),
        limit=6,
        text_limit=100,
    )
    compacted["state_first_rules"] = list(compacted.get("state_first_rules", []))[:14]

    if _v2_pack_char_count(compacted) > hard_cap:
        compacted["latest_window_events"] = _trim_v2_rows(
            list(compacted.get("latest_window_events", []))[-10:],
            limit=10,
            text_limit=180,
            protected_event_ids=protected_event_ids,
            protected_text_limit=380,
        )
        compacted["candidate_targets"] = _trim_v2_rows(
            list(compacted.get("candidate_targets", [])),
            limit=8,
            text_limit=90,
        )
        compacted["current_work_items"] = _trim_v2_rows(
            list(compacted.get("current_work_items", [])),
            limit=4,
            text_limit=120,
        )
        compacted["diagnostic_facts"] = _trim_v2_rows(
            list(compacted.get("diagnostic_facts", [])),
            limit=5,
            text_limit=100,
        )
        compacted["detected_diagnostic_facts"] = []
        compacted["retained_diagnostic_facts"] = _trim_v2_rows(
            list(compacted.get("retained_diagnostic_facts", [])),
            limit=5,
            text_limit=100,
        )
        compacted["diagnostic_fact_classifications"] = []
        compacted["accepted_behavior_hints"] = _trim_v2_rows(
            list(compacted.get("accepted_behavior_hints", [])),
            limit=2,
            text_limit=140,
        )
        compacted["decision_moment_behavior_hints"] = compacted["accepted_behavior_hints"]
        compacted["accepted_memory_behavior_contracts"] = _trim_v2_rows(
            list(compacted.get("accepted_memory_behavior_contracts", [])),
            limit=2,
            text_limit=120,
        )
        compacted["diagnostic_behavior_contracts"] = []
        compacted["diagnostic_actionability"] = []
        compacted["do_not_target_examples"] = _trim_v2_rows(
            list(compacted.get("do_not_target_examples", [])),
            limit=3,
            text_limit=80,
        )
        compacted["do_not_target"] = compacted["do_not_target_examples"]
        compacted["non_targetable_but_mentionable_facts"] = []
        compacted["forbidden_output_entities"] = []
        compacted["target_aliases"] = []
        compacted["candidate_target_classes"] = []
        compacted["service_team_owner_candidates"] = []
        compacted["state_first_rules"] = list(compacted.get("state_first_rules", []))[:10]

    return compacted


def build_incident_read_v2_context_pack(
    *,
    base_context_pack: dict[str, Any],
    allowed_targets: list[AllowedTarget],
) -> dict[str, Any]:
    candidate_targets = _target_rows_for_v2(base_context_pack)
    rejected = []
    for row in base_context_pack.get("do_not_target", []):
        rejected.append(
            {
                "display_name": row.get("display_name"),
                "reason": _compact_text(row.get("rejection_reason") or row.get("reason"), 120),
            }
        )
        if len(rejected) >= MAX_V2_REJECTED:
            break
    pack = {
        "incident_id": base_context_pack.get("incident_id"),
        "product_path": "incident_read_and_whisper_v2",
        "schema_version": "2.0",
        "context_pack_variant": base_context_pack.get("context_pack_variant", "compact"),
        "latest_window_events": _event_rows_for_v2(base_context_pack),
        "candidate_targets": candidate_targets,
        "current_work_items": base_context_pack.get("current_work_items", [])[:MAX_V2_WORK_ITEMS],
        "action_state_transitions": _compact_rows(base_context_pack.get("action_state_transitions", []), 6),
        "answered_questions_from_actions": _compact_rows(
            base_context_pack.get("answered_questions_from_actions", []),
            6,
        ),
        "do_not_ask_from_actions": base_context_pack.get("do_not_ask_from_actions", [])[:8],
        "diagnostic_facts": base_context_pack.get("retained_diagnostic_facts", [])[:MAX_V2_DIAGNOSTIC_FACTS],
        "detected_diagnostic_facts": _compact_rows(base_context_pack.get("detected_diagnostic_facts", []), 12),
        "retained_diagnostic_facts": _compact_rows(base_context_pack.get("retained_diagnostic_facts", []), 12),
        "dropped_diagnostic_facts": _compact_rows(base_context_pack.get("dropped_diagnostic_facts", []), 12),
        "diagnostic_fact_classifications": _compact_rows(
            base_context_pack.get("diagnostic_fact_classifications", []),
            12,
        ),
        "diagnostic_behavior_contracts": _compact_rows(
            base_context_pack.get("diagnostic_behavior_contracts", []),
            5,
        ),
        "diagnostic_actionability": _compact_rows(base_context_pack.get("diagnostic_actionability", []), 5),
        "accepted_behavior_hints": (
            base_context_pack.get("accepted_memory_behavior_contracts")
            or base_context_pack.get("decision_moment_behavior_hints")
            or []
        )[:MAX_V2_MEMORY_HINTS],
        "decision_moment_behavior_hints": (
            base_context_pack.get("decision_moment_behavior_hints")
            or base_context_pack.get("accepted_memory_behavior_contracts")
            or []
        )[:MAX_V2_MEMORY_HINTS],
        "accepted_memory_behavior_contracts": _compact_rows(
            base_context_pack.get("accepted_memory_behavior_contracts", []),
            5,
        ),
        "do_not_target_examples": rejected,
        "do_not_target": rejected,
        "non_targetable_but_mentionable_facts": _compact_rows(
            base_context_pack.get("non_targetable_but_mentionable_facts", []),
            12,
        ),
        "do_not_target_only": _compact_rows(base_context_pack.get("do_not_target_only", []), 12),
        "forbidden_output_entities": _compact_rows(base_context_pack.get("forbidden_output_entities", []), 12),
        "target_aliases": _compact_target_aliases(base_context_pack),
        "candidate_target_classes": _compact_rows(base_context_pack.get("candidate_target_classes", []), 12),
        "service_team_owner_candidates": _compact_rows(
            base_context_pack.get("service_team_owner_candidates", []),
            10,
        ),
        "latest_window_selection": base_context_pack.get("latest_window_selection", {}),
        "trailing_high_signal_human_event_ids": base_context_pack.get("trailing_high_signal_human_event_ids", []),
        "trailing_high_signal_human_event_ids_kept": base_context_pack.get(
            "trailing_high_signal_human_event_ids_kept",
            [],
        ),
        "trailing_high_signal_human_event_ids_dropped": base_context_pack.get(
            "trailing_high_signal_human_event_ids_dropped",
            [],
        ),
        "retained_high_signal_diagnostic_event_ids": base_context_pack.get(
            "retained_high_signal_diagnostic_event_ids",
            [],
        ),
        "dropped_high_signal_diagnostic_event_ids": base_context_pack.get(
            "dropped_high_signal_diagnostic_event_ids",
            [],
        ),
        "excluded_human_mention_count": base_context_pack.get("excluded_human_mention_count", 0),
        "observed_bot_command_candidate_count": base_context_pack.get("observed_bot_command_candidate_count", 0),
        "url_slash_false_positive_count": base_context_pack.get("url_slash_false_positive_count", 0),
        "model_exposed_command_count": base_context_pack.get("model_exposed_command_count", 0),
        "command_registry": [],
        "state_first_rules": [
            "First produce incident_state, then next_blocker, then whisper.",
            "Do not ask a person to answer their own question unless they are clearly the answer source.",
            "If Person A asked Person B/the group, prefer Person B, the reporter/support path, or the responsible owner.",
            "Treat bot/card/log evidence as context or diagnostic facts, not targetable people.",
            "Do not target pseudo-authors, labels, file rows, URL/path fragments, ticket IDs, or fused bot/person strings.",
            "Use local knowledge only as behavior hints; current incident evidence is authoritative.",
            "If a question is answered later, put it in answered_questions/do_not_ask and do not ask it visibly.",
            "If action_state_transitions shows an operational page/engagement request was accepted, executed, or completed, put that earlier ask in answered_questions/do_not_ask and do not ask whether it happened.",
            "Write one direct manual-copy ask in whisper.say_this.",
        ],
        "candidate_target_policy": {
            "source": "clear authors, explicit mentions, and current evidence service/team names only",
            "broad_catalog_injection": "disabled unless visible in evidence",
            "all_known_allowed_target_count": len(allowed_targets),
        },
        "source_context_pack_summary": {
            "provider_payload_char_count": base_context_pack.get("provider_payload_char_count"),
            "event_count": len(base_context_pack.get("latest_window_events", [])),
            "candidate_target_count": len(base_context_pack.get("candidate_targets", [])),
            "work_item_count": len(base_context_pack.get("current_work_items", [])),
            "retained_diagnostic_fact_ids": [
                fact.get("fact_id") for fact in base_context_pack.get("retained_diagnostic_facts", [])[:24]
            ],
        },
    }
    pack["model_payload_hard_cap"] = V2_MODEL_PAYLOAD_HARD_CAP
    pack = _enforce_v2_model_payload_budget(pack)
    pack["provider_payload_char_count"] = len(json.dumps(pack, default=str, sort_keys=True))
    pack["model_payload_over_cap"] = pack["provider_payload_char_count"] > V2_MODEL_PAYLOAD_HARD_CAP
    return redact_for_llm(pack)


def incident_read_v2_context_pack_summary(context_pack: dict[str, Any]) -> dict[str, Any]:
    return {
        "strategy": "incident_read_and_whisper_v2",
        "schema_version": context_pack.get("schema_version"),
        "provider_payload_char_count": context_pack.get("provider_payload_char_count"),
        "model_event_count": len(context_pack.get("latest_window_events", [])),
        "candidate_target_count": len(context_pack.get("candidate_targets", [])),
        "work_item_count": len(context_pack.get("current_work_items", [])),
        "diagnostic_fact_count": len(context_pack.get("diagnostic_facts", [])),
        "accepted_behavior_hint_count": len(context_pack.get("accepted_behavior_hints", [])),
        "action_state_transition_count": len(context_pack.get("action_state_transitions", [])),
        "answered_questions_from_actions_count": len(context_pack.get("answered_questions_from_actions", [])),
        "context_budget_repacked": bool(context_pack.get("context_budget_repacked")),
    }


def extract_incident_read_and_whisper_v2(
    context_pack: dict[str, Any],
    llm_client: LLMClient,
) -> IncidentReadAndWhisperV2:
    raw = llm_client.generate_json(
        "incident_read_and_whisper_v2",
        context_pack,
        IncidentReadAndWhisperV2,
    )
    if isinstance(raw, IncidentReadAndWhisperV2):
        return raw
    return validate_with_repair(raw, IncidentReadAndWhisperV2, context="incident_read_and_whisper_v2")


def incident_read_v2_to_incident_read(
    read_v2: IncidentReadAndWhisperV2,
    *,
    context_pack: dict[str, Any],
    latest_window_events: list[IncidentEvent],
) -> IncidentReadAndWhisper:
    candidate_targets = context_pack.get("candidate_targets", [])
    display = _canonical_display_name(read_v2.whisper.selected_target_display_name, candidate_targets)
    target_id = read_v2.whisper.selected_target_id or _target_id_for_display(display, candidate_targets)
    if target_id and not display:
        display = next(
            (
                str(row.get("display_name"))
                for row in candidate_targets
                if str(row.get("target_id")) == str(target_id)
            ),
            None,
        )
    event_text_by_id = {event.event_id: event.message for event in latest_window_events}
    evidence = read_v2.whisper.evidence or read_v2.evidence
    if not evidence and read_v2.next_blocker.evidence_event_ids:
        event_id = read_v2.next_blocker.evidence_event_ids[0]
        quote = _compact_text(event_text_by_id.get(event_id), 220)
        if quote:
            evidence = [WhisperEvidenceRef(event_id=event_id, quote=quote, confidence=0.7)]
    current_read = read_v2.next_blocker.blocker_summary or "State-first read selected the current blocker."
    already_answered = [
        item.answer_summary or item.question_text
        for item in read_v2.incident_state.answered_questions[:8]
        if (item.answer_summary or item.question_text)
    ]
    return IncidentReadAndWhisper(
        incident_id=read_v2.incident_id,
        current_read=current_read,
        latest_open_loop=read_v2.next_blocker.blocker_summary,
        already_answered=already_answered,
        selected_move=V2_MOVE_TO_V1.get(read_v2.whisper.selected_move, ICMove.ASK_NEXT_VALIDATION),
        selected_target_id=target_id,
        selected_target_display_name=display,
        say_this=read_v2.whisper.say_this,
        next_line=read_v2.whisper.next_line,
        command=None,
        evidence=evidence,
        uncertainty="; ".join(read_v2.uncertainty) if read_v2.uncertainty else None,
        confidence=read_v2.confidence,
    )


def incident_read_v2_from_v1_fixture(
    *,
    read: IncidentReadAndWhisper,
    context_pack: dict[str, Any],
) -> IncidentReadAndWhisperV2:
    selected_move = str(getattr(read.selected_move, "value", read.selected_move))
    candidate_targets = context_pack.get("candidate_targets", [])
    display = _canonical_display_name(read.selected_target_display_name, candidate_targets)
    target_type = "none"
    if display:
        target = next((row for row in candidate_targets if _key(row.get("display_name")) == _key(display)), None)
        target_type = str((target or {}).get("target_type") or "person")
        if target_type not in {"person", "team", "service"}:
            target_type = "person"
    open_questions: list[OpenQuestionV2] = []
    if read.latest_open_loop and selected_move != ICMove.NO_SAFE_RECOMMENDATION.value:
        open_questions.append(
            OpenQuestionV2(
                event_id=(read.evidence[0].event_id if read.evidence else "unknown"),
                asked_by=None,
                asked_to=[display] if display else [],
                question_text=read.latest_open_loop,
                question_type="unknown",
                answered=False,
            )
        )
    answered_questions = [
        AnsweredQuestionV2(
            question_text=str(item),
            answer_summary=str(item),
            question_type="unknown",
            evidence_event_ids=[ref.event_id for ref in read.evidence[:2]],
        )
        for item in read.already_answered[:8]
        if str(item).strip()
    ]
    state = IncidentStateV2(
        incident_id=read.incident_id,
        active_humans=[
            str(row.get("display_name"))
            for row in candidate_targets
            if row.get("target_type") == "person"
        ][:8],
        active_teams=[
            str(row.get("display_name"))
            for row in candidate_targets
            if row.get("target_type") in {"team", "service"}
        ][:8],
        open_questions=open_questions,
        answered_questions=answered_questions,
        latest_human_updates=[read.current_read],
        uncertainty_notes=[read.uncertainty] if read.uncertainty else [],
    )
    blocker = NextBlockerV2(
        blocker_type="no_safe_next_move"
        if selected_move == ICMove.NO_SAFE_RECOMMENDATION.value
        else "awaiting_validation_signal",
        blocker_summary=read.latest_open_loop or read.current_read,
        best_target_display_name=display,
        best_target_type=target_type,  # type: ignore[arg-type]
        best_target_reason="Fixture V1 read mapped into V2 state-first envelope.",
        evidence_event_ids=[item.event_id for item in read.evidence],
        rejected_targets=[
            RejectedTargetV2(
                display_name=str(item.get("display_name") or ""),
                reason=str(item.get("reason") or item.get("rejection_reason") or "not targetable"),
            )
            for item in context_pack.get("do_not_target_examples", [])[:4]
        ],
        confidence=read.confidence,
    )
    move = selected_move if selected_move in V2_MOVE_TO_V1 else "ask_validation_signal"
    if selected_move == ICMove.NO_SAFE_RECOMMENDATION.value:
        move = "no_safe_recommendation"
    return IncidentReadAndWhisperV2(
        incident_id=read.incident_id,
        incident_state=state,
        next_blocker=blocker,
        whisper=WhisperV2(
            selected_move=move,  # type: ignore[arg-type]
            selected_target_display_name=display,
            selected_target_id=read.selected_target_id,
            say_this=read.say_this,
            next_line=read.next_line,
            evidence=read.evidence,
        ),
        evidence=read.evidence,
        safety_notes=[],
        uncertainty=[read.uncertainty] if read.uncertainty else [],
        confidence=read.confidence,
    )


def decision_from_incident_read_v2(
    read_v2: IncidentReadAndWhisperV2,
    *,
    context_pack: dict[str, Any],
    allowed_targets: list[AllowedTarget],
    current_events: list[IncidentEvent],
):
    read_v1 = incident_read_v2_to_incident_read(
        read_v2,
        context_pack=context_pack,
        latest_window_events=current_events,
    )
    decision = decision_from_incident_read(
        read_v1,
        allowed_targets=allowed_targets,
        current_events=current_events,
    )
    return decision.model_copy(
        update={
            "model_metadata": {
                **decision.model_metadata,
                "product_path": "incident_read_and_whisper_v2",
                "incident_state_v2": read_v2.incident_state.model_dump(mode="json"),
                "next_blocker_v2": read_v2.next_blocker.model_dump(mode="json"),
                "whisper_v2": read_v2.whisper.model_dump(mode="json"),
            }
        }
    ), read_v1


def evaluate_incident_read_v2_quality(
    *,
    read_v2: IncidentReadAndWhisperV2 | None,
    diagnosis_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if read_v2 is None:
        return {
            "product_path": "incident_read_and_whisper_v1_legacy",
            "safety_status": "unknown",
            "usefulness_status": "unknown",
            "state_quality_status": "unknown",
            "parser_quality_status": "unknown",
            "likely_failure_category": "none",
            "failed_reasons": [],
            "warnings": [],
        }
    diagnosis_summary = diagnosis_summary or {}
    likely_failure = str(diagnosis_summary.get("likely_failure_category") or "none")
    whisper = read_v2.whisper
    say_this = whisper.say_this or ""
    selected_target = _canonical_display_name(whisper.selected_target_display_name, [])
    failed: list[str] = []
    warnings: list[str] = []
    if selected_target and is_pseudo_target_name(selected_target):
        failed.append("selected_target_is_pseudo_author")
    if selected_target and selected_target != selected_target.strip(".,:;"):
        warnings.append("selected_target_had_trailing_punctuation")
    if whisper.selected_move != "no_safe_recommendation" and not re.search(
        r"\b(can you|could you|please|confirm|share|provide|what signal|whether)\b|\?",
        say_this,
        re.I,
    ):
        failed.append("visible_output_is_not_direct_ask")
    if re.search(r"\btrust post\b", say_this, re.I) and any(
        "trust post no need" in _norm(item) or "no trust post" in _norm(item)
        for item in [*read_v2.incident_state.do_not_ask, *[q.answer_summary for q in read_v2.incident_state.answered_questions]]
    ):
        failed.append("trust_post_ask_after_answer")
    say_tokens = _tokens(say_this)
    for question in read_v2.incident_state.open_questions:
        asked_by = _key(question.asked_by)
        if not asked_by or _key(selected_target) != asked_by:
            continue
        overlap = say_tokens & _tokens(question.question_text)
        asked_to_keys = {_key(item) for item in question.asked_to if item}
        if len(overlap) >= 3 and (not asked_to_keys or asked_by not in asked_to_keys):
            failed.append("ask_the_asker_repeated_question")
            break
    for question in read_v2.incident_state.answered_questions:
        overlap = say_tokens & _tokens(question.question_text)
        if len(overlap) >= 4 and not _answered_question_repeat_allowed(
            question,
            say_this=say_this,
            selected_target=selected_target,
        ):
            failed.append("visible_output_repeats_answered_question")
            break
    state_has_content = bool(
        read_v2.incident_state.active_humans
        or read_v2.incident_state.active_teams
        or read_v2.incident_state.open_questions
        or read_v2.incident_state.diagnostic_signals
        or read_v2.incident_state.latest_human_updates
    )
    parser_status = "degraded" if likely_failure != "none" else "pass"
    state_status = "pass" if state_has_content else "degraded"
    usefulness_status = "fail" if failed else ("degraded" if likely_failure != "none" else "pass")
    return {
        "product_path": "incident_read_and_whisper_v2",
        "safety_status": "pass",
        "usefulness_status": usefulness_status,
        "state_quality_status": state_status,
        "parser_quality_status": parser_status,
        "likely_failure_category": likely_failure,
        "failed_reasons": failed,
        "warnings": warnings,
        "blocker_type": read_v2.next_blocker.blocker_type,
        "selected_target_display_name": selected_target,
        "selected_target_type": read_v2.next_blocker.best_target_type,
        "target_reason": read_v2.next_blocker.best_target_reason,
        "state_summary": {
            "incident_commander": read_v2.incident_state.incident_commander,
            "reporters": read_v2.incident_state.reporters[:5],
            "support_contacts": read_v2.incident_state.support_contacts[:5],
            "active_humans": read_v2.incident_state.active_humans[:8],
            "active_teams": read_v2.incident_state.active_teams[:8],
            "open_question_count": len(read_v2.incident_state.open_questions),
            "answered_question_count": len(read_v2.incident_state.answered_questions),
            "do_not_ask": read_v2.incident_state.do_not_ask[:8],
        },
        "rejected_targets": [item.model_dump(mode="json") for item in read_v2.next_blocker.rejected_targets[:8]],
    }
