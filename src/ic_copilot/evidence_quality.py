from __future__ import annotations

import re
from collections import Counter
from typing import Any

from ic_copilot.schemas import (
    AllowedTarget,
    BriefQualityResult,
    EventQuality,
    IncidentBrief,
    IncidentEvent,
    SemanticQuality,
)


BOT_OR_SYSTEM_NAMES = {
    "anantha app",
    "app",
    "database-agent",
    "database_agent",
    "default_agent",
    "grafana alert",
    "im-agent",
    "incident-trust-post-notification",
    "jira cloud",
    "pagerduty",
    "slackbot",
    "zoom",
    "zsrebot",
    "zsrebotstg",
    "zsrebot stg",
}

PREVIEW_CARD_TERMS = (
    "preview in slack",
    "incident in pagerduty",
    "pagerduty",
    "jira cloud",
    "zoom app",
    "join to slack channel",
    "open in ",
    "refresh",
)

LIFECYCLE_TERMS = (
    "created the channel",
    "created channel",
    "added ",
    "joined the channel",
    "left the channel",
    "pinned ",
    "renamed the channel",
    "set the channel topic",
    "workflow terminated",
)

TABLE_PREFIXES = ("|", "+---", "---", "===", "```")
TABLE_LABELS = {
    "actions taken",
    "action items",
    "average",
    "assignee",
    "audit logs",
    "awaiting sre",
    "call",
    "checkpoint",
    "command",
    "current status",
    "current update",
    "cpu usage",
    "cpu_usage",
    "customer id",
    "customer name",
    "environment",
    "error",
    "findings",
    "fix vulnerability",
    "heavy database load",
    "impact",
    "impact summary",
    "issue",
    "issue priority",
    "issue start time",
    "issue status",
    "jira cloud",
    "key observations",
    "meeting id",
    "next actions",
    "next action",
    "number of pending messages",
    "owners",
    "pagerduty",
    "pid",
    "potential risk",
    "priority",
    "processlist_db",
    "processlist_id",
    "processlist_user",
    "queue name",
    "reasoning for escalation",
    "reference links",
    "recommended actions",
    "re-evaluate severity",
    "related incidents",
    "refresh",
    "roles",
    "root cause",
    "rotate credentials",
    "severity",
    "shard detail",
    "services impacted",
    "status",
    "teams involved",
    "tenants impacted",
    "tenant running the queries",
    "the disclosed secrets include",
    "thread_id",
    "tid",
    "total error call",
    "total queries running",
    "total zdp queries running",
    "urgency",
}
LOG_OR_CODE_TERMS = (
    "exception",
    "stack trace",
    "thread_id",
    "processlist",
    "select ",
    "insert ",
    "ora-",
    "error:",
    "traceback",
)
HUMAN_DIAGNOSTIC_SIGNAL_TERMS = (
    "connection to node -1",
    "broker may not be available",
    "producer clientid",
    "notary-message-producer",
    "notary event worker",
    "pod can connect",
    "can connect to kafka",
    "curl connected",
    "connected to speed-racer-kafka",
    "connected to kafka",
    "kafka broker",
    "runtime config",
    "service config",
    "feature flag",
    "cert",
    "certificate",
)
DB_DIAGNOSTIC_SIGNAL_TERMS = (
    "cpubusypercent",
    "threshold > 90",
    "cpu / memory",
    "database cpu",
    "db cpu",
    "replication lag",
    "cpu & memory snapshot",
    "shard dune jobs",
    "database_agent",
    "database agent",
    "self-checking workflow",
    "engaging self-checking workflow",
)
QUESTION_TERMS = ("?", "can you", "could you", "please confirm", "confirm if", "confirm whether")
VALIDATION_TERMS = ("validate", "validation", "monitor", "monitoring", "stable", "still failing", "still seeing")
MITIGATION_TERMS = (
    "mitigate",
    "mitigation",
    "rollback",
    "disable",
    "restart",
    "restarted",
    "deploy",
    "hotfix",
    "fix",
    "workaround",
)
STATUS_TERMS = ("checking", "investigating", "status", "eta", "blocked", "next action", "owner", "await")
GENERATED_SUMMARY_TERMS = (
    "latest blocker is unclear",
    "semantic ledgers",
    "generated summary",
    "recommended ic focus",
)


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _compact_name(value: str | None) -> str:
    return _norm(value).strip(":")


def _looks_like_table_or_label(text: str, author: str | None = None) -> bool:
    stripped = text.strip()
    first_line = stripped.splitlines()[0] if stripped else ""
    if first_line.startswith(TABLE_PREFIXES):
        return True
    author_norm = _compact_name(author)
    if author_norm in TABLE_LABELS:
        return True
    if stripped.startswith(("🚀", "🔴", "🟡", ":robot:", ":check-img:", ":alert_red:")):
        return True
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_ /-]{1,40}:\s*.*", first_line):
        label = _compact_name(first_line.split(":", 1)[0])
        if label in TABLE_LABELS:
            return True
    lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    tableish = sum(1 for line in lines if line.startswith("|") or re.search(r"\s{2,}\S+\s{2,}", line))
    return tableish >= 3


def _looks_like_log_or_code(text: str) -> bool:
    lowered = _norm(text)
    if any(term in lowered for term in LOG_OR_CODE_TERMS):
        return True
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) >= 4:
        symbol_dense = sum(1 for line in lines if len(re.findall(r"[{}()[\\];=<>]", line)) >= 2)
        if symbol_dense >= 2:
            return True
    return False


def _looks_like_human_diagnostic_evidence(text: str) -> bool:
    lowered = _norm(text)
    if not any(term in lowered for term in HUMAN_DIAGNOSTIC_SIGNAL_TERMS):
        return False
    return any(term in lowered for term in ("kafka", "broker", "producer", "pod", "cert", "config"))


def _looks_like_diagnostic_evidence(text: str) -> bool:
    lowered = _norm(text)
    if _looks_like_human_diagnostic_evidence(text):
        return True
    if any(term in lowered for term in DB_DIAGNOSTIC_SIGNAL_TERMS):
        return True
    if re.search(r"\bdb[a-z0-9.-]+\.zuora(?::3306)?\b", lowered):
        return True
    return False


def _looks_like_explicit_work_item_evidence(text: str) -> bool:
    lowered = _norm(text)
    if "(owner:" in lowered:
        return True
    return bool(
        re.search(
            r"(?mi)^\s*(?:[-*•]\s*)?[A-Z][A-Za-z0-9 /&_.-]{2,72}:\s*"
            r"@?[A-Za-z][\w.-]*(?:\s+[A-Za-z][\w.-]*){0,3}\s+"
            r"(?:is|are|will|was|were|has|have)\s+"
            r"(?:contacting|checking|monitoring|validating|investigating|reviewing|coordinating)",
            text,
        )
    )


def classify_event_quality(event: IncidentEvent) -> EventQuality:
    tokens = event.extracted_tokens or {}
    author = event.author or ""
    author_norm = _norm(author)
    text = event.message or ""
    text_norm = _norm(text)
    combined = f"{author_norm}\n{text_norm}"
    reasons: list[str] = []
    author_type = "unknown"
    if tokens.get("is_system"):
        author_type = "system"
    elif tokens.get("is_bot") or author_norm in BOT_OR_SYSTEM_NAMES:
        author_type = "bot"
    elif author:
        author_type = "human"

    event_kind = "unknown"
    evidence_quality = "medium"
    target_source_quality = "medium"
    target_allowed = True
    blocker_allowed = True
    grounding_allowed = True

    if author_type == "human" and _looks_like_diagnostic_evidence(text):
        event_kind = "human_diagnostic_evidence"
        evidence_quality = "high"
        target_source_quality = "high"
        target_allowed = True
        blocker_allowed = True
        grounding_allowed = True
        reasons.append("human-authored diagnostic evidence")
    elif author_type in {"bot", "system"} and _looks_like_diagnostic_evidence(text):
        event_kind = "bot_diagnostic_evidence"
        evidence_quality = "medium"
        target_source_quality = "invalid"
        target_allowed = False
        blocker_allowed = True
        grounding_allowed = True
        reasons.append("bot/system diagnostic evidence can ground facts but not targets")
    elif any(term in combined for term in PREVIEW_CARD_TERMS):
        event_kind = "pagerduty_card" if "pagerduty" in combined else "jira_card" if "jira" in combined else "zoom_card" if "zoom" in combined else "preview_card"
        evidence_quality = "low"
        target_source_quality = "invalid"
        target_allowed = False
        blocker_allowed = False
        grounding_allowed = False
        reasons.append("preview/card metadata is not primary evidence")
    elif any(term in combined for term in LIFECYCLE_TERMS):
        event_kind = "slack_lifecycle"
        evidence_quality = "low"
        target_source_quality = "invalid"
        target_allowed = False
        blocker_allowed = False
        grounding_allowed = False
        reasons.append("Slack lifecycle/system text is not planner grounding")
    elif author_type in {"bot", "system"}:
        event_kind = "bot_system_message"
        evidence_quality = "low"
        target_source_quality = "invalid"
        target_allowed = False
        blocker_allowed = False
        grounding_allowed = False
        reasons.append("bot/system event is not a target source")
    elif _looks_like_table_or_label(text, author):
        if author_type == "human" and _looks_like_explicit_work_item_evidence(text):
            event_kind = "human_diagnostic_evidence"
            evidence_quality = "high"
            target_source_quality = "medium"
            target_allowed = True
            blocker_allowed = True
            grounding_allowed = True
            reasons.append("human explicit work-item evidence")
        else:
            event_kind = "table_header" if _compact_name(author) in TABLE_LABELS else "table_row"
            evidence_quality = "low"
            target_source_quality = "invalid"
            target_allowed = False
            blocker_allowed = False
            grounding_allowed = False
            reasons.append("table/key-value label is not target or blocker evidence")
    elif _looks_like_log_or_code(text):
        event_kind = "log_or_code_block"
        evidence_quality = "low"
        target_source_quality = "invalid"
        target_allowed = False
        blocker_allowed = False
        grounding_allowed = False
        reasons.append("log/code block is diagnostic evidence only")
    elif any(term in combined for term in GENERATED_SUMMARY_TERMS):
        event_kind = "generated_summary_fragment"
        evidence_quality = "invalid"
        target_source_quality = "invalid"
        target_allowed = False
        blocker_allowed = False
        grounding_allowed = False
        reasons.append("generated fallback summary is not current evidence")
    elif author_type == "human":
        if any(term in text_norm for term in QUESTION_TERMS):
            event_kind = "human_question"
        elif any(term in text_norm for term in VALIDATION_TERMS):
            event_kind = "human_validation_or_monitoring"
        elif any(term in text_norm for term in MITIGATION_TERMS):
            event_kind = "human_mitigation_or_action"
        elif any(term in text_norm for term in STATUS_TERMS):
            event_kind = "human_status_update"
        else:
            event_kind = "human_operator_message"
        evidence_quality = "high"
        target_source_quality = "high"
        target_allowed = True
        blocker_allowed = True
        grounding_allowed = True
        reasons.append("human/operator evidence")
    else:
        event_kind = "low_signal_noise"
        evidence_quality = "low"
        target_source_quality = "low"
        target_allowed = False
        blocker_allowed = False
        grounding_allowed = False
        reasons.append("untrusted or low-signal event source")

    return EventQuality(
        event_id=event.event_id,
        sequence=event.sequence,
        author=event.author,
        author_type=author_type,  # type: ignore[arg-type]
        event_kind=event_kind,  # type: ignore[arg-type]
        evidence_quality=evidence_quality,  # type: ignore[arg-type]
        target_source_quality=target_source_quality,  # type: ignore[arg-type]
        is_target_source_allowed=target_allowed,
        is_blocker_evidence_allowed=blocker_allowed,
        is_planner_grounding_allowed=grounding_allowed,
        reasons=reasons,
    )


def classify_events_quality(events: list[IncidentEvent]) -> list[EventQuality]:
    return [classify_event_quality(event) for event in events]


def event_quality_by_id(event_quality: list[EventQuality]) -> dict[str, EventQuality]:
    return {quality.event_id: quality for quality in event_quality}


def event_quality_summary(event_quality: list[EventQuality]) -> dict[str, Any]:
    kinds = Counter(quality.event_kind for quality in event_quality)
    return {
        "events": len(event_quality),
        "human_operator_events": sum(1 for quality in event_quality if quality.event_kind.startswith("human_")),
        "bot_system_events": kinds["bot_system_message"] + kinds["bot_summary"] + kinds["slack_lifecycle"],
        "bot_diagnostic_events": kinds["bot_diagnostic_evidence"],
        "preview_card_events": kinds["preview_card"] + kinds["pagerduty_card"] + kinds["jira_card"] + kinds["zoom_card"],
        "log_table_events": kinds["log_or_code_block"] + kinds["table_row"] + kinds["table_header"],
        "planner_grounding_allowed": sum(1 for quality in event_quality if quality.is_planner_grounding_allowed),
        "target_source_allowed": sum(1 for quality in event_quality if quality.is_target_source_allowed),
        "event_kinds": dict(kinds),
    }


def target_quality_summary(allowed_targets: list[AllowedTarget]) -> dict[str, int]:
    counts = Counter(target.target_quality for target in allowed_targets)
    counts["high_or_medium_targetable"] = sum(
        1 for target in allowed_targets if target.targetable and target.target_quality in {"high", "medium"}
    )
    counts["rejected_total"] = sum(1 for target in allowed_targets if not target.targetable or target.target_quality == "rejected")
    return dict(counts)


def assess_semantic_quality(
    semantic_read_result: Any,
    events: list[IncidentEvent],
    allowed_targets: list[AllowedTarget],
) -> SemanticQuality:
    qualities = classify_events_quality(events)
    successful_readers: list[str] = []
    for name in ("clean_turn_ledger", "actor_workstream_ledger", "incident_fact_ledger", "question_intent_ledger"):
        if getattr(semantic_read_result, name, None) is not None:
            successful_readers.append(name)
    failed_readers = sorted((getattr(semantic_read_result, "errors", None) or {}).keys())
    major_success = [name for name in successful_readers if name != "question_intent_ledger"]
    question_only = successful_readers == ["question_intent_ledger"]
    summary = event_quality_summary(qualities)
    human_count = int(summary["human_operator_events"])
    preview_count = int(summary["preview_card_events"])
    target_summary = target_quality_summary(allowed_targets)
    reasons: list[str] = []
    warnings: list[str] = []
    if question_only:
        reasons.append("question_intent_ledger alone is not enough for a normal recommendation")
    if not major_success:
        reasons.append("no major semantic reader succeeded")
    if human_count <= 0:
        reasons.append("no clean current human/operator evidence in latest window")
    if len(failed_readers) >= 2:
        warnings.append("multiple semantic readers failed")
    if not target_summary.get("high_or_medium_targetable", 0):
        warnings.append("no high/medium targetable candidates")

    required_reader_success = bool(major_success)
    can_plan = required_reader_success and human_count > 0 and not question_only
    status = "sufficient" if can_plan and not failed_readers else "degraded" if can_plan else "insufficient"
    blocker_quality = "high" if human_count else "low" if preview_count else "invalid"
    return SemanticQuality(
        status=status,  # type: ignore[arg-type]
        can_plan=can_plan,
        can_render_normal_recommendation=can_plan,
        failed_readers=failed_readers,
        successful_readers=successful_readers,
        required_reader_success=required_reader_success,
        question_only_success=question_only,
        human_operator_evidence_count=human_count,
        preview_card_evidence_count=preview_count,
        blocker_evidence_quality=blocker_quality,  # type: ignore[arg-type]
        target_quality_summary=target_summary,
        reasons=reasons,
        warnings=warnings,
    )


def _generated_or_preview_text(value: str) -> bool:
    normalized = _norm(value)
    return any(term in normalized for term in (*GENERATED_SUMMARY_TERMS, *PREVIEW_CARD_TERMS))


def validate_incident_brief_quality(
    brief: IncidentBrief | None,
    events: list[IncidentEvent],
    allowed_targets: list[AllowedTarget],
    semantic_quality: SemanticQuality | None,
) -> BriefQualityResult:
    if brief is None:
        return BriefQualityResult(
            passed=False,
            status="invalid",
            blocked_reasons=["IncidentBrief missing"],
        )
    qualities = event_quality_by_id(classify_events_quality(events))
    blocked: list[str] = []
    warnings: list[str] = []
    if semantic_quality is not None and not semantic_quality.can_plan:
        blocked.append("semantic quality is insufficient for normal planning")
    if _generated_or_preview_text(brief.current_summary):
        blocked.append("current summary is generated/preview-card text")
    summary_quality = "medium"
    if brief.current_summary and not _generated_or_preview_text(brief.current_summary):
        summary_quality = "high"
    else:
        summary_quality = "invalid"

    blocker = brief.latest_blocker
    blocker_quality = "invalid"
    if blocker.blocker_type == "unknown":
        blocked.append("latest blocker is unknown")
    if not blocker.evidence_ids:
        blocked.append("latest blocker has no evidence IDs")
    blocker_evidence = [qualities.get(event_id) for event_id in blocker.evidence_ids]
    blocker_human = [quality for quality in blocker_evidence if quality and quality.is_blocker_evidence_allowed]
    blocker_noise = [quality for quality in blocker_evidence if quality and not quality.is_blocker_evidence_allowed]
    if blocker.evidence_ids and not blocker_human:
        blocked.append("latest blocker is not grounded in human/operator evidence")
    if blocker_noise and not blocker_human:
        blocked.append("latest blocker evidence is preview/card/log/table/system only")
    if blocker_human:
        blocker_quality = "high"
    elif blocker_noise:
        blocker_quality = "low"

    target_by_id = {target.target_id: target for target in allowed_targets}
    referenced_ids = set(brief.recommended_ic_focus.preferred_target_ids)
    for role in brief.role_candidates:
        target = target_by_id.get(role.target_id)
        if target is not None and (not target.targetable or target.target_quality in {"low", "rejected"}):
            warnings.append(f"low-quality role candidate ignored for planning: {target.display_name}")
    for workstream in brief.active_workstreams:
        referenced_ids.update(workstream.owner_target_ids)
    target_quality = "high"
    for target_id in referenced_ids:
        target = target_by_id.get(target_id)
        if target is None:
            blocked.append(f"IncidentBrief references unknown target_id: {target_id}")
            target_quality = "invalid"
        elif not target.targetable or target.target_quality in {"low", "rejected"}:
            blocked.append(f"IncidentBrief references low/rejected target: {target.display_name}")
            target_quality = "low"
    if not referenced_ids:
        warnings.append("IncidentBrief has no preferred/role target references")
        target_quality = "medium"

    status = "high"
    if blocked:
        status = "invalid" if any("missing" in reason or "unknown" in reason for reason in blocked) else "low"
    elif warnings:
        status = "medium"
    return BriefQualityResult(
        passed=not blocked,
        status=status,  # type: ignore[arg-type]
        current_summary_quality=summary_quality,  # type: ignore[arg-type]
        latest_blocker_quality=blocker_quality,  # type: ignore[arg-type]
        target_reference_quality=target_quality,  # type: ignore[arg-type]
        blocked_reasons=blocked,
        warnings=warnings,
    )
