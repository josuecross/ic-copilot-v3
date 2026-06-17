from __future__ import annotations

import re
from urllib.parse import urlparse

from ic_copilot.evidence_quality import classify_event_quality
from ic_copilot.llm.base import LLMClient
from ic_copilot.schema_repair import validate_with_repair
from ic_copilot.work_items import extract_current_work_items
from ic_copilot.schemas import (
    ActionRecord,
    AllowedTarget,
    CleanContextBlocker,
    CleanContextEntity,
    CleanContextValue,
    CleanIncidentContext,
    CleanQuestionLedger,
    CleanRejectedEntity,
    CommandRegistryEntry,
    CurrentIncidentState,
    EntityRef,
    EntityType,
    EvidenceBackedFact,
    EvidenceRef,
    ICMove,
    ImpactState,
    IncidentBrief,
    IncidentBriefBlocker,
    IncidentBriefCompletedAction,
    IncidentBriefDoNotAsk,
    IncidentBriefEntity,
    IncidentBriefFocus,
    IncidentBriefRejectedOrNoise,
    IncidentBriefRoleCandidate,
    IncidentBriefUncertainty,
    IncidentBriefValue,
    IncidentBriefWorkstream,
    IncidentEvent,
    IncidentPhase,
    InputSizeAssessment,
    QuestionRecord,
    RoleCandidate,
    ServiceCatalogEntry,
    SharpBlockerAssessment,
    StateDelta,
    TargetShortlistItem,
    VisibleWorkstream,
)


NOISE_NAMES = {
    "anantha app",
    "app",
    "daco-bot",
    "database-agent",
    "default_agent",
    "grafana alert",
    "im-agent",
    "incident-trust-post-notification",
    "phase update",
    "incident assessment",
    "just to confirm",
    "jira cloud",
    "preview in slack",
    "pinned by",
    "show more",
    "added by zsrebot",
    "zsrebot",
    "zsrebotstg",
    "slackbot",
}
NON_TARGETABLE_LABELS = {
    "@channel",
    "@here",
    "actions taken",
    "action items",
    "average",
    "assignee",
    "audit logs",
    "awaiting sre",
    "call",
    "channel",
    "checkpoint",
    "command",
    "current status",
    "current update",
    "cpu utilization",
    "cpu_usage",
    "customer id",
    "customer name",
    "active",
    "batchcount",
    "comment",
    "createdon",
    "dedicated_topic",
    "dedicatedcluster",
    "dedicatedtopic",
    "dedicatedtopiccount",
    "docs",
    "environment",
    "envirovmentvariables",
    "error",
    "expiry",
    "findings",
    "fix vulnerability",
    "heavy database load",
    "incident commander",
    "here",
    "impact",
    "impact summary",
    "issue",
    "issue priority",
    "issue start time",
    "issue status",
    "jira cloud",
    "key observations",
    "meeting id",
    "monitor workers",
    "monitoring plan",
    "next actions",
    "next action",
    "number of pending messages",
    "open",
    "owners",
    "pagerduty",
    "pid",
    "potential risk",
    "priority",
    "processlist",
    "processlist db",
    "processlist id",
    "processlist user",
    "queue name",
    "reasoning for escalation",
    "reference links",
    "recommended actions",
    "recordfromcache",
    "recordfromdb",
    "rediskeys",
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
    "summary",
    "teams involved",
    "tenants impacted",
    "tenant running the queries",
    "tenantid",
    "the disclosed secrets include",
    "thread id",
    "thread_id",
    "tid",
    "total error call",
    "total queries running",
    "total zdp queries running",
    "topicname",
    "topicnumber",
    "trust post",
    "ttl",
    "urgency",
    "updatedby",
    "updatedon",
    "what caused the previous incident",
    "what fix/mitigation worked",
}
NON_TARGETABLE_CONTAINS = (
    "actions taken",
    "current status",
    "cpu utilization",
    "customer id",
    "customer name",
    "dedicated_topic",
    "heavy database load",
    "impact summary",
    "fix vulnerability",
    "issue priority",
    "issue start time",
    "key observations",
    "load average",
    "meeting id",
    "monitoring plan",
    "next actions",
    "next action",
    "owners",
    "processlist",
    "query check",
    "reasoning for escalation",
    "reference links",
    "root cause",
    "rotate credentials",
    "services impacted",
    "teams involved",
    "tenants impacted",
    "total queries",
    "total zdp queries",
)
NON_TARGETABLE_PREFIXES = (":alert_red:", ":check-img:", ":robot:", "|", "+---", "---", "===", "🚀", "🔴", "🟡")
TECHNICAL_HINTS = (
    "checking",
    "investigating",
    "logs",
    "error",
    "dashboard",
    "dashboards",
    "metric",
    "metrics",
    "query",
    "lookup",
    "shard",
    "tenant",
    "health check",
    "restart",
    "restarted",
    "connection",
    "limit",
    "package",
    "version",
    "rollback",
    "disable",
    "mitigation",
    "monitor",
    "monitoring",
    "status",
    "eta",
)
VALIDATION_HINTS = (
    "validate",
    "validation",
    "testing",
    "still running",
    "customer application",
    "application is responding",
    "still seeing",
    "reported",
    "zendesk",
    "ticket",
    "trust post",
)
COORDINATION_HINTS = ("ic", "incident commander", "page team", "paged", "oncall", "adding", "routing")


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _safe_id(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", _norm(value)).strip("-")[:48]


def _event_text(event: IncidentEvent) -> str:
    return f"{event.author or ''}\n{event.message}"


def _target_rejection_reason(name: str, *, source: str, catalog_confirmed: bool = False, from_bot: bool = False) -> str | None:
    stripped = " ".join(str(name).split())
    normalized = _norm(stripped)
    if not stripped:
        return "empty target"
    if catalog_confirmed:
        return None
    if from_bot and source in {"slack_author", "current_evidence"}:
        return "Bot/system message author is not targetable"
    if normalized in NOISE_NAMES:
        return "Bot/system placeholder is not targetable"
    if normalized.startswith("just to confirm"):
        return "Question prefix is not targetable"
    if re.match(r"^\d+\s+files?\b", normalized):
        return "File label is not targetable"
    if "response we would see this" in normalized:
        return "Generated summary fragment is not targetable"
    if re.match(r"^@?[a-z][\w .-]{1,80}\s+as reported here\b", normalized):
        return "Quoted mention prefix is not targetable"
    if re.match(r"^srebot[a-z0-9_.-]+$", normalized):
        return "Fused bot/person string is not targetable"
    if _looks_like_json_or_diagnostic_key(stripped):
        return "JSON/log diagnostic key is not targetable"
    if stripped.startswith(NON_TARGETABLE_PREFIXES):
        return "Table/log/header fragment is not targetable"
    label = normalized.strip(":")
    if label in NON_TARGETABLE_LABELS:
        return "Diagnostic/key-value label is not targetable"
    if any(term in normalized for term in NON_TARGETABLE_CONTAINS):
        return "Diagnostic/table fragment is not targetable"
    if source in {"slack_author", "current_evidence", "explicit_mention"}:
        stripped_label = re.sub(r"^\s*(?:[-*•]|\d+\.)\s*", "", stripped).strip().strip(":")
        normalized_label = _norm(stripped_label)
        if normalized_label in NON_TARGETABLE_LABELS:
            return "Generated summary heading is not targetable"
    if "(owner:" in normalized or re.match(r"^[A-Z][A-Za-z0-9 /&_.-]{2,72}:\s*\(Owner:", stripped):
        return "Owner/action label is not a direct target"
    if normalized in {"here", "@here", "channel", "@channel"}:
        return "Broadcast mention is not a person/team target"
    if normalized in {"the team", "team"}:
        return "Generic team phrase is not targetable"
    if re.match(r"^\d+\.\s+", stripped):
        return "Numbered section heading is not targetable"
    if re.fullmatch(r"(?:ap\s+)?(?:prod|production|sandbox|csbx|qa|stage|stg|dev)\s*\d*", normalized):
        return "Environment/shard label is not targetable"
    if re.fullmatch(r"(?:prod|csbx|sandbox|stage|stg|dev)\d{1,5}", normalized):
        return "Environment/shard label is not targetable"
    if source in {"slack_author", "current_evidence", "explicit_mention"} and normalized.endswith(
        (" investigation", " status", " impact", " update")
    ):
        if not any(term in normalized for term in (" team", " engineering", " support", " sre", " ops")):
            return "Section heading is not targetable"
    if "ticket created" in normalized:
        return "Ticket status fragment is not targetable"
    if any(term in normalized for term in ("preview in slack", "please join to slack channel")):
        return "Preview/card fragment is not targetable"
    if re.fullmatch(r"\d+", stripped):
        return "Numeric operational ID is not targetable"
    if re.fullmatch(r"P[A-Z0-9]{5,}", stripped):
        return "Policy/incident ID alone is not targetable"
    if "escalation policy" in normalized and re.search(r"\bP[A-Z0-9]{5,}\b", stripped):
        return "Bot policy option line is not targetable"
    if re.fullmatch(r"[A-Z]+-\d+", stripped, re.I):
        return "Ticket/Jira ID is not targetable"
    if re.search(r"\.(?:png|jpe?g|gif|webp|txt|log)$", stripped, re.I):
        return "File/image name is not targetable"
    if len(stripped.split()) > 8:
        return "Generated sentence fragment is not targetable"
    if stripped.endswith("(Owner") or stripped.endswith("(owner"):
        return "Chopped owner fragment is not targetable"
    if source == "current_evidence" and any(marker in normalized for marker in ("owner:", "summary:", "status:")):
        return "Generated summary/key fragment is not targetable"
    return None


JSON_OR_DIAGNOSTIC_KEY_RE = re.compile(
    r"""^\s*
    ["'{]*
    (?P<key>[A-Za-z_][A-Za-z0-9_.-]{1,64})
    ["'}]*
    \s*(?::.*)?$""",
    re.VERBOSE,
)
JSON_OR_DIAGNOSTIC_KEYS = {
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


def _looks_like_json_or_diagnostic_key(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    if stripped.startswith(("{", "[", "}", "]")) and ":" in stripped:
        return True
    match = JSON_OR_DIAGNOSTIC_KEY_RE.match(stripped)
    if not match:
        return False
    key = _norm(match.group("key")).replace(" ", "_")
    if key in JSON_OR_DIAGNOSTIC_KEYS:
        return True
    return ":" in stripped and bool(re.search(r"[A-Z_]", match.group("key"))) and len(key.split()) == 1


def _diagnostic_keys_in_text(text: str) -> list[str]:
    keys: list[str] = []
    for match in re.finditer(r"""["']?(?P<key>[A-Za-z_][A-Za-z0-9_.-]{1,64})["']?\s*:""", text):
        key = match.group("key")
        if _looks_like_json_or_diagnostic_key(f"{key}:"):
            keys.append(key)
    return list(dict.fromkeys(keys))[:12]


def _role_hint_for_text(name: str, text: str) -> str:
    text_norm = _norm(f"{name}\n{text}")
    name_norm = _norm(name)
    if name_norm in NOISE_NAMES:
        return "unknown"
    if name_norm in {"ic", "dm", "duty manager", "incident commander", "incident manager"}:
        return "ic_or_coordinator"
    if any(term in text_norm for term in COORDINATION_HINTS):
        return "ic_or_coordinator"
    if any(term in text_norm for term in VALIDATION_HINTS):
        return "reporter_or_validator"
    if any(term in text_norm for term in TECHNICAL_HINTS):
        return "technical_investigator"
    if "support" in text_norm:
        return "support_team"
    if "team" in text_norm or "engineering" in text_norm or "owner" in text_norm:
        return "owner_team"
    return "unknown"


def _is_generic_synthetic_target(name: str) -> bool:
    normalized = _norm(name)
    return normalized in {
        "investigation team",
        "active owner",
        "active investigation owner",
        "technical owner",
        "technical dri",
        "owner",
        "dri",
        "team",
    }


def _target_role_from_brief(target: AllowedTarget, brief: IncidentBrief | None) -> str:
    if brief is None:
        return target.role_hint
    for candidate in brief.role_candidates:
        if candidate.target_id == target.target_id and candidate.role_hint != "unknown":
            return candidate.role_hint
    return target.role_hint


def _latest_evidence_ids(target: AllowedTarget, event_order: dict[str, int], limit: int = 3) -> list[str]:
    return sorted(
        list(dict.fromkeys(target.evidence_ids)),
        key=lambda event_id: event_order.get(event_id, -1),
        reverse=True,
    )[:limit]


def build_target_shortlist(
    allowed_targets: list[AllowedTarget],
    brief: IncidentBrief | None,
    events: list[IncidentEvent],
    *,
    max_targets: int = 8,
) -> list[TargetShortlistItem]:
    """Rank targetable current-evidence/catalg candidates for planner input.

    This is target safety/ranking only. It does not infer incident facts or choose the IC move.
    """
    event_order = {event.event_id: index for index, event in enumerate(events)}
    latest_ids = {event.event_id for event in events[-12:]}
    context = _norm(
        " ".join(
            (
                brief.current_summary if brief else "",
                brief.latest_blocker.summary if brief else "",
                brief.recommended_ic_focus.summary if brief else "",
            )
        )
    )
    blocker = brief.latest_blocker.blocker_type if brief else "unknown"
    preferred_order = {
        target_id: index for index, target_id in enumerate(brief.recommended_ic_focus.preferred_target_ids if brief else [])
    }
    role_by_id = {candidate.target_id: candidate.role_hint for candidate in (brief.role_candidates if brief else [])}
    workstream_owner_ids = {
        target_id
        for workstream in (brief.active_workstreams if brief else [])
        if workstream.status in {"active", "waiting", "blocked", "unknown"}
        for target_id in workstream.owner_target_ids
    }
    technical_blockers = {
        "status_eta_needed",
        "monitoring_needed",
        "mitigation_status_needed",
        "validation_needed",
        "code_fix_status_needed",
        "deployment_validation_needed",
        "waiting_on_active_work",
    }
    scored: list[tuple[float, int, TargetShortlistItem]] = []
    has_latest_human_target = any(
        target.targetable
        and target.target_quality in {"high", "medium"}
        and target.source in {"slack_author", "explicit_mention", "current_evidence"}
        and any(event_id in latest_ids for event_id in target.evidence_ids)
        for target in allowed_targets
    )
    for index, target in enumerate(allowed_targets):
        if not target.targetable or target.target_type in {"bot_system", "non_targetable_noise"}:
            continue
        if target.target_quality in {"low", "rejected"}:
            continue
        if target.source_event_kind in {
            "preview_card",
            "pagerduty_card",
            "jira_card",
            "zoom_card",
            "slack_lifecycle",
            "log_or_code_block",
            "table_row",
            "table_header",
            "generated_summary_fragment",
        }:
            continue
        if _norm(target.display_name) in NOISE_NAMES:
            continue
        role = role_by_id.get(target.target_id, target.role_hint)
        evidence_ids = _latest_evidence_ids(target, event_order)
        latest_rank = max((event_order.get(event_id, -1) for event_id in evidence_ids), default=-1)
        score = 0.0
        reasons: list[str] = []
        breakdown: dict[str, float] = {}
        penalties: list[str] = []
        if target.target_id in preferred_order:
            preferred_score = 80 - preferred_order[target.target_id] * 3
            if target.source in {"catalog", "service_alias", "command_registry"} and not evidence_ids:
                preferred_score = min(preferred_score, 25)
                penalties.append("catalog preferred target has no direct current-event evidence")
            score += preferred_score
            breakdown["incident_brief_preferred"] = preferred_score
            reasons.append("IncidentBrief preferred target")
        if target.target_id in workstream_owner_ids:
            score += 38
            breakdown["active_workstream_owner"] = 38
            reasons.append("active workstream owner")
        if evidence_ids:
            score += 18
            breakdown["current_evidence"] = 18
            reasons.append("current evidence")
        if any(event_id in latest_ids for event_id in evidence_ids):
            score += 18
            breakdown["latest_window_evidence"] = 18
            reasons.append("latest-window evidence")
        if target.source in {"slack_author", "explicit_mention", "current_evidence"}:
            score += 14
            breakdown["human_or_current_source"] = 14
        elif target.source == "catalog":
            catalog_score = 8 if _norm(target.display_name) in context else 2
            score += catalog_score
            breakdown["catalog_source"] = catalog_score
        elif target.source in {"service_alias", "command_registry"}:
            score -= 8
            penalties.append("service alias/command registry target is not primary actor evidence")
        if blocker in technical_blockers:
            if role == "technical_investigator":
                score += 35
                breakdown["technical_investigator_alignment"] = 35
                reasons.append("technical investigator")
            elif role == "owner_team":
                owner_score = 18 if blocker == "mitigation_status_needed" and target.source in {"catalog", "service_alias"} and not evidence_ids else 26
                score += owner_score
                breakdown["owner_alignment"] = owner_score
                reasons.append("owner candidate")
            elif role == "reporter_or_validator":
                validation_score = 32 if blocker in {"mitigation_status_needed", "validation_needed"} else 16
                score += validation_score
                breakdown["validation_or_customer_actor_alignment"] = validation_score
                reasons.append("validation target")
            elif role == "ic_or_coordinator":
                coordinator_score = 22 if blocker == "mitigation_status_needed" else 8
                score += coordinator_score
                breakdown["coordinator_alignment"] = coordinator_score
            elif role == "support_team":
                if blocker in {"mitigation_status_needed", "validation_needed"}:
                    score += 18
                    breakdown["support_validation_alignment"] = 18
                else:
                    score -= 10
                    penalties.append("support target demoted for technical blocker")
        elif blocker == "customer_scope_needed":
            if role in {"reporter_or_validator", "support_team"}:
                score += 32
                reasons.append("customer/support validation target")
            elif role == "technical_investigator":
                score += 8
        elif blocker == "missing_owner":
            if role == "owner_team":
                score += 36
                reasons.append("owner candidate")
            elif role == "technical_investigator":
                score += 24
            elif role == "ic_or_coordinator":
                score += 12
        if _norm(target.display_name) and _norm(target.display_name) in context:
            score += 10
            breakdown["name_in_brief_context"] = 10
        if target.target_type == "service":
            score -= 4
            penalties.append("service target demoted behind human/team actor")
        if _is_generic_synthetic_target(target.display_name):
            score -= 40
            penalties.append("generic synthetic target demoted")
        if not evidence_ids and target.source in {"service_alias", "command_registry"}:
            score -= 20
            penalties.append("no direct current evidence")
        if has_latest_human_target and target.source in {"catalog", "service_alias", "command_registry"} and not evidence_ids:
            score -= 28
            penalties.append("catalog/team target demoted behind latest human actor")
        if score <= 0:
            continue
        scored.append(
            (
                score,
                -index,
                TargetShortlistItem(
                    target_id=target.target_id,
                    display_name=target.display_name,
                    target_type=target.target_type,
                    role_hint=role,  # type: ignore[arg-type]
                    why_targetable=", ".join(dict.fromkeys(reasons)) or target.reason or "targetable candidate",
                    latest_evidence_ids=evidence_ids,
                    score=round(score, 2),
                    target_quality=target.target_quality,
                    target_score_breakdown=breakdown,
                    target_evidence_age_rank=latest_rank,
                    target_selected_because=", ".join(dict.fromkeys(reasons)) or target.reason or "targetable candidate",
                    target_penalties=penalties,
                    target_role_alignment=role,
                ),
            )
        )
    scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
    if any(not _is_generic_synthetic_target(item.display_name) for _, _, item in scored):
        scored = [entry for entry in scored if not _is_generic_synthetic_target(entry[2].display_name)]
    shortlist = [item for _, _, item in scored[:max_targets]]
    return [item.model_copy(update={"rank": index}) for index, item in enumerate(shortlist, start=1)]


def _target_type_for_catalog(entry: ServiceCatalogEntry) -> str:
    kind = str(getattr(entry.kind, "value", entry.kind))
    if kind == "service":
        return "service"
    if kind == "team":
        return "team"
    return "service"


def build_allowed_targets(
    events: list[IncidentEvent],
    catalog: list[ServiceCatalogEntry],
    command_registry: list[CommandRegistryEntry] | None = None,
) -> list[AllowedTarget]:
    targets: list[AllowedTarget] = []
    by_key: set[tuple[str, str]] = set()

    def add(
        display_name: str,
        target_type: str,
        source: str,
        *,
        targetable: bool,
        evidence_ids: list[str] | None = None,
        reason: str = "",
        role_hint: str = "unknown",
        canonical_id: str | None = None,
        catalog_confirmed: bool = False,
        from_bot: bool = False,
        source_event_kind: str | None = None,
        target_quality: str | None = None,
        raw_display_name: str | None = None,
    ) -> None:
        name = " ".join(str(display_name).split())
        if not name:
            return
        raw_name = raw_display_name or name
        policy_match = re.match(r"^-?\s*(P[A-Z0-9]{5,})\s+(.+?)(?::\s*Escalation Policy)?$", name)
        if policy_match:
            policy_id, policy_target = policy_match.groups()
            raw_display_name = raw_name
            name = policy_target.strip(" -:")
            reason = (reason + "; " if reason else "") + f"Policy ID normalized away: {policy_id}"
            canonical_id = canonical_id or _safe_id(name)
            if "escalation policy" in _norm(raw_name) and not catalog_confirmed:
                targetable = False
                target_quality = "rejected"
        rejection = _target_rejection_reason(
            name,
            source=source,
            catalog_confirmed=catalog_confirmed,
            from_bot=from_bot,
        )
        if rejection:
            target_type = "non_targetable_noise"
            targetable = False
            reason = rejection
            role_hint = "unknown"
        elif not targetable:
            target_type = "non_targetable_noise"
            role_hint = "unknown"
        resolved_quality = target_quality or ("medium" if targetable else "rejected")
        if not targetable:
            resolved_quality = "rejected"
        elif source in {"slack_author", "explicit_mention"} and source_event_kind and source_event_kind.startswith("human_"):
            resolved_quality = "high"
        key = (_norm(name), source)
        if key in by_key:
            for target in targets:
                if _norm(target.display_name) == key[0] and target.source == source:
                    target.evidence_ids[:] = sorted({*target.evidence_ids, *(evidence_ids or [])})
                    existing_rank = {"rejected": 0, "low": 1, "medium": 2, "high": 3}.get(target.target_quality, 0)
                    new_rank = {"rejected": 0, "low": 1, "medium": 2, "high": 3}.get(resolved_quality, 0)
                    if targetable and new_rank >= existing_rank:
                        target.target_quality = resolved_quality  # type: ignore[assignment]
                        target.targetable = targetable
                        target.target_type = target_type  # type: ignore[assignment]
                        target.reason = reason
                        target.rejection_reason = None
                        target.role_hint = role_hint  # type: ignore[assignment]
                        target.source_event_kind = source_event_kind
                        target.normalized_display_name = _norm(name)
                        target.raw_display_name = raw_display_name or display_name
            return
        target_id = f"t{len(targets) + 1:03d}"
        targets.append(
            AllowedTarget(
                target_id=target_id,
                display_name=name,
                target_type=target_type,  # type: ignore[arg-type]
                source=source,  # type: ignore[arg-type]
                role_hint=role_hint,  # type: ignore[arg-type]
                targetable=targetable,
                evidence_ids=evidence_ids or [],
                reason=reason,
                canonical_id=canonical_id,
                target_quality=resolved_quality,  # type: ignore[arg-type]
                source_event_kind=source_event_kind,
                rejection_reason=reason if not targetable else None,
                normalized_display_name=_norm(name),
                raw_display_name=raw_display_name or display_name,
            )
        )
        by_key.add(key)

    for event in events:
        tokens = event.extracted_tokens or {}
        author = (event.author or "").strip()
        quality = classify_event_quality(event)
        is_bot_or_system = (
            bool(tokens.get("is_bot") or tokens.get("is_system"))
            or _norm(author) in NOISE_NAMES
            or quality.author_type in {"bot", "system"}
        )
        if author:
            author_override_allowed = quality.event_kind in {"log_or_code_block", "table_row", "table_header"}
            author_targetable = (not is_bot_or_system) and (
                quality.is_target_source_allowed
                or (
                    quality.author_type == "human"
                    and author_override_allowed
                    and _target_rejection_reason(author, source="slack_author") is None
                )
            )
            author_source_event_kind = (
                quality.event_kind
                if quality.is_target_source_allowed or not author_targetable
                else "human_operator_message"
            )
            add(
                author,
                "bot_system" if is_bot_or_system else "person",
                "slack_author",
                targetable=author_targetable,
                evidence_ids=[event.event_id],
                reason=(
                    "Slack author"
                    if author_targetable
                    else "Event source is not targetable"
                    if not is_bot_or_system
                    else "Bot/system Slack author"
                ),
                role_hint="unknown" if not author_targetable else _role_hint_for_text(author, _event_text(event)),
                from_bot=is_bot_or_system,
                source_event_kind=author_source_event_kind,
                target_quality="high" if author_targetable else "rejected",
                raw_display_name=author,
            )
        for mention in tokens.get("slack_mentions", []):
            mention_text = str(mention)
            mention_norm = _norm(mention_text)
            mention_is_noise = mention_norm in NOISE_NAMES or mention_norm in {"here", "channel", "@here", "@channel"}
            mention_targetable = quality.is_target_source_allowed and not mention_is_noise
            add(
                mention_text,
                "bot_system" if mention_is_noise else "person",
                "explicit_mention",
                targetable=mention_targetable,
                evidence_ids=[event.event_id],
                reason=(
                    "Explicit Slack mention"
                    if mention_targetable
                    else "Broadcast/bot mention is not targetable"
                    if mention_is_noise
                    else "Mention from low-quality evidence is not targetable"
                ),
                role_hint=_role_hint_for_text(mention_text, event.message) if mention_targetable else "unknown",
                from_bot=mention_is_noise,
                source_event_kind=quality.event_kind,
                target_quality="high" if mention_targetable else "rejected",
                raw_display_name=mention_text,
            )
        work_item_owner_source_allowed = (
            not is_bot_or_system
            and quality.event_kind
            not in {
                "bot_system_message",
                "preview_card",
                "pagerduty_card",
                "jira_card",
                "zoom_card",
                "slack_lifecycle",
                "generated_summary_fragment",
            }
        )
        if work_item_owner_source_allowed:
            for item in extract_current_work_items([event]):
                for owner_name in item.get("owner_names", []):
                    add(
                        str(owner_name),
                        "person",
                        "current_evidence",
                        targetable=True,
                        evidence_ids=[event.event_id],
                        reason=f"Explicit work-item owner for {item.get('work_item_label')}",
                        role_hint="technical_investigator",
                        canonical_id=_safe_id(str(owner_name)),
                        source_event_kind=quality.event_kind,
                        target_quality="medium",
                        raw_display_name=str(owner_name),
                    )
                owner_group = str(item.get("owner_group") or "").strip()
                if owner_group and _target_rejection_reason(owner_group, source="current_evidence") is None:
                    add(
                        owner_group,
                        "team",
                        "current_evidence",
                        targetable=True,
                        evidence_ids=[event.event_id],
                        reason=f"Explicit work-item owner group for {item.get('work_item_label')}",
                        role_hint="owner_team",
                        canonical_id=_safe_id(owner_group),
                        source_event_kind=quality.event_kind,
                        target_quality="medium",
                        raw_display_name=owner_group,
                    )
        for url in tokens.get("urls", []):
            parsed = urlparse(str(url))
            for part in parsed.path.split("/"):
                if part.isdigit() and len(part) >= 5:
                    add(
                        part,
                        "non_targetable_noise",
                        "current_evidence",
                        targetable=False,
                        evidence_ids=[event.event_id],
                        reason="URL path number is not a tenant/person/team target",
                        source_event_kind=quality.event_kind,
                        target_quality="rejected",
                        raw_display_name=part,
                    )
        for number in tokens.get("numbers", []):
            value = str(number.get("value", ""))
            context = _norm(str(number.get("context", "")))
            numeric_kind = str(number.get("numeric_evidence_kind") or "")
            if len(value) >= 5 and (
                numeric_kind in {"tenant_id", "ticket_id", "url_path_number", "metric_count_version", "untyped_numeric_id"}
                or any(term in context for term in ("jira", "ticket", "doc", "page", "url", "cm-"))
            ):
                add(
                    value,
                    "non_targetable_noise",
                    "current_evidence",
                    targetable=False,
                    evidence_ids=[event.event_id],
                    reason=f"{numeric_kind or 'Operational ID'} is not a target",
                    source_event_kind=quality.event_kind,
                    target_quality="rejected",
                    raw_display_name=value,
                )
        for noise in ("Default_Agent", "event_category", "Exit code"):
            if noise.lower() in event.message.lower():
                add(
                    noise,
                    "non_targetable_noise",
                    "current_evidence",
                    targetable=False,
                    evidence_ids=[event.event_id],
                    reason="Bot/system/log fragment is not targetable",
                    source_event_kind=quality.event_kind,
                    target_quality="rejected",
                    raw_display_name=noise,
                )
        for diagnostic_key in _diagnostic_keys_in_text(event.message):
            add(
                diagnostic_key,
                "non_targetable_noise",
                "current_evidence",
                targetable=False,
                evidence_ids=[event.event_id],
                reason="JSON/log diagnostic key is not targetable",
                source_event_kind=quality.event_kind,
                target_quality="rejected",
                raw_display_name=diagnostic_key,
            )
        if quality.is_target_source_allowed:
            for match in re.finditer(
                r"\b([A-Z][A-Za-z0-9&/-]+(?:\s+[A-Z][A-Za-z0-9&/-]+){0,3}\s+(?:Support|Engineering|SRE|Ops|Team|team))\b",
                event.message,
            ):
                if is_bot_or_system:
                    continue
                phrase = match.group(1).strip(" .,:;")
                first_word = phrase.split()[0].lower() if phrase.split() else ""
                if _norm(phrase) in NOISE_NAMES or first_word in {"can", "please", "should", "need", "does", "what"}:
                    continue
                add(
                    phrase,
                    "team",
                    "current_evidence",
                    targetable=True,
                    evidence_ids=[event.event_id],
                    reason="Current-evidence team/service phrase",
                    role_hint="support_team" if "support" in _norm(phrase) else "owner_team",
                    canonical_id=_safe_id(phrase),
                    source_event_kind=quality.event_kind,
                    target_quality="medium",
                    raw_display_name=phrase,
                )

    all_text = "\n".join(_event_text(event) for event in events).lower()
    for entry in catalog:
        names = [entry.canonical_name, *entry.aliases, entry.service_id]
        appears = any(_norm(name) and _norm(name) in all_text for name in names)
        source = "catalog" if appears else "service_alias"
        add(
            entry.canonical_name,
            _target_type_for_catalog(entry),
            source,
            targetable=True,
            reason="Catalog entry visible in evidence" if appears else "Catalog/local_knowledge candidate",
            role_hint="owner_team" if _target_type_for_catalog(entry) == "team" else "unknown",
            canonical_id=entry.service_id,
            catalog_confirmed=True,
            target_quality="medium" if appears else "low",
            raw_display_name=entry.canonical_name,
        )
        for owner_key in ("owning_team", "support_team"):
            owner = entry.ownership.get(owner_key)
            if isinstance(owner, str) and owner:
                add(
                    owner,
                    "team",
                    "catalog",
                    targetable=True,
                    reason=f"Catalog {owner_key}",
                    role_hint="support_team" if owner_key == "support_team" else "owner_team",
                    canonical_id=_safe_id(owner),
                    catalog_confirmed=True,
                    target_quality="medium",
                    raw_display_name=owner,
                )
    for command in command_registry or []:
        if command.target and command.target != "*":
            add(
                command.target,
                "team",
                "command_registry",
                targetable=True,
                reason="Command registry target",
                role_hint="owner_team",
                canonical_id=_safe_id(command.target),
                catalog_confirmed=True,
                target_quality="medium",
                raw_display_name=command.target,
            )
    return targets


def augment_allowed_targets_from_state(
    allowed_targets: list[AllowedTarget],
    state: CurrentIncidentState,
) -> list[AllowedTarget]:
    """Add exact state entities so verifier target checks do not depend on Slack display quirks."""
    targets = list(allowed_targets)
    seen = {_norm(target.display_name) for target in targets}

    def next_id() -> str:
        return f"t{len(targets) + 1:03d}"

    def target_type(entity: EntityRef) -> str:
        value = str(getattr(entity.entity_type, "value", entity.entity_type))
        if value in {"person", "team", "service"}:
            return value
        return "non_targetable_noise"

    def role_hint(entity: EntityRef) -> str:
        status = str(entity.status or "").lower()
        entity_type = str(getattr(entity.entity_type, "value", entity.entity_type))
        if entity_type in {"team", "service"}:
            return "owner_team"
        if any(term in status for term in ("working", "active", "investigat", "checking")):
            return "technical_investigator"
        if any(term in status for term in ("validat", "report", "support")):
            return "reporter_or_validator"
        return "unknown"

    for entity in [*state.engaged_entities, *state.suggested_but_not_engaged, *state.candidate_services]:
        name = entity.display_name
        if not name or _norm(name) in seen:
            continue
        kind = target_type(entity)
        rejection = _target_rejection_reason(name, source="current_evidence")
        targetable = kind != "non_targetable_noise" and rejection is None
        targets.append(
            AllowedTarget(
                target_id=next_id(),
                display_name=name,
                target_type=kind if targetable else "non_targetable_noise",  # type: ignore[arg-type]
                source="current_evidence",
                role_hint=role_hint(entity),  # type: ignore[arg-type]
                targetable=targetable,
                evidence_ids=[ref.event_id for ref in entity.evidence],
                reason=rejection or "Current state entity from evidence",
                canonical_id=entity.canonical_id,
                target_quality="medium" if targetable else "rejected",
                rejection_reason=rejection if not targetable else None,
                normalized_display_name=_norm(name),
                raw_display_name=name,
            )
        )
        seen.add(_norm(name))
    return targets


def _target_by_name_or_id(allowed_targets: list[AllowedTarget], value: str | None) -> AllowedTarget | None:
    if not value:
        return None
    value_norm = _norm(value)
    return next(
        (
            target
            for target in allowed_targets
            if target.target_id == value or _norm(target.display_name) == value_norm or _norm(target.canonical_id) == value_norm
        ),
        None,
    )


def _targetable_ids(allowed_targets: list[AllowedTarget]) -> set[str]:
    return {target.target_id for target in allowed_targets if target.targetable}


def _validated_brief_targets(brief: IncidentBrief, allowed_targets: list[AllowedTarget]) -> IncidentBrief:
    allowed_ids = {target.target_id for target in allowed_targets}
    targetable_ids = _targetable_ids(allowed_targets)
    warnings = list(brief.warnings)
    role_candidates = []
    for role in brief.role_candidates:
        if role.target_id in allowed_ids:
            role_candidates.append(role)
        else:
            warnings.append(f"removed role candidate with unallowed target_id: {role.target_id}")
    engaged = [entity for entity in brief.engaged_entities if entity.target_id in allowed_ids]
    workstreams = [
        workstream.model_copy(
            update={"owner_target_ids": [target_id for target_id in workstream.owner_target_ids if target_id in targetable_ids]}
        )
        for workstream in brief.active_workstreams
    ]
    focus = brief.recommended_ic_focus.model_copy(
        update={
            "preferred_target_ids": [
                target_id for target_id in brief.recommended_ic_focus.preferred_target_ids if target_id in targetable_ids
            ]
        }
    )
    return brief.model_copy(
        update={
            "role_candidates": role_candidates,
            "engaged_entities": engaged,
            "active_workstreams": workstreams,
            "recommended_ic_focus": focus,
            "warnings": warnings,
        }
    )


def _blocker_from_state(state: CurrentIncidentState) -> str:
    mapping = {
        "missing_owner": "missing_owner",
        "missing_impact": "customer_scope_needed",
        "missing_validation": "validation_needed",
        "deployment_validation": "deployment_validation_needed",
        "waiting_on_monitoring": "monitoring_needed",
        "waiting_on_code_fix": "code_fix_status_needed",
        "waiting_on_deploy": "deployment_validation_needed",
        "waiting_on_owner_status": "status_eta_needed",
        "waiting_on_mitigation": "mitigation_status_needed",
        "mitigation_status_or_validation": "mitigation_status_needed",
        "rollback_or_disable_status": "mitigation_status_needed",
    }
    return mapping.get(state.current_blocker or "", "unknown")


def _phase_value(value: str | IncidentPhase | None) -> IncidentPhase:
    try:
        return IncidentPhase(str(getattr(value, "value", value)))
    except ValueError:
        return IncidentPhase.UNKNOWN


def incident_brief_from_state(
    state: CurrentIncidentState,
    allowed_targets: list[AllowedTarget],
    *,
    input_size_assessment: InputSizeAssessment | None = None,
    events: list[IncidentEvent] | None = None,
    clean_context: CleanIncidentContext | None = None,
    warnings: list[str] | None = None,
) -> IncidentBrief:
    events = events or []
    event_ids = [event.event_id for event in events]
    latest_ids = [event.event_id for event in events[-8:]]
    targetable = [target for target in allowed_targets if target.targetable]

    def ids_for_name(name: str | None) -> list[str]:
        target = _target_by_name_or_id(allowed_targets, name)
        return [target.target_id] if target and target.targetable else []

    role_candidates: list[IncidentBriefRoleCandidate] = []
    for target in targetable:
        if target.evidence_ids:
            role_candidates.append(
                IncidentBriefRoleCandidate(
                    target_id=target.target_id,
                    name=target.display_name,
                    role_hint=target.role_hint if target.role_hint != "unknown" else "unknown",
                    confidence=0.72 if target.evidence_ids else 0.45,
                    evidence_ids=target.evidence_ids,
                )
            )
    for entity in state.engaged_entities + state.suggested_but_not_engaged:
        target = _target_by_name_or_id(allowed_targets, entity.display_name)
        if target and target.targetable and all(candidate.target_id != target.target_id for candidate in role_candidates):
            role_candidates.append(
                IncidentBriefRoleCandidate(
                    target_id=target.target_id,
                    name=target.display_name,
                    role_hint=target.role_hint if target.role_hint != "unknown" else "owner_team",
                    confidence=entity.confidence,
                    evidence_ids=[ref.event_id for ref in entity.evidence],
                )
            )

    completed_actions = [
        IncidentBriefCompletedAction(
            action_type=action.action_type,
            summary=action.summary,
            actor_target_ids=ids_for_name(action.actor) + ids_for_name(action.target),
            evidence_ids=[ref.event_id for ref in action.evidence] or event_ids[:1],
        )
        for action in state.actions_completed
        if [ref.event_id for ref in action.evidence] or event_ids
    ]

    blocker_type = _blocker_from_state(state)
    blocker_evidence = []
    for action in state.actions_completed[:2]:
        blocker_evidence.extend(ref.event_id for ref in action.evidence)
    for signal in state.monitoring_signals[:2]:
        blocker_evidence.extend(ref.event_id for ref in signal.evidence)
    blocker_evidence = list(dict.fromkeys(blocker_evidence or latest_ids[:2] or event_ids[:1]))

    preferred_ids = []
    for role in role_candidates:
        if role.role_hint in {"technical_investigator", "owner_team", "reporter_or_validator", "support_team"}:
            preferred_ids.append(role.target_id)
    preferred_ids = list(dict.fromkeys(preferred_ids[:3]))
    moves_by_blocker = {
        "validation_needed": [ICMove.ASK_NEXT_VALIDATION, ICMove.REQUEST_MONITORING_SIGNAL],
        "monitoring_needed": [ICMove.REQUEST_MONITORING_SIGNAL, ICMove.ASK_NEXT_VALIDATION],
        "mitigation_status_needed": [ICMove.REQUEST_STATUS_OR_ETA, ICMove.REQUEST_MITIGATION_OPTION],
        "status_eta_needed": [ICMove.REQUEST_STATUS_OR_ETA],
        "code_fix_status_needed": [ICMove.REQUEST_STATUS_OR_ETA, ICMove.ASK_CODE_FIX_STATUS],
        "missing_owner": [ICMove.CONFIRM_OWNERSHIP, ICMove.ENGAGE_OWNER],
        "customer_scope_needed": [ICMove.ASK_IMPACT],
        "deployment_validation_needed": [ICMove.CONFIRM_DEPLOYMENT_RELATED, ICMove.ASK_NEXT_VALIDATION],
        "rca_owner_needed": [ICMove.REQUEST_STATUS_OR_ETA, ICMove.HANDOFF_OR_ASSIGN_DRI],
    }

    do_not_ask = [
        IncidentBriefDoNotAsk(intent=intent, reason="Marked stale in current state.", evidence_ids=latest_ids[:2])
        for intent in state.stale_question_intents
    ]
    rejected = [
        IncidentBriefRejectedOrNoise(
            text=entity.display_name,
            reason="bot_system_placeholder" if "bot" in entity.status or "Default_Agent" in entity.display_name else "unsupported_entity",
            evidence_ids=[ref.event_id for ref in entity.evidence],
        )
        for entity in state.rejected_entities
    ]
    rejected.extend(
        IncidentBriefRejectedOrNoise(text=target.display_name, reason="other", evidence_ids=target.evidence_ids)
        for target in allowed_targets
        if not target.targetable
    )
    return IncidentBrief(
        incident_id=state.incident_id,
        based_on_event_ids=event_ids,
        latest_window_event_ids=latest_ids,
        full_context_used=not (input_size_assessment and input_size_assessment.likely_too_large_for_single_pass),
        latest_window_used=bool(input_size_assessment and input_size_assessment.likely_too_large_for_single_pass),
        partial_context=False,
        current_summary=state.compact_summary or (clean_context.clean_summary if clean_context else ""),
        phase=IncidentBriefValue(
            primary=state.phase,
            confidence=0.78 if state.phase != IncidentPhase.UNKNOWN else 0.2,
            evidence_ids=blocker_evidence[:2],
        ),
        latest_blocker=IncidentBriefBlocker(
            blocker_type=blocker_type,  # type: ignore[arg-type]
            summary=state.compact_summary or state.current_blocker or "unknown",
            evidence_ids=blocker_evidence if blocker_type != "unknown" else [],
            confidence=0.75 if blocker_type != "unknown" else 0.2,
        ),
        completed_actions=completed_actions,
        active_workstreams=[
            IncidentBriefWorkstream(
                workstream_type="monitoring" if state.monitoring_signals else "investigation",
                status="waiting" if state.monitoring_signals else "active",
                summary=state.current_blocker or state.compact_summary,
                owner_target_ids=preferred_ids,
                evidence_ids=blocker_evidence,
            )
        ]
        if blocker_type != "unknown"
        else [],
        engaged_entities=[
            IncidentBriefEntity(
                target_id=target.target_id,
                name=target.display_name,
                target_type=target.target_type,
                role_hint=target.role_hint if target.role_hint != "unknown" else "unknown",
                status="mentioned",
                evidence_ids=target.evidence_ids,
            )
            for target in targetable
            if target.evidence_ids
        ],
        role_candidates=role_candidates[:12],
        do_not_ask=do_not_ask,
        rejected_or_noise=rejected,
        recommended_ic_focus=IncidentBriefFocus(
            summary=state.compact_summary or state.current_blocker or "",
            preferred_target_ids=preferred_ids,
            acceptable_move_types=moves_by_blocker.get(blocker_type, [ICMove.NO_SAFE_RECOMMENDATION]),
            evidence_ids=blocker_evidence,
        ),
        uncertainty=[
            IncidentBriefUncertainty(
                item=unknown,
                why_it_matters="Unknown affects the next IC ask.",
                evidence_ids=latest_ids[:1],
            )
            for unknown in state.unknowns[:4]
        ],
        warnings=warnings or [],
    )


def build_deterministic_incident_brief(
    raw_text: str,
    events: list[IncidentEvent],
    current_state: CurrentIncidentState,
    allowed_targets: list[AllowedTarget],
    input_size_assessment: InputSizeAssessment,
    clean_context: CleanIncidentContext | None = None,
) -> IncidentBrief:
    del raw_text
    return incident_brief_from_state(
        current_state,
        allowed_targets,
        input_size_assessment=input_size_assessment,
        events=events,
        clean_context=clean_context,
        warnings=["IncidentBrief used deterministic compatibility fallback."],
    )


URL_RE = re.compile(r"https?://[^\s)>]+", re.I)


def _url_summary(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    path = parsed.path or ""
    if re.search(r"/browse/[A-Z][A-Z0-9]+-\d+", path, re.I):
        url_type = "jira_issue"
    elif re.search(r"/(?:pages|document|d)/\d+", path, re.I) or re.search(r"\d{5,}", path):
        url_type = "docs_or_url_path_number"
    else:
        url_type = "link"
    return {"domain": parsed.netloc, "type": url_type}


def _compact_text(text: str, *, max_chars: int) -> str:
    value = URL_RE.sub(lambda match: f"<url domain={urlparse(match.group(0)).netloc or 'unknown'}>", text)
    lines = value.splitlines()
    if len(lines) > 12 or "```" in value:
        head = " ".join(line.strip() for line in lines[:6] if line.strip())
        tail = " ".join(line.strip() for line in lines[-3:] if line.strip())
        value = f"{head} [large log/table/code block compacted; omitted middle lines] {tail}".strip()
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) > max_chars:
        return value[: max_chars - 32].rstrip() + " [truncated compact event]"
    return value


def compact_incident_brief_events(
    events: list[IncidentEvent],
    *,
    max_chars_per_event: int = 900,
    max_bot_summary_events: int = 3,
) -> list[dict]:
    compacted: list[dict] = []
    bot_summary_count = 0
    for event in events:
        tokens = dict(event.extracted_tokens or {})
        urls = [str(url) for url in tokens.get("urls", [])]
        command_candidates = [
            str(command)
            for command in tokens.get("command_candidates", [])
            if str(command).strip().startswith("@")
        ][:5]
        safe_numbers = []
        for number in tokens.get("numbers", []):
            context = _norm(str(number.get("context", ""))) if isinstance(number, dict) else ""
            value = str(number.get("value", "")) if isinstance(number, dict) else str(number)
            explicit_tenant = bool(
                re.search(r"\b(?:tenant\s+id|tenant|account\s+id|account|org\s+id)\b", context, re.I)
            )
            url_or_ticketish = any(term in context for term in ("url", "doc", "page", "jira", "ticket", "cm-"))
            if url_or_ticketish and not explicit_tenant:
                continue
            safe_numbers.append(number if isinstance(number, dict) else {"value": value})
        author_type = "bot_system" if tokens.get("is_bot") or tokens.get("is_system") else "human"
        is_bot_summary = author_type == "bot_system" and any(
            term in _norm(event.message)
            for term in ("phase", "summary", "assessment", "workflow", "trust post", "created")
        )
        if is_bot_summary:
            bot_summary_count += 1
        compact_tokens = {
            "is_bot": bool(tokens.get("is_bot")),
            "is_system": bool(tokens.get("is_system")),
            "url_summaries": [_url_summary(url) for url in urls[:6]],
            "command_candidates": command_candidates,
            "numbers": safe_numbers[:8],
        }
        if urls and bot_summary_count <= max_bot_summary_events:
            compact_tokens["url_count"] = len(urls)
        compacted.append(
            {
                "event_id": event.event_id,
                "incident_id": event.incident_id,
                "ts": event.ts,
                "sequence": event.sequence,
                "source": event.source,
                "author": event.author,
                "author_type": author_type,
                "message": _compact_text(event.message, max_chars=max_chars_per_event),
                "compact_text": _compact_text(event.message, max_chars=max_chars_per_event),
                "extracted_tokens": compact_tokens,
                "raw_metadata": {"compacted_for_incident_brief": True},
                "hash": event.hash,
            }
        )
    return compacted


def compact_allowed_targets_for_brief(allowed_targets: list[AllowedTarget], *, max_targets: int = 40) -> list[dict]:
    def score(target: AllowedTarget) -> tuple[int, int]:
        value = 0
        if target.targetable:
            value += 30
        if target.target_quality == "high":
            value += 35
        elif target.target_quality == "medium":
            value += 15
        elif target.target_quality in {"low", "rejected"}:
            value -= 40
        if target.source in {"slack_author", "explicit_mention", "current_evidence"}:
            value += 25
        if target.evidence_ids:
            value += 20
        if target.target_type in {"bot_system", "non_targetable_noise"}:
            value -= 20
        if target.source in {"service_alias", "command_registry"} and not target.evidence_ids:
            value -= 15
        return value, -len(target.display_name)

    scored = sorted(allowed_targets, key=score, reverse=True)
    kept = scored[:max_targets]
    return [
        {
            "target_id": target.target_id,
            "display_name": target.display_name,
            "target_type": target.target_type,
            "source": target.source,
            "role_hint": target.role_hint,
            "targetable": target.targetable,
            "target_quality": target.target_quality,
            "source_event_kind": target.source_event_kind,
            "evidence_ids": target.evidence_ids[:5],
            "reason": target.reason,
            "rejection_reason": target.rejection_reason,
            "canonical_id": target.canonical_id,
        }
        for target in kept
    ]


def build_incident_brief_payload(
    raw_text: str,
    events: list[IncidentEvent],
    current_state: CurrentIncidentState,
    allowed_targets: list[AllowedTarget],
    input_size_assessment: InputSizeAssessment,
    *,
    reconstructed_turns: object | None = None,
    attempt_name: str = "compact_latest_window",
    max_chars_per_event: int = 900,
    max_targets: int = 40,
) -> dict:
    compact_events = compact_incident_brief_events(events, max_chars_per_event=max_chars_per_event)
    compact_targets = compact_allowed_targets_for_brief(allowed_targets, max_targets=max_targets)
    compact_raw_text = "\n".join(
        f"{event['event_id']} {event.get('ts') or ''} {event.get('author') or ''}: {event['compact_text']}"
        for event in compact_events
    )
    compact_state = {
        "incident_id": current_state.incident_id,
        "phase": str(getattr(current_state.phase, "value", current_state.phase)),
        "current_blocker": current_state.current_blocker,
        "compact_summary": current_state.compact_summary,
        "stale_question_intents": list(current_state.stale_question_intents),
    }
    return {
        "incident_id": current_state.incident_id,
        "attempt_name": attempt_name,
        "raw_text": compact_raw_text or _compact_text(raw_text, max_chars=max_chars_per_event * max(1, len(events))),
        "events": compact_events,
        "latest_high_signal_event_ids": [event["event_id"] for event in compact_events[-12:]],
        "input_size_assessment": input_size_assessment.model_dump(mode="json"),
        "allowed_targets": compact_targets,
        "allowed_target_count": len(allowed_targets),
        "current_state": compact_state,
        "reconstructed_turns": (
            reconstructed_turns.model_dump(mode="json") if hasattr(reconstructed_turns, "model_dump") else None
        ),
        "product_safety_rules": [
            "Use only current event evidence and allowed target IDs.",
            "Do not infer tenants from URL path numbers or customers from URL domains.",
            "Do not treat bot/system lifecycle text as human commands.",
            "Unknown is acceptable and safer than invention.",
            "Produce IncidentBrief JSON only.",
        ],
    }


def incident_brief_payload_stats(payload: dict) -> dict[str, int]:
    events = payload.get("events") or []
    text = str(payload.get("raw_text") or "")
    char_count = len(text)
    return {
        "event_count": len(events),
        "char_count": char_count,
        "estimated_token_count": max(1, char_count // 4),
    }


def extract_incident_brief(
    raw_text: str,
    events: list[IncidentEvent],
    current_state: CurrentIncidentState,
    allowed_targets: list[AllowedTarget],
    input_size_assessment: InputSizeAssessment,
    llm_client: LLMClient,
    *,
    reconstructed_turns: object | None = None,
    attempt_name: str = "compact_latest_window",
    max_chars_per_event: int = 900,
    max_targets: int = 40,
) -> IncidentBrief:
    payload = build_incident_brief_payload(
        raw_text,
        events,
        current_state,
        allowed_targets,
        input_size_assessment,
        reconstructed_turns=reconstructed_turns,
        attempt_name=attempt_name,
        max_chars_per_event=max_chars_per_event,
        max_targets=max_targets,
    )
    brief = llm_client.generate_json("incident_brief_extractor", payload, IncidentBrief)
    brief = validate_with_repair(brief, IncidentBrief, context="incident_brief_extractor")
    return _validated_brief_targets(brief, allowed_targets)


def _non_aggregate_rejected_noise(items: list[IncidentBriefRejectedOrNoise]) -> list[IncidentBriefRejectedOrNoise]:
    filtered: list[IncidentBriefRejectedOrNoise] = []
    for item in items:
        text_norm = _norm(item.text)
        if "numeric operational ids" in text_norm:
            continue
        if "such as" in text_norm and len(re.findall(r"\d{5,}", item.text)) > 1:
            continue
        filtered.append(item)
    return filtered


def clean_context_from_incident_brief(brief: IncidentBrief, allowed_targets: list[AllowedTarget]) -> CleanIncidentContext:
    target_by_id = {target.target_id: target for target in allowed_targets}
    entities: list[CleanContextEntity] = []
    suggested_entities: list[CleanContextEntity] = []
    for role in brief.role_candidates:
        target = target_by_id.get(role.target_id)
        if not target:
            continue
        entity = CleanContextEntity(
            name=target.display_name,
            entity_type={
                "person": EntityType.PERSON,
                "team": EntityType.TEAM,
                "service": EntityType.SERVICE,
                "bot_system": EntityType.UNKNOWN,
                "non_targetable_noise": EntityType.UNKNOWN,
            }.get(target.target_type, EntityType.UNKNOWN),
            status="system_or_bot" if target.target_type in {"bot_system", "non_targetable_noise"} else "responded",
            targetable=target.targetable,
            confidence=role.confidence,
            evidence_ids=role.evidence_ids or target.evidence_ids,
        )
        should_suggest = (
            target.source in {"catalog", "service_alias", "command_registry"} and not target.evidence_ids
        ) or (
            target.source == "current_evidence"
            and target.target_type in {"team", "service"}
            and role.role_hint in {"owner_team", "support_team"}
        )
        if should_suggest:
            suggested_entities.append(entity.model_copy(update={"status": "suggested_not_engaged"}))
        else:
            entities.append(entity)
    for workstream in brief.active_workstreams:
        for target_id in workstream.owner_target_ids:
            target = target_by_id.get(target_id)
            if not target or not target.targetable:
                continue
            if target.evidence_ids:
                continue
            if any(entity.name == target.display_name for entity in suggested_entities):
                continue
            suggested_entities.append(
                CleanContextEntity(
                    name=target.display_name,
                    entity_type={
                        "person": EntityType.PERSON,
                        "team": EntityType.TEAM,
                    "service": EntityType.SERVICE,
                    "bot_system": EntityType.UNKNOWN,
                        "non_targetable_noise": EntityType.UNKNOWN,
                    }.get(target.target_type, EntityType.UNKNOWN),
                    status="suggested_not_engaged",
                    targetable=target.targetable,
                    confidence=0.55,
                    evidence_ids=workstream.evidence_ids,
                )
            )
    return CleanIncidentContext(
        incident_id=brief.incident_id,
        based_on_event_ids=brief.based_on_event_ids,
        source_summary=brief.current_summary,
        clean_summary=brief.current_summary,
        phase=CleanContextValue(
            value=brief.phase.primary.value if isinstance(brief.phase.primary, IncidentPhase) else str(brief.phase.primary),
            confidence=brief.phase.confidence,
            evidence_ids=brief.phase.evidence_ids,
        ),
        current_blocker=CleanContextBlocker(
            blocker_type=brief.latest_blocker.blocker_type,
            summary=brief.latest_blocker.summary,
            confidence=brief.latest_blocker.confidence,
            evidence_ids=brief.latest_blocker.evidence_ids,
        ),
        engaged_entities=[entity for entity in entities if entity.targetable],
        suggested_but_not_engaged=[entity for entity in suggested_entities if entity.targetable],
        question_ledger=CleanQuestionLedger(
            stale_question_intents=[item.intent for item in brief.do_not_ask],
            answered_questions=[
                QuestionRecord(
                    question_id=f"brief:{idx}",
                    intent=item.intent,
                    text=item.reason,
                    status="stale",
                    evidence=[EvidenceRef(event_id=evidence_id) for evidence_id in item.evidence_ids],
                )
                for idx, item in enumerate(brief.do_not_ask, start=1)
            ],
        ),
        actions_completed=[
            ActionRecord(
                action_id=f"brief-action-{idx}",
                action_type=action.action_type,
                summary=action.summary,
                evidence=[EvidenceRef(event_id=evidence_id) for evidence_id in action.evidence_ids],
            )
            for idx, action in enumerate(brief.completed_actions, start=1)
        ],
        rejected_entities=[
            CleanRejectedEntity(text=item.text, reason=item.reason, evidence_ids=item.evidence_ids)
            for item in _non_aggregate_rejected_noise(brief.rejected_or_noise)
        ],
        uncertainty_notes=[item.item for item in brief.uncertainty],
    )


def state_delta_from_incident_brief(brief: IncidentBrief, allowed_targets: list[AllowedTarget]) -> StateDelta:
    target_by_id = {target.target_id: target for target in allowed_targets}
    engaged = []
    suggested = []
    for role in brief.role_candidates:
        target = target_by_id.get(role.target_id)
        if not target or not target.targetable:
            continue
        entity_type = {
            "person": EntityType.PERSON,
            "team": EntityType.TEAM,
            "service": EntityType.SERVICE,
        }.get(target.target_type, EntityType.UNKNOWN)
        entity = EntityRef(
            entity_type=entity_type,
            display_name=target.display_name,
            canonical_id=target.canonical_id,
            status=role.role_hint,
            evidence=[EvidenceRef(event_id=evidence_id) for evidence_id in (role.evidence_ids or target.evidence_ids)],
            confidence=role.confidence,
            source="catalog" if target.source in {"catalog", "service_alias", "command_registry"} else "current_evidence",
        )
        should_suggest = (
            target.source in {"catalog", "service_alias"} and not target.evidence_ids
        ) or (
            brief.latest_blocker.blocker_type == "missing_owner"
            and target.source == "current_evidence"
            and target.target_type in {"team", "service"}
            and role.role_hint in {"owner_team", "support_team"}
        )
        if should_suggest:
            suggested.append(entity)
        else:
            engaged.append(entity)
    blocker_type = brief.latest_blocker.blocker_type
    compatibility_blocker = "missing_validation" if blocker_type == "validation_needed" else blocker_type
    return StateDelta(
        incident_id=brief.incident_id,
        phase=_phase_value(brief.phase.primary),
        impact=ImpactState(description=brief.current_summary, confidence=0.5),
        candidate_services=[entity for entity in engaged + suggested if entity.entity_type == EntityType.SERVICE],
        engaged_entities=[entity for entity in engaged if entity.entity_type != EntityType.SERVICE],
        suggested_but_not_engaged=[entity for entity in suggested if entity.entity_type != EntityType.SERVICE],
        actions_completed=[
            ActionRecord(
                action_id=f"brief-action-{idx}",
                action_type=action.action_type,
                summary=action.summary,
                evidence=[EvidenceRef(event_id=evidence_id) for evidence_id in action.evidence_ids],
            )
            for idx, action in enumerate(brief.completed_actions, start=1)
        ],
        stale_question_intents=[item.intent for item in brief.do_not_ask],
        current_blocker=compatibility_blocker,
        monitoring_signals=[
            EvidenceBackedFact(
                value=workstream.summary,
                evidence=[EvidenceRef(event_id=evidence_id) for evidence_id in workstream.evidence_ids],
                confidence=0.65,
            )
            for workstream in brief.active_workstreams
            if workstream.workstream_type in {"monitoring", "validation"}
        ],
        rejected_entities=[
            EntityRef(
                entity_type=EntityType.TENANT if item.reason == "url_path_number" else EntityType.UNKNOWN,
                display_name=item.text,
                status=f"rejected:{item.reason}",
                evidence=[EvidenceRef(event_id=evidence_id) for evidence_id in item.evidence_ids],
                confidence=1.0,
            )
            for item in _non_aggregate_rejected_noise(brief.rejected_or_noise)
        ],
        compact_summary=brief.current_summary,
    )


def sharp_blocker_from_incident_brief(
    brief: IncidentBrief,
    allowed_targets: list[AllowedTarget],
) -> SharpBlockerAssessment:
    target_by_id = {target.target_id: target for target in allowed_targets}
    role_by_id = {role.target_id: role for role in brief.role_candidates}
    technical_ids = [
        role.target_id
        for role in brief.role_candidates
        if role.role_hint in {"technical_investigator", "owner_team"}
    ]
    validation_ids = [
        role.target_id
        for role in brief.role_candidates
        if role.role_hint in {"reporter_or_validator", "support_team"}
    ]
    tech_names = [target_by_id[target_id].display_name for target_id in technical_ids if target_id in target_by_id]
    validation_names = [target_by_id[target_id].display_name for target_id in validation_ids if target_id in target_by_id]
    blocker_map = {
        "validation_needed": "missing_validation",
        "monitoring_needed": "waiting_on_monitoring",
        "mitigation_status_needed": "mitigation_status_or_validation",
        "status_eta_needed": "waiting_on_owner_status",
        "code_fix_status_needed": "waiting_on_code_fix",
        "deployment_validation_needed": "waiting_on_deploy",
        "missing_owner": "missing_owner",
        "customer_scope_needed": "missing_impact",
        "rca_owner_needed": "waiting_on_owner_status",
        "waiting_on_active_work": "waiting_on_owner_status",
        "handoff_needed": "handoff_or_dri_assignment",
    }
    move_map = {
        "missing_validation": [ICMove.ASK_NEXT_VALIDATION],
        "waiting_on_monitoring": [ICMove.REQUEST_MONITORING_SIGNAL, ICMove.ASK_NEXT_VALIDATION],
        "mitigation_status_or_validation": [ICMove.REQUEST_STATUS_OR_ETA, ICMove.REQUEST_MITIGATION_OPTION],
        "waiting_on_owner_status": [ICMove.REQUEST_STATUS_OR_ETA],
        "waiting_on_code_fix": [ICMove.REQUEST_STATUS_OR_ETA, ICMove.ASK_CODE_FIX_STATUS],
        "waiting_on_deploy": [ICMove.CONFIRM_DEPLOYMENT_RELATED, ICMove.ASK_NEXT_VALIDATION],
        "missing_owner": [ICMove.CONFIRM_OWNERSHIP, ICMove.ENGAGE_OWNER],
        "missing_impact": [ICMove.ASK_IMPACT],
    }
    blocker_type = blocker_map.get(brief.latest_blocker.blocker_type, "unclear")
    return SharpBlockerAssessment(
        incident_id=brief.incident_id,
        based_on_event_ids=brief.based_on_event_ids,
        phase=brief.phase.primary,
        blocker_type=blocker_type,  # type: ignore[arg-type]
        blocker_summary=brief.latest_blocker.summary or brief.recommended_ic_focus.summary,
        confidence=brief.latest_blocker.confidence,
        evidence_ids=brief.latest_blocker.evidence_ids,
        visible_workstreams=[
            VisibleWorkstream(
            workstream_type={
                "customer_support_validation": "validation",
                "trust_post_or_comms": "trust_post",
                "change_deployment_check": "deployment_or_hotfix",
                "rca_followup": "investigation",
            }.get(workstream.workstream_type, workstream.workstream_type),  # type: ignore[arg-type]
                status={
                    "active": "in_progress",
                    "waiting": "requested_not_confirmed",
                    "proposed": "discussed_not_started",
                }.get(workstream.status, workstream.status),
                summary=workstream.summary,
                owner_candidates=[target_by_id[target_id].display_name for target_id in workstream.owner_target_ids if target_id in target_by_id],
                evidence_ids=workstream.evidence_ids,
            )
            for workstream in brief.active_workstreams
            if workstream.workstream_type
        ],
        role_candidates=[
            RoleCandidate(
                name=target_by_id[role.target_id].display_name if role.target_id in target_by_id else role.name,
                role_type={
                    "reporter_or_validator": "reporter_validator",
                    "technical_investigator": "technical_investigator",
                    "owner_team": "owner_team",
                    "support_team": "support_team",
                    "ic_or_coordinator": "ic_or_coordinator",
                    "bot_system": "bot_or_system",
                }.get(role.role_hint, "unknown"),  # type: ignore[arg-type]
                status="validating" if role.role_hint == "reporter_or_validator" else "actively_working",
                evidence_ids=role.evidence_ids,
                confidence=role.confidence,
            )
            for role in brief.role_candidates
            if role.target_id in role_by_id and role.target_id in target_by_id
        ],
        technical_status_targets=tech_names,
        customer_or_reporter_validation_targets=validation_names,
        should_not_target_for_fix_status=validation_names,
        latest_workstream_owner_candidates=tech_names,
        validation_request_targets=validation_names,
        should_not_ask_yet=[item.intent for item in brief.do_not_ask],
        recommended_move_families=brief.recommended_ic_focus.acceptable_move_types or move_map.get(blocker_type, []),
        recommended_ask_slots=["validation signal", "status", "monitoring signal"],
        wrong_next_moves=[],
        no_invention_constraints=[
            "Use only allowed target IDs.",
            "Do not invent owners, customers, tenants, services, commands, or completion.",
        ],
    )
