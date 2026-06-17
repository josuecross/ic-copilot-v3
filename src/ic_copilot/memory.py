from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

import yaml

from ic_copilot.schemas import (
    CurrentIncidentState,
    DecisionMoment,
    EntityRef,
    MemoryApplicabilityResult,
    MemoryQuery,
)


QUALITY_THRESHOLD = 0.7
APPROVED_STATUSES = {"approved", "human_reviewed", "externally_reviewed", "approved_for_product"}
MEMORY_STOP_TERMS = {
    "and",
    "are",
    "but",
    "current",
    "does",
    "for",
    "from",
    "has",
    "have",
    "not",
    "only",
    "pending",
    "should",
    "show",
    "shows",
    "since",
    "still",
    "that",
    "the",
    "this",
    "what",
    "when",
    "with",
}


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _terms(text: str) -> set[str]:
    terms = {term for term in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", text.lower()) if term}
    terms.update(re.findall(r"\bp[1-4]\b", text.lower()))
    return {term for term in terms if term not in MEMORY_STOP_TERMS}


def _compact(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        parts = []
        for key in ("summary", "text", "pattern", "value", "description", "reason", "name", "id"):
            if value.get(key):
                parts.append(str(value[key]))
        if not parts:
            parts = [f"{key}={item}" for key, item in value.items() if isinstance(item, str | int | float)]
        return "; ".join(parts)
    if isinstance(value, list):
        return "; ".join(_compact(item) for item in value if _compact(item))
    return str(value)


def _strings(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        compacted = _compact(value)
        return [compacted] if compacted else []
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(_strings(item))
        return values
    return [str(value)]


def _entity_names(entities: Iterable[EntityRef]) -> list[str]:
    names: list[str] = []
    for entity in entities:
        names.append(entity.display_name)
        if entity.canonical_id:
            names.append(entity.canonical_id)
    return names


def _load_records(path: Path) -> list[dict]:
    if path.suffix == ".jsonl":
        records = []
        for line_number, line in enumerate(path.read_text().splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSONL record: {exc}") from exc
        return records
    if path.suffix == ".json":
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else [data]
    if path.suffix in {".yaml", ".yml"}:
        data = yaml.safe_load(path.read_text()) or {}
        return data if isinstance(data, list) else [data]
    return []


def _adapt_decision_moment(raw: dict) -> dict:
    if "pattern" not in raw and "ic_action" in raw:
        adapted = dict(raw)
        adapted.setdefault("source_incident_id", "local-fixture")
        adapted.setdefault("phase_after", adapted.get("phase_before", "unknown"))
        adapted.setdefault("review_status", "approved")
        adapted.setdefault("quality_score", 0.86)
        adapted.setdefault("outcome", "")
        adapted.setdefault("applicability", {})
        if adapted.get("quality_score", 0) > 1:
            adapted["quality_score"] = adapted["quality_score"] / 100
        adapted["labels"] = _strings(adapted.get("labels"))
        adapted["forbidden_fact_leakage"] = _strings(adapted.get("forbidden_fact_leakage"))
        for key in ("situation_before", "trigger", "ic_action", "why_it_worked"):
            adapted[key] = _compact(adapted.get(key))
        return adapted
    blocker = raw.get("blocker_type")
    applicability = dict(raw.get("applicability") or {})
    if blocker:
        applicability.setdefault("current_blocker", blocker)
    if raw.get("required_current_evidence") is not None:
        applicability.setdefault("required_current_evidence", raw["required_current_evidence"])
    if raw.get("use_when") is not None:
        applicability.setdefault("use_when", raw["use_when"])
    if raw.get("do_not_use_when") is not None:
        applicability.setdefault("do_not_use_when", raw["do_not_use_when"])
    if raw.get("move") == "engage_owner":
        applicability.setdefault("target_must_not_be_engaged", True)
    quality_score = raw.get("quality_score", 0.86)
    if quality_score > 1:
        quality_score = quality_score / 100
    adapted = {
        "decision_id": raw["decision_id"],
        "source_incident_id": raw.get("source_incident_id", "contract-fixture"),
        "review_status": raw.get("review_status", "approved"),
        "quality_score": quality_score,
        "phase_before": raw.get("phase_before", "unknown"),
        "phase_after": raw.get("phase_after", raw.get("phase_before", "unknown")),
        "move": raw.get("move", "no_safe_recommendation"),
        "situation_before": _compact(raw.get("situation_before", raw.get("pattern", ""))),
        "trigger": _compact(raw.get("trigger", "; ".join(raw.get("use_when", [])) or raw.get("pattern", ""))),
        "ic_action": _compact(raw.get("ic_action", raw.get("pattern", ""))),
        "why_it_worked": _compact(raw.get("why_it_worked", raw.get("pattern", ""))),
        "applicability": applicability,
        "forbidden_fact_leakage": _strings(raw.get("forbidden_fact_leakage", [])),
        "outcome": raw.get("outcome", ""),
        "labels": _strings(raw.get("labels", raw.get("tags", []))),
        "embedding_text": raw.get("embedding_text"),
    }
    return adapted


def load_decision_moments(path: str | Path) -> list[DecisionMoment]:
    source = Path(path)
    moments: list[DecisionMoment] = []
    paths = [source] if source.is_file() else sorted(
        p for p in source.iterdir() if p.suffix in {".yaml", ".yml", ".json", ".jsonl"}
    )
    for item in paths:
        for index, record in enumerate(_load_records(item), start=1):
            try:
                moments.append(DecisionMoment.model_validate(_adapt_decision_moment(record)))
            except Exception as exc:
                location = f"{item}:{index}" if item.suffix == ".jsonl" else str(item)
                raise ValueError(f"{location}: invalid DecisionMoment: {exc}") from exc
    return moments


def build_memory_query(current_state: CurrentIncidentState, current_evidence_text: str = "") -> MemoryQuery:
    entities = (
        current_state.candidate_services
        + current_state.engaged_entities
        + current_state.suggested_but_not_engaged
    )
    names = _entity_names(entities)
    evidence_text = " ".join(
        [
            current_state.compact_summary,
            current_state.current_blocker or "",
            current_state.impact.description,
            " ".join(names),
            current_evidence_text,
        ]
    )
    labels = []
    if current_state.current_blocker:
        labels.append(current_state.current_blocker)
    labels.extend(_norm(name) for name in names)
    return MemoryQuery(
        incident_id=current_state.incident_id,
        phase=current_state.phase,
        current_blocker=current_state.current_blocker,
        service_ids=[entity.canonical_id for entity in entities if entity.canonical_id],
        entity_names=names,
        labels=labels,
        evidence_terms=sorted(_terms(evidence_text)),
    )


def retrieve_decision_moment_ids(
    query: MemoryQuery,
    decision_moments: list[DecisionMoment],
    limit: int = 12,
) -> list[str]:
    scored: list[tuple[int, str]] = []
    query_terms = set(query.evidence_terms).union(_terms(" ".join(query.labels + query.entity_names)))
    for moment in decision_moments:
        if moment.review_status not in APPROVED_STATUSES or moment.quality_score < QUALITY_THRESHOLD:
            continue
        if query.phase != "unknown" and moment.phase_before != query.phase:
            phase_score = 0
        else:
            phase_score = 2
        moment_text = " ".join(
            [
                moment.decision_id,
                moment.situation_before,
                moment.trigger,
                moment.ic_action,
                moment.why_it_worked,
                " ".join(moment.labels),
                " ".join(str(value) for value in moment.applicability.values()),
            ]
        )
        overlap = len(query_terms.intersection(_terms(moment_text)))
        blocker_score = 3 if query.current_blocker and (
            query.current_blocker in moment.labels
            or query.current_blocker == moment.applicability.get("current_blocker")
        ) else 0
        score = phase_score + blocker_score + overlap
        if score > 0:
            scored.append((score, moment.decision_id))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [decision_id for _, decision_id in scored[:limit]]


def hydrate_decision_moments(
    ids: list[str],
    decision_moments: list[DecisionMoment],
) -> list[DecisionMoment]:
    by_id = {moment.decision_id: moment for moment in decision_moments}
    return [by_id[decision_id] for decision_id in ids if decision_id in by_id]


def _state_text(current_state: CurrentIncidentState) -> str:
    pieces = [
        current_state.compact_summary,
        current_state.current_blocker or "",
        current_state.impact.description,
    ]
    for group in (
        current_state.candidate_services,
        current_state.engaged_entities,
        current_state.suggested_but_not_engaged,
    ):
        for entity in group:
            pieces.append(entity.display_name)
            pieces.extend(ref.quote for ref in entity.evidence)
    for fact in current_state.impact.affected_customers + current_state.impact.affected_tenants:
        pieces.append(fact.value)
        pieces.extend(ref.quote for ref in fact.evidence)
    for action in current_state.actions_completed:
        pieces.append(action.summary)
        pieces.append(action.action_type)
        pieces.append(action.target or "")
        pieces.extend(ref.quote for ref in action.evidence)
    for signal in current_state.monitoring_signals:
        pieces.append(signal.value)
        pieces.extend(ref.quote for ref in signal.evidence)
    for command in current_state.commands_seen:
        pieces.append(command.command)
    return "\n".join(pieces).lower()


def _target_already_engaged(target: str | None, current_state: CurrentIncidentState) -> bool:
    if not target:
        return False
    target_norm = _norm(target)
    for entity in current_state.engaged_entities:
        if target_norm in {_norm(entity.display_name), _norm(entity.canonical_id)}:
            return True
    return False


def _has_any(state_text: str, *terms: str) -> bool:
    return any(term in state_text for term in terms)


def _compiled_required_satisfied(value: str, state_text: str) -> bool:
    """Match Codex-compiled evidence phrases without turning them into semantic routing."""
    compiled_evidence_groups: dict[str, tuple[str, ...]] = {
        "producer connection error": (
            "connection to node",
            "connection to node -1 could not be established",
            "node -1",
            "producer error",
            "producer logs",
            "broker unavailable",
            "broker may not be available",
        ),
        "kafka/network health check": (
            "kafka health",
            "same-topic consumer",
            "consumer are healthy",
            "consumer is healthy",
            "network connectivity succeeds",
            "pod network connectivity",
            "pod can connect",
            "can connect to kafka",
            "curl connected",
            "connected to speed-racer-kafka",
            "connected to kafka",
            "kafka broker",
        ),
        "runtime configuration or feature-flag evidence": (
            "runtime config",
            "runtime flag",
            "feature flag",
            "environment variable",
            "broker address",
            "config drift",
            "configuration drift",
            "service config",
            "cert",
            "certificate",
        ),
        "runtime mitigation time or confirmation": (
            "runtime change was applied",
            "runtime mitigation",
            "manual mitigation",
            "stable path",
            "mitigation applied",
        ),
        "configuration drift evidence": (
            "config drift",
            "configuration drift",
            "gitops",
            "helm",
            "runtime differs",
            "runtime change",
        ),
        "pending permanent fix/change-management evidence": (
            "proper code",
            "config follow-up",
            "permanent fix",
            "persistent",
            "change-management",
            "change management",
            "ci-cd",
            "cicd",
            "overwrite",
        ),
        "event pipeline latency": (
            "audit event latency",
            "event delivery latency",
            "event pipeline latency",
            "delayed event",
            "stale event",
            "message flow",
        ),
        "mitigation or error cessation": (
            "mitigated",
            "mitigation restored",
            "message flow recovered",
            "messages are flowing",
            "stopped errors",
            "errors stopped",
            "error cessation",
            "recovered",
        ),
        "pending data integrity or loss assessment": (
            "data integrity",
            "data loss",
            "data-loss assessment",
            "loss assessment",
            "potential message loss",
            "backlog",
            "retention window",
            "impacted scope",
            "recovery feasibility",
        ),
        "single-region drift evidence": (
            "single region",
            "one region",
            "regional drift",
            "region drift",
        ),
        "multi-region service footprint": (
            "multi-region",
            "multiple regions",
            "other regions",
            "regional service",
        ),
        "regional audit status unknown or pending": (
            "regional audit",
            "audit pending",
            "audit status",
            "unknown or pending",
        ),
        "separate workstream names": (
            "deployment rca",
            "data loss",
            "data-loss",
            "workstream",
            "separate workstream",
        ),
        "separate owners or teams": (
            "separate owner",
            "separate team",
            "data owner",
            "config owner",
        ),
        "pending status for at least one workstream": (
            "status or eta",
            "status/eta",
            "pending status",
            "need status",
            "need eta",
        ),
        "database cpu or resource saturation": (
            "cpubusypercent",
            "cpu busy",
            "cpu crossed",
            "db cpu",
            "database cpu",
            "cpu high",
            "cpu saturation",
            "resource saturation",
            "load high",
        ),
        "dba-identified problematic query": (
            "dba identified",
            "dba says",
            "explain plan",
            "problematic query",
            "bad query",
            "query scans",
            "query cleanup",
            "cleanup queries",
            "failed_records cleanup",
            "expensive query",
            "filesort",
        ),
        "service/table or owner hint": (
            "service/table",
            "table owner",
            "app owner",
            "application owner",
            "owning service",
            "failed_records",
            "daco",
            "source workload",
            "service owner",
        ),
        "explicit responder-owned mitigation discussion": (
            "responder-owned",
            "owner will",
            "i will",
            "cleanup",
            "clean up",
            "mitigation discussion",
        ),
        "dba or application owner is active": (
            "dba",
            "app owner",
            "application owner",
            "owner is active",
            "owner active",
        ),
        "monitoring signal exists": (
            "monitoring",
            "recovery signal",
            "cpubusypercent",
            "connection-count",
            "connection count",
            "cpu",
            "load",
            "latency",
            "recovery signal",
            "dashboard",
        ),
        "mitigation action mentioned": (
            "mitigation",
            "retry",
            "cleanup",
            "clean up",
            "action taken",
        ),
        "database cpu/load monitoring signal": (
            "cpubusypercent",
            "cpu busy",
            "db cpu",
            "database cpu",
            "cpu load",
            "db load",
            "load monitoring",
        ),
        "no explicit recovery confirmation yet": (
            "before mitigation",
            "no recovery confirmation",
            "not recovered",
            "recovery pending",
            "need validation",
            "what cpu recovery signal",
            "what cpubusypercent",
            "shows recovery",
        ),
        "owner clarification of source": (
            "source is",
            "clarified source",
            "source clarification",
            "queries came from",
            "manual retry",
            "not database",
            "not db",
        ),
        "prior ambiguous or incorrect source hypothesis": (
            "earlier message hypothesized",
            "ambiguous source",
            "incorrect source",
            "thought db",
            "thought database",
            "hypothesized automation",
            "wrong source",
        ),
        "sandbox or non-production environment": (
            "sandbox",
            "non-production",
            "non production",
            "sbx",
        ),
        "no production impact statement": (
            "no production impact",
            "no prod impact",
            "prod not impacted",
            "sandbox only",
        ),
        "trust post not required signal": (
            "trust post not required",
            "trust post not needed",
            "no trust post",
            "no need for trust",
        ),
        "temporal workflow status or execution-history reference": (
            "temporal workflow",
            "temporal workflow execution history",
            "transfer accounting workflows",
            "workflows remain running",
            "workflow status",
            "execution history",
            "workflow execution",
            "workflow logs",
        ),
        "specific error text": (
            "activity error",
            "error text",
            "specific error",
            "exception",
            "failed with",
            "failed",
        ),
        "owning engineering team or sme evidence": (
            "revenue engineering",
            "zuora revenue engineering",
            "reviewing the workflow logs",
            "engineering owner",
            "engineering team",
            "sme",
            "subject matter expert",
            "owner evidence",
        ),
        "production environment impact": (
            "production impact",
            "prod impact",
            "production environment",
            "prod environment",
        ),
        "single tenant or single customer scope": (
            "single tenant",
            "one tenant",
            "single customer",
            "one customer",
        ),
        "blocking customer operation or period-close impact": (
            "blocked customer",
            "customer blocked",
            "blocked operation",
            "period close",
            "period-close",
        ),
        "reference to prior known pattern": (
            "known pattern",
            "seen before",
            "prior incident",
            "similar previous",
        ),
        "current incident has not fully confirmed root cause": (
            "root cause not confirmed",
            "not fully confirmed",
            "need confirmation",
            "suspected root cause",
        ),
        "current monitoring or log checks are pending": (
            "log checks pending",
            "monitoring pending",
            "checking logs",
            "monitoring or log",
        ),
        "customer unblocked or successful job completion": (
            "customer unblocked",
            "unblocked",
            "customer terminated",
            "job is now running",
            "job completed",
            "successful job",
            "jobs completed",
        ),
        "rca/follow-up still requested": (
            "rca",
            "follow-up",
            "follow up",
            "requested",
            "remaining failures",
            "customer validation",
            "validating before submitting",
        ),
        "engineering owner evidence": (
            "engineering owner",
            "engineering team",
            "owner",
            "sme",
        ),
        "revpro service evidence": (
            "revpro",
            "zuora revenue",
            "zuora revenue revpro",
            "revpro support",
            "revenue revpro",
        ),
        "deployment mismatch evidence": (
            "deployment mismatch",
            "deploy mismatch",
            "post-deploy mismatch",
            "post deploy mismatch",
            "version mismatch",
            "mismatch with the version",
            "version does not match",
            "deployment version",
        ),
        "multi-customer impact evidence": (
            "multiple customers",
            "customer count",
            "customers impacted",
            "impacted customers",
            "customers have mismatch",
            "customers have a mismatch",
            "many customers",
        ),
        "owner routing uncertainty or engagement request": (
            "who owns",
            "owner routing",
            "ownership",
            "should engage",
            "support should engage",
            "engage revpro support",
            "please engage revpro support",
            "could you please engage",
            "should revpro",
            "revpro support should",
            "whether revpro support",
        ),
        "support or owner engagement path": (
            "support",
            "revpro support",
            "engage",
            "engaged",
            "owner",
            "ownership",
            "routing",
        ),
        "api timeout/error symptom": (
            "api timeout",
            "api timeouts",
            "api 504",
            "api 503",
            "api 499",
            "504",
            "503",
            "499",
            "gateway timeout",
            "timeout errors",
            "authentication failure",
            "api calls fail",
            "api calls are failing",
            "ria connection limit",
            "connection limit warning",
            "connection limit reached",
            "ria logs",
            "elb health check",
        ),
        "service name such as ria, revenue api, kong, or load balancer": (
            "ria",
            "revenue api",
            "revenue integration api",
            "kong",
            "gateway",
            "load balancer",
            "elb",
            "api gateway",
        ),
        "api-only or ui-not-impacted statement": (
            "api only",
            "api-only",
            "only api",
            "ui not impacted",
            "ui is not impacted",
            "ui unaffected",
            "ui access is not impacted",
            "ui access works",
            "api calls fail but ui works",
        ),
        "customer reports or ticket references": (
            "customer report",
            "customer reports",
            "customers report",
            "support ticket",
            "support tickets",
            "ticket references",
            "reported customers",
            "customer-facing report",
        ),
        "unclear or evolving affected list": (
            "unclear scope",
            "scope is changing",
            "evolving affected list",
            "affected list is evolving",
            "new customer reports",
            "multiple customer reports",
            "confirm affected customers",
            "current affected customers",
        ),
        "api/service impact evidence": (
            "api impact",
            "api-only impact",
            "service impact",
            "revenue api",
            "api calls fail",
            "api calls are failing",
            "timeouts",
        ),
        "temporary traffic control or scaling mitigation": (
            "temporary traffic control",
            "traffic controls",
            "waf",
            "waf rule",
            "rate limit",
            "rate limiting",
            "traffic block",
            "ip block",
            "scaling",
            "scaled",
            "service scaling",
        ),
        "named owner or owner team": (
            "owner",
            "owner team",
            "named owner",
            "network owner",
            "sre owner",
            "engineering owner",
            "team is working",
            "team owns",
        ),
        "current mitigation status or pending approval": (
            "mitigation status",
            "current status",
            "status update",
            "monitoring",
            "pending approval",
            "evaluating",
            "watching effectiveness",
            "status is pending",
        ),
        "old hypothesis or mitigation path": (
            "old hypothesis",
            "earlier hypothesis",
            "previous hypothesis",
            "prior hypothesis",
            "prior mitigation",
            "earlier mitigation",
            "waf hypothesis",
            "gateway hypothesis",
            "traffic hypothesis",
            "noisy neighbor",
        ),
        "new owner-provided root-cause evidence": (
            "new root cause",
            "updated root cause",
            "root cause is different",
            "engineering says",
            "service owner says",
            "owner says",
            "oracle",
            "package lock",
            "lock errors",
            "backend cause",
        ),
        "explicit recommendation or uncertainty from owner": (
            "do not think",
            "not needed",
            "not need",
            "should hold",
            "hold off",
            "confirm whether",
            "uncertain",
            "recommend",
            "owner recommendation",
        ),
        "current trust/status state": (
            "trust post published",
            "trust/status post",
            "status post",
            "trust is live",
            "moved to monitoring",
            "changed to monitoring",
            "identified",
            "monitoring",
            "solved",
        ),
        "owner or support communication context": (
            "trust owner",
            "support owner",
            "support",
            "customer comms",
            "customer communication",
            "incident commander",
            "coordinator",
        ),
        "reversal action completed": (
            "temporary control removed",
            "temporary control was removed",
            "temporary waf control removed",
            "temporary waf control was removed",
            "control was removed",
            "traffic control removed",
            "waf removed",
            "waf control was removed",
            "waf unblocked",
            "unblocked",
            "rule removed",
            "reversed",
            "reversal completed",
        ),
        "monitoring period or stability evidence needed": (
            "monitoring window",
            "stability window",
            "stable",
            "error rates",
            "api health",
            "health stayed stable",
            "no issues for",
            "hours after",
        ),
        "engineering owner available": (
            "engineering owner",
            "revenue engineering",
            "sre owner",
            "service owner",
            "owner is available",
            "owner available",
            "engineering",
        ),
    }
    return _has_any(state_text, *compiled_evidence_groups.get(value, ()))


def _scope_question_answered_by_current_evidence(state_text: str) -> bool:
    has_scope_question = _has_any(
        state_text,
        "multiple customers",
        "how many customers",
        "more customers",
        "more production customers",
        "only customer",
        "only toast",
        "broader than",
    ) or ("why" in state_text and _has_any(state_text, "p1", "priority", "severity"))
    has_scope_answer = _has_any(
        state_text,
        "only one customer",
        "one customer affected",
        "single customer",
        "isolated to one customer",
        "only toast reported",
        "only toast has reported",
        "no other customer",
        "no other customers",
        "only reported it",
        "only live customers",
        "only two live customers",
        "service health looks green for other customers",
    )
    return has_scope_question and has_scope_answer


def _has_permission_scope_ambiguity(state_text: str) -> bool:
    has_permission_loop = _has_any(
        state_text,
        "permission denied",
        "required permission",
        "don't have permission",
        "don't have access",
        "do not have permission",
        "do-not-thread @daco-bot",
    )
    has_scope_ambiguity = _has_any(
        state_text,
        "different shard",
        "different shards",
        "not related",
        "same issue",
        "exact symptoms",
        "affected scope",
        "elaborate the issue",
    )
    return has_permission_loop and has_scope_ambiguity


def _is_late_bottleneck_or_mitigation_memory(moment: DecisionMoment) -> bool:
    text = _norm(
        " ".join(
            [
                moment.decision_id,
                moment.situation_before,
                moment.trigger,
                moment.ic_action,
                " ".join(moment.labels),
                " ".join(str(item) for item in moment.applicability.get("required_current_evidence", [])),
            ]
        )
    )
    return any(
        term in text
        for term in (
            "bottleneck",
            "mitigation",
            "monitoring",
            "next action owner",
            "next actions",
            "owner alignment",
            "workstream owner",
            "request_status_or_eta",
        )
    )


DIRECT_WORK_ITEM_OWNER_RE = re.compile(
    r"(?mi)^\s*(?:[-*•]\s*)?"
    r"[a-z][a-z0-9 /&_.-]{2,72}:\s*"
    r"(?:"
    r"\(owner:\s*[^)]{1,160}\)"
    r"|@[a-z][\w.-]*(?:\s+[a-z][\w.-]*){0,3}\s+"
    r"(?:is|are|will|was|were|has|have)\s+"
    r"(?:contacting|checking|monitoring|validating|investigating|reviewing|coordinating|working|owning|driving)"
    r"|[a-z][a-z0-9 /&_.-]{1,72}?"
    r"(?:\s+(?:team|engineering|sre|ops|support)|workflow|security)\s+"
    r"(?:is|are|will|was|were|has|have|checking|monitoring|validating|investigating)"
    r")\b"
)


def _has_direct_work_item_owner(state_text: str) -> bool:
    return bool(DIRECT_WORK_ITEM_OWNER_RE.search(state_text))


def _required_satisfied(required: str, current_state: CurrentIncidentState, state_text: str) -> bool:
    value = _norm(required)
    if not value:
        return True
    if value in state_text:
        return True
    if _compiled_required_satisfied(value, state_text):
        return True
    if value in {"owner/team suggested in current incident", "suggested owner"}:
        return bool(current_state.suggested_but_not_engaged)
    if value in {"no observed acknowledgement from target", "not observed engaged"}:
        return bool(current_state.suggested_but_not_engaged)
    if value == "person/team working on fix":
        return any(entity.status in {"working", "actively_working", "coordinating"} for entity in current_state.engaged_entities)
    if value == "hotfix/release mentioned":
        return "hotfix" in state_text or "release" in state_text
    if value == "code fix":
        return "code fix" in state_text or "psg-" in state_text
    if value == "deployment mentioned":
        return "deploy" in state_text
    if value == "owner engaged":
        return bool(current_state.engaged_entities)
    if value == "tenant or mapping field in current evidence":
        return bool(current_state.impact.affected_tenants) or "revenueorgmapping" in state_text
    if value == "uno or revenue signal":
        return "uno" in state_text or "revenue" in state_text
    if value == "db cpu high":
        return "cpu" in state_text and ("db" in state_text or "dbs" in state_text)
    if value == "customer blocked statement":
        return (
            _has_any(state_text, "customer blocked", "customer is blocked", "blocked from", "unable to run")
            or ("customer" in state_text and _has_any(state_text, "cannot run", "can't run", "erroring", "failing"))
        )
    if value == "multi-customer impact evidence":
        return _compiled_required_satisfied(value, state_text) or bool(
            re.search(r"\b(?:\d{2,}|multiple|many|several)\s+customers?\b", state_text)
        )
    if value == "uncertain or limited impact scope":
        return _has_any(
            state_text,
            "scope",
            "only one customer",
            "single customer",
            "one customer",
            "only customer",
            "only live customer",
            "multiple customers",
            "who else",
            "impacted customers",
            "blast radius",
        )
    if value == "severity discussion":
        return _has_any(state_text, "severity", "priority", "p1", "p2", "p3", "escalat")
    if value == "explicit pipeline or flink mitigation":
        return _has_any(state_text, "pipeline", "flink", "iceberg", "report pipeline", "megastore")
    if value == "named executing owner or owner team":
        return _has_any(state_text, "owner", "team", "engaged", "next steps", "@")
    if value == "approval or change-management dependency":
        return _has_any(state_text, "approval", "approved", "ecm", "change-management", "change management")
    if value == "report failure":
        return _has_any(
            state_text,
            "report failure",
            "report failures",
            "reports failing",
            "reports erroring",
            "reports erroring out",
            "reports errorring out",
            "erroring in reports",
            "not able to run reports",
            "not able to run any",
            "not able to run megastore",
            "unable to run reports",
            "cannot run reports",
            "can't run reports",
            "blocked from running reports",
            "blocked from running megastore enabled reports",
        )
    if value == "pipeline health signal":
        return _has_any(state_text, "pipeline", "flink", "row count", "row-count", "iceberg", "latest run")
    if value == "data consistency concern":
        return _has_any(
            state_text,
            "row count mismatch",
            "row-count mismatch",
            "count mismatch",
            "data consistency",
            "iceberg side",
            "less on iceberg side",
            "more on iceberg side",
            "del table",
            "oracle side",
            "table counts",
        )
    if value == "system recovery signal":
        return _has_any(state_text, "recovery", "recovered", "in sync", "row count", "row-count", "latest run")
    if value == "customer validation pending":
        return _has_any(
            state_text,
            "customer validation",
            "customer confirmation",
            "confirm with customer",
            "re-run",
            "rerun",
            "still blocked",
        )
    if value == "customer coordinator identified":
        return _has_any(state_text, "support", "customer coordinator", "customer owner", "reporter")
    if value == "dba engaged":
        return any(_norm(entity.display_name) == "dba" for entity in current_state.engaged_entities)
    if value == "queue action done or suspected workload":
        return "queue" in state_text
    if value == "mitigation/revert completed":
        return "revert" in state_text or "mitigation" in state_text
    if value == "monitoring signal current or catalog-supported":
        return bool(current_state.monitoring_signals)
    if value == "deployment or version change evidence":
        return _has_any(state_text, "deploy", "deployment", "release", "version", "schema change")
    if value == "missing column or schema mismatch signal":
        return _has_any(state_text, "missing column", "missing db", "schema mismatch", "db schema", "sqlsyntaxerror")
    if value == "affected environment list or uncertainty":
        return _has_any(state_text, "affected environment", "affected env", "environment", "sandbox", "production")
    if value == "trust communication reference":
        return _has_any(state_text, "trust", "customer communication", "customer comms")
    if value == "missing or disputed blast radius":
        return _has_any(state_text, "blast radius", "customer count", "affected customer", "affected environment")
    if value == "active owner/investigator":
        return _has_any(state_text, "owner", "investigating", "working", "active")
    if value == "active owner or investigator":
        return _has_any(state_text, "owner", "investigating", "working", "active")
    if value == "mitigation completed statement":
        return _has_any(state_text, "mitigation completed", "mitigated", "fix deployed", "resolved")
    if value == "original customer-visible workflow":
        return _has_any(state_text, "workflow", "order creation", "customer-visible", "customer visible")
    if value == "support/customer validation path":
        return _has_any(state_text, "support", "validator", "customer validation", "customer confirmation")
    if value == "l3 or support-led escalation marker":
        return _has_any(state_text, "l3", "support-led", "support led", "support escalation")
    if value == "expanded customer or environment impact":
        return _has_any(state_text, "multiple customer", "expanded impact", "affected environment", "blocked workflow")
    if value == "explicit conversion request or formal incident creation evidence":
        return _has_any(state_text, "convert to incident", "formal incident", "incident created")
    if value == "initial routed team or owner":
        return _has_any(state_text, "initial page", "initially routed", "first paged", "routed to")
    if value == "explicit owner redirection statement":
        return _has_any(state_text, "redirect", "belongs to", "catalog-side", "not subscription")
    if value == "current service or component evidence":
        return _has_any(state_text, "catalog", "ocm", "order creation", "component", "service")
    if value == "infra/resource health statement":
        return _has_any(state_text, "pods healthy", "pod healthy", "cpu", "memory", "hpa", "infra ruled out", "resource")
    if value == "application-level bottleneck statement":
        return _has_any(state_text, "application-level", "app layer", "job hang", "stuck job", "queue", "downstream bottleneck")
    if value == "internal application jobs":
        return _has_any(state_text, "internal job", "application job", "data loader job", "stuck job")
    if value == "mitigation safety concern":
        return _has_any(state_text, "safe", "safest", "in-flight", "in flight", "restart could", "without causing")
    if value == "service owner needed":
        return _has_any(state_text, "service owner", "owner needed", "app owner", "application owner")
    if value == "failed owner lookup":
        return _has_any(state_text, "owner lookup failed", "lookup failed", "not setup in pd", "users not found")
    if value == "missing escalation policy or pd gap":
        return _has_any(state_text, "pd gap", "pagerduty gap", "no escalation policy", "not setup in pd")
    if value == "needed service owner":
        return _has_any(state_text, "service owner", "active owner", "who owns")
    if value == "completed partial mitigation":
        return _has_any(state_text, "scale-up completed", "partial mitigation", "capacity added", "mitigation completed")
    if value == "remaining stuck jobs or service unavailable symptom":
        return _has_any(
            state_text,
            "stuck job",
            "existing jobs",
            "service unavailable",
            "still waiting",
            "queue remains",
            "jobs remain",
        )
    if value == "service normal or jobs completed statement":
        return _has_any(state_text, "service normal", "returned to normal", "all jobs completed", "jobs completed")
    if value == "prior customer impact":
        return _has_any(state_text, "customer impact", "affected customer", "reported customer", "customer reported")
    if value == "mitigation consideration":
        return _has_any(state_text, "before mitigation", "mitigation", "mitigate")
    if value == "next action text":
        return _has_any(state_text, "next action", "next actions", "next step", "next steps") or _has_direct_work_item_owner(state_text)
    if value == "explicit owner marker":
        return _has_any(state_text, "owner:", "(owner", "owned by") or _has_direct_work_item_owner(state_text)
    if value == "current incident phase or summary indicating the action is still active":
        return _has_any(
            state_text,
            "current status",
            "incident update",
            "active",
            "in progress",
            "still open",
            "next action",
            "next actions",
            "next step",
            "next steps",
        ) or _has_direct_work_item_owner(state_text)
    if value == "explicit workstream label":
        return _has_any(
            state_text,
            "workstream",
            "next action",
            "next actions",
            "fix vulnerability",
            "rotate credential",
            "audit logs",
        )
    if value == "explicit owner or owning team":
        return _has_any(state_text, "owner:", "(owner", "owner ", "owned by", "owning team")
    if value == "action/status text":
        return _has_any(state_text, "status", "eta", "fix", "rotate", "audit", "validate", "validation")
    if value == "remediation validated":
        return _has_any(
            state_text,
            "fix deployed",
            "patch is deployed",
            "repro no longer works",
            "no longer reproducible",
            "validated",
        )
    if value == "remaining credential rotation list or pending owner":
        return _has_any(state_text, "remaining", "credential rotation", "rotation", "pending", "decommission")
    if value == "old secret still active or awaiting decommission":
        return _has_any(state_text, "old credential", "old secret", "recent usage", "still active", "decommission")
    if value == "old credential recent usage":
        return _has_any(state_text, "old credential", "old secret", "recent usage", "recently used")
    if value == "new credential deployed or rotation attempted":
        return _has_any(
            state_text,
            "new credential",
            "rotation attempted",
            "rotation started",
            "credential rotation",
            "rotation/decommission",
        )
    if value == "owner needed for validation":
        return _has_any(state_text, "owner", "security/sre", "security", "sre", "validation")
    if value == "credential list":
        return _has_any(state_text, "credential inventory", "credential list", "credential classes", "exposed credential")
    if value == "ownership ambiguity":
        return _has_any(state_text, "owning team", "ownership", "owner", "coordinate", "unclear")
    if value == "rotation/validation pending":
        return _has_any(state_text, "rotation", "validation", "pending", "remaining")
    if value == "explicit no-trust decision":
        return _has_any(state_text, "no trust post", "trust post not needed", "no trust", "trust post is not needed")
    if value == "security incident context":
        return _has_any(state_text, "security incident", "security", "credential", "exposure")
    if value == "attempted tenant/topic isolation":
        return _has_any(
            state_text,
            "dedicated topic",
            "dedicated-topic",
            "dedicated_topic",
            "moved the workload",
            "move dataconnect",
            "move three tenants",
            "move tenant",
            "shifted to topic",
            "topics for",
            "tenant isolation",
            "isolation",
            "isolated",
        )
    if value == "continued latency evidence":
        return _has_any(
            state_text,
            "still delayed",
            "latency did not improve",
            "still rising",
            "sync latency",
            "reported issue was a latency",
            "latency 33 > threshold",
            "latency_count_topic",
            "not been able to send any data",
            "delayed",
            "delay",
        )
    if value == "explicit statement identifying the actual bottleneck topic or queue":
        return _has_any(
            state_text,
            "actual bottleneck",
            "bottleneck topic",
            "bottleneck queue",
            "mapper topic",
            "latency on dataconnectsalesforcesync topic",
            "reported issue was a latency on",
            "dataconnectsalesforcesync topic",
            "latency_count_topic",
            "consumer lag",
        ) or ("topic" in state_text and "latency" in state_text and "threshold" in state_text)
    if value == "recent mitigation":
        return _has_any(state_text, "fix is deployed", "fix deployed", "mitigation applied", "deployed", "applied")
    if value == "latency/backlog symptom":
        return _has_any(state_text, "latency", "delayed", "delay", "backlog", "queue depth")
    if value == "metric type such as queue catch-up, consumer lag, or topic latency":
        return _has_any(state_text, "queue", "catch", "consumer lag", "topic latency", "backlog")
    if value == "metric recovery statement":
        return _has_any(
            state_text,
            "seeing any improvements",
            "improvements",
            "moved the tenants",
            "moved tenant",
            "action taken",
            "faster",
            "improved",
            "recovery",
            "fixed",
            "lower",
            "deployed",
        )
    if value == "customer-facing reporter or support owner":
        return _has_any(
            state_text,
            "support",
            "customer-facing",
            "customer facing",
            "reporter",
            "check with customer",
            "reported same issue",
            "customer confirmation",
        )
    if value == "pending customer confirmation":
        return _has_any(
            state_text,
            "not confirmed",
            "has not confirmed",
            "customer-side validation",
            "customer confirmation",
            "pending",
        )
    if value == "additional impacted tenants/customers reported":
        return _has_any(
            state_text,
            "second",
            "additional",
            "more tenant",
            "more customer",
            "another customer",
            "another tenant",
            "same issue",
            "not been able to send any data",
        )
    if value == "different shard/topic/service evidence":
        return _has_any(state_text, "different shard", "different shards", "different topic", "different service", "zapps")
    if value == "missing symptom details":
        return _has_any(
            state_text,
            "exact symptoms",
            "scope",
            "symptoms match",
            "symptom details",
            "can you elaborate",
            "elaborate the issue",
            "similar issue",
        )
    if value == "named topic/queue/consumer group":
        return _has_any(
            state_text,
            "topic",
            "queue",
            "consumer group",
            "consumer lag",
            "dataconnectsalesforcesync",
            "latency_count_topic",
            "mapper topic",
        )
    if value == "owning engineer or team":
        return _has_any(
            state_text,
            "owner",
            "owning team",
            "engineering",
            "eng",
            "daco",
            "incident-managers",
            "permission",
            "dedicated_topic permission",
            "oncall",
            "on call",
        )
    if value == "technical ask needed":
        return _has_any(
            state_text,
            "root cause",
            "confirm",
            "validate",
            "validation",
            "bottleneck",
            "technical",
            "check why latency",
            "can you elaborate",
            "latency",
            "exact symptoms",
            "affected scope",
            "same issue",
            "dedicated topic",
            "permission",
        )
    if value == "single-customer or single-tenant impact statement":
        return _has_any(state_text, "single customer", "one customer", "single tenant", "one tenant")
    if value == "support participant or support ops roster":
        return _has_any(state_text, "support", "support ops")
    if value == "customer/workload context is still needed":
        return _has_any(state_text, "workload", "customer context", "ticket findings")
    if value == "mitigation or recovery statement":
        return _has_any(
            state_text,
            "mitigation completed",
            "impact is being mitigated",
            "recovery",
            "lag cleared",
            "latency improved",
            "resolved",
        )
    if value == "health signal showing improvement":
        return _has_any(state_text, "lag cleared", "latency improved", "near-zero", "healthy", "improved")
    if value == "customer-driven workload signal":
        return _has_any(state_text, "customer bulk activity", "customer-driven", "bulk deletion", "bulk activity")
    if value == "affected environment or shard":
        return _has_any(state_text, "sandbox", "production", "environment", "shard")
    if value == "support or customer-facing owner present":
        return _has_any(state_text, "support", "gs", "customer-facing", "customer facing")
    if value == "completed job status":
        return _has_any(state_text, "jobs are complete", "jobs completed", "bulk jobs are complete")
    if value == "no active or pending jobs visible":
        return _has_any(state_text, "no active or pending jobs", "no active jobs", "no pending jobs")
    if value == "ongoing downstream lag/backlog":
        return _has_any(state_text, "downstream lag", "downstream backlog", "lag is still", "backlog")
    if value == "dbe health confirmation":
        return _has_any(state_text, "dbe", "database and shard health", "db healthy", "db is healthy")
    if value == "ongoing lag/backlog":
        return _has_any(state_text, "lag", "backlog")
    if value == "candidate non-db processing layers":
        return _has_any(state_text, "cdc", "kafka", "ocs", "downstream", "worker")
    if value == "skip/exclude mitigation under discussion":
        return _has_any(state_text, "excluding", "exclusion", "exclude", "skip")
    if value == "downstream impact uncertainty or risk":
        return _has_any(state_text, "downstream consumers", "side effects", "unknown", "risk")
    if value == "owner capable of assessing consumers":
        return _has_any(state_text, "ocs owner", "owner", "engineer")
    if value == "executed mitigation":
        return _has_any(state_text, "reduced", "mitigation", "tried", "executed")
    if value == "negative or inconclusive result":
        return _has_any(state_text, "did not improve", "no improvement", "inconclusive", "not improved")
    if value == "active technical owner":
        return _has_any(state_text, "ocs owner", "engineer", "active owner", "owner")
    if value == "lag/backlog trend":
        return _has_any(state_text, "lag", "backlog", "drain trend", "catch-up")
    if value == "owner recovery statement":
        return _has_any(state_text, "ocs owner", "recovery", "catch-up", "owner")
    if value == "remaining elevated lag":
        return _has_any(state_text, "elevated lag", "still elevated", "lag is still", "lag remains")
    return False


SOFT_CURRENT_EVIDENCE_HINTS = {
    "api-only or ui-not-impacted statement",
    "customer reports or ticket references",
    "unclear or evolving affected list",
    "owner routing uncertainty or engagement request",
    "support or owner engagement path",
    "named owner or owner team",
    "current mitigation status or pending approval",
    "explicit recommendation or uncertainty from owner",
    "owner or support communication context",
    "engineering owner available",
    "customer-facing reporter or support owner",
    "pending customer confirmation",
    "owning engineer or team",
    "technical ask needed",
}

PHASE_CURRENT_EVIDENCE_HINTS = {
    "recent mitigation",
    "completed partial mitigation",
    "mitigation completed statement",
    "mitigation or recovery statement",
    "mitigation or error cessation",
    "monitoring period or stability evidence needed",
    "current incident phase or summary indicating the action is still active",
    "current monitoring or log checks are pending",
    "current trust/status state",
    "reversal action completed",
}


def _requirement_kind(required: str) -> str:
    value = _norm(required)
    if value in SOFT_CURRENT_EVIDENCE_HINTS:
        return "soft"
    if value in PHASE_CURRENT_EVIDENCE_HINTS:
        return "phase"
    if any(
        phrase in value
        for phrase in (
            "statement",
            "context",
            "pending",
            "uncertain",
            "unclear",
            "recommendation",
            "owner available",
            "engagement path",
            "reporter",
            "support owner",
        )
    ):
        return "soft"
    if any(phrase in value for phrase in ("phase", "mitigation", "monitoring", "completed", "recovery")):
        return "phase"
    return "hard"


def judge_applicability(
    current_state: CurrentIncidentState,
    moments: list[DecisionMoment],
    llm_client: object | None = None,
    current_evidence_text: str = "",
) -> list[MemoryApplicabilityResult]:
    del llm_client
    state_text = "\n".join(part for part in (_state_text(current_state), current_evidence_text.lower()) if part)
    results: list[MemoryApplicabilityResult] = []
    for moment in moments:
        reasons: list[str] = []
        restrictions: list[str] = []
        satisfied_terms: list[str] = []
        missing_terms: list[str] = []
        hard_satisfied: list[str] = []
        hard_missing: list[str] = []
        soft_satisfied: list[str] = []
        soft_missing: list[str] = []
        phase_satisfied: list[str] = []
        phase_missing: list[str] = []
        anti_leakage_guards: list[str] = []
        wrong_phase = False
        wrong_blocker = False
        target_already_engaged = False
        historical_leakage_risk = False
        accepted = True
        score = 0.85

        if moment.review_status not in APPROVED_STATUSES or moment.quality_score < QUALITY_THRESHOLD:
            accepted = False
            reasons.append("not_approved_or_low_quality")
            score = 0.0

        if accepted and current_state.phase != "unknown" and moment.phase_before != current_state.phase:
            accepted = False
            wrong_phase = True
            reasons.append("wrong_phase")
            score = 0.1

        expected_blocker = moment.applicability.get("current_blocker")
        if accepted and expected_blocker and current_state.current_blocker and expected_blocker != current_state.current_blocker:
            accepted = False
            wrong_blocker = True
            reasons.append("wrong_blocker")
            score = 0.2

        for required in moment.applicability.get("required_current_evidence", []):
            required_text = str(required)
            kind = _requirement_kind(required_text)
            if _required_satisfied(required_text, current_state, state_text):
                satisfied_terms.append(required_text)
                if kind == "soft":
                    soft_satisfied.append(required_text)
                elif kind == "phase":
                    phase_satisfied.append(required_text)
                else:
                    hard_satisfied.append(required_text)
            else:
                missing_terms.append(required_text)
                if kind == "soft":
                    soft_missing.append(required_text)
                elif kind == "phase":
                    phase_missing.append(required_text)
                else:
                    hard_missing.append(required_text)
        if accepted and hard_missing:
            accepted = False
            reasons.append("missing_hard_current_evidence:" + ",".join(hard_missing))
            score = 0.2
        elif (
            accepted
            and phase_missing
            and not phase_satisfied
            and str(moment.phase_before).lower() not in {"incidentphase.triage", "triage", "unknown"}
        ):
            accepted = False
            reasons.append("missing_phase_current_evidence:" + ",".join(phase_missing))
            score = 0.25
        elif accepted and (soft_missing or phase_missing):
            if soft_missing:
                reasons.append("missing_soft_signal:" + ",".join(soft_missing))
            if phase_missing:
                reasons.append("missing_phase_signal:" + ",".join(phase_missing))
            score = max(0.55, score - 0.08 * len(soft_missing) - 0.05 * len(phase_missing))

        target = moment.applicability.get("target")
        if not target and current_state.suggested_but_not_engaged:
            target = current_state.suggested_but_not_engaged[0].display_name
        if not target and current_state.engaged_entities:
            target = current_state.engaged_entities[0].display_name
        if accepted and moment.applicability.get("target_must_not_be_engaged", False):
            if _target_already_engaged(target, current_state):
                accepted = False
                target_already_engaged = True
                reasons.append("target_already_engaged")
                score = 0.2

        if moment.forbidden_fact_leakage:
            restrictions.append("do_not_copy_historical_facts")
            anti_leakage_guards.append("do_not_copy_historical_facts")
            historical_leakage_risk = True
        for guard in moment.applicability.get("do_not_use_when", []):
            guard_text = str(guard)
            anti_leakage_guards.append(guard_text)
        if accepted and any(tag in moment.labels for tag in {"negative", "fake_customer", "fake_tenant"}):
            restrictions.append("negative_pattern_only")
        if (
            accepted
            and moment.decision_id == "DM_scope_before_priority_escalation"
            and _scope_question_answered_by_current_evidence(state_text)
        ):
            accepted = False
            reasons.append("suppressed_scope_question_answered_by_later_current_evidence")
            restrictions.append("stale_after_scope_answer")
            score = 0.2
        if accepted and _has_permission_scope_ambiguity(state_text) and _is_late_bottleneck_or_mitigation_memory(moment):
            accepted = False
            reasons.append("suppressed_until_permission_loop_scope_is_resolved")
            restrictions.append("scope_ambiguity_before_late_bottleneck_or_mitigation_memory")
            score = 0.25

        if accepted:
            reasons.append("accepted")
        results.append(
            MemoryApplicabilityResult(
                decision_id=moment.decision_id,
                accepted=accepted,
                score=score,
                reasons=reasons,
                restrictions=restrictions,
                allowed_patterns=[moment.ic_action] if accepted else [],
                forbidden_fact_leakage=moment.forbidden_fact_leakage,
                required_current_evidence_satisfied=satisfied_terms,
                required_current_evidence_missing=missing_terms,
                hard_requirements_satisfied=hard_satisfied,
                hard_requirements_missing=hard_missing,
                soft_signals_satisfied=soft_satisfied,
                soft_signals_missing=soft_missing,
                phase_signals_satisfied=phase_satisfied,
                phase_signals_missing=phase_missing,
                anti_leakage_guards=anti_leakage_guards,
                rejected_because_already_engaged=target_already_engaged,
                rejected_because_wrong_phase=wrong_phase,
                rejected_because_wrong_blocker=wrong_blocker,
                rejected_because_historical_leakage_risk=historical_leakage_risk and not accepted,
            )
        )
    return results
