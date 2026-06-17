from __future__ import annotations

import concurrent.futures
import re
from dataclasses import dataclass
from typing import Any

from ic_copilot.incident_brief import compact_allowed_targets_for_brief, compact_incident_brief_events
from ic_copilot.llm.base import LLMClient
from ic_copilot.schema_repair import validate_with_repair
from ic_copilot.schemas import (
    ActorLedgerItem,
    ActorWorkstreamLedger,
    AllowedTarget,
    CleanTurn,
    CleanTurnLedger,
    CurrentIncidentState,
    ICMove,
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
    IncidentFactLedger,
    IncidentPhase,
    InputSizeAssessment,
    LedgerFact,
    QuestionIntentItem,
    QuestionIntentLedger,
    WorkstreamLedgerItem,
)


LEDGER_PROMPTS: dict[str, type] = {
    "clean_turn_ledger": CleanTurnLedger,
    "actor_workstream_ledger": ActorWorkstreamLedger,
    "incident_fact_ledger": IncidentFactLedger,
    "question_intent_ledger": QuestionIntentLedger,
}


@dataclass
class ParallelSemanticReadResult:
    clean_turn_ledger: CleanTurnLedger | None = None
    actor_workstream_ledger: ActorWorkstreamLedger | None = None
    incident_fact_ledger: IncidentFactLedger | None = None
    question_intent_ledger: QuestionIntentLedger | None = None
    errors: dict[str, str] | None = None

    @property
    def success_count(self) -> int:
        return sum(
            item is not None
            for item in (
                self.clean_turn_ledger,
                self.actor_workstream_ledger,
                self.incident_fact_ledger,
                self.question_intent_ledger,
            )
        )


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


CONFIRMATION_RESOLVED_TERMS = (
    "got reply",
    "confirmed",
    "customer said",
    "they have been",
    "they are doing",
    "we found",
    "root cause points to",
    "identified",
)
STOP_OR_PAUSE_TERMS = ("can we stop", "can they stop", "pause", "stop the process", "can stop", "can pause")
SCOPE_VALIDATION_TERMS = (
    "same activity",
    "sandboxes",
    "sandbox",
    "confirm whether ongoing",
    "also affecting",
    "limited to",
)
MONITORING_SIGNAL_TERMS = ("monitor", "signal", "lag", "latency", "db load", "database load", "worker pod", "metric")


def _is_human_operator_event(event: IncidentEvent) -> bool:
    tokens = event.extracted_tokens or {}
    return bool(event.author) and not bool(tokens.get("is_bot") or tokens.get("is_system"))


def _target_for_author(allowed_targets: list[AllowedTarget], author: str | None) -> AllowedTarget | None:
    if not author:
        return None
    author_norm = _norm(author)
    return next(
        (
            target
            for target in allowed_targets
            if target.targetable
            and target.target_quality in {"high", "medium"}
            and _norm(target.display_name) == author_norm
        ),
        None,
    )


def _mentioned_target_names(event: IncidentEvent, allowed_targets: list[AllowedTarget]) -> list[str]:
    mention_norms = {
        _norm(str(mention))
        for mention in (event.extracted_tokens or {}).get("slack_mentions", [])
        if _norm(str(mention)) not in {"here", "@here", "channel", "@channel"}
    }
    return [
        target.display_name
        for target in allowed_targets
        if target.targetable and target.target_quality in {"high", "medium"} and _norm(target.display_name) in mention_norms
    ]


def _fallback_workstream_for_event(event: IncidentEvent, allowed_targets: list[AllowedTarget]) -> WorkstreamLedgerItem | None:
    text_norm = _norm(event.message)
    owner_names = [name for name in [event.author, *_mentioned_target_names(event, allowed_targets)] if name]
    summary = " ".join(event.message.split())[:260]
    if not owner_names or not summary:
        return None
    if any(term in text_norm for term in STOP_OR_PAUSE_TERMS):
        return WorkstreamLedgerItem(
            type="mitigation",
            status="in_progress",
            owner_or_actor_names=owner_names[:3],
            summary=f"Mitigation/pause decision is unresolved in latest human evidence: {summary}",
            evidence_ids=[event.event_id],
        )
    if any(term in text_norm for term in SCOPE_VALIDATION_TERMS):
        return WorkstreamLedgerItem(
            type="validation",
            status="in_progress",
            owner_or_actor_names=owner_names[:3],
            summary=f"Scope validation is unresolved in latest human evidence: {summary}",
            evidence_ids=[event.event_id],
        )
    if any(term in text_norm for term in MONITORING_SIGNAL_TERMS):
        return WorkstreamLedgerItem(
            type="monitoring",
            status="in_progress",
            owner_or_actor_names=owner_names[:3],
            summary=f"Recovery monitoring/status signal is visible in latest human evidence: {summary}",
            evidence_ids=[event.event_id],
        )
    if any(term in text_norm for term in CONFIRMATION_RESOLVED_TERMS):
        return WorkstreamLedgerItem(
            type="customer_comms",
            status="completed",
            owner_or_actor_names=owner_names[:3],
            summary=f"Customer/support confirmation is answered in latest human evidence: {summary}",
            evidence_ids=[event.event_id],
        )
    if any(term in text_norm for term in ("checking", "investigating", "status", "eta", "confirm")):
        return WorkstreamLedgerItem(
            type="investigation",
            status="in_progress",
            owner_or_actor_names=owner_names[:3],
            summary=f"Investigation/status work is visible in latest human evidence: {summary}",
            evidence_ids=[event.event_id],
        )
    return None


def build_fallback_workstream_ledger(
    incident_id: str,
    events: list[IncidentEvent],
    allowed_targets: list[AllowedTarget],
) -> ActorWorkstreamLedger:
    """Build conservative workstream metadata from latest human events.

    This is not semantic truth. It is deterministic evidence plumbing used when
    actor/workstream readers fail or return no active workstreams.
    """
    latest_human = [event for event in events if _is_human_operator_event(event)][-10:]
    actors_by_name: dict[str, ActorLedgerItem] = {}
    workstreams: list[WorkstreamLedgerItem] = []
    seen_workstreams: set[tuple[str, tuple[str, ...]]] = set()
    for event in latest_human:
        target = _target_for_author(allowed_targets, event.author)
        if target:
            text_norm = _norm(event.message)
            role_hint = target.role_hint
            if any(term in text_norm for term in (*STOP_OR_PAUSE_TERMS, *SCOPE_VALIDATION_TERMS, *CONFIRMATION_RESOLVED_TERMS)):
                role_hint = "reporter_or_validator"
            elif any(term in text_norm for term in MONITORING_SIGNAL_TERMS):
                role_hint = "technical_investigator"
            actors_by_name[target.display_name] = ActorLedgerItem(
                name=target.display_name,
                actor_type="person" if target.target_type == "person" else "team" if target.target_type == "team" else "service",
                role_hint=role_hint,  # type: ignore[arg-type]
                current_status="actively_working",
                last_visible_action=" ".join(event.message.split())[:220],
                evidence_ids=[event.event_id],
                targetable=True,
            )
        workstream = _fallback_workstream_for_event(event, allowed_targets)
        if workstream:
            key = (workstream.type, tuple(workstream.evidence_ids))
            if key not in seen_workstreams:
                workstreams.append(workstream)
                seen_workstreams.add(key)
    return ActorWorkstreamLedger(
        incident_id=incident_id,
        actors=list(actors_by_name.values()),
        workstreams=workstreams[-6:],
        warnings=["deterministic_fallback_workstream_builder_used"],
    )


def _phase_value(value: str | None) -> IncidentPhase:
    label = _norm(value).replace(" ", "_")
    mapping = {
        "triage": IncidentPhase.TRIAGE,
        "engagement": IncidentPhase.ENGAGEMENT,
        "investigation": IncidentPhase.INVESTIGATION,
        "investigating": IncidentPhase.INVESTIGATION,
        "mitigation": IncidentPhase.MITIGATION,
        "monitoring": IncidentPhase.MONITORING,
        "validation": IncidentPhase.MONITORING,
        "verification": IncidentPhase.VERIFICATION,
        "handoff": IncidentPhase.HANDOFF,
        "closed": IncidentPhase.CLOSED,
        "resolved": IncidentPhase.RESOLVED,
    }
    return mapping.get(label, IncidentPhase.UNKNOWN)


def _blocker_type(value: str | None) -> str:
    text = _norm(value)
    if any(term in text for term in STOP_OR_PAUSE_TERMS):
        return "mitigation_status_needed"
    if any(term in text for term in SCOPE_VALIDATION_TERMS):
        return "validation_needed"
    if any(term in text for term in ("owner", "dri", "engage")):
        return "missing_owner"
    if any(term in text for term in ("code fix", "hotfix", "fix status")):
        return "code_fix_status_needed"
    if any(term in text for term in ("deploy", "deployment", "release")):
        return "deployment_validation_needed"
    if any(term in text for term in ("monitor", "metric", "dashboard", "signal", "stable", "health")):
        return "monitoring_needed"
    if any(term in text for term in ("mitigation", "rollback", "disable", "restart", "workaround")):
        return "mitigation_status_needed"
    if any(term in text for term in ("status", "eta", "waiting", "active work", "still running")):
        return "status_eta_needed"
    if any(term in text for term in ("validate", "validation", "confirm", "scope", "result")):
        return "validation_needed"
    if any(term in text for term in ("customer", "tenant", "impact", "scope")):
        return "customer_scope_needed"
    if "rca" in text or "root cause" in text:
        return "rca_owner_needed"
    return "unknown"


def _target_by_name(allowed_targets: list[AllowedTarget], name: str) -> AllowedTarget | None:
    name_norm = _norm(name)
    return next((target for target in allowed_targets if _norm(target.display_name) == name_norm), None)


def _event_ids(events: list[IncidentEvent]) -> list[str]:
    return [event.event_id for event in events]


def _visible_operator_intent(events: list[IncidentEvent], ledger: CleanTurnLedger | None) -> tuple[str, str, list[str]] | None:
    intent_terms = (
        "can you confirm",
        "could you confirm",
        "please confirm",
        "confirm if",
        "confirm whether",
        "got reply",
        "customer said",
        "they have been",
        "they are doing",
        "can we stop",
        "can they stop",
        "stop the process",
        "pause",
        "same activity",
        "sandboxes",
        "await",
        "need",
        "next action",
        "next actions",
        "checking",
        "status",
        "validation",
        "validate",
    )
    candidate_rows: list[tuple[str, str]] = []
    if ledger is not None:
        candidate_rows.extend(
            (event_id, turn.summary)
            for turn in ledger.clean_turns[-12:]
            for event_id in (turn.event_ids or [])
            if turn.summary
        )
    if not candidate_rows:
        candidate_rows.extend((event.event_id, event.message) for event in events[-12:])
    for event_id, text in reversed(candidate_rows):
        text_norm = _norm(text)
        if not any(term in text_norm for term in intent_terms):
            continue
        if any(term in text_norm for term in STOP_OR_PAUSE_TERMS):
            blocker = "mitigation_status_needed"
        elif any(term in text_norm for term in SCOPE_VALIDATION_TERMS):
            blocker = "validation_needed"
        elif any(term in text_norm for term in ("monitor", "metric", "dashboard", "signal", "cpu", "query", "load")):
            blocker = "monitoring_needed"
        elif any(term in text_norm for term in ("mitigation", "queue", "rollback", "disable", "dedicated queue")):
            blocker = "mitigation_status_needed"
        elif any(term in text_norm for term in ("status", "eta", "checking", "await")):
            blocker = "status_eta_needed"
        else:
            blocker = "validation_needed"
        return blocker, text.strip()[:260], [event_id]
    return None


def _generic_blocker_text(value: str | None) -> bool:
    text = _norm(value)
    if not text:
        return True
    generic_exact = {
        "need current status or validation signal.",
        "validation status is the visible blocker.",
        "technical investigation status is the visible blocker.",
        "latest blocker is unclear from the semantic ledgers.",
    }
    if text in {item.rstrip(".") for item in generic_exact} or text in generic_exact:
        return True
    return "visible blocker" in text or "unclear from semantic ledgers" in text


def build_semantic_read_payload(
    *,
    incident_id: str,
    events: list[IncidentEvent],
    allowed_targets: list[AllowedTarget],
    input_size_assessment: InputSizeAssessment,
    current_state: CurrentIncidentState,
    max_chars_per_event: int = 500,
    max_targets: int = 10,
) -> dict[str, Any]:
    compact_events = compact_incident_brief_events(events, max_chars_per_event=max_chars_per_event)
    compact_targets = compact_allowed_targets_for_brief(allowed_targets, max_targets=max_targets)
    rejected_examples = [
        {
            "display_name": target.display_name,
            "reason": target.reason,
            "evidence_ids": target.evidence_ids[:3],
        }
        for target in allowed_targets
        if not target.targetable
    ][:12]
    return {
        "incident_id": incident_id,
        "events": compact_events,
        "event_ids": [event["event_id"] for event in compact_events],
        "allowed_targets": compact_targets,
        "allowed_target_count": len(allowed_targets),
        "allowed_target_payload_count": len(compact_targets),
        "rejected_noise_examples": rejected_examples,
        "input_size_assessment": input_size_assessment.model_dump(mode="json"),
        "current_state_summary": {
            "incident_id": current_state.incident_id,
            "phase": str(getattr(current_state.phase, "value", current_state.phase)),
            "current_blocker": current_state.current_blocker,
            "compact_summary": current_state.compact_summary,
            "stale_question_intents": list(current_state.stale_question_intents),
        },
        "rules": [
            "Use current event evidence only.",
            "Preserve event IDs.",
            "Do not infer tenants from URL path numbers.",
            "Do not infer customers from URL domains.",
            "Do not turn bot placeholders, logs, table fragments, or ticket IDs into targetable actors.",
        ],
    }


def extract_clean_turn_ledger(payload: dict[str, Any], llm_client: LLMClient) -> CleanTurnLedger:
    return validate_with_repair(llm_client.generate_json("clean_turn_ledger", payload, CleanTurnLedger), CleanTurnLedger, context="clean_turn_ledger")


def extract_actor_workstream_ledger(payload: dict[str, Any], llm_client: LLMClient) -> ActorWorkstreamLedger:
    return validate_with_repair(
        llm_client.generate_json("actor_workstream_ledger", payload, ActorWorkstreamLedger),
        ActorWorkstreamLedger,
        context="actor_workstream_ledger",
    )


def extract_incident_fact_ledger(payload: dict[str, Any], llm_client: LLMClient) -> IncidentFactLedger:
    return validate_with_repair(
        llm_client.generate_json("incident_fact_ledger", payload, IncidentFactLedger),
        IncidentFactLedger,
        context="incident_fact_ledger",
    )


def extract_question_intent_ledger(payload: dict[str, Any], llm_client: LLMClient) -> QuestionIntentLedger:
    return validate_with_repair(
        llm_client.generate_json("question_intent_ledger", payload, QuestionIntentLedger),
        QuestionIntentLedger,
        context="question_intent_ledger",
    )


def run_parallel_semantic_read(
    *,
    incident_id: str,
    events: list[IncidentEvent],
    allowed_targets: list[AllowedTarget],
    input_size_assessment: InputSizeAssessment,
    current_state: CurrentIncidentState,
    llm_client: LLMClient,
    max_workers: int = 4,
) -> tuple[ParallelSemanticReadResult, dict[str, Any]]:
    payload = build_semantic_read_payload(
        incident_id=incident_id,
        events=events,
        allowed_targets=allowed_targets,
        input_size_assessment=input_size_assessment,
        current_state=current_state,
    )
    calls = {
        "clean_turn_ledger": extract_clean_turn_ledger,
        "actor_workstream_ledger": extract_actor_workstream_ledger,
        "incident_fact_ledger": extract_incident_fact_ledger,
        "question_intent_ledger": extract_question_intent_ledger,
    }
    result = ParallelSemanticReadResult(errors={})
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(calls))) as pool:
        future_to_name = {pool.submit(func, payload, llm_client): name for name, func in calls.items()}
        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                value = future.result()
            except Exception as exc:  # caller records sanitized error
                result.errors[name] = f"{exc.__class__.__name__}: {exc}"
                continue
            setattr(result, name, value)
    summary = {
        "reader_count": len(calls),
        "success_count": result.success_count,
        "failed_readers": sorted((result.errors or {}).keys()),
        "event_count": len(events),
        "allowed_target_count": len(allowed_targets),
    }
    return result, {"summary": summary, "payload": payload}


def build_deterministic_clean_turn_ledger(incident_id: str, events: list[IncidentEvent]) -> CleanTurnLedger:
    turns: list[CleanTurn] = []
    for index, event in enumerate(events, start=1):
        text = _norm(event.message)
        tokens = event.extracted_tokens or {}
        is_bot = bool(tokens.get("is_bot") or tokens.get("is_system"))
        message_type = "human_status"
        if is_bot:
            message_type = "phase_update" if "phase" in text or "assessment" in text else "noise"
        elif "?" in event.message:
            message_type = "question"
        elif any(term in text for term in ("validate", "confirm", "still running", "responding")):
            message_type = "answer"
        elif any(term in text for term in ("log", "error", "health", "connection", "dashboard", "metric")):
            message_type = "diagnostic_log"
        elif any(term in text for term in ("restart", "rollback", "disable", "mitigat", "fix")):
            message_type = "mitigation"
        turns.append(
            CleanTurn(
                turn_id=f"turn-{index:03d}",
                speaker=event.author or "unknown",
                speaker_type="bot" if is_bot else "human",
                event_ids=[event.event_id],
                time_hint=event.ts,
                message_type=message_type,  # type: ignore[arg-type]
                summary=" ".join(event.message.split())[:220],
                key_values={},
                is_noise=message_type == "noise",
            )
        )
    return CleanTurnLedger(incident_id=incident_id, clean_turns=turns)


def build_deterministic_actor_workstream_ledger(
    incident_id: str,
    events: list[IncidentEvent],
    allowed_targets: list[AllowedTarget],
) -> ActorWorkstreamLedger:
    actors: list[ActorLedgerItem] = []
    for target in allowed_targets:
        if not target.evidence_ids and target.source not in {"catalog", "command_registry"}:
            continue
        actors.append(
            ActorLedgerItem(
                name=target.display_name,
                actor_type={"person": "person", "team": "team", "service": "service", "bot_system": "bot", "non_targetable_noise": "unknown"}.get(
                    target.target_type,
                    "unknown",
                ),  # type: ignore[arg-type]
                role_hint="bot_system" if target.target_type == "bot_system" else target.role_hint,  # type: ignore[arg-type]
                current_status="actively_working" if target.role_hint == "technical_investigator" else "mentioned",
                last_visible_action=target.reason,
                evidence_ids=target.evidence_ids[:5],
                targetable=target.targetable,
                not_targetable_reason="" if target.targetable else target.reason,
            )
        )
    all_text = _norm("\n".join(event.message for event in events))
    workstreams: list[WorkstreamLedgerItem] = []
    if any(term in all_text for term in ("investigat", "checking", "log", "dashboard", "metric")):
        workstreams.append(
            WorkstreamLedgerItem(
                type="investigation",
                status="in_progress",
                owner_or_actor_names=[actor.name for actor in actors if actor.role_hint in {"technical_investigator", "owner_team"}][:3],
                summary="Technical investigation is visible in current evidence.",
                evidence_ids=_event_ids(events[-6:]),
            )
        )
    owner_gap = any(
        term in all_text for term in ("should be engaged", "should check", "not see", "not here")
    )
    if not owner_gap and any(term in all_text for term in ("validat", "confirm", "still running", "responding")):
        workstreams.append(
            WorkstreamLedgerItem(
                type="validation",
                status="in_progress",
                owner_or_actor_names=[actor.name for actor in actors if actor.role_hint == "reporter_or_validator"][:3],
                summary="Validation or current symptom confirmation is visible.",
                evidence_ids=_event_ids(events[-6:]),
            )
        )
    if any(term in all_text for term in ("trust post", "customer comm")):
        workstreams.append(
            WorkstreamLedgerItem(
                type="trust_post",
                status="completed" if "no need" in all_text or "not needed" in all_text else "unknown",
                summary="Trust Post/customer comms are mentioned in current evidence.",
                evidence_ids=_event_ids(events),
            )
        )
    fallback = build_fallback_workstream_ledger(incident_id, events, allowed_targets)
    actor_names = {_norm(actor.name) for actor in actors}
    actors.extend(actor for actor in fallback.actors if _norm(actor.name) not in actor_names)
    seen_workstreams = {(workstream.type, tuple(workstream.evidence_ids)) for workstream in workstreams}
    for workstream in fallback.workstreams:
        key = (workstream.type, tuple(workstream.evidence_ids))
        if key not in seen_workstreams:
            workstreams.append(workstream)
            seen_workstreams.add(key)
    warnings = fallback.warnings if fallback.workstreams else []
    return ActorWorkstreamLedger(incident_id=incident_id, actors=actors, workstreams=workstreams, warnings=warnings)


def build_deterministic_incident_fact_ledger(incident_id: str, events: list[IncidentEvent]) -> IncidentFactLedger:
    all_text = "\n".join(event.message for event in events)
    text = _norm(all_text)
    phase = "investigation" if any(term in text for term in ("investigat", "checking", "log", "dashboard")) else "unknown"
    owner_gap = any(
        term in text
        for term in (
            "should be engaged",
            "should check",
            "not see",
            "not here",
            "not in channel",
            "owner confirms",
        )
    )
    if owner_gap:
        phase = "engagement"
    blocker = "Need current status or validation signal."
    if owner_gap:
        blocker = "Owner engagement or ownership confirmation is the visible blocker."
    security_details = any(term in text for term in ("security", "vulnerability", "exposure")) and any(
        term in text for term in ("details", "jira", "issue", "link", "report")
    )
    if security_details:
        blocker = "Validation, exposure scope, or containment confirmation is the visible blocker."
    if not owner_gap and not security_details and any(
        term in text for term in ("validat", "still running", "responding")
    ):
        blocker = "Validation status is the visible blocker."
    if any(term in text for term in ("trust post", "no need")) and "validat" not in text:
        blocker = "Trust Post/customer communications status is mentioned."
    tenants: list[LedgerFact] = []
    for event in events:
        for match in re.finditer(r"\b(?:tenant id|tenant|account id|account|org id)\s*[:#-]?\s*(\d{5,})\b", event.message, re.I):
            tenants.append(LedgerFact(value=match.group(1), summary="Explicit tenant/account evidence", evidence_ids=[event.event_id], confidence=0.9))
    rejected = []
    for event in events:
        for match in re.finditer(r"/(?:pages|wiki|docs)/(\d{5,})", event.message, re.I):
            rejected.append(
                IncidentBriefRejectedOrNoise(text=match.group(1), reason="url_path_number", evidence_ids=[event.event_id])
            )
    return IncidentFactLedger(
        incident_id=incident_id,
        phase=LedgerFact(value=phase, summary=phase, evidence_ids=_event_ids(events[-6:]), confidence=0.7),
        tenants=tenants,
        symptoms=[LedgerFact(value="current incident symptoms", summary=all_text[:220], evidence_ids=_event_ids(events[:3]), confidence=0.6)],
        current_blocker=LedgerFact(value=blocker, summary=blocker, evidence_ids=_event_ids(events[-4:]), confidence=0.7),
        rejected_noise=rejected,
        evidence_ids=_event_ids(events),
    )


def build_deterministic_question_intent_ledger(incident_id: str, events: list[IncidentEvent]) -> QuestionIntentLedger:
    text = _norm("\n".join(event.message for event in events))
    stale: list[str] = []
    do_not: list[QuestionIntentItem] = []
    if "trust post" in text and ("no need" in text or "not needed" in text):
        stale.append("ask_trust_post_needed")
        do_not.append(QuestionIntentItem(intent="ask_trust_post_needed", summary="Trust Post was already answered as not needed.", evidence_ids=_event_ids(events)))
    if any(term in text for term in ("zendesk", "jira", "ticket")):
        stale.append("ask_for_ticket_link")
        do_not.append(QuestionIntentItem(intent="ask_for_ticket_link", summary="Ticket/link evidence is already visible.", evidence_ids=_event_ids(events)))
    if any(term in text for term in ("details link", "vulnerability", "wf-")):
        stale.append("request_details_from_researcher")
        do_not.append(QuestionIntentItem(intent="request_details_from_researcher", summary="Details/report link evidence is already visible.", evidence_ids=_event_ids(events)))
    return QuestionIntentLedger(
        incident_id=incident_id,
        stale_question_intents=list(dict.fromkeys(stale)),
        do_not_ask=do_not,
        evidence_ids=_event_ids(events),
    )


def reduce_ledgers_to_incident_brief(
    *,
    incident_id: str,
    events: list[IncidentEvent],
    allowed_targets: list[AllowedTarget],
    semantic_read: ParallelSemanticReadResult,
) -> IncidentBrief:
    fact = semantic_read.incident_fact_ledger
    actors = semantic_read.actor_workstream_ledger
    questions = semantic_read.question_intent_ledger
    event_ids = _event_ids(events)
    phase_value = _phase_value(fact.phase.value if fact and fact.phase else None)
    blocker_text = fact.current_blocker.summary or fact.current_blocker.value if fact and fact.current_blocker else ""
    blocker_type = _blocker_type(blocker_text)
    visible_intent = _visible_operator_intent(events, semantic_read.clean_turn_ledger)
    if visible_intent is not None and _generic_blocker_text(blocker_text):
        blocker_type, blocker_text, _ = visible_intent
        if phase_value == IncidentPhase.UNKNOWN:
            phase_value = IncidentPhase.INVESTIGATION
    if blocker_type == "unknown" and actors:
        active_types = {workstream.type for workstream in actors.workstreams if workstream.status in {"in_progress", "blocked"}}
        if "validation" in active_types:
            blocker_type = "validation_needed"
            blocker_text = blocker_text or "Validation is still in progress."
        elif "investigation" in active_types:
            blocker_type = "status_eta_needed"
            blocker_text = blocker_text or "Technical investigation status is the visible blocker."
    if blocker_type == "unknown" and visible_intent is not None:
        blocker_type, blocker_text, _ = visible_intent
        if phase_value == IncidentPhase.UNKNOWN:
            phase_value = IncidentPhase.INVESTIGATION
    if not blocker_text:
        blocker_text = "Latest blocker is unclear from the semantic ledgers."
    reducer_context_norm = _norm(
        " ".join(
            (
                blocker_text,
                fact.phase.summary if fact and fact.phase else "",
                fact.symptoms[0].summary if fact and fact.symptoms else "",
                fact.diagnostic_signals[0].summary if fact and fact.diagnostic_signals else "",
            )
        )
    )
    targetable_by_name = { _norm(target.display_name): target for target in allowed_targets if target.targetable }
    role_candidates: list[IncidentBriefRoleCandidate] = []
    engaged: list[IncidentBriefEntity] = []
    preferred_ids: list[str] = []
    if actors:
        if blocker_type == "missing_owner":
            preferred_roles = {"owner_team", "support_team", "technical_investigator"}
        elif blocker_type in {
            "status_eta_needed",
            "mitigation_status_needed",
            "monitoring_needed",
            "code_fix_status_needed",
        }:
            preferred_roles = {"technical_investigator", "owner_team"}
            if blocker_type == "mitigation_status_needed":
                preferred_roles.update({"reporter_or_validator", "support_team", "ic_or_coordinator"})
        else:
            preferred_roles = {
                "reporter_or_validator",
                "technical_investigator",
                "owner_team",
                "support_team",
            }
        relevant_workstream_types = {
            "mitigation_status_needed": {"mitigation"},
            "monitoring_needed": {"monitoring", "investigation"},
            "validation_needed": {"validation", "customer_comms"},
            "status_eta_needed": {"investigation", "monitoring", "mitigation"},
        }.get(blocker_type, set())
        for workstream in actors.workstreams:
            if relevant_workstream_types and workstream.type not in relevant_workstream_types:
                continue
            if workstream.status not in {"in_progress", "blocked", "unknown"}:
                continue
            for name in workstream.owner_or_actor_names:
                target = targetable_by_name.get(_norm(name))
                if target and target.target_id not in preferred_ids:
                    preferred_ids.append(target.target_id)
        for actor in actors.actors:
            target = _target_by_name(allowed_targets, actor.name)
            if not target or not target.targetable:
                continue
            role_candidates.append(
                IncidentBriefRoleCandidate(
                    target_id=target.target_id,
                    name=target.display_name,
                    role_hint=actor.role_hint if actor.role_hint != "bot_system" else "unknown",  # type: ignore[arg-type]
                    confidence=0.75 if actor.evidence_ids else 0.5,
                    evidence_ids=actor.evidence_ids or target.evidence_ids,
                )
            )
            engaged.append(
                IncidentBriefEntity(
                    target_id=target.target_id,
                    name=target.display_name,
                    target_type=target.target_type if target.target_type in {"person", "team", "service"} else "person",  # type: ignore[arg-type]
                    role_hint=actor.role_hint if actor.role_hint != "bot_system" else "unknown",  # type: ignore[arg-type]
                    status=actor.current_status,
                    evidence_ids=actor.evidence_ids or target.evidence_ids,
                )
            )
        for actor in actors.actors:
            target = targetable_by_name.get(_norm(actor.name))
            has_current_actor_evidence = bool(
                target and (actor.evidence_ids or _norm(target.display_name) in reducer_context_norm)
            )
            if (
                target
                and actor.role_hint in preferred_roles
                and has_current_actor_evidence
                and target.target_id not in preferred_ids
            ):
                preferred_ids.append(target.target_id)
    if not preferred_ids and visible_intent is not None:
        visible_ids = set(visible_intent[2])
        for target in allowed_targets:
            if not target.targetable:
                continue
            if visible_ids.intersection(target.evidence_ids):
                preferred_ids.append(target.target_id)
            if len(preferred_ids) >= 3:
                break
    workstreams = []
    if actors:
        for workstream in actors.workstreams:
            owner_ids = [
                targetable_by_name[_norm(name)].target_id
                for name in workstream.owner_or_actor_names
                if _norm(name) in targetable_by_name
            ]
            workstreams.append(
                IncidentBriefWorkstream(
                    workstream_type={
                        "customer_comms": "trust_post_or_comms",
                        "deployment_or_change": "change_deployment_check",
                        "trust_post": "trust_post_or_comms",
                        "unknown": "other",
                    }.get(workstream.type, workstream.type),  # type: ignore[arg-type]
                    status={"in_progress": "active", "not_started": "proposed"}.get(workstream.status, workstream.status),  # type: ignore[arg-type]
                    summary=workstream.summary,
                    owner_target_ids=owner_ids,
                    evidence_ids=workstream.evidence_ids,
                )
            )
    do_not_ask = []
    if questions:
        for item in questions.do_not_ask:
            do_not_ask.append(IncidentBriefDoNotAsk(intent=item.intent, reason=item.summary, evidence_ids=item.evidence_ids))
        for intent in questions.stale_question_intents:
            if all(existing.intent != intent for existing in do_not_ask):
                do_not_ask.append(IncidentBriefDoNotAsk(intent=intent, reason="Question intent was marked stale by semantic read.", evidence_ids=questions.evidence_ids))
    rejected = list(fact.rejected_noise if fact else [])
    uncertainty = []
    if fact:
        uncertainty.extend(
            IncidentBriefUncertainty(item=item.value or item.summary, why_it_matters=item.summary or "Uncertain current fact.", evidence_ids=item.evidence_ids)
            for item in fact.uncertainty
        )
    summary_parts = []
    if fact and fact.symptoms:
        summary_parts.append(fact.symptoms[0].summary or fact.symptoms[0].value)
    if fact and fact.diagnostic_signals:
        summary_parts.append(fact.diagnostic_signals[0].summary or fact.diagnostic_signals[0].value)
    if not summary_parts and semantic_read.clean_turn_ledger and semantic_read.clean_turn_ledger.clean_turns:
        summary_parts.append("; ".join(turn.summary for turn in semantic_read.clean_turn_ledger.clean_turns[-3:] if turn.summary))
    current_summary = " ".join(part for part in summary_parts if part).strip()[:900] or blocker_text
    acceptable_moves = {
        "missing_owner": [ICMove.CONFIRM_OWNERSHIP, ICMove.ENGAGE_OWNER],
        "validation_needed": [ICMove.ASK_NEXT_VALIDATION],
        "monitoring_needed": [ICMove.REQUEST_MONITORING_SIGNAL, ICMove.REQUEST_STATUS_OR_ETA],
        "mitigation_status_needed": [ICMove.REQUEST_MITIGATION_OPTION, ICMove.REQUEST_STATUS_OR_ETA],
        "status_eta_needed": [ICMove.REQUEST_STATUS_OR_ETA, ICMove.ASK_NEXT_VALIDATION],
        "code_fix_status_needed": [ICMove.REQUEST_STATUS_OR_ETA],
        "deployment_validation_needed": [ICMove.CONFIRM_DEPLOYMENT_RELATED, ICMove.ASK_NEXT_VALIDATION],
        "customer_scope_needed": [ICMove.ASK_IMPACT, ICMove.ASK_NEXT_VALIDATION],
        "rca_owner_needed": [ICMove.REQUEST_STATUS_OR_ETA],
    }.get(blocker_type, [ICMove.ASK_NEXT_VALIDATION])
    return IncidentBrief(
        incident_id=incident_id,
        based_on_event_ids=event_ids,
        latest_window_event_ids=event_ids,
        latest_window_used=True,
        partial_context=False,
        current_summary=current_summary,
        phase=IncidentBriefValue(primary=phase_value, confidence=0.75 if phase_value != IncidentPhase.UNKNOWN else 0.3, evidence_ids=event_ids[-6:]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type=blocker_type,  # type: ignore[arg-type]
            summary=blocker_text,
            evidence_ids=(
                fact.current_blocker.evidence_ids
                if fact and fact.current_blocker
                else (visible_intent[2] if visible_intent else event_ids[-4:])
            ),
            confidence=0.75 if blocker_type != "unknown" else 0.3,
        ),
        completed_actions=[
            IncidentBriefCompletedAction(action_type="current_action", summary=item.summary or item.value, evidence_ids=item.evidence_ids)
            for item in (fact.completed_actions if fact else [])
            if item.evidence_ids
        ],
        active_workstreams=workstreams,
        engaged_entities=engaged,
        role_candidates=role_candidates,
        do_not_ask=do_not_ask,
        rejected_or_noise=rejected,
        recommended_ic_focus=IncidentBriefFocus(
            summary=blocker_text,
            preferred_target_ids=preferred_ids[:4],
            acceptable_move_types=acceptable_moves,
            evidence_ids=(
                fact.current_blocker.evidence_ids
                if fact and fact.current_blocker
                else (visible_intent[2] if visible_intent else event_ids[-4:])
            ),
        ),
        uncertainty=uncertainty,
        warnings=[
            *(semantic_read.clean_turn_ledger.warnings if semantic_read.clean_turn_ledger else []),
            *(semantic_read.actor_workstream_ledger.warnings if semantic_read.actor_workstream_ledger else []),
            *(semantic_read.incident_fact_ledger.warnings if semantic_read.incident_fact_ledger else []),
            *(semantic_read.question_intent_ledger.warnings if semantic_read.question_intent_ledger else []),
        ],
    )
