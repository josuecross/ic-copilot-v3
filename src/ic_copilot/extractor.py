from __future__ import annotations

import re
from urllib.parse import urlparse

from ic_copilot.llm.base import LLMClient
from ic_copilot.schema_repair import validate_with_repair
from ic_copilot.schemas import (
    ActionRecord,
    CleanContextEntity,
    CleanIncidentContext,
    CurrentIncidentState,
    EvidenceBackedFact,
    EntityRef,
    EntityType,
    EvidenceRef,
    ImpactState,
    IncidentEvent,
    IncidentPhase,
    LinkRef,
    QuestionRecord,
    Severity,
    StateDelta,
)


TRUST_POST_INTENTS = (
    "ask_trust_post_needed",
    "confirm_trust_post_needed",
    "trust_post_confirmation",
)
SECURITY_DETAILS_INTENTS = (
    "request_details_from_researcher",
    "request_vulnerability_details",
    "ask_reporter_for_more_details",
    "ask_security_reporter_for_details",
    "request_observations",
    "request_next_actions_from_reporter",
    "ask_reporter_observations_next_actions",
)
SYSTEM_ENTITY_LABELS = {
    "added by zsrebot",
    "app",
    "default_agent",
    "incident assessment",
    "jira cloud",
    "phase update",
    "pinned by",
    "preview in slack",
    "show more",
}
SYSTEM_AUTHORS = {
    "app",
    "ic",
    "ic bot",
    "im-agent",
    "incident assessment",
    "jira cloud",
    "phase update",
    "preview in slack",
    "security",
    "show more",
    "slackbot",
    "support",
    "zsrebot",
}


def _event_ref(event: IncidentEvent) -> EvidenceRef:
    return EvidenceRef(event_id=event.event_id, quote=event.message)


def _trust_post_answered_no_need(message: str) -> bool:
    lower = message.lower()
    if "trust post" not in lower and "trustpost" not in lower:
        return False
    return any(
        phrase in lower
        for phrase in (
            "trust post no need",
            "trust post not needed",
            "trust post is not needed",
            "no trust post",
            "trustpost no need",
            "trustpost not needed",
        )
    )


def _trust_post_pending_question(message: str) -> bool:
    lower = message.lower()
    if "trust post" not in lower and "trustpost" not in lower:
        return False
    if _trust_post_answered_no_need(message):
        return False
    return any(term in lower for term in ("needed", "need", "required", "confirm", "customer comms", "?"))


def _apply_trust_post_evidence(delta: StateDelta, events: list[IncidentEvent]) -> StateDelta:
    answered_events = [event for event in events if _trust_post_answered_no_need(event.message)]
    pending_events = [event for event in events if _trust_post_pending_question(event.message)]
    if not answered_events and not pending_events:
        return delta

    update: dict[str, object] = {}
    stale_intents = set(delta.stale_question_intents)
    answered_questions = list(delta.answered_questions)
    open_questions = list(delta.open_questions)
    actions_completed = list(delta.actions_completed)

    if answered_events:
        first = answered_events[0]
        stale_intents.update(TRUST_POST_INTENTS)
        answered_questions.append(
            QuestionRecord(
                question_id=f"{first.event_id}:trust_post",
                intent="ask_trust_post_needed",
                text="Is a Trust Post needed?",
                target="Support",
                status="answered",
                answer="Trust Post No Need",
                evidence=[_event_ref(first)],
                answered_evidence=[_event_ref(first)],
            )
        )
        actions_completed.append(
            ActionRecord(
                action_id=f"{first.event_id}:trust_post_no_need",
                action_type="customer_comms_update",
                summary="Trust Post answered as not needed.",
                actor=first.author,
                target="Support",
                evidence=[_event_ref(first)],
                confidence=0.9,
            )
        )

    elif pending_events and delta.current_blocker in {None, "", "missing_customer_comms"}:
        first = pending_events[0]
        open_questions.append(
            QuestionRecord(
                question_id=f"{first.event_id}:trust_post",
                intent="trust_post_confirmation",
                text="Confirm whether a Trust Post is needed.",
                target="Support",
                status="open",
                evidence=[_event_ref(first)],
            )
        )
        update["current_blocker"] = "customer_comms_pending"

    update["stale_question_intents"] = sorted(stale_intents)
    update["answered_questions"] = answered_questions
    update["open_questions"] = open_questions
    update["actions_completed"] = actions_completed
    return delta.model_copy(update=update)


def _has_security_context(message: str) -> bool:
    lower = message.lower()
    return any(
        term in lower
        for term in (
            "security incident",
            "security vulnerability",
            "vulnerability",
            "sensitive data",
            "researcher",
            "security researcher",
            "workflow product",
            "workflow",
        )
    )


def _asks_security_details(message: str) -> bool:
    lower = message.lower()
    if not any(
        term in lower
        for term in (
            "detail",
            "details",
            "more info",
            "more information",
            "next action",
            "next proposed action",
            "observation",
            "observations",
            "proposed actions",
            "report",
        )
    ):
        return False
    return any(term in lower for term in ("researcher", "reporter", "vulnerability", "security", "bimodh"))


def _provides_security_details(event: IncidentEvent) -> bool:
    lower = event.message.lower()
    has_link = bool(event.extracted_tokens.get("urls"))
    return has_link and any(
        term in lower
        for term in (
            "details",
            "detail link",
            "wf",
            "jira",
            "issue",
            "vulnerability report",
            "researcher provided",
            "report link",
        )
    )


def _entity(name: str, entity_type: EntityType, event: IncidentEvent, status: str = "mentioned") -> EntityRef:
    return EntityRef(
        entity_type=entity_type,
        display_name=name,
        status=status,
        evidence=[_event_ref(event)],
        confidence=0.86,
        source="current_evidence",
    )


def _url_path_number_rejections(url: str) -> list[tuple[str, str]]:
    path = urlparse(url).path
    reason = "jira_issue_number_not_tenant" if re.search(r"/browse/[A-Z][A-Z0-9]+-\d+", path, re.I) else "url_path_number"
    return [(number, reason) for number in re.findall(r"(?<![A-Za-z0-9])\d{5,}(?![A-Za-z0-9])", path)]


TENANT_ID_RE = re.compile(
    r"\b(?:tenant\s+id|tenant|account\s+id|account|org\s+id)\s*(?:[:=#-]|\bis\b)?\s*(\d{5,})\b",
    re.I,
)


def _explicit_tenant_evidence(events: list[IncidentEvent]) -> dict[str, IncidentEvent]:
    evidence: dict[str, IncidentEvent] = {}
    for event in events:
        for match in TENANT_ID_RE.finditer(event.message):
            evidence.setdefault(match.group(1), event)
    return evidence


def _is_system_entity_label(value: str | None) -> bool:
    normalized = re.sub(r"\s+", " ", (value or "").strip().lower().replace("-", " "))
    raw = (value or "").strip().lower()
    return normalized in SYSTEM_ENTITY_LABELS or raw in SYSTEM_ENTITY_LABELS


def _filter_system_entities(delta: StateDelta) -> StateDelta:
    update: dict[str, object] = {}
    for field in ("engaged_entities", "suggested_but_not_engaged"):
        values = [entity for entity in getattr(delta, field) if not _is_system_entity_label(entity.display_name)]
        if len(values) != len(getattr(delta, field)):
            update[field] = values
    return delta.model_copy(update=update) if update else delta


def _apply_negative_entity_evidence(delta: StateDelta, events: list[IncidentEvent]) -> StateDelta:
    explicit_tenants = _explicit_tenant_evidence(events)
    rejected = [
        entity
        for entity in delta.rejected_entities
        if not (
            entity.display_name in explicit_tenants
            and entity.status in {"rejected:url_path_number", "rejected:jira_issue_number_not_tenant"}
        )
    ]
    seen = {(entity.display_name, entity.status) for entity in rejected}
    for event in events:
        if "Default_Agent" in event.message:
            key = ("Default_Agent", "rejected:bot_system_message")
            if key not in seen:
                rejected.append(_entity("Default_Agent", EntityType.TEAM, event, "rejected:bot_system_message"))
                seen.add(key)
        for url in event.extracted_tokens.get("urls", []):
            for number, reason in _url_path_number_rejections(url):
                if number in explicit_tenants:
                    continue
                key = (number, f"rejected:{reason}")
                if key not in seen:
                    entity_type = EntityType.JIRA if reason == "jira_issue_number_not_tenant" else EntityType.TENANT
                    rejected.append(_entity(number, entity_type, event, f"rejected:{reason}"))
                    seen.add(key)
    impact = delta.impact or ImpactState()
    affected_tenants = list(impact.affected_tenants)
    known_tenants = {fact.value for fact in affected_tenants}
    for number, event in explicit_tenants.items():
        if number not in known_tenants:
            affected_tenants.append(
                EvidenceBackedFact(
                    value=number,
                    evidence=[_event_ref(event)],
                    confidence=0.92,
                )
            )
            known_tenants.add(number)
    update: dict[str, object] = {}
    if len(rejected) != len(delta.rejected_entities):
        update["rejected_entities"] = rejected
    if affected_tenants != list(impact.affected_tenants):
        update["impact"] = impact.model_copy(
            update={
                "affected_tenants": affected_tenants,
                "confidence": max(impact.confidence, 0.72),
            }
        )
    return delta.model_copy(update=update) if update else delta


def _evidence_for_ids(
    evidence_ids: list[str],
    events_by_id: dict[str, IncidentEvent],
    *,
    confidence: float = 0.8,
) -> list[EvidenceRef]:
    refs: list[EvidenceRef] = []
    for event_id in evidence_ids:
        event = events_by_id.get(event_id)
        refs.append(
            EvidenceRef(
                event_id=event_id,
                quote=event.message if event else "",
                confidence=confidence,
            )
        )
    return refs


def _clean_entity_to_ref(
    entity: CleanContextEntity,
    events_by_id: dict[str, IncidentEvent],
    *,
    status: str | None = None,
) -> EntityRef:
    return EntityRef(
        entity_type=entity.entity_type,
        display_name=entity.name,
        status=status or entity.status,
        evidence=_evidence_for_ids(entity.evidence_ids, events_by_id, confidence=entity.confidence),
        confidence=entity.confidence,
        source="current_evidence",
    )


def _entity_key(entity: EntityRef) -> tuple[str, str]:
    entity_type = str(getattr(entity.entity_type, "value", entity.entity_type))
    return (entity_type, entity.display_name.strip().lower())


def _append_entities(existing: list[EntityRef], additions: list[EntityRef]) -> list[EntityRef]:
    merged = list(existing)
    seen = {_entity_key(entity) for entity in merged}
    for entity in additions:
        key = _entity_key(entity)
        if key in seen:
            continue
        merged.append(entity)
        seen.add(key)
    return merged


def _apply_clean_context(
    delta: StateDelta,
    clean_context: CleanIncidentContext | None,
    events: list[IncidentEvent],
) -> StateDelta:
    if clean_context is None:
        return delta
    events_by_id = {event.event_id: event for event in events}
    update: dict[str, object] = {}

    if delta.phase in {None, IncidentPhase.UNKNOWN, "unknown"}:
        phase = clean_context.phase.value
        if phase and phase != "unknown":
            update["phase"] = phase

    if delta.severity is None:
        severity = clean_context.severity.value.upper()
        if severity in {item.value for item in Severity} and severity != Severity.UNKNOWN.value:
            update["severity"] = EvidenceBackedFact(
                value=severity,
                evidence=_evidence_for_ids(
                    clean_context.severity.evidence_ids,
                    events_by_id,
                    confidence=clean_context.severity.confidence,
                ),
                confidence=clean_context.severity.confidence,
            )

    if not delta.current_blocker and clean_context.current_blocker.blocker_type not in {"", "unknown"}:
        update["current_blocker"] = clean_context.current_blocker.blocker_type

    if not delta.compact_summary and clean_context.clean_summary:
        update["compact_summary"] = clean_context.clean_summary

    candidate_services = [
        _clean_entity_to_ref(entity, events_by_id)
        for entity in clean_context.candidate_services
        if str(getattr(entity.entity_type, "value", entity.entity_type))
        in {EntityType.SERVICE.value, EntityType.TEAM.value}
        and entity.name
        and not _is_system_entity_label(entity.name)
    ]
    if candidate_services:
        update["candidate_services"] = _append_entities(delta.candidate_services, candidate_services)

    engaged_entities = [
        _clean_entity_to_ref(entity, events_by_id)
        for entity in clean_context.engaged_entities
        if entity.targetable
        and entity.status != "system_or_bot"
        and entity.name
        and not _is_system_entity_label(entity.name)
    ]
    if engaged_entities:
        update["engaged_entities"] = _append_entities(delta.engaged_entities, engaged_entities)

    suggested = [
        _clean_entity_to_ref(entity, events_by_id, status="suggested_not_engaged")
        for entity in clean_context.suggested_but_not_engaged
        if entity.targetable and entity.name and not _is_system_entity_label(entity.name)
    ]
    if suggested:
        update["suggested_but_not_engaged"] = _append_entities(delta.suggested_but_not_engaged, suggested)

    stale_intents = set(delta.stale_question_intents)
    stale_intents.update(clean_context.question_ledger.stale_question_intents)
    if stale_intents:
        update["stale_question_intents"] = sorted(stale_intents)

    if clean_context.question_ledger.open_questions:
        update["open_questions"] = [*delta.open_questions, *clean_context.question_ledger.open_questions]
    if clean_context.question_ledger.answered_questions:
        update["answered_questions"] = [
            *delta.answered_questions,
            *clean_context.question_ledger.answered_questions,
        ]

    if clean_context.actions_completed:
        update["actions_completed"] = [*delta.actions_completed, *clean_context.actions_completed]
    if clean_context.monitoring_signals:
        update["monitoring_signals"] = [*delta.monitoring_signals, *clean_context.monitoring_signals]

    if clean_context.rejected_entities:
        rejected = list(delta.rejected_entities)
        seen = {(entity.display_name, entity.status) for entity in rejected}
        for entity in clean_context.rejected_entities:
            key = (entity.text, f"rejected:{entity.reason}")
            if key in seen:
                continue
            rejected.append(
                EntityRef(
                    entity_type=entity.rejected_entity_type,
                    display_name=entity.text,
                    status=f"rejected:{entity.reason}",
                    evidence=_evidence_for_ids(entity.evidence_ids, events_by_id),
                    confidence=0.86,
                    source="current_evidence",
                )
            )
            seen.add(key)
        update["rejected_entities"] = rejected

    if clean_context.uncertainty_notes:
        update["unknowns"] = [*delta.unknowns, *clean_context.uncertainty_notes]
    if clean_context.do_not_invent:
        update["safety_flags"] = [*delta.safety_flags, *clean_context.do_not_invent]

    return delta.model_copy(update=update) if update else delta


def _apply_security_incident_evidence(delta: StateDelta, events: list[IncidentEvent]) -> StateDelta:
    security_events = [event for event in events if _has_security_context(event.message)]
    if not security_events:
        return delta

    update: dict[str, object] = {}
    if delta.phase in {None, IncidentPhase.UNKNOWN, "unknown"}:
        update["phase"] = IncidentPhase.ENGAGEMENT

    candidate_services = list(delta.candidate_services)
    candidate_names = {entity.display_name.lower() for entity in candidate_services}
    first = security_events[0]
    if any("workflow" in event.message.lower() for event in security_events) and "workflow" not in candidate_names:
        candidate_services.append(_entity("Workflow", EntityType.SERVICE, first))
    if "security" not in candidate_names:
        candidate_services.append(_entity("Security", EntityType.TEAM, first))
    update["candidate_services"] = candidate_services

    if delta.severity is None:
        for event in security_events:
            match = re.search(r"\b(P[1-4])\b", event.message, re.I)
            if match:
                update["severity"] = EvidenceBackedFact(
                    value=match.group(1).upper(),
                    evidence=[_event_ref(event)],
                    confidence=0.88,
                )
                break

    engaged = [entity for entity in delta.engaged_entities if not _is_system_entity_label(entity.display_name)]
    engaged_names = {entity.display_name.lower() for entity in engaged}
    for event in events:
        author = (event.author or "").strip()
        if not author or author.lower() in SYSTEM_AUTHORS or _is_system_entity_label(author):
            continue
        if author.lower() not in engaged_names:
            engaged.append(_entity(author, EntityType.PERSON, event, "active"))
            engaged_names.add(author.lower())
    if len(engaged) != len(delta.engaged_entities):
        update["engaged_entities"] = engaged

    ask_indexes = [index for index, event in enumerate(events) if _asks_security_details(event.message)]
    details_indexes = [index for index, event in enumerate(events) if _provides_security_details(event)]
    details_after_ask = bool(ask_indexes and any(detail > min(ask_indexes) for detail in details_indexes))
    if details_after_ask:
        detail_event = events[min(index for index in details_indexes if index > min(ask_indexes))]
        stale = set(delta.stale_question_intents)
        stale.update(SECURITY_DETAILS_INTENTS)
        answered = list(delta.answered_questions)
        answered.append(
            QuestionRecord(
                question_id=f"{detail_event.event_id}:security_details",
                intent="request_details_from_researcher",
                text="Ask the security researcher/reporter for vulnerability details.",
                target="security reporter",
                status="answered",
                answer="Reporter provided a details link.",
                evidence=[_event_ref(events[min(ask_indexes)])],
                answered_evidence=[_event_ref(detail_event)],
            )
        )
        update["stale_question_intents"] = sorted(stale)
        update["answered_questions"] = answered
        if delta.current_blocker in {None, "", "request_details_from_researcher"}:
            update["current_blocker"] = "missing_validation"
    elif delta.current_blocker in {None, ""}:
        update["current_blocker"] = "missing_validation"

    summary = delta.compact_summary
    if not summary:
        update["compact_summary"] = "Security/vulnerability incident evidence is present; use current evidence for owner, scope, containment, and validation."
    return delta.model_copy(update=update)


def extract_state_delta(
    events: list[IncidentEvent],
    current_state: CurrentIncidentState,
    llm_client: LLMClient,
    clean_context: CleanIncidentContext | None = None,
) -> StateDelta:
    links: list[LinkRef] = []
    for event in events:
        for url in event.extracted_tokens.get("urls", []):
            links.append(LinkRef(url=url, evidence=[EvidenceRef(event_id=event.event_id, quote=event.message)]))
    payload = {
        "incident_id": current_state.incident_id,
        "events": [event.model_dump(mode="json") for event in events],
        "current_state": current_state.model_dump(mode="json"),
        "clean_context": clean_context.model_dump(mode="json") if clean_context else None,
        "links": [link.model_dump(mode="json") for link in links],
    }
    delta = llm_client.generate_json("state_delta_extractor", payload, StateDelta)
    validated = validate_with_repair(delta, StateDelta, context="state_delta_extractor")
    validated = _apply_clean_context(validated, clean_context, events)
    validated = _apply_trust_post_evidence(validated, events)
    validated = _apply_security_incident_evidence(validated, events)
    validated = _apply_negative_entity_evidence(validated, events)
    validated = _filter_system_entities(validated)
    seen = {link.url for link in validated.links_seen}
    validated.links_seen.extend(link for link in links if link.url not in seen)
    return validated
