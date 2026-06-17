from __future__ import annotations

import re

from ic_copilot.llm.base import LLMClient
from ic_copilot.schema_repair import validate_with_repair
from ic_copilot.schemas import (
    CleanContextBlocker,
    CleanContextEntity,
    CleanContextFact,
    CleanContextValue,
    CleanIncidentContext,
    CleanQuestionLedger,
    CleanRejectedEntity,
    CurrentIncidentState,
    EntityType,
    EvidenceRef,
    IncidentEvent,
    InputSizeAssessment,
    QuestionRecord,
    SlackTurnReconstruction,
)


DETAILS_REQUEST_INTENTS = (
    "ask_reporter_for_more_details",
    "ask_security_reporter_for_details",
    "request_details_from_researcher",
    "request_vulnerability_details",
    "request_observations",
    "request_next_actions_from_reporter",
    "ask_reporter_observations_next_actions",
)
SYSTEM_AUTHORS = {
    "added by zsrebot",
    "app",
    "channel",
    "dm",
    "docs",
    "ic bot",
    "im-agent",
    "incident assessment",
    "jira cloud",
    "phase update",
    "pinned by",
    "preview in slack",
    "severity",
    "show more",
    "slackbot",
    "summary",
    "trust post",
    "zsrebot",
}


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _event_ref(event: IncidentEvent) -> EvidenceRef:
    return EvidenceRef(event_id=event.event_id, quote=event.message)


def _event_ids(events: list[IncidentEvent], *needles: str) -> list[str]:
    ids = []
    for event in events:
        text = _norm(f"{event.author or ''} {event.message}")
        if all(_norm(needle) in text for needle in needles):
            ids.append(event.event_id)
    return ids


def _has_security_context(text: str) -> bool:
    text_norm = _norm(text)
    return any(
        term in text_norm
        for term in ("security", "vulnerability", "sensitive data", "researcher", "workflow", "wf-")
    )


def _asks_for_details(text: str) -> bool:
    text_norm = _norm(text)
    if not any(
        term in text_norm
        for term in ("detail", "details", "observation", "observations", "proposed action", "next action", "report")
    ):
        return False
    return any(term in text_norm for term in ("bimodh", "researcher", "reporter", "security", "vulnerability"))


def _provides_details(event: IncidentEvent) -> bool:
    text_norm = _norm(event.message)
    if not event.extracted_tokens.get("urls"):
        return False
    return any(term in text_norm for term in ("details", "wf-", "jira", "issue", "vulnerability", "report"))


def _url_rejections(events: list[IncidentEvent]) -> list[CleanRejectedEntity]:
    rejected: list[CleanRejectedEntity] = []
    seen: set[tuple[str, str]] = set()
    explicit_tenants = {
        match.group(1)
        for event in events
        for match in re.finditer(
            r"\b(?:tenant\s+id|tenant|account\s+id|account|org\s+id)\s*(?:[:=#-]|\bis\b)?\s*(\d{5,})\b",
            event.message,
            re.I,
        )
    }
    for event in events:
        if "Default_Agent" in event.message:
            key = ("Default_Agent", "unsupported_default_agent")
            if key not in seen:
                rejected.append(
                    CleanRejectedEntity(
                        text="Default_Agent",
                        rejected_entity_type=EntityType.TEAM,
                        reason="unsupported_default_agent",
                        evidence_ids=[event.event_id],
                    )
                )
                seen.add(key)
        for url in event.extracted_tokens.get("urls", []):
            reason = "jira_issue_number_not_tenant" if re.search(r"/browse/[A-Z][A-Z0-9]+-\d+", url, re.I) else "url_path_number"
            for number in re.findall(r"(?<![A-Za-z0-9])\d{5,}(?![A-Za-z0-9])", url):
                if number in explicit_tenants:
                    continue
                key = (number, reason)
                if key in seen:
                    continue
                rejected.append(
                    CleanRejectedEntity(
                        text=number,
                        rejected_entity_type=EntityType.JIRA if reason == "jira_issue_number_not_tenant" else EntityType.TENANT,
                        reason=reason,
                        evidence_ids=[event.event_id],
                    )
                )
                seen.add(key)
    return rejected


def _deterministic_clean_context(
    raw_text: str,
    events: list[IncidentEvent],
    current_state: CurrentIncidentState,
) -> CleanIncidentContext:
    text = "\n".join(event.message for event in events)
    all_text = f"{raw_text}\n{text}"
    security = _has_security_context(all_text)
    severity_match = re.search(r"\b(P[1-4])\b", all_text, re.I)
    based_on = [event.event_id for event in events]
    details_ask_indexes = [idx for idx, event in enumerate(events) if _asks_for_details(event.message)]
    details_answer_indexes = [idx for idx, event in enumerate(events) if _provides_details(event)]
    details_after_ask = bool(
        details_ask_indexes and any(answer_idx > min(details_ask_indexes) for answer_idx in details_answer_indexes)
    )
    stale_intents = list(DETAILS_REQUEST_INTENTS) if details_after_ask else []
    answered_questions: list[QuestionRecord] = []
    if details_after_ask:
        ask_event = events[min(details_ask_indexes)]
        answer_event = events[min(idx for idx in details_answer_indexes if idx > min(details_ask_indexes))]
        answered_questions.append(
            QuestionRecord(
                question_id=f"{answer_event.event_id}:security_details",
                intent="request_details_from_researcher",
                text="Ask reporter for vulnerability details, observations, or proposed next actions.",
                target="security reporter",
                status="answered",
                answer="Reporter provided a vulnerability/Jira/details link.",
                evidence=[_event_ref(ask_event)],
                answered_evidence=[_event_ref(answer_event)],
            )
        )

    candidate_services: list[CleanContextEntity] = []
    if "workflow" in _norm(all_text):
        candidate_services.append(
            CleanContextEntity(
                name="Workflow",
                entity_type=EntityType.SERVICE,
                status="mentioned",
                targetable=False,
                confidence=0.85,
                evidence_ids=_event_ids(events, "workflow") or based_on[:1],
            )
        )
    if security:
        candidate_services.append(
            CleanContextEntity(
                name="Security",
                entity_type=EntityType.TEAM,
                status="mentioned",
                targetable=False,
                confidence=0.75,
                evidence_ids=_event_ids(events, "security") or based_on[:1],
            )
        )

    engaged: list[CleanContextEntity] = []
    seen_people: set[str] = set()
    for event in events:
        author = (event.author or "").strip()
        if not author or _norm(author) in SYSTEM_AUTHORS or _norm(author) in {"ic", "support", "security"}:
            continue
        if author in seen_people:
            continue
        engaged.append(
            CleanContextEntity(
                name=author,
                entity_type=EntityType.PERSON,
                status="responded",
                targetable=True,
                confidence=0.82,
                evidence_ids=[event.event_id],
            )
        )
        seen_people.add(author)

    clean_summary = (
        "Security/vulnerability incident evidence is present; details link is already provided, so move to owner, scope, containment, and validation."
        if security and details_after_ask
        else "Clean incident context extracted from current Slack evidence."
    )
    return CleanIncidentContext(
        incident_id=current_state.incident_id,
        based_on_event_ids=based_on,
        source_summary=text[:1000],
        clean_summary=clean_summary,
        phase=CleanContextValue(value="engagement" if security else "unknown", confidence=0.72, evidence_ids=based_on[:1]),
        severity=CleanContextValue(value=severity_match.group(1).upper() if severity_match else "unknown", confidence=0.85 if severity_match else 0.0, evidence_ids=based_on[:1]),
        current_blocker=CleanContextBlocker(
            blocker_type="missing_validation" if security else "unknown",
            summary="Need owner, exposure scope, containment, or validation step." if security else "",
            confidence=0.76 if security else 0.0,
            evidence_ids=based_on,
        ),
        incident_kind=[
            CleanContextFact(fact_type="kind", value="security", confidence=0.8, evidence_ids=based_on)
        ]
        if security
        else [],
        candidate_services=candidate_services,
        engaged_entities=engaged,
        question_ledger=CleanQuestionLedger(
            answered_questions=answered_questions,
            stale_question_intents=stale_intents,
        ),
        rejected_entities=_url_rejections(events),
        do_not_invent=[
            "Do not infer tenants from URL path numbers.",
            "Do not infer customers from URL domains.",
            "Do not turn bot/system labels into targetable humans.",
        ],
        uncertainty_notes=["Owner, exposure scope, containment, and mitigation remain unconfirmed."] if security else [],
    )


def extract_clean_incident_context(
    raw_text: str,
    events: list[IncidentEvent],
    current_state: CurrentIncidentState,
    llm_client: LLMClient,
    *,
    reconstructed_turns: SlackTurnReconstruction | None = None,
    input_size_assessment: InputSizeAssessment | None = None,
    turn_reconstruction_warning: str | None = None,
) -> CleanIncidentContext:
    payload = {
        "incident_id": current_state.incident_id,
        "raw_text": raw_text,
        "events": [event.model_dump(mode="json") for event in events],
        "reconstructed_turns": reconstructed_turns.model_dump(mode="json") if reconstructed_turns else None,
        "input_size_assessment": input_size_assessment.model_dump(mode="json") if input_size_assessment else None,
        "turn_reconstruction_warning": turn_reconstruction_warning,
        "current_state": current_state.model_dump(mode="json"),
        "rules": [
            "Use only current evidence and stable event IDs.",
            "Prefer reconstructed turns for speaker and role interpretation when present.",
            "No customers from URL domains.",
            "No tenants from URL path numbers.",
            "Bot/system labels are not targetable humans.",
            "Unknown is allowed.",
        ],
    }
    try:
        context = llm_client.generate_json("clean_incident_context_extractor", payload, CleanIncidentContext)
    except NotImplementedError:
        context = _deterministic_clean_context(raw_text, events, current_state)
    validated = validate_with_repair(context, CleanIncidentContext, context="clean_incident_context_extractor")
    return validated
