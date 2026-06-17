from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from ic_copilot.actionability import analyze_visible_actionability
from ic_copilot.catalog import resolve_service_or_team
from ic_copilot.llm.redaction import redact_for_llm
from ic_copilot.raw_paste_contract import (
    db_cpu_initial_contract,
    expected_memory_contracts,
    extract_diagnostic_facts,
    target_class_for_allowed_target,
    visible_terms_satisfied,
)
from ic_copilot.run_diagnosis import diagnose_open_loops, stale_output_risks_for_output
from ic_copilot.schemas import (
    AllowedTarget,
    BriefQualityResult,
    CommandRegistryEntry,
    CurrentIncidentState,
    DecisionMoment,
    EntityType,
    EventQuality,
    ICDecision,
    ICMove,
    IncidentEvent,
    IncidentBrief,
    IncidentPhase,
    MemoryApplicabilityResult,
    SemanticQuality,
    ServiceCatalogEntry,
    SharpBlockerAssessment,
    VerifierResult,
)
from ic_copilot.work_items import extract_current_work_items


FAKE_PERSON_FRAGMENTS = ("Gaurav Could", "Gaurav Trisha", "MD. Please")
TENANT_CONTEXT_WORDS = (
    "tenant",
    "tenant id",
    "account",
    "account id",
    "customer account",
)
OPERATIONAL_ID_CONTEXT_WORDS = (
    "alert",
    "batch",
    "build",
    "change",
    "change ticket",
    "cm",
    "ecra",
    "ecm",
    "incident",
    "incident #",
    "jira",
    "job",
    "l3",
    "lag",
    "line",
    "pagerduty",
    "pd incident",
    "proactive outreach ticket",
    "psg",
    "run",
    "sync id",
    "ticket",
    "version",
    "workflow",
    "zd",
    "zendesk",
    "zr",
)
PRIVATE_ID_PLACEHOLDER_RE = re.compile(
    r"\[(?:REDACTED_)?(?:TENANT|ACCOUNT|CUSTOMER|ORG)(?:_ID)?\]|\b(?:TENANT_ID|ACCOUNT_ID|CUSTOMER_ID|ORG_ID)\b",
    re.IGNORECASE,
)
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
    "requires dedicated_topic permission",
)
PERMISSION_LOOP_ACTION_TERMS = (
    "perform this move",
    "execute the move",
    "run the command",
    "move tenant",
    "move the tenant",
    "move affected tenant",
    "perform the command",
    "use daco-bot command",
    "who has the access",
    "who has access",
    "who can perform",
    "who can execute",
)
TRUST_POST_INTENTS = {
    "ask_trust_post_needed",
    "confirm_trust_post_needed",
    "trust_post_confirmation",
}
DETAILS_REQUEST_INTENTS = {
    "ask_reporter_for_more_details",
    "ask_reporter_observations_next_actions",
    "ask_security_reporter_for_details",
    "request_details_from_researcher",
    "request_next_actions_from_reporter",
    "request_observations",
    "request_vulnerability_details",
}
SECURITY_DETAILS_INTENTS = DETAILS_REQUEST_INTENTS
OWNER_LOOPED_IN_INTENTS = {
    "already_looped_in",
    "ask_if_owner_engaged",
    "ask_if_team_engaged",
    "ask_if_team_involved",
}
EXPLICIT_STALE_INTENTS = DETAILS_REQUEST_INTENTS | TRUST_POST_INTENTS | OWNER_LOOPED_IN_INTENTS
TRUST_POST_NO_NEED_PHRASES = (
    "trust post no need",
    "trust post not needed",
    "trust post is not needed",
    "no trust post",
    "trustpost no need",
    "trustpost not needed",
)
TECHNICAL_SHARP_BLOCKERS = {
    "missing_mitigation",
    "mitigation_status_or_validation",
    "rollback_or_disable_status",
    "waiting_on_code_fix",
    "waiting_on_deploy",
    "waiting_on_owner_status",
    "waiting_on_monitoring",
    "missing_validation",
}
UNRESOLVED_RCA_BLOCKERS = {
    "missing_validation",
    "mitigation_status_or_validation",
    "rollback_or_disable_status",
    "waiting_on_owner_status",
    "waiting_on_monitoring",
    "waiting_on_code_fix",
    "waiting_on_deploy",
}


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _has_clear_actionable_validation_thread(events: list[IncidentEvent] | None) -> bool:
    text_norm = _norm("\n".join(event.message for event in events or []))
    has_report_or_impact = any(
        phrase in text_norm
        for phrase in (
            "report failure",
            "reports failing",
            "reports erroring",
            "not able to run reports",
            "cannot run reports",
            "customer is blocked",
            "blocked from running",
        )
    )
    has_validation_or_signal = any(
        phrase in text_norm
        for phrase in (
            "row-count",
            "row count",
            "count mismatch",
            "iceberg",
            "del table",
            "pipeline",
            "validation",
            "monitoring signal",
            "next signal",
        )
    )
    has_scope_answer = any(
        phrase in text_norm
        for phrase in (
            "only one customer",
            "only reported",
            "only toast",
            "no other customer",
            "single customer",
            "service health looks green for other customers",
        )
    )
    return has_report_or_impact and has_validation_or_signal and has_scope_answer


def final_output_text(decision: ICDecision | dict[str, Any]) -> str:
    values = []
    if isinstance(decision, dict):
        output = decision.get("output", decision)
    else:
        output = decision.output
    for value in output.values():
        if not value:
            continue
        if isinstance(value, dict):
            command_value = value.get("command_text") or value.get("command") or value.get("text")
            values.append(str(command_value) if command_value else " ".join(str(item) for item in value.values() if item))
        elif hasattr(value, "command_text"):
            values.append(str(getattr(value, "command_text")))
        elif hasattr(value, "command"):
            values.append(str(getattr(value, "command")))
        else:
            values.append(str(value))
    return "\n".join(values).strip()


def _directly_addresses_target(text_norm: str, variants: set[str]) -> bool:
    ask_terms = r"(?:can you|could you|please|confirm|provide|share)"
    for variant in variants:
        escaped = re.escape(variant)
        patterns = (
            rf"(?<![a-z0-9]){escaped}(?![a-z0-9])(?:\s+team)?\s*(?:/|,|\band\b)[^.;!?]{{0,140}}\b{ask_terms}\b",
            rf"(?<![a-z0-9]){escaped}(?![a-z0-9])(?:\s+team)?\s+\b{ask_terms}\b",
            rf"\b{ask_terms}\s+(?:ask\s+)?(?<![a-z0-9]){escaped}(?![a-z0-9])",
        )
        if any(re.search(pattern, text_norm) for pattern in patterns):
            return True
    return False


def _target_name_pattern(name_norm: str) -> str:
    return rf"(?<![a-z0-9])@?{re.escape(name_norm)}(?![a-z0-9])"


def _selected_alias_covers_non_targetable(
    name_norm: str,
    *,
    selected_target_names: set[str],
    targetable_ids_by_name: dict[str, set[str]],
    selected_target_ids: set[str],
) -> bool:
    if targetable_ids_by_name.get(name_norm, set()).intersection(selected_target_ids):
        return True
    if len(name_norm) < 4:
        return False
    return any(
        selected_name
        and (
            selected_name == name_norm
            or selected_name.startswith(f"{name_norm} ")
            or selected_name.endswith(f" {name_norm}")
            or f" {name_norm} " in f" {selected_name} "
        )
        for selected_name in selected_target_names
    )


def _decision_text(decision: ICDecision) -> str:
    return final_output_text(decision)


def _coerce_decision(decision: ICDecision | dict, state: CurrentIncidentState) -> ICDecision:
    if isinstance(decision, ICDecision):
        return decision
    output = {
        "say_this": decision.get("say_this") or decision.get("output", {}).get("say_this", ""),
        "next_line": decision.get("next_line") or decision.get("output", {}).get("next_line", ""),
    }
    command = decision.get("command_suggestion") or decision.get("command") or decision.get("output", {}).get("command")
    if isinstance(command, dict):
        command = command.get("command") or command.get("text")
    if command:
        output["command"] = command
    targets = []
    target_name = decision.get("target_team") or decision.get("target") or decision.get("target_service")
    if target_name:
        targets.append(
            {
                "entity_type": "team",
                "display_name": target_name,
                "status": "targeted",
                "evidence": [],
                "confidence": 0.5,
            }
        )
    return ICDecision.model_validate(
        {
            "decision_id": decision.get("decision_id", "dict-decision"),
            "incident_id": decision.get("incident_id", state.incident_id),
            "move": decision.get("move", "no_safe_recommendation"),
            "phase": decision.get("phase", state.phase),
            "output": output,
            "targets": targets,
            "rationale": [decision.get("why", "")] if decision.get("why") else [],
            "grounding": [
                {"event_id": event_id, "quote": ""}
                for event_id in decision.get("evidence_ids", [])
            ],
            "confidence": decision.get("confidence", 0.5),
        }
    )


def _state_text(state: CurrentIncidentState, include_links: bool = True) -> str:
    pieces = [
        state.compact_summary,
        state.current_blocker or "",
        state.impact.description,
        state.severity.value if state.severity else "",
    ]
    if state.severity:
        pieces.extend(ref.quote for ref in state.severity.evidence)
    for ref in state.impact.evidence:
        pieces.append(ref.quote)
    for fact in state.impact.affected_customers + state.impact.affected_tenants:
        pieces.append(fact.value)
        pieces.extend(ref.quote for ref in fact.evidence)
    for group in (state.candidate_services, state.engaged_entities, state.suggested_but_not_engaged):
        for entity in group:
            pieces.append(entity.display_name)
            pieces.append(entity.canonical_id or "")
            pieces.extend(ref.quote for ref in entity.evidence)
    for command in state.commands_seen:
        pieces.append(command.command)
    for action in state.actions_completed:
        pieces.append(action.summary)
        pieces.append(action.target or "")
        pieces.extend(ref.quote for ref in action.evidence)
    for signal in state.monitoring_signals:
        pieces.append(signal.value)
        pieces.extend(str(value) for value in signal.metadata.values() if value)
        pieces.extend(ref.quote for ref in signal.evidence)
    for entity in state.rejected_entities:
        pieces.append(entity.display_name)
        pieces.extend(ref.quote for ref in entity.evidence)
    if include_links:
        pieces.extend(link.url for link in state.links_seen)
    return "\n".join(piece for piece in pieces if piece)


def collect_current_evidence_terms(state: CurrentIncidentState) -> set[str]:
    text = _state_text(state, include_links=False)
    terms = {_norm(piece) for piece in text.splitlines() if piece}
    for fact in state.impact.affected_customers + state.impact.affected_tenants:
        terms.add(_norm(fact.value))
    for command in state.commands_seen:
        terms.add(_norm(command.command))
    return {term for term in terms if term}


def collect_allowed_targets(
    state: CurrentIncidentState,
    catalog: list[ServiceCatalogEntry],
) -> dict[str, set[str]]:
    allowed = {
        "people": set(),
        "teams": set(),
        "services": set(),
        "customers": {_norm(fact.value) for fact in state.impact.affected_customers},
        "tenants": {_norm(fact.value) for fact in state.impact.affected_tenants},
    }
    for group in (state.candidate_services, state.engaged_entities, state.suggested_but_not_engaged):
        for entity in group:
            key = {
                EntityType.PERSON: "people",
                EntityType.TEAM: "teams",
                EntityType.SERVICE: "services",
            }.get(entity.entity_type)
            if key:
                allowed[key].add(_norm(entity.display_name))
                if entity.canonical_id:
                    allowed[key].add(_norm(entity.canonical_id))
    for entry in catalog:
        allowed["services"].update({_norm(entry.service_id), _norm(entry.canonical_name)})
        allowed["services"].update(_norm(alias) for alias in entry.aliases)
        for value in entry.ownership.values():
            if isinstance(value, str):
                allowed["people"].add(_norm(value))
            elif isinstance(value, list):
                allowed["people"].update(_norm(item) for item in value if isinstance(item, str))
    return allowed


def _current_service_norms(state: CurrentIncidentState, catalog: list[ServiceCatalogEntry]) -> set[str]:
    service_terms: set[str] = set()
    current_names: set[str] = set()
    for group in (state.candidate_services, state.engaged_entities, state.suggested_but_not_engaged):
        for entity in group:
            # If a catalog service label is also visible as a current-evidence team/person
            # label (for example "DBA"), mentioning it is grounded; do not reinterpret it
            # as an unrelated service claim.
            service_terms.add(_norm(entity.display_name))
            if entity.canonical_id:
                service_terms.add(_norm(entity.canonical_id))
            if entity.entity_type == EntityType.SERVICE:
                for value in (entity.display_name, entity.canonical_id):
                    if value:
                        service_terms.add(_norm(value))
                        current_names.add(_norm(value))

    for entry in catalog:
        labels = {_norm(entry.service_id), _norm(entry.canonical_name), *{_norm(alias) for alias in entry.aliases}}
        if labels.intersection(current_names):
            service_terms.update(labels)
    return {term for term in service_terms if term}


def _catalog_service_mentions(text: str, catalog: list[ServiceCatalogEntry]) -> list[tuple[str, ServiceCatalogEntry]]:
    mentions: list[tuple[str, ServiceCatalogEntry]] = []
    text_norm = _norm(text)
    ignored = {"app", "service", "team", "owner", "catalog", "workflow", "support", "revenue", "dba", "sre"}
    for entry in catalog:
        labels = [entry.service_id, entry.canonical_name, *entry.aliases]
        for label in labels:
            label_norm = _norm(label)
            if len(label_norm) < 3 or label_norm in ignored:
                continue
            high_confidence_label = (
                any(separator in label_norm for separator in ("-", "_", "/"))
                or (label.isupper() and len(label_norm) >= 3)
                or " service" in label_norm
            )
            if not high_confidence_label:
                continue
            pattern = rf"(?<![a-z0-9]){re.escape(label_norm)}(?![a-z0-9])"
            if re.search(pattern, text_norm):
                mentions.append((label, entry))
                break
    return mentions


def _explicit_context_contains(term: str, text: str, context_words: tuple[str, ...]) -> bool:
    escaped = re.escape(term)
    context = "|".join(re.escape(word) for word in sorted(context_words, key=len, reverse=True))
    context_pattern = rf"(?<![A-Za-z0-9])(?:{context})(?![A-Za-z0-9])"
    before = rf"{context_pattern}[^\n]{{0,80}}\b{escaped}\b"
    after = rf"\b{escaped}\b[^\n]{{0,80}}{context_pattern}"
    return bool(re.search(before, text, re.I) or re.search(after, text, re.I))


def _allowed_customers(state: CurrentIncidentState) -> set[str]:
    return {_norm(fact.value) for fact in state.impact.affected_customers}


def _allowed_tenants(state: CurrentIncidentState) -> set[str]:
    return {_norm(fact.value) for fact in state.impact.affected_tenants}


def _domain_labels(state: CurrentIncidentState) -> set[str]:
    labels: set[str] = set()
    for link in state.links_seen:
        host = urlparse(link.url).hostname or ""
        for part in host.split("."):
            if part and part not in {"www", "com", "net", "org", "io", "zuora"}:
                labels.add(part)
    return labels


def _allowed_people(state: CurrentIncidentState, catalog: list[ServiceCatalogEntry]) -> set[str]:
    people = set()
    for group in (state.candidate_services, state.engaged_entities, state.suggested_but_not_engaged):
        for entity in group:
            if entity.entity_type == EntityType.PERSON:
                people.add(_norm(entity.display_name))
    for entry in catalog:
        for value in entry.ownership.values():
            if isinstance(value, str):
                people.add(_norm(value))
            elif isinstance(value, list):
                people.update(_norm(item) for item in value if isinstance(item, str))
    return people


def _target_supported(
    target_name: str,
    target_type: EntityType,
    state: CurrentIncidentState,
    catalog: list[ServiceCatalogEntry],
) -> bool:
    state_names = {
        _norm(entity.display_name)
        for group in (state.candidate_services, state.engaged_entities, state.suggested_but_not_engaged)
        for entity in group
    }
    state_ids = {
        _norm(entity.canonical_id)
        for group in (state.candidate_services, state.engaged_entities, state.suggested_but_not_engaged)
        for entity in group
        if entity.canonical_id
    }
    target_norm = _norm(target_name)
    if target_norm in state_names or target_norm in state_ids:
        return True
    if target_type in {EntityType.SERVICE, EntityType.TEAM}:
        return bool(resolve_service_or_team(target_name, catalog))
    if target_type == EntityType.PERSON:
        return target_norm in _allowed_people(state, catalog)
    return target_norm in _norm(_state_text(state))


def _normalized_question_intent(text: str) -> str | None:
    lower = text.lower()
    if _asks_security_details(lower):
        return "request_details_from_researcher"
    if "trust post" in lower or "trustpost" in lower:
        if any(term in lower for term in ("need", "needed", "required", "confirm", "status", "?")):
            return "ask_trust_post_needed"
    if "looped in" in lower or "already engaged" in lower or "already involved" in lower:
        return "already_looped_in"
    if "impact" in lower and ("clarify" in lower or "what" in lower or "scope" in lower):
        return "clarify_impact"
    return None


def _trust_post_answered_no_need(state: CurrentIncidentState) -> bool:
    stale_intents = {_norm(intent) for intent in state.stale_question_intents}
    if stale_intents.intersection(TRUST_POST_INTENTS):
        return True
    for question in state.answered_questions:
        text = f"{question.intent} {question.text} {question.answer or ''}"
        text_norm = _norm(text)
        if any(intent in text_norm for intent in TRUST_POST_INTENTS):
            return True
        if "trust post" in text_norm or "trustpost" in text_norm:
            if any(phrase in text_norm for phrase in TRUST_POST_NO_NEED_PHRASES):
                return True
    for action in state.actions_completed:
        summary = _norm(action.summary)
        if ("trust post" in summary or "trustpost" in summary) and any(
            phrase in summary for phrase in TRUST_POST_NO_NEED_PHRASES
        ):
            return True
    return False


def _security_details_provided(state: CurrentIncidentState) -> bool:
    stale_intents = {_norm(intent) for intent in state.stale_question_intents}
    if stale_intents.intersection(DETAILS_REQUEST_INTENTS):
        return True
    for question in state.answered_questions:
        text = _norm(f"{question.intent} {question.text} {question.answer or ''}")
        if any(intent in text for intent in DETAILS_REQUEST_INTENTS):
            return True
        if ("detail" in text or "details" in text) and any(
            term in text for term in ("researcher", "reporter", "vulnerability", "security")
        ):
            return True
    for link in state.links_seen:
        link_text = _norm(link.url)
        if any(term in link_text for term in ("jira", "wf", "vulnerab", "security")):
            return True
    return False


def _details_request_intent(stale_intents: set[str]) -> str:
    priority = (
        "request_details_from_researcher",
        "ask_reporter_for_more_details",
        "ask_security_reporter_for_details",
        "request_vulnerability_details",
        "request_observations",
        "request_next_actions_from_reporter",
        "ask_reporter_observations_next_actions",
    )
    for intent in priority:
        if intent in stale_intents:
            return intent
    return "request_details_from_researcher"


def _match_details_request_phrase(segment_norm: str) -> str | None:
    if (
        any(
            phrase in segment_norm
            for phrase in (
                "details link has already been provided",
                "details have already been provided",
                "details are in",
                "details link",
            )
        )
        and "?" not in segment_norm
        and not any(
            phrase in segment_norm
            for phrase in ("ask", "can you", "could you", "please provide", "please share", "request", "what are")
        )
    ):
        return None
    patterns = (
        ("share more details", r"\bshare\b.{0,30}\bmore details\b"),
        ("provide more details", r"\bprovide\b.{0,30}\bmore details\b"),
        ("provide your observations", r"\bprovide\b.{0,30}\byour observations\b"),
        ("what are your observations", r"\bwhat\b.{0,20}\byour observations\b"),
        ("next actions proposed", r"\bnext actions proposed\b"),
        ("proposed actions", r"\b(?:next proposed actions|proposed next actions|proposed actions)\b"),
        ("what are your next actions", r"\bwhat\b.{0,30}\byour next actions\b"),
        ("details regarding the vulnerability", r"\bdetails\b.{0,40}\bregarding\b.{0,30}\bvulnerability\b"),
        ("provide vulnerability details", r"\bprovide\b.{0,40}\bvulnerability details\b"),
        ("request details from the researcher", r"\brequest details from (?:the )?researcher\b"),
        ("what did the researcher report", r"\bwhat did (?:the )?researcher report\b"),
        ("can you share the report", r"\bcan you\b.{0,30}\bshare\b.{0,20}\breport\b"),
        ("can you provide context", r"\bcan you\b.{0,30}\bprovide context\b"),
        ("provide additional details", r"\bprovide\b.{0,30}\badditional details\b"),
        ("share details", r"\bshare\b.{0,30}\bdetails\b"),
        ("provide details", r"\bprovide\b.{0,30}\bdetails\b"),
        ("vulnerability details", r"\bvulnerability details\b"),
        ("report details", r"\breport details\b"),
    )
    for phrase, pattern in patterns:
        if re.search(pattern, segment_norm):
            return phrase
    return None


def _asks_security_details(segment_norm: str) -> bool:
    return _match_details_request_phrase(segment_norm) is not None


def _details_request_allowed(segment_norm: str) -> bool:
    if _match_details_request_phrase(segment_norm):
        return False
    if (
        "exposure scope" in segment_norm
        or "containment" in segment_norm
        or "mitigation option" in segment_norm
        or "validation step" in segment_norm
        or "next validation" in segment_norm
        or "owner confirmation" in segment_norm
        or "confirm owner" in segment_norm
        or "externally accessible" in segment_norm
        or "exploitable" in segment_norm
    ):
        return True
    return False


def _stale_finding(
    *,
    intent: str,
    matched_family: str,
    matched_phrase: str,
    reason: str,
) -> dict[str, str]:
    return {
        "intent": intent,
        "matched_family": matched_family,
        "matched_phrase": matched_phrase,
        "reason": reason,
    }


def _format_stale_finding(finding: dict[str, str]) -> str:
    return (
        f"stale question intent: {finding['intent']} "
        f"family={finding['matched_family']} "
        f"phrase={finding['matched_phrase']} "
        f"reason={finding['reason']}"
    )


def _asks_trust_post_needed(segment_norm: str) -> bool:
    if "trust post" not in segment_norm and "trustpost" not in segment_norm:
        return False
    no_need_statement = any(phrase in segment_norm for phrase in TRUST_POST_NO_NEED_PHRASES)
    if no_need_statement and "confirm" not in segment_norm and "?" not in segment_norm:
        return False
    return bool(
        "?" in segment_norm
        or "confirm whether" in segment_norm
        or "please confirm" in segment_norm
        or re.search(r"\b(?:do we|should we|can .{0,40}confirm|is .{0,40}needed)\b", segment_norm)
        or re.search(r"\btrust ?post\b.{0,40}\b(?:needed|required|status)\b", segment_norm)
    )


def detect_stale_question_findings(text: str, state: CurrentIncidentState) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    engaged_or_suggested = {
        _norm(entity.display_name)
        for group in (state.engaged_entities, state.suggested_but_not_engaged)
        for entity in group
    }
    stale_terms = ("looped in", "already engaged", "already involved", "already on this")
    stale_intents = {_norm(item) for item in state.stale_question_intents}
    trust_post_answered = _trust_post_answered_no_need(state)
    security_details_provided = _security_details_provided(state)
    segments = [segment for segment in re.split(r"(?<=[.!?])\s+|\n+", text) if segment.strip()]
    for segment in segments:
        segment_norm = _norm(segment)
        question_like = "?" in segment or segment_norm.startswith(("do we ", "is ", "are ", "has ", "have "))
        matched_details_phrase = _match_details_request_phrase(segment_norm)
        if security_details_provided and matched_details_phrase and not _details_request_allowed(segment_norm):
            findings.append(
                _stale_finding(
                    intent=_details_request_intent(stale_intents),
                    matched_family="details_request",
                    matched_phrase=matched_details_phrase,
                    reason="Reporter already provided vulnerability details link after the ask.",
                )
            )
            continue
        if trust_post_answered and _asks_trust_post_needed(segment_norm):
            findings.append(
                _stale_finding(
                    intent="ask_trust_post_needed",
                    matched_family="trust_post",
                    matched_phrase="trust post confirmation",
                    reason="Trust Post was already answered as not needed.",
                )
            )
            continue
        if not question_like:
            continue
        for name in engaged_or_suggested:
            if not name or name not in segment_norm:
                continue
            if any(term in segment_norm for term in stale_terms):
                findings.append(
                    _stale_finding(
                        intent="already_looped_in",
                        matched_family="owner_looped_in",
                        matched_phrase=name,
                        reason=f"Target is already engaged or suggested: {name}.",
                    )
                )
                continue
            question_pattern = (
                rf"(?:(?:do we know|do we have)\b[^\n?]{{0,80}}{re.escape(name)}"
                rf"|(?:is|are)\s+{re.escape(name)})"
                rf"[^\n?]{{0,80}}(?:engaged|involved|on this|looped)"
            )
            if re.search(question_pattern, segment_norm):
                findings.append(
                    _stale_finding(
                        intent="ask_if_owner_engaged",
                        matched_family="owner_looped_in",
                        matched_phrase=name,
                        reason=f"Target is already engaged or suggested: {name}.",
                    )
                )
        intent = _normalized_question_intent(segment)
        if intent and intent in stale_intents and intent in EXPLICIT_STALE_INTENTS:
            findings.append(
                _stale_finding(
                    intent=intent,
                    matched_family="explicit_intent",
                    matched_phrase=intent,
                    reason="The intent is already marked stale in current state.",
                )
            )
        for stale_intent in stale_intents.intersection(EXPLICIT_STALE_INTENTS):
            tokens = [
                token
                for token in re.split(r"[_\W]+", stale_intent)
                if len(token) >= 4 and token not in {"whether", "already", "needed"}
            ]
            if tokens and all(token in segment_norm for token in tokens[-2:]):
                findings.append(
                    _stale_finding(
                        intent=stale_intent,
                        matched_family="explicit_intent",
                        matched_phrase=stale_intent,
                        reason="The intent is already marked stale in current state.",
                    )
                )
    deduped: dict[tuple[str, str, str], dict[str, str]] = {}
    for finding in findings:
        key = (finding["intent"], finding["matched_family"], finding["matched_phrase"])
        deduped[key] = finding
    return list(deduped.values())


def detect_stale_question(text: str, state: CurrentIncidentState) -> list[str]:
    return [_format_stale_finding(finding) for finding in detect_stale_question_findings(text, state)]


def detect_generic_impact(text: str) -> bool:
    text_norm = _norm(text)
    return any(
        phrase in text_norm
        for phrase in (
            "clarify impact",
            "clarify scope",
            "what is the impact",
            "what's the impact",
            "what customers are impacted",
            "provide impact",
            "impact and owner",
            "impact/scope",
            "scope and impact",
        )
    )


def _asks_customer_comms_or_trust_post(text_norm: str) -> bool:
    return any(
        phrase in text_norm
        for phrase in (
            "customer communications",
            "customer communication",
            "customer comms",
            "customer-facing update",
            "customer facing update",
            "trust post",
            "trustpost",
        )
    )


def _unsafe_executable_action_phrases(text: str) -> list[str]:
    text_norm = _norm(text)
    findings: list[str] = []
    dedicated_topic_execution_patterns = (
        r"\bperform\s+this\s+move\b",
        r"\bexecute\s+the\s+move\b",
        r"\brun\s+the\s+command\b",
        r"\bmove\s+(?:the\s+)?(?:tenant|\[tenant_id\]|\[redacted_tenant_id\])\b",
        r"\bmove\s+[^.?!]{0,60}\bto\s+(?:a\s+)?(?:dedicated\s+)?topic\b",
        r"\bperform\s+the\s+command\b",
        r"\buse\s+daco-bot\s+command\b",
    )
    for pattern in dedicated_topic_execution_patterns:
        for match in re.finditer(pattern, text_norm):
            findings.append(match.group(0))
    unsafe_terms = (
        "truncate",
        "ssh",
        "disable",
        "rollback",
        "roll back",
        "restart",
        "deploy",
        "delete",
        "scale",
        "curl",
        "sql",
        "kubectl",
        "aws",
        "gcloud",
        "az",
        "page",
        "post",
        "remediate",
    )
    allowed_context = (
        "confirm",
        "status",
        "whether",
        "validation",
        "signal",
        "eta",
        "blocker",
        "remaining",
        "discussed",
    )
    for term in unsafe_terms:
        term_pattern = re.escape(term)
        patterns = (
            rf"\b(?:run|execute|perform|start|kick off|go ahead and)\b.{{0,50}}\b({term_pattern})\b",
            rf"\b(?:please|can you|should we|we should|need to|needs to)\s+({term_pattern})\b",
        )
        for pattern in patterns:
            match = re.search(pattern, text_norm)
            if not match:
                continue
            window = text_norm[max(0, match.start() - 40) : match.end() + 40]
            if any(context in window for context in allowed_context):
                continue
            findings.append(match.group(0))
    return findings


def _looks_like_json_or_diagnostic_target(value: str | None) -> bool:
    stripped = (value or "").strip()
    if not stripped:
        return False
    if stripped.startswith(("{", "[", "}", "]")) and ":" in stripped:
        return True
    match = JSON_DIAGNOSTIC_TARGET_RE.match(stripped)
    if not match:
        return False
    key = re.sub(r"[^a-z0-9_]+", "_", match.group("key").strip().lower()).strip("_")
    if key in JSON_DIAGNOSTIC_TARGET_KEYS:
        return True
    return ":" in stripped and bool(re.search(r"[A-Z_]", match.group("key"))) and len(key.split()) == 1


def _visible_private_identifier_mentions(
    speech_text: str,
    *,
    allowed_tenants: set[str],
    semantic_state_text: str,
) -> list[str]:
    findings: list[str] = []
    for match in PRIVATE_ID_PLACEHOLDER_RE.finditer(speech_text):
        findings.append(match.group(0))
    for number in re.findall(r"\b\d{5,}\b", speech_text):
        if _norm(number) in allowed_tenants:
            findings.append(number)
            continue
        if _explicit_context_contains(number, speech_text, TENANT_CONTEXT_WORDS) and _explicit_context_contains(
            number,
            semantic_state_text,
            TENANT_CONTEXT_WORDS,
        ):
            findings.append(number)
    return list(dict.fromkeys(findings))


def _permission_denied_actor_names(current_events: list[IncidentEvent]) -> dict[str, list[str]]:
    denied: dict[str, list[str]] = {}
    for event in current_events:
        text_norm = _norm(event.message)
        if not any(term in text_norm for term in PERMISSION_DENIED_TERMS):
            continue
        tokens = event.extracted_tokens or {}
        actor_names: list[str] = []
        if not (tokens.get("is_bot") or tokens.get("is_system")) and event.author:
            actor_names.append(event.author)
        actor_names.extend(str(item) for item in tokens.get("slack_mentions", []) if str(item).lower() not in {"here", "channel"})
        for name in actor_names:
            key = _norm(name).lstrip("@")
            if not key:
                continue
            denied.setdefault(key, []).append(event.event_id)
    return denied


def _name_overlaps(left: str, right: str) -> bool:
    left_norm = _norm(left).lstrip("@")
    right_norm = _norm(right).lstrip("@")
    if not left_norm or not right_norm:
        return False
    if left_norm == right_norm or left_norm in right_norm or right_norm in left_norm:
        return True
    return bool(set(left_norm.split()).intersection(set(right_norm.split())))


def _permission_denied_wrong_owner_result(
    *,
    decision: ICDecision,
    allowed_targets: list[AllowedTarget],
    current_events: list[IncidentEvent],
    speech_text_norm: str,
) -> tuple[str | None, dict[str, Any]]:
    detail: dict[str, Any] = {
        "passed": True,
        "selected_targets": _target_names_for_decision(decision, allowed_targets),
        "permission_denied_names": [],
        "matched_evidence_ids": [],
        "operational_permission_loop": False,
    }
    if decision.move == ICMove.NO_SAFE_RECOMMENDATION:
        return None, detail
    operational_loop = any(term in speech_text_norm for term in PERMISSION_LOOP_ACTION_TERMS)
    if not operational_loop:
        return None, detail
    denied = _permission_denied_actor_names(current_events)
    detail["permission_denied_names"] = sorted(denied)
    detail["operational_permission_loop"] = True
    selected = detail["selected_targets"]
    for selected_name in selected:
        for denied_name, evidence_ids in denied.items():
            if _name_overlaps(selected_name, denied_name):
                detail["passed"] = False
                detail["matched_evidence_ids"] = evidence_ids
                return (
                    f"permission-denied wrong-owner loop: {selected_name} is asked about performing/executing "
                    "a permission-blocked operation despite current evidence that they lack permission",
                    detail,
                )
    return None, detail


def _sharp_blocker_misaligned(text_norm: str, sharp_blocker: SharpBlockerAssessment | None) -> str | None:
    if sharp_blocker is None or sharp_blocker.blocker_type not in TECHNICAL_SHARP_BLOCKERS:
        return None
    if _asks_customer_comms_or_trust_post(text_norm):
        if any(phrase in text_norm for phrase in ("no need", "not needed", "already answered", "answered as not needed")):
            return None
        return (
            "output_asks_wrong_blocker: "
            f"{sharp_blocker.blocker_type} is sharper than customer communications or Trust Post"
        )
    if detect_generic_impact(text_norm) and sharp_blocker.blocker_type != "missing_impact":
        return f"output_asks_wrong_blocker: generic impact ask despite {sharp_blocker.blocker_type}"
    return None


def _asks_root_cause_as_primary(text_norm: str) -> bool:
    if not any(term in text_norm for term in ("root cause", "rca", "root-cause")):
        return False
    if any(
        phrase in text_norm
        for phrase in (
            "rca follow-up",
            "root cause follow-up",
            "capture notes for rca",
            "track rca separately",
        )
    ):
        return False
    return bool(
        re.search(r"\b(?:provide|share|confirm|give|need|needs|ask for)\b.{0,80}\b(?:root cause|rca|root-cause)\b", text_norm)
        or "root cause analysis" in text_norm
    )


def _no_premature_rca_failure(
    text_norm: str,
    state: CurrentIncidentState,
    sharp_blocker: SharpBlockerAssessment | None,
) -> str | None:
    blocker = sharp_blocker.blocker_type if sharp_blocker is not None else state.current_blocker
    unresolved_phase = state.phase in {
        IncidentPhase.ENGAGEMENT,
        IncidentPhase.INVESTIGATION,
        IncidentPhase.MITIGATION,
        IncidentPhase.MONITORING,
        IncidentPhase.VERIFICATION,
    }
    if blocker in UNRESOLVED_RCA_BLOCKERS and unresolved_phase and _asks_root_cause_as_primary(text_norm):
        return f"premature RCA ask while {blocker} is still unresolved"
    return None


def _role_target_misaligned(text_norm: str, sharp_blocker: SharpBlockerAssessment | None) -> str | None:
    if sharp_blocker is None:
        return None
    technical_targets = {_norm(name) for name in sharp_blocker.technical_status_targets}
    reporter_targets = {_norm(name) for name in sharp_blocker.should_not_target_for_fix_status}
    if not technical_targets or not reporter_targets:
        return None
    technical_terms = (
        "fix status",
        "root cause",
        "rca",
        "technical status",
        "mitigation status",
        "rollback status",
        "disable status",
        "stability status",
    )
    if not any(phrase in text_norm for phrase in technical_terms):
        return None
    for reporter in reporter_targets:
        if not reporter:
            continue
        reporter_pattern = rf"(?<![a-z0-9]){re.escape(reporter)}(?![a-z0-9])"
        asks_reporter_for_technical_work = any(
            re.search(rf"{reporter_pattern}[^.?!;]{{0,120}}\b{re.escape(term)}\b", text_norm)
            or re.search(rf"\b{re.escape(term)}\b[^.?!;]{{0,80}}{reporter_pattern}", text_norm)
            for term in technical_terms
        )
        if asks_reporter_for_technical_work:
            return f"reporter/validator {reporter} asked for technical fix status while technical target is visible"
    return None


def _fallback(decision: ICDecision) -> ICDecision:
    return ICDecision(
        decision_id=f"fallback-{decision.decision_id}",
        incident_id=decision.incident_id,
        move=ICMove.NO_SAFE_RECOMMENDATION,
        phase=decision.phase,
        output={"say_this": "I do not have a safe, grounded next move yet."},
        targets=[],
        rationale=["Verifier blocked the proposed decision."],
        grounding=[],
        confidence=0.2,
    )


def collect_forbidden_historical_facts(
    accepted_memories: list[MemoryApplicabilityResult | DecisionMoment],
    hydrated_moments: list[DecisionMoment] | None = None,
) -> list[str]:
    facts: list[str] = []
    for memory in accepted_memories:
        if isinstance(memory, MemoryApplicabilityResult):
            if memory.accepted:
                facts.extend(memory.forbidden_fact_leakage)
        else:
            facts.extend(memory.forbidden_fact_leakage)
    for moment in hydrated_moments or []:
        facts.extend(moment.forbidden_fact_leakage)
    return facts


def _accepted_forbidden_facts(accepted_memories: list[MemoryApplicabilityResult | DecisionMoment]) -> list[str]:
    return collect_forbidden_historical_facts(accepted_memories)


def detect_unregistered_commands(
    text: str,
    command_registry: list[CommandRegistryEntry],
    allowed_targets: list[AllowedTarget] | None = None,
) -> list[str]:
    findings: list[str] = []
    allowed_targets = allowed_targets or []
    for match in re.finditer(r"(?m)(^|\s)(/[a-z][\w-]*(?:\s+[^\n]+)?|@\w+\s+\w+(?:\s+[A-Za-z0-9_. -]+)?)", text):
        candidate = " ".join(match.group(2).strip().split())
        entry = _matching_command_registry_entry(candidate, command_registry)
        if entry is not None and entry.requires_human_approval:
            continue
        if candidate.startswith("@") and _is_allowed_human_address_command_like(candidate, allowed_targets):
            continue
        if candidate.startswith("/") or candidate.startswith("@"):
            findings.append(candidate)
    return findings


def _matching_command_registry_entry(
    command: str,
    command_registry: list[CommandRegistryEntry],
) -> CommandRegistryEntry | None:
    command_norm = _norm(command)
    for entry in command_registry:
        if entry.exact and _norm(entry.command) == command_norm:
            return entry
        if entry.pattern and re.match(entry.pattern, command):
            return entry
    return None


def _registry_command_target_supported(
    command: str,
    entry: CommandRegistryEntry,
    catalog: list[ServiceCatalogEntry],
) -> bool:
    if not entry.requires_catalog_target or not entry.pattern:
        return True
    match = re.match(entry.pattern, command)
    if not match or not match.groups():
        return False
    target = match.group(1)
    return bool(resolve_service_or_team(target, catalog))


def _number_kind_for_current_events(number: str, current_events: list[IncidentEvent]) -> set[str]:
    kinds: set[str] = set()
    for event in current_events:
        for token in (event.extracted_tokens or {}).get("numbers", []):
            if str(token.get("value")) == number:
                kinds.add(str(token.get("numeric_evidence_kind") or "untyped_numeric_id"))
    return kinds


def is_non_targetable_fact_mention_allowed(
    text_term: str,
    *,
    decision: ICDecision,
    current_event_text_by_id: dict[str, str],
    current_events: list[IncidentEvent],
) -> bool:
    """Allow grounded facts that are not valid targets.

    Targetability and mentionability are different safety questions. Numeric
    operational IDs, tenant IDs, tickets, environments, and diagnostic labels
    must never become selected targets, but they may be mentioned when the
    model grounds them in current incident evidence.
    """
    term = str(text_term or "").strip()
    if not term:
        return False
    term_norm = _norm(term)
    cited_text = "\n".join(
        current_event_text_by_id.get(evidence.event_id, "")
        for evidence in decision.grounding
        if evidence.event_id in current_event_text_by_id
    )
    current_text = "\n".join(current_event_text_by_id.values())
    if term_norm not in _norm(cited_text or current_text):
        return False
    if re.fullmatch(r"\d{5,}", term):
        kinds = _number_kind_for_current_events(term, current_events)
        if kinds and kinds.issubset({"url_path_number"}):
            return False
        return bool(kinds.intersection({"tenant_id", "ticket_id", "metric_count_version", "untyped_numeric_id"}))
    return term_norm in _norm(cited_text)


def _allowed_manual_address_prefixes(allowed_targets: list[AllowedTarget]) -> set[str]:
    prefixes: set[str] = set()
    for target in allowed_targets:
        if (
            not target.targetable
            or target.target_type in {"bot_system", "non_targetable_noise"}
            or target.target_quality in {"low", "rejected"}
        ):
            continue
        name_norm = _norm(target.display_name)
        if not name_norm:
            continue
        prefixes.add(name_norm)
        if "/" in name_norm:
            slash_parts = [part.strip() for part in name_norm.split("/") if part.strip()]
            prefixes.update(part for part in slash_parts if len(part) >= 3)
            prefixes.add(" ".join(slash_parts))
        first = name_norm.split()[0]
        if target.target_type == "person" and len(first) >= 4:
            prefixes.add(first)
    return prefixes


def _is_allowed_human_address_command_like(candidate: str, allowed_targets: list[AllowedTarget]) -> bool:
    raw_norm = _norm(candidate).lstrip("@")
    if not raw_norm:
        return False
    dangerous_address_verbs = {
        "curl",
        "delete",
        "deploy",
        "disable",
        "execute",
        "kubectl",
        "page",
        "post",
        "remediate",
        "restart",
        "rollback",
        "run",
        "scale",
        "ssh",
    }
    for prefix in _allowed_manual_address_prefixes(allowed_targets):
        if raw_norm == prefix:
            return True
        if not raw_norm.startswith(f"{prefix} "):
            continue
        rest = raw_norm[len(prefix) :].strip()
        rest_words = rest.split()
        first = rest_words[0] if rest_words else ""
        first_command = next(
            (word for word in rest_words if word not in {"and", "or", "please", "can", "could", "you"}),
            "",
        )
        if first in dangerous_address_verbs or first_command in dangerous_address_verbs:
            return False
        break
    candidate_norm = re.sub(r"\b(?:and|or|please|can|could|confirm|provide|share)\b.*$", "", raw_norm).strip()
    candidate_norm = candidate_norm.strip(",;:/ ")
    if not candidate_norm:
        return False
    return any(
        candidate_norm == prefix or candidate_norm.startswith(f"{prefix} ")
        for prefix in _allowed_manual_address_prefixes(allowed_targets)
    )


INTENT_STOPWORDS = {
    "about",
    "and",
    "any",
    "are",
    "can",
    "could",
    "current",
    "do",
    "for",
    "from",
    "have",
    "latest",
    "need",
    "please",
    "provide",
    "share",
    "status",
    "the",
    "this",
    "when",
    "with",
    "you",
}


def _stem_intent_token(token: str) -> str:
    mapping = {
        "fixed": "fix",
        "fixing": "fix",
        "credentials": "credential",
        "keys": "key",
        "logs": "log",
        "rotating": "rotate",
        "rotation": "rotate",
        "vulnerabilities": "vulnerability",
    }
    if token in mapping:
        return mapping[token]
    if len(token) > 5 and token.endswith("ing"):
        return token[:-3]
    if len(token) > 4 and token.endswith("ed"):
        return token[:-2]
    return token


def _intent_tokens(text: str) -> set[str]:
    return {
        _stem_intent_token(token)
        for token in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", _norm(text))
        if token not in INTENT_STOPWORDS and not token.isdigit()
    }


def _intent_equivalent(left: str, right: str) -> bool:
    left_tokens = _intent_tokens(left)
    right_tokens = _intent_tokens(right)
    if not left_tokens or not right_tokens:
        return False
    overlap = left_tokens & right_tokens
    if len(overlap) >= 3:
        return True
    if overlap and len(overlap) == min(len(left_tokens), len(right_tokens)) and overlap.intersection(
        {"audit", "credential", "eta", "fix", "rotate", "status", "vulnerability"}
    ):
        return True
    return len(overlap) >= 2 and len(overlap) / min(len(left_tokens), len(right_tokens)) >= 0.6


def _primary_ask_text(text_norm: str) -> str:
    return re.split(r"\b(?:while|as|with)\b", text_norm, maxsplit=1)[0]


IMPLEMENTATION_STATUS_PHRASES = (
    "can it be done",
    "can this be done",
    "can we get this done",
    "eta",
    "status",
    "completed",
    "completion",
    "finish",
    "finished",
    "deploy",
    "production-ready",
    "production ready",
    "fix completed",
    "implementation",
    "rollout",
    "ecm steps",
    "change steps",
)
DEADLINE_CLARIFICATION_PHRASES = (
    "required deadline",
    "need-by",
    "need by",
    "business deadline",
    "security deadline",
    "required by",
    "priority requirement",
    "how soon do you need",
    "when do we need",
)


def _output_action_type(text_norm: str) -> str:
    implementation = any(phrase in text_norm for phrase in IMPLEMENTATION_STATUS_PHRASES) or bool(
        re.search(r"\bcan\b.{0,80}\bbe done\b", text_norm)
    )
    deadline = any(phrase in text_norm for phrase in DEADLINE_CLARIFICATION_PHRASES)
    if implementation and deadline:
        return "mixed_deadline_and_implementation"
    if implementation:
        return "implementation_status_eta_or_feasibility"
    if deadline:
        return "deadline_clarification"
    return "action_reference"


def _asks_ic_to_route_or_coordinate(text_norm: str) -> bool:
    return any(
        phrase in text_norm
        for phrase in (
            "route",
            "coordinate",
            "ask the owner",
            "pull in",
            "align with",
            "can you get",
        )
    )


def _work_item_matches_primary_ask(item: dict[str, Any], text_norm: str) -> bool:
    primary = _primary_ask_text(text_norm)
    label_tokens = _intent_tokens(str(item.get("work_item_label") or ""))
    action_tokens = _intent_tokens(str(item.get("status_or_action") or ""))
    primary_tokens = _intent_tokens(primary)
    if not primary_tokens:
        return False
    label_overlap = label_tokens & primary_tokens
    action_overlap = action_tokens & primary_tokens
    if label_tokens and label_tokens.issubset(primary_tokens):
        return True
    if len(label_overlap) >= 2 or len(action_overlap) >= 3:
        return True
    if len(action_overlap) >= 2 and action_overlap.intersection(
        {"action_type", "audit", "credential", "input", "key", "log", "validation"}
    ):
        return True
    if "fix" in label_tokens and "fix" in primary_tokens:
        return True
    if "vulnerability" in label_tokens and "fix" in primary_tokens:
        return True
    if {"input", "validation"}.issubset(action_tokens) and {"input", "validation"}.issubset(primary_tokens):
        return True
    if {"audit", "log"} & label_tokens and {"audit", "log", "key"} & primary_tokens:
        return True
    if {"rotate", "credential"} & label_tokens and {"rotate", "credential", "key"} & primary_tokens:
        return True
    return False


def _name_matches_owner(target_name: str, item: dict[str, Any]) -> bool:
    target = _norm(target_name).lstrip("@")
    if not target:
        return False
    owner_names = {_norm(str(name)).lstrip("@") for name in item.get("owner_names", [])}
    owner_group = _norm(str(item.get("owner_group") or ""))
    if target in owner_names:
        return True
    if any(owner and (target in owner or owner in target) for owner in owner_names):
        return True
    if owner_group and (target == owner_group or target == f"{owner_group} team" or owner_group in target):
        return True
    return False


def _action_owner_alignment_result(
    *,
    decision: ICDecision,
    allowed_targets: list[AllowedTarget],
    current_work_items: list[dict[str, Any]],
    speech_text_norm: str,
) -> tuple[str | None, dict[str, Any]]:
    detail: dict[str, Any] = {
        "passed": True,
        "matched_work_item_label": None,
        "output_action_type": _output_action_type(speech_text_norm),
        "selected_target": None,
        "selected_target_ids": [],
        "expected_owners": [],
    }
    if decision.move == ICMove.NO_SAFE_RECOMMENDATION:
        return None, detail
    work_items = current_work_items
    if not work_items:
        return None, detail
    allowed_by_id = {target.target_id: target for target in allowed_targets}
    selected_targets = [
        allowed_by_id[target_id]
        for target_id in decision.target_ids
        if target_id in allowed_by_id and allowed_by_id[target_id].targetable
    ]
    if not selected_targets:
        return None, detail
    unique_selected_names = list(dict.fromkeys(target.display_name for target in selected_targets))
    unique_selected_ids = list(dict.fromkeys(target.target_id for target in selected_targets))
    matched_items = [item for item in work_items if _work_item_matches_primary_ask(item, speech_text_norm)]
    if not matched_items:
        return None, detail
    output_type = _output_action_type(speech_text_norm)
    for item in matched_items:
        expected = [*item.get("owner_names", [])]
        if item.get("owner_group"):
            expected.append(str(item.get("owner_group")))
        detail.update(
            {
                "matched_work_item_label": item.get("work_item_label"),
                "selected_target": ", ".join(unique_selected_names),
                "selected_target_ids": unique_selected_ids,
                "expected_owners": expected,
            }
        )
        for target in selected_targets:
            if target.role_hint == "ic_or_coordinator" and _asks_ic_to_route_or_coordinate(speech_text_norm):
                return None, detail
            if _name_matches_owner(target.display_name, item):
                return None, detail
        if output_type == "deadline_clarification":
            return None, detail
    labels = ", ".join(str(item.get("work_item_label")) for item in matched_items)
    target_names = ", ".join(unique_selected_names)
    expected = ", ".join(
        str(owner)
        for item in matched_items
        for owner in [*item.get("owner_names", []), item.get("owner_group")]
        if owner
    )
    detail["passed"] = False
    return (
        f"action owner mismatch: {target_names} asked about {labels} "
        f"as {output_type} but explicit owner is {expected}",
        detail,
    )


def _stale_open_loop_contradiction(
    *,
    decision: ICDecision,
    current_work_items: list[dict[str, Any]],
) -> tuple[str | None, dict[str, Any]]:
    detail: dict[str, Any] = {
        "passed": True,
        "metadata_only": False,
        "metadata_repair_reason": None,
        "old_question_event_id": None,
        "later_work_item_evidence_id": None,
        "output_intent_type": _output_action_type(_norm(str(decision.output.get("say_this") or ""))),
    }
    if decision.move == ICMove.NO_SAFE_RECOMMENDATION or not current_work_items:
        return None, detail
    latest_open_loop = str(decision.model_metadata.get("latest_open_loop") or decision.domain_intent or "")
    say_this = str(decision.output.get("say_this") or "")
    for answered in decision.model_metadata.get("already_answered", []) or []:
        answered_text = str(answered)
        if say_this and _intent_equivalent(answered_text, say_this):
            detail["later_work_item_evidence_id"] = current_work_items[0].get("evidence_id")
            if _answered_metadata_has_current_answer(answered_text, current_work_items):
                detail["passed"] = False
                return "already_answered repeats SAY THIS while later owner/action evidence is present", detail
            detail["metadata_only"] = True
            detail["metadata_repair_reason"] = "stale_open_loop_metadata_only"
            return None, detail
        if latest_open_loop and _intent_equivalent(answered_text, latest_open_loop):
            detail["metadata_only"] = True
            detail["metadata_repair_reason"] = "stale_open_loop_metadata_only"
            detail["later_work_item_evidence_id"] = current_work_items[0].get("evidence_id")
            return None, detail
    output_type = _output_action_type(_norm(f"{latest_open_loop} {say_this}"))
    if output_type in {"implementation_status_eta_or_feasibility", "mixed_deadline_and_implementation"}:
        for item in current_work_items:
            if _work_item_matches_primary_ask(item, _norm(f"{latest_open_loop} {say_this}")):
                detail["later_work_item_evidence_id"] = item.get("evidence_id")
                detail["output_intent_type"] = output_type
                return None, detail
    return None, detail


def _answered_metadata_has_current_answer(answered_text: str, current_work_items: list[dict[str, Any]]) -> bool:
    answered_norm = _norm(answered_text)
    if not answered_norm:
        return False
    definite_answer_terms = (
        "already",
        "eta is",
        "eta:",
        "completed",
        "complete",
        "resolved",
        "deployed",
        "provided",
        "confirmed",
        "no need",
        "not needed",
    )
    question_terms = (
        "can we",
        "can you",
        "could we",
        "could you",
        "when do",
        "when is",
        "how soon",
        "do we need",
    )
    if any(term in answered_norm for term in question_terms) and not any(
        term in answered_norm for term in definite_answer_terms
    ):
        return False
    answer_terms = (
        "already answered",
        "completed",
        "complete",
        "done",
        "fixed",
        "resolved",
        "deployed",
        "rolled out",
        "eta is",
        "eta:",
        "provided",
        "confirmed",
        "no need",
        "not needed",
    )
    if any(term in answered_norm for term in answer_terms):
        return True
    for item in current_work_items:
        item_text = _norm(
            " ".join(
                str(item.get(key) or "")
                for key in ("work_item_label", "owner_group", "status_or_action")
            )
        )
        if not item_text:
            continue
        if any(term in item_text for term in answer_terms) and _intent_tokens(answered_norm) & _intent_tokens(item_text):
            return True
    return False


GENERIC_STATUS_RECAP_PHRASES = (
    "current status of the case",
    "case status",
    "status of the case",
    "status update",
    "provide status",
    "provide the current status",
    "share current status",
    "zoom discussion",
    "zoom details",
    "discussed on zoom",
    "bridge discussion",
    "discussion details",
)
STATUS_UPDATE_MARKERS = (
    "incident update",
    "current status",
    "current update",
    "findings",
    "next steps",
    "next actions",
    "severity",
    "downgrade",
    "impact",
    "impacted",
    "investigation",
    "monitoring",
    "trust post",
)


def _looks_like_generic_status_recap_ask(speech_text_norm: str) -> bool:
    if not speech_text_norm:
        return False
    statusish = any(
        phrase in speech_text_norm
        for phrase in (
            "current status",
            "case status",
            "status of the case",
            "status update",
            "provide status",
            "share status",
        )
    )
    recapish = any(
        phrase in speech_text_norm
        for phrase in (
            "zoom",
            "discussion",
            "discussed",
            "bridge details",
            "case including",
            "including the",
        )
    )
    return (statusish and recapish) or any(phrase in speech_text_norm for phrase in GENERIC_STATUS_RECAP_PHRASES)


def _human_like_event(event: IncidentEvent, quality: EventQuality | None) -> bool:
    if quality is not None:
        if quality.author_type == "human" or quality.event_kind.startswith("human_"):
            return True
        if quality.author_type in {"bot", "system"}:
            return False
    tokens = event.extracted_tokens or {}
    return not bool(tokens.get("is_bot") or tokens.get("is_system"))


def _status_update_marker_count(text_norm: str) -> int:
    return sum(1 for marker in STATUS_UPDATE_MARKERS if marker in text_norm)


def _target_names_for_decision(decision: ICDecision, allowed_targets: list[AllowedTarget]) -> list[str]:
    by_id = {target.target_id: target for target in allowed_targets}
    names = [
        by_id[target_id].display_name
        for target_id in decision.target_ids
        if target_id in by_id and by_id[target_id].display_name
    ]
    display = str(decision.output.get("target") or decision.output.get("selected_target_display_name") or "").strip()
    if display:
        names.append(display)
    return list(dict.fromkeys(names))


def _author_matches_any_name(author: str | None, names: list[str]) -> bool:
    author_norm = _norm(author).lstrip("@")
    if not author_norm:
        return False
    for name in names:
        name_norm = _norm(name).lstrip("@")
        if not name_norm:
            continue
        if author_norm == name_norm or author_norm in name_norm or name_norm in author_norm:
            return True
    return False


def _stale_status_recap_result(
    *,
    decision: ICDecision,
    allowed_targets: list[AllowedTarget],
    current_events: list[IncidentEvent],
    event_quality_by_id: dict[str, EventQuality],
    current_work_items: list[dict[str, Any]],
    speech_text_norm: str,
) -> tuple[str | None, dict[str, Any]]:
    detail: dict[str, Any] = {
        "passed": True,
        "matched_event_id": None,
        "matched_event_author": None,
        "selected_targets": _target_names_for_decision(decision, allowed_targets),
        "work_item_count": len(current_work_items),
    }
    if decision.move == ICMove.NO_SAFE_RECOMMENDATION or not _looks_like_generic_status_recap_ask(speech_text_norm):
        return None, detail
    selected_names = detail["selected_targets"]
    for event in current_events:
        text_norm = _norm(event.message)
        if _status_update_marker_count(text_norm) < 3:
            continue
        if not _human_like_event(event, event_quality_by_id.get(event.event_id)):
            continue
        target_author_match = _author_matches_any_name(event.author, selected_names)
        if not target_author_match and not current_work_items:
            continue
        detail.update(
            {
                "passed": False,
                "matched_event_id": event.event_id,
                "matched_event_author": event.author,
            }
        )
        return (
            "stale visible status/Zoom recap ask after later human incident update supplied status and next-step context",
            detail,
        )
    return None, detail


CONFIRMED_PRIORITY_OUTPUT_RE = re.compile(
    r"\b(?:severity|priority)\s+(?:has\s+been\s+|was\s+|is\s+)?(?:updated|changed|set|converted)\s+(?:to\s+)?p[1-4]\b"
    r"|\b(?:is\s+now|now|confirmed\s+as)\s+(?:a\s+)?p[1-4]\b"
    r"|\b(?:noted|said|stated|mentioned)\s+this\s+is\s+(?:a\s+)?p[1-4]\b"
    r"|\bthis\s+is\s+now\s+(?:a\s+)?p[1-4]\b",
    re.IGNORECASE,
)
CONFIRMED_PRIORITY_EVIDENCE_RE = re.compile(
    r"\b(?:priority|severity)\s+(?:has\s+been\s+|was\s+|is\s+)?(?:updated|changed|set|converted)\s+(?:to\s+)?p[1-4]\b"
    r"|\b(?:we\s+are|we're)\s+(?:changing|setting|converting)\s+(?:this\s+)?(?:to\s+)?p[1-4]\b"
    r"|\b(?:changed|set|converted)\s+(?:incident\s+)?(?:priority|severity)\s+(?:to\s+)?p[1-4]\b"
    r"|\bincident\s+priority\s+p[1-4]\b",
    re.IGNORECASE,
)
PROPOSED_PRIORITY_RE = re.compile(
    r"\b(?:should\s+be|needs?\s+to\s+be|can\s+we\s+make|maybe|propos(?:e|ed)|request(?:ing)?|asking)\s+(?:a\s+)?p[1-4]\b",
    re.IGNORECASE,
)


def _has_confirmed_priority_evidence(current_events: list[IncidentEvent]) -> bool:
    for event in current_events:
        text = event.message or ""
        if CONFIRMED_PRIORITY_EVIDENCE_RE.search(text) and not PROPOSED_PRIORITY_RE.search(text):
            return True
    return False


def _unconfirmed_priority_claim_result(
    *,
    speech_text: str,
    current_events: list[IncidentEvent],
) -> tuple[str | None, dict[str, Any]]:
    detail = {
        "passed": True,
        "visible_priority_claim": None,
        "confirmed_priority_evidence_found": False,
    }
    match = CONFIRMED_PRIORITY_OUTPUT_RE.search(speech_text)
    if not match:
        return None, detail
    detail["visible_priority_claim"] = match.group(0)
    confirmed = _has_confirmed_priority_evidence(current_events)
    detail["confirmed_priority_evidence_found"] = confirmed
    if confirmed:
        return None, detail
    detail["passed"] = False
    return "visible output treats proposed severity/priority as confirmed without current priority-change evidence", detail


def _looks_like_useless_self_summary(decision: ICDecision, speech_text_norm: str) -> bool:
    if decision.move == ICMove.NO_SAFE_RECOMMENDATION:
        return False
    actionable_terms = (
        "can you",
        "could you",
        "please confirm",
        "confirm whether",
        "share",
        "provide",
        "validate",
        "check",
        "what ",
        "whether",
        "?",
    )
    has_actionable_ask = any(term in speech_text_norm for term in actionable_terms)
    restates_person_claim = bool(
        re.search(r"\b(?:noted|said|mentioned|stated)\s+(?:this|that|it)\s+(?:is|was)\b", speech_text_norm)
    )
    return (decision.move == ICMove.SUMMARIZE_CURRENT_STATE or restates_person_claim) and not has_actionable_ask


def verify_ic_decision(
    decision: ICDecision | dict,
    current_state: CurrentIncidentState | dict,
    catalog: list[ServiceCatalogEntry],
    accepted_memories: list[MemoryApplicabilityResult | DecisionMoment],
    command_registry: list[CommandRegistryEntry] | None = None,
    sharp_blocker_assessment: SharpBlockerAssessment | dict | None = None,
    incident_brief: IncidentBrief | dict | None = None,
    allowed_targets: list[AllowedTarget] | list[dict] | None = None,
    semantic_quality: SemanticQuality | dict | None = None,
    incident_brief_quality: BriefQualityResult | dict | None = None,
    event_quality: list[EventQuality] | list[dict] | None = None,
    current_events: list[IncidentEvent] | list[dict] | None = None,
    current_work_items: list[dict[str, Any]] | None = None,
) -> VerifierResult:
    if isinstance(current_state, dict):
        current_state = CurrentIncidentState.model_validate(current_state)
    if isinstance(sharp_blocker_assessment, dict):
        sharp_blocker_assessment = SharpBlockerAssessment.model_validate(sharp_blocker_assessment)
    if isinstance(incident_brief, dict):
        incident_brief = IncidentBrief.model_validate(incident_brief)
    if isinstance(semantic_quality, dict):
        semantic_quality = SemanticQuality.model_validate(semantic_quality)
    if isinstance(incident_brief_quality, dict):
        incident_brief_quality = BriefQualityResult.model_validate(incident_brief_quality)
    allowed_targets = [AllowedTarget.model_validate(target) for target in (allowed_targets or [])]
    event_quality = [EventQuality.model_validate(quality) for quality in (event_quality or [])]
    event_quality_by_id = {quality.event_id: quality for quality in event_quality}
    current_events = [IncidentEvent.model_validate(event) for event in (current_events or [])]
    current_work_items = list(current_work_items or extract_current_work_items(current_events))
    current_event_text_by_id = {event.event_id: event.message for event in current_events}
    current_event_text = "\n".join(
        f"{event.event_id} {event.author or ''}: {event.message}" for event in current_events
    )
    decision = _coerce_decision(decision, current_state)
    command_registry = command_registry or []
    text = _decision_text(decision)
    text_norm = _norm(text)
    speech_text = "\n".join(
        str(decision.output.get(key) or "")
        for key in ("say_this", "next_line")
    )
    speech_text_norm = _norm(speech_text)
    if redact_for_llm(text) != text:
        checks_secret_pending = True
    else:
        checks_secret_pending = False
    state_text = _state_text(current_state)
    state_text_norm = _norm(state_text)
    brief_evidence_text = ""
    if incident_brief is not None:
        brief_evidence_text = "\n".join(
            piece
            for piece in (
                incident_brief.current_summary,
                incident_brief.latest_blocker.summary,
                incident_brief.recommended_ic_focus.summary,
                *[item.summary for item in incident_brief.completed_actions],
                *[item.summary for item in incident_brief.active_workstreams],
                *[item.reason for item in incident_brief.do_not_ask],
            )
            if piece
        )
    semantic_state_text = "\n".join(
        piece
        for piece in (
            _state_text(current_state, include_links=False),
            brief_evidence_text,
            current_event_text,
        )
        if piece
    )
    semantic_state_text_norm = _norm(semantic_state_text)

    checks = {
        "schema_valid": True,
        "evidence_grounded": True,
        "no_fake_customer": True,
        "no_fake_tenant": True,
        "no_fake_person": True,
        "no_fake_team": True,
        "no_fake_service": True,
        "no_historical_fact_leakage": True,
        "no_stale_question": True,
        "valid_command": True,
        "target_exists": True,
        "phase_compatible": True,
        "monitoring_signal_supported": True,
        "not_too_generic": True,
        "sharp_blocker_aligned": True,
        "no_premature_rca": True,
        "role_target_aligned": True,
        "action_owner_aligned": True,
        "stale_open_loop_contradiction": True,
        "stale_answered_open_loop": True,
        "stale_visible_status_recap": True,
        "target_in_allowed_targets": True,
        "no_non_targetable_target": True,
        "named_target_requires_target_id": True,
        "target_ids_match_targets": True,
        "output_target_in_selected_targets": True,
        "no_targetless_named_team_ask": True,
        "generated_summary_as_evidence": True,
        "generated_summary_not_primary_evidence": True,
        "semantic_quality_sufficient": True,
        "incident_brief_quality_sufficient": True,
        "no_preview_card_grounding": True,
        "no_noise_targets": True,
        "selected_target_quality": True,
        "no_question_only_semantic_recommendation": True,
        "no_generic_unclear_blocker": True,
        "no_policy_id_as_target": True,
        "no_log_label_as_target": True,
        "latest_blocker_respected": True,
        "no_executable_action_wording": True,
        "no_private_identifier_in_visible_output": True,
        "permission_denied_wrong_owner_loop": True,
        "no_json_log_target": True,
        "severity_claim_confirmed": True,
        "no_useless_self_summary": True,
        "no_passive_we_need_owner_statement": True,
        "visible_output_is_direct_ask": True,
        "selected_move_matches_visible_intent": True,
        "no_low_quality_named_person_as_owner": True,
        "unresolved_loop_requires_question": True,
        "accepted_memory_target_class_satisfied": True,
        "accepted_memory_visible_intent_satisfied": True,
        "no_safe_despite_accepted_memory": True,
        "no_safe_despite_diagnostic_signal": True,
        "reporter_not_owner_when_owner_candidate_exists": True,
        "bot_diagnostic_context_preserved": True,
        "raw_paste_evidence_preservation": True,
        "expires_correctly": True,
    }
    blocked: list[str] = []
    allowed: list[str] = []
    if checks_secret_pending:
        checks["no_secret_leakage"] = False
        blocked.append("output contains secret-like material")

    if not decision.expiration:
        checks["expires_correctly"] = False
        blocked.append("decision has no expiration")
    elif re.match(r"^\d{4}-\d{2}-\d{2}", str(decision.expiration)):
        try:
            expires_at = datetime.fromisoformat(str(decision.expiration).replace("Z", "+00:00"))
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= datetime.now(timezone.utc):
                checks["expires_correctly"] = False
                blocked.append("decision expiration is in the past")
        except ValueError:
            checks["expires_correctly"] = False
            blocked.append(f"decision expiration is not parseable: {decision.expiration}")

    normal_recommendation = decision.move != ICMove.NO_SAFE_RECOMMENDATION
    verifier_fallback_decision = str(decision.decision_id or "").startswith("fallback-")
    expected_quality_safe_fallback = (
        decision.move == ICMove.NO_SAFE_RECOMMENDATION
        and (
            (semantic_quality is not None and not semantic_quality.can_render_normal_recommendation)
            or (incident_brief_quality is not None and not incident_brief_quality.passed)
        )
    )
    if semantic_quality is not None:
        if normal_recommendation and not semantic_quality.can_render_normal_recommendation:
            checks["semantic_quality_sufficient"] = False
            blocked.append(
                "semantic quality is insufficient for normal recommendation: "
                + ", ".join(semantic_quality.reasons or [semantic_quality.status])
            )
        if normal_recommendation and semantic_quality.question_only_success:
            checks["no_question_only_semantic_recommendation"] = False
            blocked.append("question_intent_ledger alone cannot drive a normal recommendation")
    if incident_brief_quality is not None and normal_recommendation and not incident_brief_quality.passed:
        checks["incident_brief_quality_sufficient"] = False
        blocked.append(
            "IncidentBrief quality is insufficient: "
            + ", ".join(incident_brief_quality.blocked_reasons or [incident_brief_quality.status])
        )

    if normal_recommendation and current_events and not decision.grounding:
        checks["evidence_grounded"] = False
        blocked.append("normal recommendation has no current-event grounding evidence")
    if (decision.targets or decision.target_ids) and not decision.grounding:
        checks["evidence_grounded"] = False
        blocked.append("targeted decision has no grounding evidence")

    synthetic_grounding_terms = (
        "latest blocker is unclear",
        "semantic ledgers",
        "generated summary",
        "incidentbrief",
        "recommended ic focus",
    )
    grounding_quality_seen = {"allowed": 0, "noise": 0}
    for evidence in decision.grounding:
        quote_norm = _norm(evidence.quote)
        source_norm = _norm(evidence.source)
        event_text = current_event_text_by_id.get(evidence.event_id)
        if current_events and event_text is None:
            checks["evidence_grounded"] = False
            blocked.append(f"grounding event_id is not in current/latest evidence: {evidence.event_id}")
        elif event_text is not None and quote_norm:
            event_norm = _norm(event_text)
            redacted_event_norm = _norm(str(redact_for_llm(event_text)))
            if (
                quote_norm not in event_norm
                and event_norm not in quote_norm
                and quote_norm not in redacted_event_norm
                and redacted_event_norm not in quote_norm
            ):
                checks["evidence_grounded"] = False
                blocked.append(f"grounding quote is not from event {evidence.event_id}: {evidence.quote[:80]}")
        if any(term in quote_norm for term in synthetic_grounding_terms) or source_norm in {
            "generated",
            "internal_summary",
            "memory",
        }:
            checks["generated_summary_as_evidence"] = False
            checks["generated_summary_not_primary_evidence"] = False
            checks["evidence_grounded"] = False
            blocked.append(f"grounding uses generated/internal summary instead of original evidence: {evidence.quote[:80]}")
        quality = event_quality_by_id.get(evidence.event_id)
        if quality is not None:
            if quality.is_planner_grounding_allowed:
                grounding_quality_seen["allowed"] += 1
            else:
                grounding_quality_seen["noise"] += 1
    if normal_recommendation and grounding_quality_seen["noise"] and not grounding_quality_seen["allowed"]:
        checks["no_preview_card_grounding"] = False
        checks["evidence_grounded"] = False
        blocked.append("grounding evidence is preview/card/log/table/system only")

    allowed_customer_norms = _allowed_customers(current_state)
    for label in _domain_labels(current_state):
        title = label.replace("-", " ").title()
        if re.search(rf"\b{re.escape(title)}\b", text) and _norm(title) not in allowed_customer_norms:
            checks["no_fake_customer"] = False
            blocked.append(f"customer-like term only appears in URL domain: {title}")
    customer_phrases = re.findall(r"\bcustomer\s+([A-Z][A-Za-z0-9&.-]*(?:\s+[A-Z][A-Za-z0-9&.-]*)?)", text)
    customer_phrases += re.findall(r"\b([A-Z][A-Za-z0-9&.-]*(?:\s+[A-Z][A-Za-z0-9&.-]*)?)\s+customer\b", text)
    for phrase in customer_phrases:
        phrase_norm = _norm(phrase)
        if phrase_norm and phrase_norm not in allowed_customer_norms:
            if not _explicit_context_contains(phrase, semantic_state_text, ("customer", "customers")):
                checks["no_fake_customer"] = False
                blocked.append(f"ungrounded customer claim: {phrase}")

    allowed_tenants = _allowed_tenants(current_state)
    private_id_mentions = _visible_private_identifier_mentions(
        speech_text,
        allowed_tenants=allowed_tenants,
        semantic_state_text=semantic_state_text,
    )
    if normal_recommendation and private_id_mentions:
        checks["no_private_identifier_in_visible_output"] = False
        checks["no_fake_tenant"] = False
        blocked.append(
            "visible output includes raw/private tenant/account identifier; use affected tenant or tenant/topic instead: "
            + ", ".join(private_id_mentions[:3])
        )
    for number in re.findall(r"\b\d{5,}\b", text):
        if _norm(number) in allowed_tenants:
            continue
        output_claims_tenant = _explicit_context_contains(number, text, TENANT_CONTEXT_WORDS)
        current_supports_tenant = _explicit_context_contains(number, semantic_state_text, TENANT_CONTEXT_WORDS)
        current_supports_operational_id = _explicit_context_contains(
            number,
            semantic_state_text,
            OPERATIONAL_ID_CONTEXT_WORDS,
        )
        output_uses_operational_context = _explicit_context_contains(
            number,
            text,
            OPERATIONAL_ID_CONTEXT_WORDS,
        )
        if current_supports_operational_id and output_uses_operational_context and not output_claims_tenant:
            continue
        if output_claims_tenant and current_supports_tenant:
            continue
        if output_claims_tenant or not current_supports_tenant:
            checks["no_fake_tenant"] = False
            blocked.append(f"ungrounded tenant/account number: {number}")

    for fragment in FAKE_PERSON_FRAGMENTS:
        if fragment in text:
            checks["no_fake_person"] = False
            blocked.append(f"display-name fragment used as person: {fragment}")
    if re.search(r"\b[A-Z][a-z]+\s+(?:Could|Please|Trisha)\b", text):
        match = re.search(r"\b[A-Z][a-z]+\s+(?:Could|Please|Trisha)\b", text)
        if match and _norm(match.group(0)) not in _allowed_people(current_state, catalog):
            checks["no_fake_person"] = False
            blocked.append(f"display-name fragment used as person: {match.group(0)}")

    for rejected in current_state.rejected_entities:
        name = rejected.display_name
        if name and _norm(name) in text_norm:
            reason = rejected.status.replace("rejected:", "") if rejected.status.startswith("rejected:") else "rejected"
            blocked.append(f"output uses rejected entity {name}: {reason}")
            if rejected.entity_type == EntityType.CUSTOMER:
                checks["no_fake_customer"] = False
            elif rejected.entity_type == EntityType.TENANT:
                checks["no_fake_tenant"] = False
            elif rejected.entity_type == EntityType.PERSON:
                checks["no_fake_person"] = False
            elif rejected.entity_type == EntityType.TEAM:
                checks["no_fake_team"] = False
            elif rejected.entity_type == EntityType.SERVICE:
                checks["no_fake_service"] = False

    allowed_targetable_names = {
        _norm(target.display_name)
        for target in (allowed_targets or [])
        if target.targetable and target.display_name
    }
    allowed_targets_by_id_global = {target.target_id: target for target in (allowed_targets or [])}
    selected_allowed_target_exists = any(
        target_id in allowed_targets_by_id_global and allowed_targets_by_id_global[target_id].targetable
        for target_id in decision.target_ids
    )
    for target in decision.targets:
        if _norm(target.display_name) in allowed_targetable_names:
            continue
        if not _target_supported(target.display_name, target.entity_type, current_state, catalog):
            checks["target_exists"] = False
            blocked.append(f"target lacks current evidence or catalog support: {target.display_name}")
            if target.entity_type == EntityType.TEAM:
                checks["no_fake_team"] = False
            if target.entity_type == EntityType.SERVICE:
                checks["no_fake_service"] = False
            if target.entity_type == EntityType.PERSON:
                checks["no_fake_person"] = False

    if allowed_targets:
        allowed_by_id = {target.target_id: target for target in allowed_targets}
        targetable_names = {_norm(target.display_name) for target in allowed_targets if target.targetable}
        targetable_ids_by_name: dict[str, set[str]] = {}
        for target in allowed_targets:
            if target.targetable:
                targetable_ids_by_name.setdefault(_norm(target.display_name), set()).add(target.target_id)
        non_targetable = {
            _norm(target.display_name): target
            for target in allowed_targets
            if not target.targetable and target.display_name
        }
        selected_target_ids = set(decision.target_ids)
        selected_target_names = {
            _norm(allowed_by_id[target_id].display_name)
            for target_id in selected_target_ids
            if target_id in allowed_by_id
        }
        for target_id in selected_target_ids:
            target = allowed_by_id.get(target_id)
            if target is None:
                checks["target_in_allowed_targets"] = False
                blocked.append(f"target_id is not in allowed_targets: {target_id}")
            elif not target.targetable:
                checks["no_non_targetable_target"] = False
                checks["no_noise_targets"] = False
                blocked.append(f"target_id is non-targetable: {target.display_name} ({target.reason})")
            elif target.target_quality in {"low", "rejected"}:
                checks["selected_target_quality"] = False
                checks["no_noise_targets"] = False
                blocked.append(f"target_id has low/rejected target quality: {target.display_name} ({target.target_quality})")
            elif target.source_event_kind in {
                "preview_card",
                "bot_diagnostic_evidence",
                "bot_lifecycle",
                "bot_owner_request",
                "pagerduty_card",
                "jira_card",
                "zoom_card",
                "log_or_code_block",
                "table_row",
                "table_header",
                "slack_lifecycle",
                "generated_summary_fragment",
            }:
                checks["selected_target_quality"] = False
                checks["no_noise_targets"] = False
                blocked.append(f"target_id comes from noisy evidence: {target.display_name} ({target.source_event_kind})")
            elif _looks_like_json_or_diagnostic_target(target.display_name) or _norm(target.display_name) == "daco-bot":
                checks["no_json_log_target"] = False
                checks["no_noise_targets"] = False
                blocked.append(f"target_id is JSON/log/bot diagnostic target: {target.display_name}")
        for target in decision.targets:
            target_norm = _norm(target.display_name)
            if _looks_like_json_or_diagnostic_target(target.display_name) or target_norm == "daco-bot":
                checks["no_json_log_target"] = False
                checks["no_noise_targets"] = False
                blocked.append(f"target is JSON/log/bot diagnostic target: {target.display_name}")
            if target_norm not in targetable_names:
                checks["target_in_allowed_targets"] = False
                blocked.append(f"target is not in allowed_targets: {target.display_name}")
            selected_duplicate_alias = bool(
                targetable_ids_by_name.get(target_norm, set()).intersection(selected_target_ids)
            )
            if target_norm in non_targetable and not selected_duplicate_alias:
                checks["no_non_targetable_target"] = False
                checks["no_noise_targets"] = False
                blocked.append(
                    f"target is non-targetable: {target.display_name} ({non_targetable[target_norm].reason})"
                )
            matching_target_ids = targetable_ids_by_name.get(target_norm, set())
            if matching_target_ids and matching_target_ids.isdisjoint(selected_target_ids):
                checks["target_ids_match_targets"] = False
                blocked.append(
                    f"decision.targets includes {target.display_name} without matching target_id {sorted(matching_target_ids)[0]}"
                )
        for name, target in non_targetable.items():
            if _selected_alias_covers_non_targetable(
                name,
                selected_target_names=selected_target_names,
                targetable_ids_by_name=targetable_ids_by_name,
                selected_target_ids=selected_target_ids,
            ):
                continue
            if (
                target.display_name
                and is_non_targetable_fact_mention_allowed(
                    target.display_name,
                    decision=decision,
                    current_event_text_by_id=current_event_text_by_id,
                    current_events=current_events,
                )
            ):
                continue
            directly_addressed_noise = name and _directly_addresses_target(speech_text_norm, {name})
            if directly_addressed_noise and target.reason and target.target_type == "non_targetable_noise":
                checks["no_non_targetable_target"] = False
                checks["no_noise_targets"] = False
                blocked.append(f"output mentions non-targetable candidate: {target.display_name} ({target.reason})")
        direct_named_targets: list[AllowedTarget] = []
        for target in allowed_targets:
            if not target.targetable:
                continue
            if target.target_quality in {"low", "rejected"}:
                continue
            target_norm = _norm(target.display_name)
            if len(target_norm) <= 2 or target_norm in {"ic", "dm", "sre", "support"}:
                continue
            name_variants = {target_norm}
            if target.target_type == "team" and not target_norm.endswith(" team"):
                name_variants.add(f"{target_norm} team")
            if _directly_addresses_target(speech_text_norm, name_variants):
                direct_named_targets.append(target)
        if decision.move != ICMove.NO_SAFE_RECOMMENDATION:
            for target in direct_named_targets:
                matching_target_ids = targetable_ids_by_name.get(_norm(target.display_name), {target.target_id})
                target_norm = _norm(target.display_name)
                selected_name_covers_target = any(
                    target_norm and (target_norm in selected_name or selected_name in target_norm)
                    for selected_name in selected_target_names
                )
                if matching_target_ids.isdisjoint(selected_target_ids) and not selected_name_covers_target:
                    checks["named_target_requires_target_id"] = False
                    checks["output_target_in_selected_targets"] = False
                    blocked.append(f"output names target without selected target_id: {target.display_name}")
            asks_named_team = bool(direct_named_targets) and any(
                phrase in speech_text_norm
                for phrase in ("can you", "could you", "please", "confirm", "provide", "share")
            )
            if asks_named_team and not selected_target_ids:
                checks["no_targetless_named_team_ask"] = False
                blocked.append("output asks a named target/team without target_ids")

        noisy_target_terms = (
            "app",
            "daco-bot",
            "zsrebot",
            "default_agent",
            "docs",
            "error",
            "status",
            "severity",
            "environment",
            "summary",
            "refresh",
            "open",
            "zoom",
            "pagerduty",
            "incident",
            "customer id",
            "customer name",
            "shard detail",
            "total queries running",
            "pid",
            "tid",
            "recordfromdb",
            "recordfromcache",
            "rediskeys",
            "topicname",
            "topicnumber",
            "tenantid",
        )
        for term in noisy_target_terms:
            if re.search(rf"\b{re.escape(term)}\b\s*,?\s*(?:can you|could you|please|confirm|provide|share)", speech_text_norm):
                checks["no_log_label_as_target"] = False
                checks["no_noise_targets"] = False
                blocked.append(f"noise/log/card label used as target: {term}")
        if re.search(r"\bP[A-Z0-9]{5,}\b", speech_text):
            checks["no_policy_id_as_target"] = False
            blocked.append("PagerDuty policy/incident-like ID appears as target text")
        if _directly_addresses_target(speech_text_norm, {"daco-bot"}):
            checks["no_json_log_target"] = False
            checks["no_noise_targets"] = False
            blocked.append("bot command surface used as visible target: daco-bot")

    current_service_terms = _current_service_norms(current_state, catalog)
    for label, entry in _catalog_service_mentions(text, catalog):
        entry_terms = {_norm(entry.service_id), _norm(entry.canonical_name), *{_norm(alias) for alias in entry.aliases}}
        if any(term and term in state_text_norm for term in entry_terms):
            continue
        if current_events and any(term and term in _norm(semantic_state_text) for term in entry_terms):
            continue
        if not current_service_terms.intersection(entry_terms):
            checks["no_fake_service"] = False
            blocked.append(f"ungrounded catalog service claim: {label}")

    for forbidden in _accepted_forbidden_facts(accepted_memories):
        if (
            forbidden
            and _norm(forbidden) in text_norm
            and _norm(forbidden) not in state_text_norm
            and _norm(forbidden) not in semantic_state_text_norm
        ):
            checks["no_historical_fact_leakage"] = False
            blocked.append(f"historical fact leaked: {forbidden}")

    stale_reasons = detect_stale_question(text, current_state)
    if stale_reasons:
        checks["no_stale_question"] = False
        blocked.extend(stale_reasons)
    stale_open_loop_reason, stale_open_loop_detail = _stale_open_loop_contradiction(
        decision=decision,
        current_work_items=current_work_items,
    )
    if stale_open_loop_reason:
        checks["no_stale_question"] = False
        checks["stale_open_loop_contradiction"] = False
        blocked.append(stale_open_loop_reason)
    elif stale_open_loop_detail.get("metadata_only"):
        allowed.append("metadata_only_stale_open_loop_repaired")

    stale_status_reason, stale_status_detail = _stale_status_recap_result(
        decision=decision,
        allowed_targets=allowed_targets,
        current_events=current_events,
        event_quality_by_id=event_quality_by_id,
        current_work_items=current_work_items,
        speech_text_norm=speech_text_norm,
    )
    if stale_status_reason:
        checks["no_stale_question"] = False
        checks["stale_visible_status_recap"] = False
        blocked.append(stale_status_reason)
    answered_open_loop_risks = stale_output_risks_for_output(
        speech_text,
        current_events,
        event_quality,
    )
    answered_open_loop_errors = [risk for risk in answered_open_loop_risks if risk.get("severity") == "error"]
    if answered_open_loop_errors:
        checks["no_stale_question"] = False
        checks["stale_answered_open_loop"] = False
        for risk in answered_open_loop_errors:
            blocked.append(
                "visible output repeats an open-loop question already answered by later human evidence: "
                f"{risk.get('risk_type')} answered_by={risk.get('answered_by_event_id')}"
            )
    if answered_open_loop_risks:
        allowed.append(f"answered_open_loop_detail: {answered_open_loop_risks}")

    severity_reason, severity_detail = _unconfirmed_priority_claim_result(
        speech_text=speech_text,
        current_events=current_events,
    )
    if severity_reason:
        checks["severity_claim_confirmed"] = False
        blocked.append(severity_reason)
    allowed.append(f"severity_confirmation_detail: {severity_detail}")

    if _looks_like_useless_self_summary(decision, speech_text_norm):
        checks["not_too_generic"] = False
        checks["no_useless_self_summary"] = False
        blocked.append(
            "visible output only restates a person's claim/current state without asking for impact scope, owner action, validation, or monitoring"
        )

    open_loop_detail = diagnose_open_loops(current_events, event_quality)
    actionability_detail = analyze_visible_actionability(
        decision,
        allowed_targets=allowed_targets,
        unresolved_open_loops=open_loop_detail.get("unresolved_open_loops", []),
    )
    if actionability_detail.get("passive_owner_statement"):
        checks["no_passive_we_need_owner_statement"] = False
        checks["not_too_generic"] = False
    if actionability_detail.get("low_quality_named_owner_terms"):
        checks["no_low_quality_named_person_as_owner"] = False
        checks["role_target_aligned"] = False
    if actionability_detail.get("move_visible_intent_mismatch") and not actionability_detail.get("direct_ask"):
        checks["selected_move_matches_visible_intent"] = False
    if actionability_detail.get("unresolved_loop_without_question"):
        checks["visible_output_is_direct_ask"] = False
        checks["unresolved_loop_requires_question"] = False
        checks["not_too_generic"] = False
    if actionability_detail.get("no_safe_wording_quality") == "weak_finality":
        checks["no_safe_wording_quality"] = False
        checks["not_too_generic"] = False
    blocked.extend(actionability_detail.get("hard_fail_reasons", []))
    allowed.append(f"visible_actionability_detail: {actionability_detail}")

    planning_failure = decision.model_metadata.get("planning_failure") or {}
    provider_output_invalid = bool(
        planning_failure.get("provider_output_was_invalid")
        or decision.model_metadata.get("provider_output_was_invalid")
    )
    accepted_memory_ids: list[str] = []
    for memory in accepted_memories:
        if isinstance(memory, MemoryApplicabilityResult):
            if memory.accepted:
                accepted_memory_ids.append(memory.decision_id)
        elif isinstance(memory, DecisionMoment):
            accepted_memory_ids.append(memory.decision_id)
    accepted_memory_ids = list(dict.fromkeys(accepted_memory_ids))
    actionable_memory_contracts = [
        contract
        for contract in expected_memory_contracts(accepted_memory_ids)
        if contract.get("expected_target_classes") or contract.get("expected_visible_term_groups")
    ]
    actionable_memory_available = bool(actionable_memory_contracts)
    valid_candidate_target_available = any(
        target.targetable
        and target.target_quality in {"high", "medium"}
        and target.target_type not in {"bot_system", "non_targetable_noise"}
        for target in allowed_targets or []
    )
    if (
        decision.move == ICMove.NO_SAFE_RECOMMENDATION
        and not verifier_fallback_decision
        and provider_output_invalid
        and actionable_memory_available
        and valid_candidate_target_available
        and _has_clear_actionable_validation_thread(current_events)
    ):
        checks["no_safe_despite_accepted_memory"] = False
        checks["not_too_generic"] = False
        blocked.append(
            "no_safe_recommendation came from planning/model schema failure despite accepted memory, valid targets, "
            "and current validation/monitoring evidence"
        )
        allowed.append("planning_model_schema_invalid")

    metadata = decision.model_metadata or {}
    retained_diagnostic_facts = list(metadata.get("retained_diagnostic_facts") or [])
    detected_diagnostic_facts = list(metadata.get("detected_diagnostic_facts") or [])
    dropped_diagnostic_facts = list(metadata.get("dropped_diagnostic_facts") or [])
    if not detected_diagnostic_facts and current_events:
        detected_diagnostic_facts = extract_diagnostic_facts(current_events, event_quality_by_id)
    if not retained_diagnostic_facts and detected_diagnostic_facts and not metadata.get("dropped_diagnostic_facts"):
        retained_diagnostic_facts = detected_diagnostic_facts
    if detected_diagnostic_facts and not retained_diagnostic_facts:
        checks["raw_paste_evidence_preservation"] = False
        checks["not_too_generic"] = False
        blocked.append("raw paste diagnostic facts were detected but not retained in the model-facing context")
    bot_detected = [
        fact
        for fact in detected_diagnostic_facts
        if str(fact.get("source_event_kind") or "").startswith("bot_diagnostic")
        or str(fact.get("author_type") or "") == "bot"
    ]
    bot_retained = [
        fact
        for fact in retained_diagnostic_facts
        if str(fact.get("source_event_kind") or "").startswith("bot_diagnostic")
        or str(fact.get("author_type") or "") == "bot"
    ]
    retained_fact_ids = {str(fact.get("fact_id") or "") for fact in retained_diagnostic_facts}
    bot_detected_fact_ids = {str(fact.get("fact_id") or "") for fact in bot_detected if fact.get("fact_id")}
    bot_fact_class_retained = bool(bot_detected_fact_ids) and bot_detected_fact_ids.issubset(retained_fact_ids)
    if bot_detected and not bot_retained and not bot_fact_class_retained:
        checks["bot_diagnostic_context_preserved"] = False
        blocked.append("bot diagnostic evidence was detected but dropped before planning")
    elif bot_detected and not bot_retained and bot_fact_class_retained:
        allowed.append("bot diagnostic fact class preserved through equivalent retained current evidence")

    selected_targets_for_contract = [
        allowed_targets_by_id_global[target_id]
        for target_id in decision.target_ids
        if target_id in allowed_targets_by_id_global
    ]
    selected_target_classes = {
        target_class_for_allowed_target(target, accepted_memory_ids=accepted_memory_ids)
        for target in selected_targets_for_contract
    }
    candidate_target_class_rows = list(metadata.get("candidate_target_classes") or [])
    better_owner_candidates = [
        row
        for row in candidate_target_class_rows
        if row.get("target_class") in {"explicit_action_owner", "service_owner", "config_owner", "database_owner", "investigating_human"}
    ]
    diagnostic_contracts = list(metadata.get("diagnostic_behavior_contracts") or [])
    db_cpu_contract = db_cpu_initial_contract(retained_diagnostic_facts)
    if db_cpu_contract is not None and not any(
        contract.get("decision_id") == db_cpu_contract.get("decision_id") for contract in diagnostic_contracts
    ):
        diagnostic_contracts.append(db_cpu_contract)
    memory_contracts = [*actionable_memory_contracts, *diagnostic_contracts]
    memory_target_details: list[dict[str, Any]] = []
    memory_intent_details: list[dict[str, Any]] = []
    for contract in memory_contracts:
        expected_classes = set(contract.get("expected_target_classes") or [])
        target_passed = not expected_classes or bool(selected_target_classes.intersection(expected_classes))
        detail = {
            "accepted_memory_id": contract.get("decision_id"),
            "expected_target_class": sorted(expected_classes),
            "selected_target_class": sorted(selected_target_classes),
            "available_better_targets": better_owner_candidates[:6],
            "passed": target_passed,
        }
        memory_target_details.append(detail)
        if normal_recommendation and not target_passed:
            checks["accepted_memory_target_class_satisfied"] = False
            checks["role_target_aligned"] = False
            blocked.append(
                "selected target class does not satisfy accepted memory expectation: "
                f"{contract.get('decision_id')}"
            )
        term_passed, missing_terms = visible_terms_satisfied(
            speech_text,
            [list(group) for group in contract.get("expected_visible_term_groups") or []],
        )
        intent_detail = {
            "accepted_memory_id": contract.get("decision_id"),
            "expected_terms": contract.get("expected_visible_term_groups") or [],
            "missing_terms": missing_terms,
            "passed": term_passed,
        }
        memory_intent_details.append(intent_detail)
        if normal_recommendation and not term_passed:
            checks["accepted_memory_visible_intent_satisfied"] = False
            checks["not_too_generic"] = False
            blocked.append(
                "visible output does not satisfy accepted memory intent terms: "
                f"{contract.get('decision_id')} missing={', '.join(missing_terms)}"
            )
        if (
            normal_recommendation
            and "reporter" in selected_target_classes
            and better_owner_candidates
            and expected_classes.intersection({"service_owner", "config_owner", "database_owner", "explicit_action_owner"})
        ):
            checks["reporter_not_owner_when_owner_candidate_exists"] = False
            checks["role_target_aligned"] = False
            blocked.append(
                "selected target is reporter/validator while accepted memory expects owner/config/service class "
                "and a better current owner candidate exists"
            )
    if memory_contracts:
        allowed.append(f"accepted_memory_target_class_detail: {memory_target_details}")
        allowed.append(f"accepted_memory_visible_intent_detail: {memory_intent_details}")
    if (
        decision.move == ICMove.NO_SAFE_RECOMMENDATION
        and not verifier_fallback_decision
        and (actionable_memory_available or bool(diagnostic_contracts))
        and valid_candidate_target_available
        and retained_diagnostic_facts
    ):
        checks["no_safe_despite_accepted_memory"] = False
        checks["no_safe_despite_diagnostic_signal"] = False
        checks["not_too_generic"] = False
        if db_cpu_contract is not None:
            blocked.append(
                "no_safe_recommendation despite retained DB CPU alert diagnostics and a targetable candidate"
            )
        else:
            blocked.append(
                "no_safe_recommendation despite accepted memory, retained diagnostic facts, and a targetable candidate"
            )
    db_cpu_fact_ids = {str(fact.get("fact_id") or "") for fact in retained_diagnostic_facts}
    if (
        decision.move == ICMove.NO_SAFE_RECOMMENDATION
        and not verifier_fallback_decision
        and db_cpu_contract is not None
        and any(row.get("target_class") in {"database_owner", "service_owner"} for row in candidate_target_class_rows)
    ):
        checks["no_safe_despite_diagnostic_signal"] = False
        checks["not_too_generic"] = False
        blocked.append(
            "no_safe_recommendation despite retained DB CPU alert diagnostics and a database-owner candidate"
        )
    if normal_recommendation and db_cpu_contract is not None and "failed_records_workload" not in db_cpu_fact_ids:
        selected_names = {_norm(target.display_name) for target in selected_targets_for_contract}
        forbidden_db_initial_targets = {
            "daco",
            "daco / sync",
            "temporal workflow service",
            "transfer accounting",
            "workflow service",
        }
        if selected_names.intersection(forbidden_db_initial_targets):
            checks["accepted_memory_target_class_satisfied"] = False
            checks["role_target_aligned"] = False
            blocked.append(
                "selected target does not match early DB CPU diagnostics before app-specific culprit evidence exists"
            )
    if retained_diagnostic_facts:
        allowed.append(
            "raw_paste_diagnostic_fact_detail: "
            + str(
                {
                    "diagnostic_facts_seen": [fact.get("fact_id") for fact in detected_diagnostic_facts],
                    "diagnostic_facts_retained": [fact.get("fact_id") for fact in retained_diagnostic_facts],
                    "diagnostic_facts_dropped": [fact.get("fact_id") for fact in dropped_diagnostic_facts],
                }
            )
        )

    action_owner_failure, action_owner_detail = _action_owner_alignment_result(
        decision=decision,
        allowed_targets=allowed_targets,
        current_work_items=current_work_items,
        speech_text_norm=speech_text_norm,
    )
    if action_owner_failure:
        checks["role_target_aligned"] = False
        checks["action_owner_aligned"] = False
        blocked.append(action_owner_failure)
    allowed.append(f"action_owner_alignment_detail: {action_owner_detail}")
    allowed.append(f"stale_superseded_question_detail: {stale_open_loop_detail}")
    allowed.append(f"stale_status_recap_detail: {stale_status_detail}")
    permission_failure, permission_detail = _permission_denied_wrong_owner_result(
        decision=decision,
        allowed_targets=allowed_targets,
        current_events=current_events,
        speech_text_norm=speech_text_norm,
    )
    if permission_failure:
        checks["permission_denied_wrong_owner_loop"] = False
        checks["role_target_aligned"] = False
        blocked.append(permission_failure)
    allowed.append(f"permission_denied_wrong_owner_detail: {permission_detail}")

    command = decision.output.get("command")
    if isinstance(command, dict):
        command = command.get("command_text") or command.get("command") or command.get("text")
    if command:
        registry_entry = _matching_command_registry_entry(command, command_registry)
        if registry_entry is None:
            checks["valid_command"] = False
            blocked.append(f"command is not in registry: {command}")
        elif not registry_entry.requires_human_approval:
            checks["valid_command"] = False
            blocked.append(f"command does not require human approval: {command}")
        elif registry_entry.danger_level not in {"read_only_lookup", "read_only"}:
            checks["valid_command"] = False
            blocked.append(f"command is not allowed in Phase 1.5: {command}")
        elif not _registry_command_target_supported(command, registry_entry, catalog):
            checks["valid_command"] = False
            blocked.append(f"command target is not catalog-supported: {command}")
        else:
            allowed.append(f"verified command: {command}")

    unregistered_commands = detect_unregistered_commands(text, command_registry, allowed_targets)
    if unregistered_commands:
        checks["valid_command"] = False
        for command_text in unregistered_commands:
            blocked.append(f"unregistered command-like output: {command_text}")

    engaged_names = {_norm(entity.display_name) for entity in current_state.engaged_entities}
    if decision.move == ICMove.ENGAGE_OWNER:
        for target in decision.targets:
            if _norm(target.display_name) in engaged_names:
                checks["phase_compatible"] = False
                blocked.append(f"engage-owner move targets already engaged entity: {target.display_name}")
    if current_state.current_blocker == "waiting_on_code_fix" and decision.move == ICMove.ENGAGE_OWNER:
        checks["phase_compatible"] = False
        blocked.append("asks for owner while current blocker is code-fix ETA")
    monitor_moves = {ICMove.MONITOR_NEXT, ICMove.REQUEST_MONITORING_SIGNAL}
    if decision.move in monitor_moves and not current_state.engaged_entities and not selected_allowed_target_exists:
        checks["phase_compatible"] = False
        blocked.append("asks for monitoring before owner/investigation exists")

    if decision.move in monitor_moves:
        known_signal = bool(current_state.monitoring_signals)
        for target in decision.targets:
            for entry in resolve_service_or_team(target.display_name, catalog):
                known_signal = known_signal or bool(entry.known_signals)
        if current_events:
            current_event_norm = _norm(current_event_text)
            signal_terms = (
                "dashboard",
                "db load",
                "event latency",
                "health",
                "lag",
                "metric",
                "metrics",
                "monitor",
                "monitoring",
                "pod",
                "queue",
                "signal",
                "worker",
            )
            known_signal = known_signal or any(term in current_event_norm for term in signal_terms)
        known_signal = known_signal or any(
            isinstance(memory, MemoryApplicabilityResult) and memory.accepted for memory in accepted_memories
        )
        if incident_brief is not None:
            brief_moves = {str(getattr(move, "value", move)) for move in incident_brief.recommended_ic_focus.acceptable_move_types}
            known_signal = known_signal or (
                incident_brief.latest_blocker.blocker_type == "monitoring_needed"
                and bool(incident_brief.latest_blocker.evidence_ids)
            )
            known_signal = known_signal or (
                ICMove.REQUEST_MONITORING_SIGNAL.value in brief_moves
                and bool(incident_brief.recommended_ic_focus.evidence_ids)
            )
        if not known_signal:
            checks["monitoring_signal_supported"] = False
            blocked.append("monitoring move has no current, catalog, or accepted-memory signal support")

    if "impact and owner" in text_norm:
        checks["not_too_generic"] = False
        blocked.append("generic impact and owner question")
    elif detect_generic_impact(text) and current_state.current_blocker not in {None, "missing_impact"}:
        checks["not_too_generic"] = False
        blocked.append("generic impact question despite sharper current blocker")

    if not text:
        checks["not_too_generic"] = False
        blocked.append("empty decision output")
    if (
        decision.move == ICMove.NO_SAFE_RECOMMENDATION
        and sharp_blocker_assessment is not None
        and sharp_blocker_assessment.blocker_type in TECHNICAL_SHARP_BLOCKERS
        and not expected_quality_safe_fallback
    ):
        checks["not_too_generic"] = False
        blocked.append("no_safe_recommendation despite clear sharp technical blocker")
    if (
        sharp_blocker_assessment is not None
        and sharp_blocker_assessment.blocker_type in TECHNICAL_SHARP_BLOCKERS
        and (sharp_blocker_assessment.technical_status_targets or sharp_blocker_assessment.customer_or_reporter_validation_targets)
        and any(
            phrase in text_norm
            for phrase in (
                "no clear next validation",
                "no clear next status",
                "no clear next move",
                "no safe grounded next move",
                "no useful next move",
                "no new validation",
                "no new status",
                "continuing monitoring and investigation",
            )
        )
    ):
        checks["not_too_generic"] = False
        blocked.append("generic no-clear output despite role-aware sharp blocker targets")
    if (
        sharp_blocker_assessment is not None
        and sharp_blocker_assessment.blocker_type in TECHNICAL_SHARP_BLOCKERS
        and (sharp_blocker_assessment.technical_status_targets or sharp_blocker_assessment.customer_or_reporter_validation_targets)
        and not str(decision.output.get("next_line") or "").strip()
    ):
        checks["not_too_generic"] = False
        blocked.append("missing actionable next line despite role-aware sharp blocker targets")

    sharp_mismatch = _sharp_blocker_misaligned(text_norm, sharp_blocker_assessment)
    if sharp_mismatch:
        checks["sharp_blocker_aligned"] = False
        blocked.append(sharp_mismatch)

    rca_mismatch = _no_premature_rca_failure(text_norm, current_state, sharp_blocker_assessment)
    if rca_mismatch:
        checks["no_premature_rca"] = False
        blocked.append(rca_mismatch)

    role_mismatch = _role_target_misaligned(text_norm, sharp_blocker_assessment)
    if role_mismatch:
        checks["role_target_aligned"] = False
        blocked.append(role_mismatch)

    if incident_brief is not None:
        blocker = incident_brief.latest_blocker.blocker_type
        if normal_recommendation:
            blocker_qualities = [
                event_quality_by_id[event_id]
                for event_id in incident_brief.latest_blocker.evidence_ids
                if event_id in event_quality_by_id
            ]
            if blocker_qualities and not any(quality.is_blocker_evidence_allowed for quality in blocker_qualities):
                checks["no_preview_card_grounding"] = False
                checks["incident_brief_quality_sufficient"] = False
                blocked.append("IncidentBrief latest blocker evidence is preview/card/log/table/system only")
            unclear_terms = ("latest blocker is unclear", "blocker is unclear", "unclear from semantic")
            if any(term in text_norm for term in unclear_terms):
                checks["no_generic_unclear_blocker"] = False
                checks["not_too_generic"] = False
                blocked.append("normal recommendation is based on unclear blocker text")
        allowed_by_id = {target.target_id: target for target in allowed_targets}
        valid_preferred_ids = [
            target_id
            for target_id in incident_brief.recommended_ic_focus.preferred_target_ids
            if target_id in allowed_by_id
            and allowed_by_id[target_id].targetable
            and allowed_by_id[target_id].target_quality in {"high", "medium"}
        ]
        no_safe_with_useful_target = (
            decision.move == ICMove.NO_SAFE_RECOMMENDATION
            and not expected_quality_safe_fallback
            and bool(valid_preferred_ids)
            and (
                blocker != "unknown"
                or bool((incident_brief.current_summary or "").strip())
                or "unclear" not in _norm(incident_brief.recommended_ic_focus.summary)
            )
        )
        if no_safe_with_useful_target:
            checks["not_too_generic"] = False
            blocked.append("no_safe_recommendation despite IncidentBrief blocker and valid preferred targets")
        if not decision.target_ids and not decision.targets:
            named_allowed_targets = [
                target.display_name
                for target in allowed_targets
                if target.targetable
                and len(_norm(target.display_name)) > 2
                and _norm(target.display_name) not in {"ic", "dm", "sre", "support"}
                and _norm(target.display_name) in text_norm
            ]
            if named_allowed_targets:
                checks["target_in_allowed_targets"] = False
                blocked.append(f"output names target without selected target_id: {named_allowed_targets[0]}")
        if blocker != "unknown":
            expected_terms = {
                "validation_needed": ("validation", "validate", "confirm", "signal", "stable", "still seeing", "check", "identify"),
                "monitoring_needed": ("monitor", "signal", "stable", "stability", "health", "success criteria"),
                "mitigation_status_needed": ("mitigation", "status", "rollback", "disable", "eta", "validation"),
                "status_eta_needed": ("status", "eta", "blocker", "update"),
                "code_fix_status_needed": ("code", "fix", "hotfix", "eta", "release"),
                "deployment_validation_needed": ("deployment", "change", "validation", "rollback", "status"),
                "missing_owner": ("owner", "own", "dri", "confirm"),
                "customer_scope_needed": ("impact", "scope", "customer", "tenant", "affected"),
                "rca_owner_needed": ("rca", "root cause", "follow-up", "owner", "monitor"),
                "handoff_needed": ("handoff", "dri", "owner", "assign"),
                "waiting_on_active_work": ("status", "eta", "blocker", "validation", "signal"),
            }.get(blocker, ())
            if expected_terms and not any(term in text_norm for term in expected_terms):
                checks["latest_blocker_respected"] = False
                blocked.append(f"output does not address IncidentBrief latest blocker: {blocker}")
        for do_not_ask in incident_brief.do_not_ask:
            intent_tokens = [token for token in re.split(r"[_\W]+", do_not_ask.intent.lower()) if len(token) > 4]
            if do_not_ask.intent.startswith("ask_if_"):
                if do_not_ask.intent == "ask_if_deployed":
                    repeats_deploy_check = bool(
                        re.search(r"\b(?:whether|if)\b[^.?!]{0,80}\bdeploy", text_norm)
                        or re.search(r"\b(?:has the|have the|is it|is the|are the)\b[^.?!]{0,80}\bdeploy", text_norm)
                    )
                    if not repeats_deploy_check:
                        continue
                elif do_not_ask.intent == "ask_if_testing_done":
                    repeats_testing_check = bool(
                        re.search(r"\b(?:whether|if)\b[^.?!]{0,80}\b(?:testing|test).{0,40}\bdone", text_norm)
                        or re.search(r"\b(?:is|are|has|have)\b[^.?!]{0,80}\b(?:testing|test).{0,40}\bdone", text_norm)
                    )
                    if not repeats_testing_check:
                        continue
                else:
                    asks_whether = any(
                        phrase in text_norm
                        for phrase in (
                            "whether",
                            "if ",
                            "is it",
                            "is the",
                            "are the",
                            "has the",
                            "have the",
                            "do we",
                        )
                    )
                    if not asks_whether:
                        continue
            if intent_tokens and all(token in text_norm for token in intent_tokens[-2:]):
                checks["no_stale_question"] = False
                blocked.append(f"output repeats IncidentBrief do_not_ask intent: {do_not_ask.intent}")
        brief_text_norm = _norm(
            " ".join(
                (
                    incident_brief.current_summary,
                    incident_brief.latest_blocker.summary,
                    incident_brief.recommended_ic_focus.summary,
                    " ".join(action.summary for action in incident_brief.completed_actions),
                    " ".join(workstream.summary for workstream in incident_brief.active_workstreams),
                )
            )
        )
        ticket_visible = any(term in brief_text_norm for term in ("zendesk", "jira", "l3 ticket", "ticket "))
        if ticket_visible and re.search(r"\b(?:share|send|provide|create|open)\b[^.?!]{0,80}\b(?:zendesk|jira|ticket)\b", text_norm):
            checks["no_stale_question"] = False
            blocked.append("output asks for ticket sharing even though ticket evidence is already visible")
        reporter_names = {
            allowed_by_id[role.target_id].display_name
            for role in incident_brief.role_candidates
            if role.role_hint == "reporter_or_validator" and role.target_id in allowed_by_id
        }
        technical_names = {
            allowed_by_id[role.target_id].display_name
            for role in incident_brief.role_candidates
            if role.role_hint in {"technical_investigator", "owner_team"} and role.target_id in allowed_by_id
        }
        if reporter_names and technical_names:
            technical_role_terms = ("fix status", "root cause", " rca", "mitigation owner")
            for reporter in reporter_names:
                reporter_norm = _norm(reporter)
                reporter_pattern = rf"(?<![a-z0-9]){re.escape(reporter_norm)}(?![a-z0-9])"
                asks_reporter_for_technical_work = any(
                    re.search(rf"{reporter_pattern}[^.?!;]{{0,120}}{re.escape(term.strip())}", text_norm)
                    or re.search(rf"{re.escape(term.strip())}[^.?!;]{{0,80}}{reporter_pattern}", text_norm)
                    for term in technical_role_terms
                )
                if asks_reporter_for_technical_work:
                    checks["role_target_aligned"] = False
                    blocked.append(f"reporter/validator is asked for fix/RCA ownership despite technical target: {reporter}")

    unsafe_actions = _unsafe_executable_action_phrases(text)
    if unsafe_actions:
        checks["no_executable_action_wording"] = False
        checks["valid_command"] = False
        for phrase in unsafe_actions:
            blocked.append(f"unsafe executable action wording: {phrase}")

    passed = all(checks.values())
    if passed:
        return VerifierResult(
            passed=True,
            final_status="pass",
            checks=checks,
            blocked_claims=[],
            allowed_claims=allowed or ["decision passed deterministic verifier"],
            rewrite_instructions=[],
        )

    return VerifierResult(
        passed=False,
        final_status="fallback_required",
        checks=checks,
        blocked_claims=blocked,
        allowed_claims=allowed,
        rewrite_instructions=["Use fallback unless a grounded rewrite can be produced."],
        fallback_decision=_fallback(decision),
    )
