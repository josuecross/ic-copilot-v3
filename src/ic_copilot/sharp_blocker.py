from __future__ import annotations

import re

from pydantic import ValidationError

from ic_copilot.llm.base import LLMClient
from ic_copilot.schema_repair import normalize_phase
from ic_copilot.schema_repair import validate_with_repair
from ic_copilot.schemas import (
    CleanIncidentContext,
    CurrentIncidentState,
    EvidenceBackedFact,
    EvidenceRef,
    GroundedOwnerCandidate,
    ICMove,
    IncidentPhase,
    RoleCandidate,
    ServiceCatalogEntry,
    SharpBlockerAssessment,
    VisibleWorkstream,
    WrongNextMove,
)


TECHNICAL_BLOCKERS = {
    "missing_mitigation",
    "mitigation_status_or_validation",
    "rollback_or_disable_status",
    "waiting_on_code_fix",
    "waiting_on_deploy",
    "waiting_on_owner_status",
    "waiting_on_monitoring",
    "missing_validation",
}
OWNER_STATUSES = {"mentioned", "asked", "responded", "assigned", "actively_working", "unknown"}
NON_TARGETABLE_LABELS = {
    "added by zsrebot",
    "app",
    "channel",
    "dm",
    "docs",
    "ic bot",
    "im-agent",
    "incident.io",
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


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)


def _looks_like_planner_decision_payload(value: object) -> bool:
    return isinstance(value, dict) and {"decision_id", "move", "output"}.issubset(value)


def _repair_assessment_payload(value: object) -> object:
    if not isinstance(value, dict):
        return value
    repaired = dict(value)
    if "phase" in repaired:
        repaired["phase"] = normalize_phase(repaired.get("phase"))
    owner_status_aliases = {
        "active": "actively_working",
        "working": "actively_working",
        "engaged": "responded",
        "looped_in": "mentioned",
        "looped in": "mentioned",
    }
    workstream_status_aliases = {
        "active": "in_progress",
        "working": "in_progress",
        "started": "in_progress",
        "done": "completed",
        "complete": "completed",
        "requested": "requested_not_confirmed",
        "pending": "requested_not_confirmed",
    }
    owners = []
    for item in repaired.get("active_owner_candidates") or []:
        if isinstance(item, dict):
            item = dict(item)
            status = str(item.get("status") or "").strip().lower()
            if status in owner_status_aliases:
                item["status"] = owner_status_aliases[status]
        owners.append(item)
    if owners:
        repaired["active_owner_candidates"] = owners
    workstreams = []
    for item in repaired.get("visible_workstreams") or []:
        if isinstance(item, dict):
            item = dict(item)
            status = str(item.get("status") or "").strip().lower()
            if status in workstream_status_aliases:
                item["status"] = workstream_status_aliases[status]
        workstreams.append(item)
    if workstreams:
        repaired["visible_workstreams"] = workstreams
    return repaired


def _mentions_unapproved_command(text_norm: str) -> bool:
    return (
        "no remediation command" in text_norm
        or "not approved" in text_norm
        or "not authorized" in text_norm
        or bool(re.search(r"\brun\s+[/@a-z0-9_.:-]+", text_norm))
    )


def _event_ids_from_context(clean_context: CleanIncidentContext, state: CurrentIncidentState) -> list[str]:
    ids = list(clean_context.based_on_event_ids)
    for ref in (state.severity.evidence if state.severity else []):
        ids.append(ref.event_id)
    for group in (state.candidate_services, state.engaged_entities, state.suggested_but_not_engaged):
        for entity in group:
            ids.extend(ref.event_id for ref in entity.evidence)
    seen: set[str] = set()
    result: list[str] = []
    for event_id in ids:
        if event_id and event_id not in seen:
            result.append(event_id)
            seen.add(event_id)
    return result


def _combined_text(clean_context: CleanIncidentContext, state: CurrentIncidentState) -> str:
    pieces = [
        clean_context.source_summary,
        clean_context.clean_summary,
        clean_context.current_blocker.summary,
        state.compact_summary,
        state.current_blocker or "",
        state.impact.description,
    ]
    for fact in clean_context.facts + clean_context.incident_kind:
        pieces.append(fact.value)
    for group in (clean_context.candidate_services, clean_context.engaged_entities):
        for entity in group:
            pieces.append(entity.name)
    for question in state.open_questions + state.answered_questions + clean_context.question_ledger.open_questions + clean_context.question_ledger.answered_questions:
        pieces.extend([question.intent, question.text, question.answer or ""])
        pieces.extend(ref.quote for ref in question.evidence + question.answered_evidence)
    for action in state.actions_completed + clean_context.actions_completed:
        pieces.extend([action.action_type, action.summary, action.actor or "", action.target or ""])
        pieces.extend(ref.quote for ref in action.evidence)
    for signal in state.monitoring_signals + clean_context.monitoring_signals:
        pieces.append(signal.value)
        pieces.extend(ref.quote for ref in signal.evidence)
    return "\n".join(piece for piece in pieces if piece)


def _status_from_text(text_norm: str) -> str:
    if _contains_any(text_norm, ("completed", "complete", "resolved", "mitigated", "success", "green")):
        return "completed"
    if _contains_any(text_norm, ("in progress", "working", "investigating", "checking", "monitoring")):
        return "in_progress"
    if _contains_any(text_norm, ("blocked", "cannot", "can't", "waiting on", "no access")):
        return "blocked"
    if _contains_any(text_norm, ("please", "asked", "request", "can you", "need to", "needs to")):
        return "requested_not_confirmed"
    return "unknown"


def _owner_candidates(clean_context: CleanIncidentContext, state: CurrentIncidentState) -> list[GroundedOwnerCandidate]:
    candidates: list[GroundedOwnerCandidate] = []
    seen: set[str] = set()

    def add(name: str, entity_type: str, status: str, evidence_ids: list[str], confidence: float) -> None:
        key = _norm(name)
        if not key or key in seen or key in NON_TARGETABLE_LABELS or key == "default_agent":
            return
        candidates.append(
            GroundedOwnerCandidate(
                name=name,
                entity_type=entity_type,  # type: ignore[arg-type]
                source="current_evidence",
                status=status if status in OWNER_STATUSES else "unknown",  # type: ignore[arg-type]
                confidence=confidence,
                evidence_ids=evidence_ids,
            )
        )
        seen.add(key)

    for entity in clean_context.engaged_entities:
        if not entity.targetable or entity.status == "system_or_bot":
            continue
        entity_type = "person" if str(entity.entity_type) == "person" else "team"
        status = "actively_working" if entity.status in {"active", "working", "actively_working"} else "responded"
        add(entity.name, entity_type, status, entity.evidence_ids, entity.confidence)
    for entity in state.engaged_entities + state.suggested_but_not_engaged:
        entity_type = str(getattr(entity.entity_type, "value", entity.entity_type))
        normalized_type = "person" if entity_type == "person" else "service" if entity_type == "service" else "team"
        status = "actively_working" if "work" in entity.status or "active" in entity.status else "responded"
        add(entity.display_name, normalized_type, status, [ref.event_id for ref in entity.evidence], entity.confidence)
    return candidates


def _entity_text(name: str, evidence_ids: list[str], clean_context: CleanIncidentContext, state: CurrentIncidentState) -> str:
    pieces = [name]
    wanted = set(evidence_ids)
    for group in (clean_context.engaged_entities, clean_context.candidate_services, clean_context.suggested_but_not_engaged):
        for entity in group:
            if entity.name == name:
                pieces.append(entity.status)
                pieces.extend(entity.evidence_ids)
    for group in (state.engaged_entities, state.candidate_services, state.suggested_but_not_engaged):
        for entity in group:
            if entity.display_name == name:
                pieces.append(entity.status)
                pieces.extend(ref.quote for ref in entity.evidence)
                wanted.update(ref.event_id for ref in entity.evidence)
    for action in state.actions_completed + clean_context.actions_completed:
        action_ids = {ref.event_id for ref in action.evidence}
        if (action.actor and _norm(action.actor) == _norm(name)) or (action.target and _norm(action.target) == _norm(name)):
            pieces.extend([action.action_type, action.summary])
            wanted.update(action_ids)
        elif wanted.intersection(action_ids):
            pieces.extend([action.action_type, action.summary])
    for signal in state.monitoring_signals + clean_context.monitoring_signals:
        signal_ids = {ref.event_id for ref in signal.evidence}
        if wanted.intersection(signal_ids):
            pieces.append(signal.value)
            pieces.extend(str(value) for value in signal.metadata.values() if value)
    return "\n".join(piece for piece in pieces if piece)


def _role_candidates(
    clean_context: CleanIncidentContext,
    state: CurrentIncidentState,
    owners: list[GroundedOwnerCandidate],
) -> list[RoleCandidate]:
    candidates: list[RoleCandidate] = []
    seen: set[str] = set()

    def add(name: str, role_type: str, status: str, evidence_ids: list[str], confidence: float) -> None:
        key = _norm(name)
        if not key or key in seen:
            return
        candidates.append(
            RoleCandidate(
                name=name,
                role_type=role_type,  # type: ignore[arg-type]
                status=status,  # type: ignore[arg-type]
                evidence_ids=evidence_ids,
                confidence=confidence,
            )
        )
        seen.add(key)

    for owner in owners:
        name = owner.name
        text_norm = _norm(_entity_text(name, owner.evidence_ids, clean_context, state))
        if _norm(name) in NON_TARGETABLE_LABELS or _norm(name) == "default_agent":
            add(name, "bot_or_system", "mentioned", owner.evidence_ids, owner.confidence)
            continue
        if _contains_any(text_norm, ("support", "customer support")):
            add(name, "support_team", "mentioned", owner.evidence_ids, owner.confidence)
            continue
        if _contains_any(text_norm, ("oncall", "paged", "page team", "page was sent")) and owner.entity_type == "team":
            add(name, "owner_team", "paged", owner.evidence_ids, max(owner.confidence, 0.72))
            continue
        if _contains_any(text_norm, ("ic:", "incident commander", "coordinat", "adding", "page team", "oncall")):
            add(name, "ic_or_coordinator", "responded", owner.evidence_ids, owner.confidence)
            continue
        if _contains_any(
            text_norm,
            (
                "validate",
                "validating",
                "testing",
                "still running",
                "application is responding",
                "customer application",
                "customer still",
                "still seeing",
                "reported",
            ),
        ):
            add(name, "reporter_validator", "validating", owner.evidence_ids, max(owner.confidence, 0.74))
            continue
        if _contains_any(
            text_norm,
            (
                "checking",
                "investigating",
                "logs",
                "log ",
                "error",
                "exception",
                "limit reached",
                "health check",
                "task restarted",
                "restarted",
                "package/version",
                "build version",
                "mitigation",
                "hotfix",
                "rollback",
                "disable",
            ),
        ):
            add(name, "technical_investigator", "actively_working", owner.evidence_ids, max(owner.confidence, 0.78))
            continue
        add(name, "unknown", owner.status if owner.status in {"asked", "responded", "mentioned", "unknown"} else "unknown", owner.evidence_ids, owner.confidence)

    return candidates


def _role_target_lists(roles: list[RoleCandidate]) -> dict[str, list[str]]:
    technical = [
        role.name
        for role in roles
        if role.role_type in {"technical_investigator", "owner_team"} and role.status in {"actively_working", "paged", "responded"}
    ]
    validators = [
        role.name
        for role in roles
        if role.role_type == "reporter_validator" and role.status in {"asked", "responded", "validating", "mentioned"}
    ]
    support = [role.name for role in roles if role.role_type == "support_team"]
    coordinators = [role.name for role in roles if role.role_type in {"ic_or_coordinator", "duty_manager"}]
    return {
        "technical": list(dict.fromkeys(technical)),
        "validators": list(dict.fromkeys(validators)),
        "support": list(dict.fromkeys(support)),
        "coordinators": list(dict.fromkeys(coordinators)),
    }


def _workstream(
    workstream_type: str,
    summary: str,
    *,
    status: str,
    owners: list[str],
    evidence_ids: list[str],
    unsafe_to_execute: bool = False,
) -> VisibleWorkstream:
    return VisibleWorkstream(
        workstream_type=workstream_type,  # type: ignore[arg-type]
        summary=summary,
        status=status,  # type: ignore[arg-type]
        owner_candidates=owners,
        evidence_ids=evidence_ids,
        unsafe_to_execute=unsafe_to_execute,
    )


def _visible_workstreams(text: str, evidence_ids: list[str], owners: list[GroundedOwnerCandidate]) -> list[VisibleWorkstream]:
    text_norm = _norm(text)
    owner_names = [owner.name for owner in owners[:4]]
    status = _status_from_text(text_norm)
    workstreams: list[VisibleWorkstream] = []
    unapproved_command_mention = _mentions_unapproved_command(text_norm)
    if (
        _contains_any(text_norm, ("rollback", "roll back", "disable", "disabled", "revert", "reverted"))
        and not unapproved_command_mention
    ):
        workstreams.append(
            _workstream(
                "rollback_or_disable",
                "Rollback, revert, or disablement is being discussed or requested.",
                status=status if status != "unknown" else "requested_not_confirmed",
                owners=owner_names,
                evidence_ids=evidence_ids,
                unsafe_to_execute=True,
            )
        )
    if _contains_any(text_norm, ("mitigation", "mitigate", "workaround", "containment", "fix", "cleanup", "clean up", "truncate")):
        workstreams.append(
            _workstream(
                "mitigation",
                "Mitigation or cleanup work is visible but needs status and validation.",
                status=status,
                owners=owner_names,
                evidence_ids=evidence_ids,
                unsafe_to_execute=_contains_any(text_norm, ("truncate", "ssh", "delete", "restart", "deploy")),
            )
        )
    if _contains_any(text_norm, ("hotfix", "code fix", "patch", "release blocker", "release blockers")):
        workstreams.append(
            _workstream(
                "code_fix",
                "Code fix or hotfix work is visible.",
                status=status,
                owners=owner_names,
                evidence_ids=evidence_ids,
            )
        )
    if _contains_any(text_norm, ("deploy", "deployment", "cm-", "change management", "change ticket")):
        workstreams.append(
            _workstream(
                "deployment_or_hotfix",
                "Deployment or change-management work is visible.",
                status=status,
                owners=owner_names,
                evidence_ids=evidence_ids,
                unsafe_to_execute=True,
            )
        )
    if _contains_any(text_norm, ("monitor", "dashboard", "alert", "metric", "signal", "graph")):
        workstreams.append(
            _workstream(
                "monitoring",
                "Monitoring signals or dashboards are visible.",
                status=status,
                owners=owner_names,
                evidence_ids=evidence_ids,
            )
        )
    if _contains_any(text_norm, ("validation", "validate", "confirmed", "verify", "success criteria", "resolved")):
        workstreams.append(
            _workstream(
                "validation",
                "Validation or success criteria need confirmation.",
                status=status,
                owners=owner_names,
                evidence_ids=evidence_ids,
            )
        )
    if _contains_any(text_norm, ("customer comms", "customer communication", "customer communications", "customer-facing")):
        workstreams.append(
            _workstream(
                "customer_comms",
                "Customer communications are mentioned.",
                status=status,
                owners=owner_names,
                evidence_ids=evidence_ids,
            )
        )
    if _contains_any(text_norm, ("trust post", "trustpost")):
        trust_status = "completed" if _contains_any(text_norm, ("no need", "not needed", "not required")) else status
        workstreams.append(
            _workstream(
                "trust_post",
                "Trust Post/customer-comms coordination is mentioned.",
                status=trust_status,
                owners=owner_names,
                evidence_ids=evidence_ids,
            )
        )
    return workstreams


def _blocker_from_workstreams(
    state: CurrentIncidentState,
    workstreams: list[VisibleWorkstream],
    text_norm: str,
) -> tuple[str, list[ICMove], list[str]]:
    types = {item.workstream_type for item in workstreams}
    if "monitoring" in types and state.current_blocker == "waiting_on_monitoring":
        return (
            "waiting_on_monitoring",
            [ICMove.REQUEST_MONITORING_SIGNAL, ICMove.ASK_NEXT_VALIDATION],
            ["monitoring signal", "success criteria", "remaining failures"],
        )
    if "rollback_or_disable" in types:
        return (
            "rollback_or_disable_status",
            [ICMove.REQUEST_STATUS_OR_ETA, ICMove.ASK_NEXT_VALIDATION, ICMove.REQUEST_MITIGATION_OPTION],
            ["rollback/disable status", "remaining affected scope", "ETA or blocker", "validation signal"],
        )
    if "code_fix" in types:
        return (
            "waiting_on_code_fix",
            [ICMove.REQUEST_STATUS_OR_ETA, ICMove.ASK_CODE_FIX_STATUS],
            ["code-fix status", "ETA", "release blockers", "validation signal"],
        )
    if "mitigation" in types:
        return (
            "mitigation_status_or_validation",
            [ICMove.REQUEST_STATUS_OR_ETA, ICMove.REQUEST_MITIGATION_OPTION, ICMove.ASK_NEXT_VALIDATION],
            ["mitigation status", "remaining affected scope", "ETA or blocker", "validation signal"],
        )
    if "deployment_or_hotfix" in types and state.current_blocker in {"waiting_on_deploy", "deployment_pending"}:
        return (
            "waiting_on_deploy",
            [ICMove.CONFIRM_DEPLOYMENT_RELATED, ICMove.REQUEST_STATUS_OR_ETA],
            ["deployment status", "release blocker", "rollback criteria", "validation plan"],
        )
    if "trust_post" in types and "no need" not in text_norm and state.current_blocker == "customer_comms_pending":
        return ("trust_post_status", [ICMove.CONFIRM_CUSTOMER_COMMS], ["Trust Post status"])
    if "customer_comms" in types and state.current_blocker in {"customer_comms_pending", "waiting_on_customer_confirmation"}:
        return ("customer_comms_status", [ICMove.CONFIRM_CUSTOMER_COMMS], ["customer communications status"])
    if state.current_blocker:
        mapping = {
            "missing_owner": ([ICMove.CONFIRM_OWNERSHIP, ICMove.ENGAGE_OWNER], ["owner confirmation", "next validation step"]),
            "missing_impact": ([ICMove.ASK_IMPACT], ["affected scope", "customer/tenant impact if known"]),
            "missing_validation": ([ICMove.ASK_NEXT_VALIDATION], ["next validation step", "validation signal"]),
            "waiting_on_monitoring": ([ICMove.REQUEST_MONITORING_SIGNAL], ["monitoring signal", "success criteria"]),
            "waiting_on_mitigation": ([ICMove.REQUEST_STATUS_OR_ETA, ICMove.REQUEST_MITIGATION_OPTION], ["mitigation status", "ETA or blocker"]),
        }
        moves, slots = mapping.get(state.current_blocker, ([ICMove.ASK_NEXT_VALIDATION], ["next validation step"]))
        return state.current_blocker, moves, slots
    return "unclear", [ICMove.NO_SAFE_RECOMMENDATION], []


def _wrong_next_moves(blocker_type: str, evidence_ids: list[str], text_norm: str) -> list[WrongNextMove]:
    wrong: list[WrongNextMove] = []
    if blocker_type in TECHNICAL_BLOCKERS:
        wrong.extend(
            [
                WrongNextMove(
                    move_or_intent="customer_comms_status",
                    reason="A technical mitigation/status/validation blocker is visible; customer comms is not the sharp blocker.",
                    evidence_ids=evidence_ids,
                ),
                WrongNextMove(
                    move_or_intent="trust_post_status",
                    reason="Do not ask Trust Post unless current evidence makes it the active blocker.",
                    evidence_ids=evidence_ids,
                ),
                WrongNextMove(
                    move_or_intent="generic_impact_clarification",
                    reason="Do not ask generic impact when the visible blocker is mitigation/status/validation.",
                    evidence_ids=evidence_ids,
                ),
            ]
        )
    if "trust post" in text_norm and _contains_any(text_norm, ("no need", "not needed", "not required")):
        wrong.append(
            WrongNextMove(
                move_or_intent="trust_post_status",
                reason="Trust Post was already answered as not needed.",
                evidence_ids=evidence_ids,
            )
        )
    return wrong


def _deterministic_assessment(
    clean_context: CleanIncidentContext,
    current_state: CurrentIncidentState,
    catalog_matches: list[ServiceCatalogEntry],
) -> SharpBlockerAssessment:
    del catalog_matches
    evidence_ids = _event_ids_from_context(clean_context, current_state)
    text = _combined_text(clean_context, current_state)
    text_norm = _norm(text)
    owners = _owner_candidates(clean_context, current_state)
    role_candidates = _role_candidates(clean_context, current_state, owners)
    role_targets = _role_target_lists(role_candidates)
    workstreams = _visible_workstreams(text, evidence_ids, owners)
    blocker_type, moves, slots = _blocker_from_workstreams(current_state, workstreams, text_norm)
    summary = clean_context.current_blocker.summary or current_state.compact_summary or clean_context.clean_summary
    if blocker_type in {"rollback_or_disable_status", "mitigation_status_or_validation"}:
        summary = summary or "Visible evidence shows mitigation, rollback, disablement, or cleanup work needs status and validation."
    already_done: list[EvidenceBackedFact] = []
    not_confirmed: list[EvidenceBackedFact] = []
    for workstream in workstreams:
        fact = EvidenceBackedFact(
            value=workstream.summary,
            evidence=[EvidenceRef(event_id=event_id, quote="") for event_id in workstream.evidence_ids[:3]],
            confidence=0.72,
        )
        if workstream.status == "completed":
            already_done.append(fact)
        elif workstream.workstream_type in {"rollback_or_disable", "mitigation", "cleanup", "code_fix", "deployment_or_hotfix", "validation"}:
            not_confirmed.append(fact)
    phase_value = clean_context.phase.value if clean_context.phase.value != "unknown" else current_state.phase
    try:
        phase = IncidentPhase(phase_value)
    except ValueError:
        phase = current_state.phase
    return SharpBlockerAssessment(
        incident_id=current_state.incident_id,
        based_on_event_ids=evidence_ids,
        phase=phase,
        blocker_type=blocker_type,  # type: ignore[arg-type]
        blocker_summary=summary[:500],
        confidence=0.78 if blocker_type not in {"unclear", "none"} else 0.35,
        evidence_ids=evidence_ids,
        visible_workstreams=workstreams,
        active_owner_candidates=owners,
        role_candidates=role_candidates,
        latest_workstream_owner_candidates=role_targets["technical"] or [owner.name for owner in owners[:2]],
        validation_request_targets=role_targets["validators"],
        technical_status_targets=role_targets["technical"],
        customer_or_reporter_validation_targets=role_targets["validators"],
        should_not_target_for_fix_status=role_targets["validators"],
        should_not_ask_yet=[
            "root_cause_analysis"
        ] if blocker_type in TECHNICAL_BLOCKERS else [],
        already_done=already_done,
        not_confirmed_yet=not_confirmed,
        wrong_next_moves=_wrong_next_moves(blocker_type, evidence_ids, text_norm),
        recommended_move_families=moves,
        recommended_ask_slots=slots,
        no_invention_constraints=[
            "Do not invent owners, customers, tenants, impact, or mitigation completion.",
            "Shell snippets and rollback/disable discussions are evidence only, not executable commands.",
            "Prefer status, remaining scope, ETA/blocker, and validation signal over customer comms unless explicitly blocked there.",
        ],
    )


def assess_sharp_blocker(
    clean_context: CleanIncidentContext,
    current_state: CurrentIncidentState,
    catalog_matches: list[ServiceCatalogEntry],
    llm_client: LLMClient,
) -> SharpBlockerAssessment:
    payload = {
        "incident_id": current_state.incident_id,
        "clean_context": clean_context.model_dump(mode="json"),
        "current_state": current_state.model_dump(mode="json"),
        "catalog_matches": [entry.model_dump(mode="json") for entry in catalog_matches],
        "rules": [
            "Identify the sharpest IC blocker, not root cause.",
            "Prefer mitigation/status/validation when visible work is already being discussed.",
            "Do not classify customer communications as the blocker unless current evidence says it is.",
            "Shell snippets are evidence only and must not become command suggestions.",
            "Do not invent owners, customers, tenants, impact, or mitigation completion.",
        ],
    }
    try:
        assessment = llm_client.generate_json("sharp_blocker_assessment", payload, SharpBlockerAssessment)
    except (NotImplementedError, ValidationError):
        assessment = _deterministic_assessment(clean_context, current_state, catalog_matches)
    assessment = _repair_assessment_payload(assessment)
    try:
        return validate_with_repair(assessment, SharpBlockerAssessment, context="sharp_blocker_assessment")
    except ValidationError:
        if _looks_like_planner_decision_payload(assessment) or isinstance(assessment, dict):
            return _deterministic_assessment(clean_context, current_state, catalog_matches)
        raise


def build_deterministic_sharp_blocker_assessment(
    clean_context: CleanIncidentContext,
    current_state: CurrentIncidentState,
    catalog_matches: list[ServiceCatalogEntry],
) -> SharpBlockerAssessment:
    return _deterministic_assessment(clean_context, current_state, catalog_matches)
