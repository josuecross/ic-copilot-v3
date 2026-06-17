from __future__ import annotations

import re

from ic_copilot.schemas import (
    AllowedTarget,
    CommandRegistryEntry,
    CurrentIncidentState,
    EntityType,
    EvidenceRef,
    ICDecision,
    ICMove,
    IncidentBrief,
    MemoryApplicabilityResult,
    ServiceCatalogEntry,
    SharpBlockerAssessment,
    VerifierResult,
)


SECURITY_DETAIL_INTENTS = {
    "ask_reporter_for_more_details",
    "ask_reporter_observations_next_actions",
    "ask_security_reporter_for_details",
    "request_details_from_researcher",
    "request_next_actions_from_reporter",
    "request_observations",
    "request_vulnerability_details",
}
TECHNICAL_SHARP_BLOCKERS = {
    "missing_mitigation",
    "missing_validation",
    "mitigation_status_or_validation",
    "rollback_or_disable_status",
    "waiting_on_code_fix",
    "waiting_on_deploy",
    "waiting_on_monitoring",
    "waiting_on_owner_status",
}
NON_TARGETABLE_LABELS = {
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


def _blocked_stale_intents(verifier_result: VerifierResult) -> list[str]:
    intents: list[str] = []
    for claim in verifier_result.blocked_claims:
        match = re.search(r"stale question intent:\s*([A-Za-z0-9_-]+)", claim)
        if match:
            intents.append(match.group(1))
    return sorted(set(intents))


def _state_text(state: CurrentIncidentState) -> str:
    pieces = [
        state.compact_summary,
        state.current_blocker or "",
        state.severity.value if state.severity else "",
        state.impact.description,
    ]
    for group in (state.candidate_services, state.engaged_entities, state.suggested_but_not_engaged):
        for entity in group:
            pieces.append(entity.display_name)
            pieces.extend(ref.quote for ref in entity.evidence)
    for question in state.answered_questions + state.open_questions:
        pieces.extend([question.intent, question.text, question.answer or ""])
        pieces.extend(ref.quote for ref in question.evidence + question.answered_evidence)
    for action in state.actions_completed:
        pieces.append(action.summary)
        pieces.extend(ref.quote for ref in action.evidence)
    for link in state.links_seen:
        pieces.append(link.url)
        pieces.extend(ref.quote for ref in link.evidence)
    return "\n".join(piece for piece in pieces if piece)


def _has_security_context(state: CurrentIncidentState) -> bool:
    text = _norm(_state_text(state))
    return any(
        term in text
        for term in (
            "security",
            "vulnerability",
            "sensitive data",
            "researcher",
            "wf-",
            "workflow",
            "exposure",
        )
    )


def _details_link_exists(state: CurrentIncidentState) -> bool:
    if any(_norm(intent) in SECURITY_DETAIL_INTENTS for intent in state.stale_question_intents):
        return True
    for question in state.answered_questions:
        text = _norm(f"{question.intent} {question.text} {question.answer or ''}")
        if any(intent in text for intent in SECURITY_DETAIL_INTENTS):
            return True
    for link in state.links_seen:
        link_text = _norm(link.url)
        if any(term in link_text for term in ("jira", "wf-", "vulnerab", "security")):
            return True
    return False


def _service_label(state: CurrentIncidentState) -> str:
    names = [entity.display_name for entity in state.candidate_services + state.engaged_entities]
    for name in names:
        lowered = name.lower()
        if "workflow" in lowered:
            return "Workflow"
        if "security" in lowered:
            return "Security"
    return "the affected service"


def _has_security_current_evidence(state: CurrentIncidentState) -> bool:
    return any("security" in entity.display_name.lower() for entity in state.candidate_services + state.engaged_entities)


def _visible_people(state: CurrentIncidentState) -> list[str]:
    people: list[str] = []
    for entity in state.engaged_entities + state.suggested_but_not_engaged:
        if entity.entity_type == EntityType.PERSON and entity.display_name not in people:
            people.append(entity.display_name)
    return people


def _target_phrase(state: CurrentIncidentState) -> str:
    people = _visible_people(state)
    if people:
        return "/".join(people[:2])
    if state.engaged_entities:
        return "/".join(entity.display_name for entity in state.engaged_entities[:2])
    return "Current IC or active DRI"


def _target_ids_for_phrase(target_phrase: str, allowed_targets: list[AllowedTarget] | None) -> list[str]:
    phrase_norm = _norm(target_phrase)
    ids = [
        target.target_id
        for target in allowed_targets or []
        if target.targetable and _norm(target.display_name) and _norm(target.display_name) in phrase_norm
    ]
    return list(dict.fromkeys(ids))


def _grounding(state: CurrentIncidentState) -> list[EvidenceRef]:
    evidence: list[EvidenceRef] = []
    for group in (state.candidate_services, state.engaged_entities, state.suggested_but_not_engaged):
        for entity in group:
            evidence.extend(entity.evidence)
    for question in state.answered_questions + state.open_questions:
        evidence.extend(question.evidence)
        evidence.extend(question.answered_evidence)
    for action in state.actions_completed:
        evidence.extend(action.evidence)
    for link in state.links_seen:
        evidence.extend(link.evidence)
    seen: set[str] = set()
    deduped: list[EvidenceRef] = []
    for ref in evidence:
        key = f"{ref.event_id}:{ref.quote}"
        if key not in seen:
            seen.add(key)
            deduped.append(ref)
    return deduped


def _base_metadata(
    original_decision: ICDecision,
    verifier_result: VerifierResult,
    *,
    reason: str,
    repaired_move: ICMove | str,
) -> dict:
    repaired_move_value = repaired_move.value if isinstance(repaired_move, ICMove) else str(repaired_move)
    metadata = dict(original_decision.model_metadata)
    metadata.update(
        {
            "repair_attempted": True,
            "repair_reason": reason,
            "repaired_from_move": original_decision.move,
            "repaired_to_move": repaired_move_value,
            "original_domain_intent": original_decision.domain_intent,
            "original_blocked_claims": verifier_result.blocked_claims,
        }
    )
    return metadata


def _security_repair(
    original_decision: ICDecision,
    verifier_result: VerifierResult,
    current_state: CurrentIncidentState,
    allowed_targets: list[AllowedTarget] | None = None,
) -> ICDecision | None:
    blocked_intents = set(_blocked_stale_intents(verifier_result))
    stale_security_details = bool(blocked_intents.intersection(SECURITY_DETAIL_INTENTS))
    ungrounded_service = any("ungrounded catalog service claim" in claim for claim in verifier_result.blocked_claims)
    if not (
        _has_security_context(current_state)
        and _details_link_exists(current_state)
        and (stale_security_details or ungrounded_service or verifier_result.blocked_claims)
    ):
        return None

    service = _service_label(current_state)
    service_phrase = "Workflow product" if service == "Workflow" else service
    security_suffix = "/Security" if _has_security_current_evidence(current_state) and service != "Security" else ""
    severity = current_state.severity.value if current_state.severity else "security"
    target_phrase = _target_phrase(current_state)
    target_ids = _target_ids_for_phrase(f"{target_phrase} {service} Security", allowed_targets)
    repaired_move = ICMove.ASK_NEXT_VALIDATION
    output = {
        "say_this": (
            f"This is a {severity} security incident for {service_phrase}, and the vulnerability details link has already "
            "been provided."
        ),
        "next_line": (
            f"{target_phrase}, can we confirm the {service}{security_suffix} owner, exposure scope, and the next "
            "containment or validation step?"
        ),
    }
    return ICDecision(
        decision_id=f"repair-{original_decision.decision_id}",
        incident_id=original_decision.incident_id,
        move=repaired_move,
        phase=current_state.phase,
        domain_intent=original_decision.domain_intent,
        model_metadata=_base_metadata(
            original_decision,
            verifier_result,
            reason=(
                "stale_security_details_after_link"
                if stale_security_details
                else "ungrounded_service_repair"
                if ungrounded_service
                else "blocked_security_next_move_repair"
            ),
            repaired_move=repaired_move,
        ),
        output=output,
        target_ids=target_ids,
        targets=[],
        rationale=[
            "Verifier blocked a stale researcher-details ask.",
            "Current evidence already contains a vulnerability/details link, so the safe next IC move is owner/scope/containment/validation.",
        ],
        grounding=_grounding(current_state),
        confidence=0.64,
    )


def _generic_repair(
    original_decision: ICDecision,
    verifier_result: VerifierResult,
    current_state: CurrentIncidentState,
) -> ICDecision | None:
    if current_state.phase == "unknown" or not current_state.current_blocker:
        return None
    has_grounding_surface = bool(
        current_state.candidate_services
        or current_state.engaged_entities
        or current_state.suggested_but_not_engaged
        or current_state.compact_summary
    )
    if not has_grounding_surface:
        return None

    target = _target_phrase(current_state)
    service = _service_label(current_state)
    move = ICMove.ASK_NEXT_VALIDATION
    next_line = f"{target}, can we confirm the next validation step from current incident evidence?"
    say_this = "The model asked a stale question; the useful next move is the current blocker."
    if current_state.current_blocker == "missing_owner":
        move = ICMove.CONFIRM_OWNERSHIP
        next_line = f"{target}, can we confirm the owner for {service} and the next validation step?"
    elif current_state.current_blocker == "missing_impact":
        move = ICMove.ASK_IMPACT
        next_line = f"{target}, can we confirm affected scope only from current evidence?"
    elif current_state.current_blocker == "waiting_on_monitoring":
        move = ICMove.REQUEST_MONITORING_SIGNAL
        next_line = f"{target}, can we confirm the monitoring signal and success criteria?"
    elif current_state.current_blocker in {"waiting_on_mitigation", "missing_mitigation"}:
        move = ICMove.REQUEST_MITIGATION_OPTION
        next_line = f"{target}, can we confirm the containment or mitigation option and validation signal?"

    return ICDecision(
        decision_id=f"repair-{original_decision.decision_id}",
        incident_id=original_decision.incident_id,
        move=move,
        phase=current_state.phase,
        domain_intent=original_decision.domain_intent,
        model_metadata=_base_metadata(
            original_decision,
            verifier_result,
            reason=f"stale_question_repair_for_{current_state.current_blocker}",
            repaired_move=move,
        ),
        output={"say_this": say_this, "next_line": next_line},
        targets=[],
        rationale=["Verifier blocked a stale question; repaired to a grounded current-blocker question."],
        grounding=_grounding(current_state),
        confidence=0.58,
    )


def _sharp_target_phrase(sharp_blocker_assessment: SharpBlockerAssessment, current_state: CurrentIncidentState) -> str:
    names = [
        owner.name
        for owner in sharp_blocker_assessment.active_owner_candidates
        if owner.name
        and _norm(owner.name) not in NON_TARGETABLE_LABELS
        and owner.status in {"asked", "responded", "assigned", "actively_working"}
    ]
    if not names:
        names = [
            entity.display_name
            for entity in current_state.engaged_entities
            if entity.display_name and _norm(entity.display_name) not in NON_TARGETABLE_LABELS
        ]
    return "/".join(dict.fromkeys(names[:2])) if names else "Active technical owner"


def _join_names(names: list[str], fallback: str) -> str:
    unique = [name for name in dict.fromkeys(names) if name]
    if not unique:
        return fallback
    return "/".join(unique[:2])


def _humanize_slots(slots: list[str]) -> list[str]:
    return [slot.replace("_", " ") for slot in slots]


def _sharp_repair(
    original_decision: ICDecision,
    verifier_result: VerifierResult,
    current_state: CurrentIncidentState,
    sharp_blocker_assessment: SharpBlockerAssessment | None,
) -> ICDecision | None:
    if sharp_blocker_assessment is None:
        return None
    blocker = sharp_blocker_assessment.blocker_type
    repairable = (
        not verifier_result.checks.get("sharp_blocker_aligned", True)
        or not verifier_result.checks.get("not_too_generic", True)
        or not verifier_result.checks.get("no_premature_rca", True)
        or not verifier_result.checks.get("role_target_aligned", True)
        or original_decision.move == ICMove.NO_SAFE_RECOMMENDATION
    )
    if not repairable or blocker not in TECHNICAL_SHARP_BLOCKERS:
        return None
    technical_targets = list(sharp_blocker_assessment.technical_status_targets)
    validation_targets = list(sharp_blocker_assessment.customer_or_reporter_validation_targets)
    target = _join_names(technical_targets, _sharp_target_phrase(sharp_blocker_assessment, current_state))
    slots = _humanize_slots(sharp_blocker_assessment.recommended_ask_slots or [
        "status",
        "remaining affected scope",
        "validation signal",
    ])
    ask = ", ".join(slots[:3])
    context = sharp_blocker_assessment.blocker_summary or "technical mitigation/status and validation"
    move = ICMove.REQUEST_STATUS_OR_ETA
    if blocker in {"mitigation_status_or_validation", "missing_mitigation"}:
        move = ICMove.REQUEST_MITIGATION_OPTION
    if blocker == "missing_validation":
        move = ICMove.ASK_NEXT_VALIDATION
    if blocker == "waiting_on_code_fix":
        move = ICMove.REQUEST_STATUS_OR_ETA
    if technical_targets and validation_targets:
        next_line = (
            f"{_join_names(technical_targets, 'Technical owner')}, can you confirm system stability/status; "
            f"{_join_names(validation_targets, 'validator')}, can you confirm application/customer validation result?"
        )
    elif validation_targets and not technical_targets:
        next_line = (
            f"{_join_names(validation_targets, 'Validator')}, can you confirm the validation result, current symptom, "
            "and any remaining affected scope?"
        )
    else:
        next_line = f"{target}, can you confirm {ask} from current incident evidence?"
    return ICDecision(
        decision_id=f"repair-{original_decision.decision_id}",
        incident_id=original_decision.incident_id,
        move=move,
        phase=current_state.phase,
        domain_intent=original_decision.domain_intent or blocker,
        model_metadata=_base_metadata(
            original_decision,
            verifier_result,
            reason=f"sharp_blocker_repair_for_{blocker}",
            repaired_move=move,
        ),
        output={
            "say_this": f"The sharp blocker is {context}.",
            "next_line": next_line,
        },
        targets=[],
        rationale=["Verifier blocked an output aimed at the wrong blocker; repaired to the sharp blocker."],
        grounding=_grounding(current_state),
        confidence=max(0.6, sharp_blocker_assessment.confidence),
    )


def repair_blocked_decision(
    original_decision: ICDecision,
    verifier_result: VerifierResult,
    current_state: CurrentIncidentState,
    catalog_matches: list[ServiceCatalogEntry],
    command_registry: list[CommandRegistryEntry],
    accepted_memories: list[MemoryApplicabilityResult],
    sharp_blocker_assessment: SharpBlockerAssessment | None = None,
    incident_brief: IncidentBrief | None = None,
    allowed_targets: list[AllowedTarget] | None = None,
) -> ICDecision | None:
    del catalog_matches, command_registry, accepted_memories
    if verifier_result.passed:
        return None
    has_repairable_service_mismatch = any(
        "ungrounded catalog service claim" in claim for claim in verifier_result.blocked_claims
    )
    has_repairable_security_context = _has_security_context(current_state) and _details_link_exists(current_state)
    if has_repairable_security_context and not verifier_result.checks.get("no_stale_question", True):
        security_repair = _security_repair(original_decision, verifier_result, current_state, allowed_targets)
        if security_repair is not None:
            return security_repair
    if incident_brief is not None and (
        not verifier_result.checks.get("target_in_allowed_targets", True)
        or not verifier_result.checks.get("no_non_targetable_target", True)
        or not verifier_result.checks.get("latest_blocker_respected", True)
        or not verifier_result.checks.get("not_too_generic", True)
        or not verifier_result.checks.get("role_target_aligned", True)
        or not verifier_result.checks.get("phase_compatible", True)
        or (
            original_decision.move == ICMove.NO_SAFE_RECOMMENDATION
            and incident_brief.latest_blocker.blocker_type != "unknown"
        )
    ):
        from ic_copilot.planner import plan_ic_decision

        repaired = plan_ic_decision(
            current_state,
            [],
            [],
            llm_client=None,
            sharp_blocker_assessment=sharp_blocker_assessment,
            incident_brief=incident_brief,
            allowed_targets=allowed_targets or [],
        )
        return repaired.model_copy(
            update={
                "decision_id": f"repair-{original_decision.decision_id}",
                "model_metadata": _base_metadata(
                    original_decision,
                    verifier_result,
                    reason=f"incident_brief_repair_for_{incident_brief.latest_blocker.blocker_type}",
                    repaired_move=repaired.move,
                ),
                "rationale": [
                    *repaired.rationale,
                    "Verifier repaired the decision using IncidentBrief and allowed target IDs.",
                ],
            }
        )
    sharp_repair = _sharp_repair(original_decision, verifier_result, current_state, sharp_blocker_assessment)
    if sharp_repair is not None:
        return sharp_repair
    if (
        verifier_result.checks.get("no_stale_question", True)
        and not has_repairable_service_mismatch
        and not has_repairable_security_context
    ):
        return None
    return _security_repair(original_decision, verifier_result, current_state, allowed_targets) or _generic_repair(
        original_decision,
        verifier_result,
        current_state,
    )
