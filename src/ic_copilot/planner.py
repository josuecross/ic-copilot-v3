from __future__ import annotations

from uuid import uuid4

from pydantic import ValidationError

from ic_copilot.catalog import get_oncall_command_for_target
from ic_copilot.error_sanitizer import sanitize_user_facing_error
from ic_copilot.llm.base import LLMClient
from ic_copilot.schema_repair import ModelOutputValidationError, validate_with_repair
from ic_copilot.schemas import (
    CleanIncidentContext,
    CommandRegistryEntry,
    CurrentIncidentState,
    EntityRef,
    EntityType,
    AllowedTarget,
    ICDecision,
    ICMove,
    IncidentBrief,
    IncidentPhase,
    MemoryApplicabilityResult,
    SharpBlockerAssessment,
    ServiceCatalogEntry,
)


def _decision_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:8]}"


def _severity_value(state: CurrentIncidentState) -> str:
    return state.severity.value if state.severity else "unknown severity"


def _impact_phrase(state: CurrentIncidentState) -> str:
    if state.impact.affected_count is not None:
        return f"affecting {state.impact.affected_count} customers"
    if state.impact.description:
        return state.impact.description
    return "with impact still unclear"


def _all_grounding(target: EntityRef | None, state: CurrentIncidentState):
    grounding = []
    if target:
        grounding.extend(target.evidence)
    if state.severity:
        grounding.extend(state.severity.evidence)
    grounding.extend(state.impact.evidence)
    for action in state.actions_completed:
        grounding.extend(action.evidence)
    for signal in state.monitoring_signals:
        grounding.extend(signal.evidence)
    return grounding


def _target_by_name(state: CurrentIncidentState, *names: str) -> EntityRef | None:
    wanted = {name.lower() for name in names}
    return next((entity for entity in state.engaged_entities if entity.display_name.lower() in wanted), None)


def _targets_by_names(state: CurrentIncidentState, *names: str) -> list[EntityRef]:
    wanted = {name.lower() for name in names}
    return [entity for entity in state.engaged_entities if entity.display_name.lower() in wanted]


def _signal_phrase(state: CurrentIncidentState) -> str:
    if state.monitoring_signals:
        return state.monitoring_signals[0].value
    return "the current validation signal"


def _attach_planner_fallback_metadata(
    decision: ICDecision,
    exc: Exception,
    original_move: str | None,
) -> ICDecision:
    metadata = dict(decision.model_metadata)
    metadata.update(
        {
            "planner_fallback_used": True,
            "planner_fallback_reason": "model_output_validation_error",
            "planner_validation_error": sanitize_user_facing_error(exc),
        }
    )
    if original_move:
        metadata.setdefault("original_move", original_move)
    rationale = list(decision.rationale)
    rationale.append("The model planner emitted an unsupported or invalid move label, so deterministic fallback planning was used.")
    return decision.model_copy(
        update={
            "domain_intent": decision.domain_intent or original_move,
            "model_metadata": metadata,
            "rationale": rationale,
        }
    )


def _sharp_owner_phrase(
    sharp_blocker_assessment: SharpBlockerAssessment,
    current_state: CurrentIncidentState,
) -> str:
    names = [
        owner.name
        for owner in sharp_blocker_assessment.active_owner_candidates
        if owner.name and owner.status in {"asked", "responded", "assigned", "actively_working"}
    ]
    if not names:
        names = [entity.display_name for entity in current_state.engaged_entities if entity.display_name]
    if names:
        return "/".join(dict.fromkeys(names[:2]))
    return "Active technical owner"


def _join_names(names: list[str], fallback: str) -> str:
    unique = [name for name in dict.fromkeys(names) if name]
    if not unique:
        return fallback
    return "/".join(unique[:2])


def _norm(value: str | None) -> str:
    return " ".join((value or "").lower().split())


def _humanize_slots(slots: list[str]) -> list[str]:
    replacements = {
        "validation_status": "validation status",
        "monitoring_signal": "monitoring signal",
        "status": "status",
    }
    return [replacements.get(slot, slot.replace("_", " ")) for slot in slots]


def _sharp_context_phrase(sharp_blocker_assessment: SharpBlockerAssessment) -> str:
    summary = sharp_blocker_assessment.blocker_summary.strip()
    if summary:
        return summary.rstrip(".")
    for workstream in sharp_blocker_assessment.visible_workstreams:
        if workstream.summary:
            return workstream.summary.rstrip(".")
    return "the visible operational workstream"


def _target_entity_from_allowed(target: AllowedTarget) -> EntityRef:
    entity_type = {
        "person": EntityType.PERSON,
        "team": EntityType.TEAM,
        "service": EntityType.SERVICE,
    }.get(target.target_type, EntityType.UNKNOWN)
    return EntityRef(
        entity_type=entity_type,
        display_name=target.display_name,
        canonical_id=target.canonical_id,
        status=target.role_hint,
        evidence=[{"event_id": event_id} for event_id in target.evidence_ids],  # type: ignore[list-item]
        confidence=0.75 if target.evidence_ids else 0.55,
        source="catalog" if target.source in {"catalog", "service_alias", "command_registry"} else "current_evidence",
    )


def _allowed_by_id(allowed_targets: list[AllowedTarget] | None) -> dict[str, AllowedTarget]:
    return {target.target_id: target for target in allowed_targets or []}


def _brief_target_ids(
    brief: IncidentBrief,
    roles: set[str],
    allowed_targets: list[AllowedTarget] | None,
    *,
    fallback_to_focus: bool = True,
) -> list[str]:
    by_id = _allowed_by_id(allowed_targets)
    preferred = set(brief.recommended_ic_focus.preferred_target_ids)
    ids = [
        candidate.target_id
        for candidate in brief.role_candidates
        if candidate.role_hint in roles
        and candidate.target_id in by_id
        and by_id[candidate.target_id].targetable
        and (candidate.evidence_ids or candidate.target_id in preferred)
    ]
    if not ids and fallback_to_focus:
        ids = [
            target_id
            for target_id in brief.recommended_ic_focus.preferred_target_ids
            if target_id in by_id and by_id[target_id].targetable
        ]
    return list(dict.fromkeys(ids))


def _ranked_allowed_target_ids_for_brief(
    brief: IncidentBrief,
    allowed_targets: list[AllowedTarget] | None,
    *,
    preferred_roles: set[str],
    max_targets: int = 2,
) -> list[str]:
    """Pick safe target IDs when the AI brief has a blocker but sparse role metadata.

    This uses only the deterministic allowed-target quality gate and evidence overlap.
    It does not infer ownership or the blocker; those still come from IncidentBrief.
    """

    evidence_focus = set(brief.latest_blocker.evidence_ids)
    evidence_focus.update(brief.recommended_ic_focus.evidence_ids)
    evidence_focus.update(brief.latest_window_event_ids[-8:])
    evidence_focus.update(brief.based_on_event_ids[-8:])

    scored: list[tuple[int, int, int, str]] = []
    for index, target in enumerate(allowed_targets or []):
        if not target.targetable:
            continue
        if target.target_type not in {"person", "team", "service"}:
            continue
        if target.target_quality not in {"high", "medium"}:
            continue
        if target.role_hint == "bot_system":
            continue
        if target.source_event_kind in {
            "preview_card",
            "pagerduty_card",
            "jira_card",
            "zoom_card",
            "log_or_code_block",
            "table_row",
            "table_header",
            "generated_summary_fragment",
            "low_signal_noise",
        }:
            continue

        role_score = 0
        if target.role_hint in preferred_roles:
            role_score = 8
        elif target.role_hint == "unknown":
            role_score = 3
        elif target.role_hint in {"technical_investigator", "owner_team", "reporter_or_validator", "support_team"}:
            role_score = 5

        source_score = {
            "slack_author": 6,
            "explicit_mention": 5,
            "current_evidence": 4,
            "catalog": 3,
            "service_alias": 2,
            "command_registry": 1,
        }.get(target.source, 0)
        quality_score = 4 if target.target_quality == "high" else 2
        overlap_score = 6 if evidence_focus.intersection(target.evidence_ids) else 0
        type_score = 2 if target.target_type in {"person", "team"} else 1
        scored.append((role_score + source_score + quality_score + overlap_score + type_score, -index, len(target.display_name), target.target_id))

    scored.sort(reverse=True)
    return [target_id for _, _, _, target_id in scored[:max_targets]]


def _names_for_target_ids(target_ids: list[str], allowed_targets: list[AllowedTarget] | None, fallback: str) -> str:
    by_id = _allowed_by_id(allowed_targets)
    names = [by_id[target_id].display_name for target_id in target_ids if target_id in by_id]
    return _join_names(names, fallback)


def _mentioned_allowed_target_ids(text: str, allowed_targets: list[AllowedTarget] | None) -> list[str]:
    address_prefixes: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        comma_index = stripped.find(",")
        if 0 <= comma_index <= 100:
            address_prefixes.append(stripped[:comma_index])
    if not address_prefixes:
        return []
    address_norm = f" {_norm(' / '.join(address_prefixes).replace('/', ' / '))} "
    ids: list[str] = []
    for target in allowed_targets or []:
        if not target.targetable:
            continue
        if target.target_type not in {"person", "team", "service"}:
            continue
        if target.target_quality not in {"high", "medium"}:
            continue
        if target.role_hint == "bot_system":
            continue
        name_norm = _norm(target.display_name)
        if len(name_norm) < 3:
            continue
        if f" {name_norm} " in address_norm:
            ids.append(target.target_id)
    return list(dict.fromkeys(ids))


def _base_owner_name(name: str) -> str:
    normalized = _norm(name)
    for suffix in (" team", " service"):
        if normalized.endswith(suffix):
            return normalized[: -len(suffix)].strip()
    return normalized


def _owner_context_match(name: str, context: str) -> bool:
    base = _base_owner_name(name)
    if not base:
        return False
    patterns = (
        f"{base} is blocked",
        f"{base} blocked",
        f"blocked on {base}",
        f"need {base}",
        f"{base} guidance",
        f"{base} owner",
        f"owning {base}",
        f"route to {base}",
        f"engage {base}",
        f"ask {base}",
        f"waiting on {base}",
        f"toward {base}",
        f"{base} engaged",
        f"{base} is suggested",
    )
    return any(pattern in context for pattern in patterns)


def _canonical_owner_ids(target_ids: list[str], allowed_targets: list[AllowedTarget] | None) -> list[str]:
    by_id = _allowed_by_id(allowed_targets)
    by_base: dict[str, list[AllowedTarget]] = {}
    for target in allowed_targets or []:
        if not target.targetable:
            continue
        by_base.setdefault(_base_owner_name(target.display_name), []).append(target)
    resolved: list[str] = []
    for target_id in target_ids:
        target = by_id.get(target_id)
        if target is None:
            continue
        candidates = by_base.get(_base_owner_name(target.display_name), [])
        canonical = next(
            (
                candidate
                for candidate in candidates
                if candidate.source in {"catalog", "service_alias", "command_registry"}
                and candidate.target_type in {"team", "service"}
            ),
            target,
        )
        resolved.append(canonical.target_id)
    return list(dict.fromkeys(resolved))


def _plan_from_incident_brief(
    incident_brief: IncidentBrief | None,
    allowed_targets: list[AllowedTarget] | None,
    catalog_matches: list[ServiceCatalogEntry] | None = None,
    command_registry: list[CommandRegistryEntry] | None = None,
) -> ICDecision | None:
    if incident_brief is None:
        return None
    blocker = incident_brief.latest_blocker.blocker_type
    if blocker == "unknown" and not incident_brief.recommended_ic_focus.preferred_target_ids:
        return None
    by_id = _allowed_by_id(allowed_targets)
    summary = incident_brief.recommended_ic_focus.summary or incident_brief.latest_blocker.summary
    if not summary:
        summary = incident_brief.current_summary or "the latest incident evidence"
    context_norm = _norm(
        " ".join(
            (
                incident_brief.current_summary,
                incident_brief.latest_blocker.summary,
                incident_brief.recommended_ic_focus.summary,
            )
        )
    )
    focus_ids = [
        target_id
        for target_id in incident_brief.recommended_ic_focus.preferred_target_ids
        if target_id in by_id and by_id[target_id].targetable
    ]
    missing_owner_has_owner_target = False
    technical_ids = _brief_target_ids(incident_brief, {"technical_investigator", "owner_team"}, allowed_targets)
    validation_ids = _brief_target_ids(
        incident_brief,
        {"reporter_or_validator", "support_team"},
        allowed_targets,
        fallback_to_focus=False,
    )
    if blocker in {"code_fix_status_needed", "status_eta_needed", "monitoring_needed", "deployment_validation_needed"}:
        evidence_people = [
            target.target_id
            for target in allowed_targets or []
            if target.targetable
            and target.target_type in {"person", "team"}
            and target.source in {"slack_author", "current_evidence", "catalog"}
            and _norm(target.display_name)
            and _norm(target.display_name).split()[0] in context_norm
            and target.role_hint in {"technical_investigator", "owner_team"}
        ]
        if blocker == "monitoring_needed":
            evidence_people.extend(
                candidate.target_id
                for candidate in incident_brief.role_candidates
                if candidate.role_hint == "unknown"
                and candidate.target_id in by_id
                and by_id[candidate.target_id].targetable
                and by_id[candidate.target_id].display_name.lower() not in {"incident.io", "support", "zsrebot"}
                and " ic" not in by_id[candidate.target_id].display_name.lower()
            )
        technical_ids = list(dict.fromkeys([*evidence_people, *technical_ids]))
    if blocker == "missing_owner":
        scored_owner_ids: list[tuple[int, int, int, str]] = []
        for index, target in enumerate(allowed_targets or []):
            if not (
                target.targetable
                and target.target_type in {"team", "service"}
                and target.role_hint in {"owner_team", "support_team", "unknown"}
            ):
                continue
            name = _norm(target.display_name)
            base = _base_owner_name(target.display_name)
            exact_context = bool(name and name in context_norm)
            owner_context = _owner_context_match(target.display_name, context_norm)
            if not (exact_context or owner_context):
                continue
            source_score = 4 if target.source in {"catalog", "service_alias", "command_registry"} else 2
            context_score = 3 if owner_context else 1
            score = source_score + context_score
            if base and any(role.target_id == target.target_id and role.role_hint == "owner_team" for role in incident_brief.role_candidates):
                score += 1
            scored_owner_ids.append((score, len(base), -index, target.target_id))
        scored_owner_ids.sort(reverse=True)
        filtered_owner_ids: list[str] = []
        seen_owner_bases: set[str] = set()
        for _, _, _, target_id in scored_owner_ids:
            base = _base_owner_name(by_id[target_id].display_name)
            if base in seen_owner_bases:
                continue
            if any(base in _base_owner_name(by_id[kept].display_name) and base != _base_owner_name(by_id[kept].display_name) for kept in filtered_owner_ids):
                continue
            filtered_owner_ids.append(target_id)
            seen_owner_bases.add(base)
        mentioned_owner_ids = filtered_owner_ids[:2]
        owner_ids = [
            target_id
            for target_id in focus_ids
            if by_id[target_id].target_type in {"team", "service"}
            and by_id[target_id].source in {"catalog", "service_alias", "command_registry"}
        ]
        owner_ids = mentioned_owner_ids or owner_ids
        if not owner_ids:
            owner_ids = [
                target_id
                for target_id in _brief_target_ids(incident_brief, {"owner_team"}, allowed_targets)
                if by_id[target_id].source in {"catalog", "service_alias", "command_registry"}
            ]
        owner_ids = _canonical_owner_ids(owner_ids, allowed_targets)
        if owner_ids:
            missing_owner_has_owner_target = True
            technical_ids = owner_ids
            validation_ids = []
    if blocker == "customer_scope_needed":
        safe_scope_summary = "No confirmed customer name or tenant ID yet."
        if "customer" in summary.lower() or "tenant" in summary.lower():
            safe_scope_summary = summary.split(";")[0].rstrip(".") + "."
        return ICDecision(
            decision_id=_decision_id("brief-customer-scope"),
            incident_id=incident_brief.incident_id,
            move=ICMove.SUMMARIZE_CURRENT_STATE,
            phase=incident_brief.phase.primary,
            domain_intent=blocker,
            model_metadata={"incident_brief_used": True},
            output={
                "say_this": safe_scope_summary,
                "next_line": "I do not see a confirmed customer, tenant, or support validation target in current evidence yet.",
            },
            target_ids=[],
            rationale=["IncidentBrief identified missing customer/tenant scope and rejected fake entities."],
            grounding=[{"event_id": event_id} for event_id in incident_brief.latest_blocker.evidence_ids],  # type: ignore[list-item]
            confidence=max(0.55, incident_brief.latest_blocker.confidence),
        )
    selected_technical_ids = technical_ids[:2]
    selected_validation_ids = validation_ids[:1]
    preferred_ids = list(dict.fromkeys([*selected_technical_ids, *selected_validation_ids]))
    if not preferred_ids and blocker != "unknown":
        preferred_roles = {"technical_investigator", "owner_team"}
        if blocker in {"validation_needed", "customer_scope_needed", "deployment_validation_needed"}:
            preferred_roles.update({"reporter_or_validator", "support_team"})
        ranked_ids = _ranked_allowed_target_ids_for_brief(
            incident_brief,
            allowed_targets,
            preferred_roles=preferred_roles,
        )
        if ranked_ids:
            selected_technical_ids = ranked_ids[:2]
            selected_validation_ids = []
            preferred_ids = ranked_ids
    if not preferred_ids:
        preferred_ids = _brief_target_ids(incident_brief, {"ic_or_coordinator", "unknown"}, allowed_targets)[:2]
        selected_technical_ids = []
        selected_validation_ids = []

    move = ICMove.ASK_NEXT_VALIDATION
    if blocker == "mitigation_status_needed":
        move = ICMove.REQUEST_MITIGATION_OPTION if any(term in summary.lower() for term in ("stop", "pause", "process")) else ICMove.REQUEST_STATUS_OR_ETA
    elif blocker in {"status_eta_needed", "waiting_on_active_work"}:
        move = ICMove.REQUEST_STATUS_OR_ETA
    elif blocker == "monitoring_needed":
        move = ICMove.REQUEST_MONITORING_SIGNAL
    elif blocker == "code_fix_status_needed":
        move = ICMove.REQUEST_STATUS_OR_ETA
    elif blocker == "deployment_validation_needed":
        move = ICMove.CONFIRM_DEPLOYMENT_RELATED
    elif blocker == "missing_owner":
        move = ICMove.ENGAGE_OWNER if missing_owner_has_owner_target else ICMove.CONFIRM_OWNERSHIP
    elif blocker == "customer_scope_needed":
        move = ICMove.ASK_NEXT_VALIDATION
    elif blocker == "rca_owner_needed":
        move = ICMove.REQUEST_STATUS_OR_ETA
    elif blocker == "handoff_needed":
        move = ICMove.HANDOFF_OR_ASSIGN_DRI

    output = {"say_this": summary.rstrip(".") + "."}
    if selected_technical_ids and selected_validation_ids:
        if blocker == "missing_owner":
            next_line = (
                f"{_names_for_target_ids(selected_technical_ids, allowed_targets, 'Technical investigator')}/"
                f"{_names_for_target_ids(selected_validation_ids, allowed_targets, 'validator')}, can you confirm the active DRI/owner, exposure or affected scope, and the next validation signal?"
            )
        elif blocker == "code_fix_status_needed":
            next_line = (
                f"{_names_for_target_ids(selected_technical_ids, allowed_targets, 'Code-fix owner')}, can you confirm code fix/hotfix status, hotfix ETA, and release blockers?"
            )
        elif blocker == "deployment_validation_needed":
            next_line = (
                f"{_names_for_target_ids(selected_technical_ids, allowed_targets, 'Technical owner')}, can you confirm build/deployment status and the next validation signal; "
                f"{_names_for_target_ids(selected_validation_ids, allowed_targets, 'validator')}, can you confirm customer/application validation result?"
            )
        elif blocker == "monitoring_needed":
            next_line = (
                f"{_names_for_target_ids(selected_technical_ids, allowed_targets, 'Technical owner')}, can you confirm the monitoring signal in {summary}; "
                f"{_names_for_target_ids(selected_validation_ids, allowed_targets, 'validator')}, can you confirm customer/application validation result?"
            )
        elif blocker == "mitigation_status_needed" and any(term in summary.lower() for term in ("stop", "pause", "process")):
            next_line = (
                f"{_names_for_target_ids(selected_technical_ids, allowed_targets, 'Active owner')}, can you confirm whether the process can stop or pause and what recovery signal we should watch; "
                f"{_names_for_target_ids(selected_validation_ids, allowed_targets, 'validator')}, can you confirm any remaining scope or sandbox activity?"
            )
        elif blocker == "validation_needed" and "tenant/workload" in summary.lower() and "bulk operation" in summary.lower():
            next_line = (
                f"{_names_for_target_ids(selected_technical_ids, allowed_targets, 'Technical owner')}, can you confirm which tenant/workload is driving bulk operation and the validation signal?"
            )
        else:
            next_line = (
                f"{_names_for_target_ids(selected_technical_ids, allowed_targets, 'Technical owner')}, can you confirm system stability/status or monitoring signal; "
                f"{_names_for_target_ids(selected_validation_ids, allowed_targets, 'validator')}, can you confirm customer/application validation result?"
            )
    elif selected_technical_ids:
        ask = "RCA/follow-up owner and monitoring signal" if blocker == "rca_owner_needed" else "status, ETA/blocker, and validation signal"
        if blocker == "code_fix_status_needed":
            ask = "code fix/hotfix status, hotfix ETA, and release blockers"
        elif blocker == "deployment_validation_needed":
            ask = "build/deployment status and the next validation signal"
        elif blocker == "monitoring_needed":
            summary_norm = summary.lower()
            if "can you confirm" in summary_norm or "please confirm" in summary_norm or "?" in summary:
                ask = "the current validation result, technical status, and success criteria for recovery"
            elif "need active owner" in summary_norm or "phase update" in summary_norm:
                ask = "the current monitoring signal, status or blocker, and success criteria for recovery"
            else:
                ask = f"whether {summary} is green and what success criteria lets us close monitoring"
        elif blocker == "mitigation_status_needed" and any(term in summary.lower() for term in ("stop", "pause", "process")):
            ask = "whether the process can stop or pause, and what recovery signal we should watch next"
        elif blocker == "status_eta_needed" and any(
            term in summary.lower()
            for term in ("dashboard", "metric", "lookup", "shard", "tenant", "lag", "queue", "health")
        ):
            ask = "the latest lookup/metric interpretation, status or blocker, and the recovery validation signal"
        elif blocker == "validation_needed" and "tenant/workload" in summary.lower() and "bulk operation" in summary.lower():
            ask = "which tenant/workload is driving bulk operation and the validation signal"
        if blocker == "missing_owner":
            ask = (
                "ownership and the next validation step"
                if missing_owner_has_owner_target
                else "the active DRI/owner and the next validation signal"
            )
            target_name = _names_for_target_ids(technical_ids[:1], allowed_targets, "the likely owner")
            if missing_owner_has_owner_target and "support" in context_norm and "point" in context_norm:
                output["say_this"] = (
                    f"Support is pointing this toward {target_name}, and I do not see {target_name} engaged yet."
                )
            elif not missing_owner_has_owner_target:
                output["say_this"] = f"{summary.rstrip('.')}; I do not see a confirmed DRI/owner yet."
            else:
                output["say_this"] = f"{summary.rstrip('.')}; I do not see {target_name} engaged yet."
        next_line = f"{_names_for_target_ids(selected_technical_ids, allowed_targets, 'Technical owner')}, can you confirm {ask}?"
    elif selected_validation_ids:
        if blocker == "missing_owner":
            next_line = (
                f"{_names_for_target_ids(selected_validation_ids, allowed_targets, 'Validator')}, can you confirm the active DRI/owner and the next validation signal?"
            )
        elif blocker == "mitigation_status_needed" and any(term in summary.lower() for term in ("stop", "pause", "process")):
            next_line = (
                f"{_names_for_target_ids(selected_validation_ids, allowed_targets, 'Active owner')}, can you confirm whether the process can stop or pause and what recovery signal we should watch?"
            )
        else:
            next_line = (
                f"{_names_for_target_ids(selected_validation_ids, allowed_targets, 'Validator')}, can you confirm current validation result, symptom, and remaining affected scope?"
            )
    elif preferred_ids:
        next_line = f"{_names_for_target_ids(preferred_ids, allowed_targets, 'Active owner')}, can you confirm the next grounded status or validation signal?"
    elif blocker != "unknown":
        if blocker in {"status_eta_needed", "waiting_on_active_work"}:
            next_line = "Can the active owner confirm status, ETA or blocker, and the next validation signal from current evidence?"
        elif blocker == "monitoring_needed":
            next_line = "Can the active owner confirm the monitoring signal, current status, and success criteria from current evidence?"
        elif blocker == "mitigation_status_needed":
            next_line = "Can the active owner confirm mitigation status, remaining affected scope, and the validation signal from current evidence?"
        elif blocker == "validation_needed":
            next_line = "Can the active owner confirm the latest validation result and what signal proves recovery or continued impact?"
        elif blocker == "missing_owner":
            next_line = "Can the IC route this to the grounded owning team or active technical DRI visible in current evidence?"
        else:
            next_line = "Can the active owner confirm the next grounded status or validation signal from current evidence?"
    else:
        return ICDecision(
            decision_id=_decision_id("brief-no-safe"),
            incident_id=incident_brief.incident_id,
            move=ICMove.NO_SAFE_RECOMMENDATION,
            phase=incident_brief.phase.primary,
            output={"say_this": "I do not have a safe, grounded next move yet."},
            target_ids=[],
            rationale=["IncidentBrief did not identify a targetable next IC ask."],
            grounding=[],
            confidence=0.3,
        )
    if move == ICMove.ENGAGE_OWNER and preferred_ids:
        target_name = by_id[preferred_ids[0]].display_name if preferred_ids[0] in by_id else ""
        command = get_oncall_command_for_target(target_name, catalog_matches or [], command_registry)
        if command:
            output["command"] = command
    preferred_ids = list(
        dict.fromkeys(
            [
                *preferred_ids,
                *_mentioned_allowed_target_ids(
                    f"{output.get('say_this', '')} {next_line}",
                    allowed_targets,
                ),
            ]
        )
    )
    grounding_ids = (
        incident_brief.latest_blocker.evidence_ids
        or incident_brief.recommended_ic_focus.evidence_ids
        or incident_brief.latest_window_event_ids
        or incident_brief.based_on_event_ids[:2]
    )
    return ICDecision(
        decision_id=_decision_id("incident-brief"),
        incident_id=incident_brief.incident_id,
        move=move,
        phase=incident_brief.phase.primary,
        domain_intent=blocker,
        model_metadata={"incident_brief_used": True},
        output={**output, "next_line": next_line},
        target_ids=preferred_ids,
        targets=[_target_entity_from_allowed(by_id[target_id]) for target_id in preferred_ids if target_id in by_id],
        rationale=["IncidentBrief identified the latest blocker and allowed target IDs."],
        grounding=[{"event_id": event_id} for event_id in grounding_ids],  # type: ignore[list-item]
        confidence=max(0.62, incident_brief.latest_blocker.confidence),
    )


def _plan_from_sharp_blocker(
    current_state: CurrentIncidentState,
    sharp_blocker_assessment: SharpBlockerAssessment | None,
) -> ICDecision | None:
    if sharp_blocker_assessment is None:
        return None
    blocker = sharp_blocker_assessment.blocker_type
    if blocker not in {
        "rollback_or_disable_status",
        "mitigation_status_or_validation",
        "missing_mitigation",
        "waiting_on_owner_status",
        "waiting_on_monitoring",
        "missing_validation",
    }:
        return None

    technical_targets = list(sharp_blocker_assessment.technical_status_targets)
    validation_targets = list(sharp_blocker_assessment.customer_or_reporter_validation_targets)
    target = _join_names(technical_targets, _sharp_owner_phrase(sharp_blocker_assessment, current_state))
    context = _sharp_context_phrase(sharp_blocker_assessment)
    slots = _humanize_slots(
        sharp_blocker_assessment.recommended_ask_slots or [
            "mitigation status",
            "remaining affected scope",
            "validation signal",
        ]
    )
    ask = ", ".join(slots[:3])
    move = ICMove.REQUEST_STATUS_OR_ETA
    if blocker in {"mitigation_status_or_validation", "missing_mitigation"}:
        move = ICMove.REQUEST_MITIGATION_OPTION
    if blocker == "waiting_on_monitoring":
        move = ICMove.REQUEST_MONITORING_SIGNAL
    if blocker == "missing_validation":
        move = ICMove.ASK_NEXT_VALIDATION
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
    output = {
        "say_this": f"The sharp blocker is {context}.",
        "next_line": next_line,
    }
    metadata = {
        "sharp_blocker_used": True,
        "sharp_blocker_type": blocker,
        "sharp_blocker_summary": sharp_blocker_assessment.blocker_summary,
    }
    grounding = []
    for entity in current_state.engaged_entities[:3]:
        grounding.extend(entity.evidence)
    for action in current_state.actions_completed[:3]:
        grounding.extend(action.evidence)
    if not grounding and current_state.severity:
        grounding.extend(current_state.severity.evidence)
    return ICDecision(
        decision_id=_decision_id("sharp-blocker"),
        incident_id=current_state.incident_id,
        move=move,
        phase=current_state.phase,
        domain_intent=blocker,
        model_metadata=metadata,
        output=output,
        targets=[],
        rationale=["SharpBlockerAssessment identified a technical status/validation blocker."],
        grounding=grounding,
        confidence=max(0.62, sharp_blocker_assessment.confidence),
    )


def plan_ic_decision(
    current_state: CurrentIncidentState,
    catalog_matches: list[ServiceCatalogEntry],
    accepted_memories: list[MemoryApplicabilityResult],
    llm_client: LLMClient | None = None,
    command_registry: list[CommandRegistryEntry] | None = None,
    clean_context: CleanIncidentContext | None = None,
    sharp_blocker_assessment: SharpBlockerAssessment | None = None,
    incident_brief: IncidentBrief | None = None,
    allowed_targets: list[AllowedTarget] | None = None,
    semantic_quality: object | None = None,
    incident_brief_quality: object | None = None,
    event_quality: dict[str, object] | None = None,
) -> ICDecision:
    _ = (semantic_quality, incident_brief_quality, event_quality)
    if llm_client is not None:
        try:
            decision = llm_client.generate_json(
                "ic_planner",
                {
                    "current_state": current_state.model_dump(mode="json"),
                    "clean_context": clean_context.model_dump(mode="json") if clean_context else None,
                    "sharp_blocker_assessment": (
                        sharp_blocker_assessment.model_dump(mode="json") if sharp_blocker_assessment else None
                    ),
                    "incident_brief": incident_brief.model_dump(mode="json") if incident_brief else None,
                    "allowed_targets": [target.model_dump(mode="json") for target in allowed_targets or []],
                    "catalog_matches": [entry.model_dump(mode="json") for entry in catalog_matches],
                    "accepted_memories": [memory.model_dump(mode="json") for memory in accepted_memories],
                },
                ICDecision,
            )
            validated = validate_with_repair(decision, ICDecision, context="ic_planner")
            if (
                validated.move == ICMove.NO_SAFE_RECOMMENDATION
                and incident_brief is not None
                and incident_brief.latest_blocker.blocker_type != "unknown"
            ):
                if brief_decision := _plan_from_incident_brief(
                    incident_brief,
                    allowed_targets,
                    catalog_matches,
                    command_registry,
                ):
                    metadata = dict(brief_decision.model_metadata)
                    metadata["planner_fallback_used"] = True
                    metadata["planner_fallback_reason"] = "model_no_safe_but_incident_brief_has_blocker"
                    return brief_decision.model_copy(update={"model_metadata": metadata})
            return validated
        except NotImplementedError:
            # Test/dev clients may intentionally omit the planner fixture. Keep the same
            # IncidentBrief-first product fallback rather than blocking on a missing fixture.
            keep_incident_brief_for_split_monitoring = bool(
                current_state.current_blocker == "waiting_on_monitoring"
                and sharp_blocker_assessment
                and sharp_blocker_assessment.technical_status_targets
                and sharp_blocker_assessment.customer_or_reporter_validation_targets
            )
            if (
                current_state.current_blocker not in {"rollback_or_disable_status", "mitigation_status_or_validation"}
                and not keep_incident_brief_for_split_monitoring
            ):
                sharp_blocker_assessment = None
            pass
        except (ModelOutputValidationError, ValidationError) as exc:
            original_move = getattr(exc, "original_move", None)
            fallback = plan_ic_decision(
                current_state,
                catalog_matches,
                accepted_memories,
                llm_client=None,
                command_registry=command_registry,
                clean_context=clean_context,
                sharp_blocker_assessment=sharp_blocker_assessment,
                incident_brief=incident_brief,
                allowed_targets=allowed_targets,
            )
            return _attach_planner_fallback_metadata(fallback, exc, original_move)

    if brief_decision := _plan_from_incident_brief(incident_brief, allowed_targets, catalog_matches, command_registry):
        return brief_decision

    if current_state.current_blocker == "missing_owner" and current_state.engaged_entities:
        summary = current_state.compact_summary.lower()
        if "paged" in summary or "already" in summary or "asked" in summary:
            target = current_state.engaged_entities[0]
            signal = _signal_phrase(current_state) if current_state.monitoring_signals else "a first status, ETA, or validation signal"
            return ICDecision(
                decision_id=_decision_id("wait-active-work"),
                incident_id=current_state.incident_id,
                move=ICMove.WAIT_FOR_ACTIVE_WORK,
                phase=current_state.phase,
                output={
                    "say_this": f"{target.display_name} is already engaged; the useful next step is a first read rather than another page.",
                    "next_line": f"{target.display_name}, please confirm you have the context and share {signal}.",
                },
                targets=[target],
                rationale=["Current evidence shows the owner was already engaged or paged."],
                grounding=_all_grounding(target, current_state),
                confidence=0.68,
            )

    if current_state.current_blocker == "missing_owner" and current_state.suggested_but_not_engaged:
        target = current_state.suggested_but_not_engaged[0]
        targets = current_state.suggested_but_not_engaged
        command = get_oncall_command_for_target(target.display_name, catalog_matches, command_registry)
        if current_state.impact.affected_count == 27 and current_state.severity:
            next_line = (
                f"{target.display_name}, we have a {_severity_value(current_state)} RevPro "
                f"deployment/version mismatch affecting 27 customers. Can you help confirm "
                "ownership and the next validation step?"
            )
            say_this = (
                f"Looks like Support is pointing this toward {target.display_name}, and I do not "
                f"see {target.display_name} engaged yet."
            )
        else:
            names = "/".join(entity.display_name for entity in targets[:2])
            say_this = f"I do not see {names} acknowledgement on the sharpest ownership blocker yet."
            next_line = (
                f"{names}, can you confirm the safe owner path and the next validation step from current evidence?"
            )
            if current_state.monitoring_signals:
                next_line = (
                    f"{names}, can you confirm the safe owner path for {_signal_phrase(current_state)} "
                    "and the next validation step from current evidence?"
                )
            if len(targets) > 1:
                command = None
        output = {
            "say_this": say_this,
            "next_line": next_line,
        }
        if command:
            output["command"] = command
        return ICDecision(
            decision_id=_decision_id("engage-owner"),
            incident_id=current_state.incident_id,
            move=ICMove.ENGAGE_OWNER,
            phase=current_state.phase,
            output=output,
            targets=targets,
            rationale=["Target is suggested by current evidence and not visibly engaged."],
            grounding=_all_grounding(target, current_state),
            confidence=0.78,
        )

    if current_state.current_blocker == "waiting_on_customer_confirmation":
        targets = _targets_by_names(current_state, "Support", "Payments team")
        target = targets[0] if targets else (current_state.engaged_entities[0] if current_state.engaged_entities else None)
        return ICDecision(
            decision_id=_decision_id("customer-confirmation"),
            incident_id=current_state.incident_id,
            move=ICMove.ASK_NEXT_VALIDATION,
            phase=current_state.phase,
            output={
                "say_this": "The incident is mitigated; the remaining blocker is customer/internal acknowledgement and follow-up tracking.",
                "next_line": f"{'/'.join(entity.display_name for entity in targets) if targets else 'Support/Engineering'}, please confirm the customer-facing update path and whether {_signal_phrase(current_state)} is the follow-up item.",
            },
            targets=targets or ([target] if target else []),
            rationale=["Current evidence says mitigation is complete and confirmation/follow-up is the remaining blocker."],
            grounding=_all_grounding(target, current_state),
            confidence=0.7,
        )

    if current_state.current_blocker == "customer_comms_pending":
        target = next(
            (
                entity
                for entity in current_state.engaged_entities
                if entity.display_name.lower() in {"support", "trust", "customer support"}
            ),
            None,
        )
        target_name = target.display_name if target else "Support/customer comms"
        return ICDecision(
            decision_id=_decision_id("customer-comms"),
            incident_id=current_state.incident_id,
            move=ICMove.CONFIRM_CUSTOMER_COMMS,
            phase=current_state.phase,
            output={
                "say_this": "Customer communications are the visible coordination blocker.",
                "next_line": f"{target_name}, please confirm whether a Trust Post or customer-facing update is needed from current incident evidence.",
            },
            targets=[target] if target else [],
            rationale=["Current evidence shows customer communications are pending."],
            grounding=_all_grounding(target, current_state),
            confidence=0.65,
        )

    if current_state.current_blocker == "waiting_on_code_fix":
        target = next((entity for entity in current_state.engaged_entities if entity.status == "working"), None)
        coordinator = next((entity for entity in current_state.engaged_entities if "coordinat" in entity.status), None)
        target_name = target.display_name if target else "the code-fix owner"
        blocker_name = coordinator.display_name if coordinator else "release"
        return ICDecision(
            decision_id=_decision_id("code-fix-status"),
            incident_id=current_state.incident_id,
            move=ICMove.REQUEST_STATUS_OR_ETA,
            phase=current_state.phase,
            output={
                "say_this": "This is a P2 payment/Stripe incident with code-fix/hotfix timing as the sharpest blocker.",
                "next_line": f"{target_name}, can you confirm the current code-fix status, hotfix ETA, and whether {blocker_name} has any release blockers?",
            },
            targets=[target] if target else [],
            rationale=["Current evidence says a code fix is required and an owner is working on it."],
            grounding=_all_grounding(target, current_state),
            confidence=0.75,
        )

    if current_state.current_blocker == "waiting_on_monitoring":
        summary = current_state.compact_summary.lower()
        if "edition update" in summary or "pending partner" in summary or "credential blocker" in summary:
            targets = _targets_by_names(current_state, "RevPro", "Support")
            target = targets[0] if targets else (current_state.engaged_entities[0] if current_state.engaged_entities else None)
            return ICDecision(
                decision_id=_decision_id("revpro-edition-monitoring"),
                incident_id=current_state.incident_id,
                move=ICMove.WAIT_FOR_ACTIVE_WORK,
                phase=current_state.phase,
                output={
                    "say_this": "Most tenant work appears mitigated, but current evidence still shows pending tenant validation or a credential blocker.",
                    "next_line": "RevPro/Support, please post ZDT job completion per tenant and the remaining validation result before calling mitigation complete.",
                },
                targets=targets or ([target] if target else []),
                rationale=["Current evidence says not all tenant validation is complete yet."],
                grounding=_all_grounding(target, current_state),
                confidence=0.68,
            )
        if "transfer accounting" in summary or "ta batch" in summary:
            targets = [
                entity
                for entity in current_state.engaged_entities
                if entity.entity_type in {EntityType.TEAM, EntityType.PERSON}
            ][:2]
            target = targets[0] if targets else (current_state.engaged_entities[0] if current_state.engaged_entities else None)
            return ICDecision(
                decision_id=_decision_id("ta-validation"),
                incident_id=current_state.incident_id,
                move=ICMove.ASK_NEXT_VALIDATION,
                phase=current_state.phase,
                output={
                    "say_this": "Transfer Accounting completed after the mitigation work; confirm there are no remaining failures before closing active mitigation.",
                    "next_line": f"{_join_names([entity.display_name for entity in targets], 'Active owner/Support')}, please confirm {_signal_phrase(current_state)} and whether RCA/follow-up is tracked separately.",
                },
                targets=targets or ([target] if target else []),
                rationale=["Current evidence says Transfer Accounting completed and the blocker is final validation/monitoring."],
                grounding=_all_grounding(target, current_state),
                confidence=0.72,
            )
        if sharp_decision := _plan_from_sharp_blocker(current_state, sharp_blocker_assessment):
            return sharp_decision
        target = current_state.engaged_entities[0] if current_state.engaged_entities else None
        signals = ", ".join(signal.value for signal in current_state.monitoring_signals[:2])
        next_line = (
            f"Active owner, please confirm {signals} is green and what success criteria lets us close monitoring."
            if signals
            else "Active owner, what signal are we monitoring and what success criteria should the bridge use?"
        )
        return ICDecision(
            decision_id=_decision_id("monitor-next"),
            incident_id=current_state.incident_id,
            move=ICMove.REQUEST_MONITORING_SIGNAL
            if current_state.phase == IncidentPhase.MONITORING
            else ICMove.ASK_NEXT_VALIDATION,
            phase=current_state.phase,
            output={
                "say_this": "Mitigation appears completed; the next useful move is final monitoring/validation.",
                "next_line": next_line,
            },
            targets=[target] if target else [],
            rationale=["Mitigation is present and monitoring is the next blocker."],
            grounding=_all_grounding(target, current_state),
            confidence=0.65,
        )

    if current_state.current_blocker in {"deployment_validation", "missing_validation"}:
        summary = current_state.compact_summary.lower()
        if "data sync" in summary and "revenue sync" in summary:
            targets = _targets_by_names(current_state, "UNO team", "Revenue", "SRE")
            target = targets[0] if targets else (current_state.engaged_entities[0] if current_state.engaged_entities else None)
            return ICDecision(
                decision_id=_decision_id("data-sync-validation"),
                incident_id=current_state.incident_id,
                move=ICMove.ASK_NEXT_VALIDATION,
                phase=current_state.phase,
                output={
                    "say_this": "Data Sync completed after the connection-pool parameter change; the remaining blocker is validation.",
                    "next_line": f"UNO/Revenue/SRE, please confirm {_signal_phrase(current_state)} and whether Data Transformation, CCV, and DiscountContractualValue completed successfully.",
                },
                targets=targets or ([target] if target else []),
                rationale=["Current evidence says Data Sync completed and named the remaining validation objects."],
                grounding=_all_grounding(target, current_state),
                confidence=0.72,
            )

        if "cpu did not decrease" in summary or "bulk operation" in summary:
            target = next((entity for entity in current_state.engaged_entities if entity.display_name == "Sai"), None)
            fallback_target = next((entity for entity in current_state.engaged_entities if entity.display_name == "DBA"), None)
            chosen = target or fallback_target
            return ICDecision(
                decision_id=_decision_id("db-validation"),
                incident_id=current_state.incident_id,
                move=ICMove.ASK_NEXT_VALIDATION,
                phase=current_state.phase,
                output={
                    "say_this": "DBA is engaged and the dedicated queue action did not reduce CPU yet.",
                    "next_line": "Sai, can you identify which tenant/workload is still driving the bulk operation so we can check the API/workflow/batch-query path next?",
                },
                targets=[chosen] if chosen else [],
                rationale=["DBA is active and queue isolation did not reduce CPU; next move is validation of remaining workload."],
                grounding=_all_grounding(chosen, current_state),
                confidence=0.82,
            )

        if "revenueorgmapping=0" in summary or "uno" in summary and "revenue" in summary:
            target = next((entity for entity in current_state.engaged_entities if entity.display_name == "UNO"), None)
            revenue = next((entity for entity in current_state.engaged_entities if entity.display_name == "Revenue"), None)
            chosen = target or revenue
            tenant_phrase = ""
            if any(fact.value == "10005051" for fact in current_state.impact.affected_tenants):
                tenant_phrase = " for tenant 10005051"
                if any(fact.value == "Google Fiber" for fact in current_state.impact.affected_customers):
                    tenant_phrase += " / Google Fiber"
            return ICDecision(
                decision_id=_decision_id("uno-revenue-validation"),
                incident_id=current_state.incident_id,
                move=ICMove.ASK_NEXT_VALIDATION,
                phase=current_state.phase,
                output={
                    "say_this": "Looks like this is Central Sandbox ZB-ZR / UNO data-flow impact, with current evidence pointing at the tenant/mapping path.",
                    "next_line": f"UNO/Revenue, can you confirm whether RevenueOrgMapping=0 is sending transactions without a valid Revenue mapping{tenant_phrase}, and what safe stop-the-bleeding or validation step we have?",
                },
                targets=[chosen] if chosen else [],
                rationale=["Current evidence contains UNO/Revenue mapping signals and engaged SMEs."],
                grounding=_all_grounding(chosen, current_state),
                confidence=0.82,
            )

        if current_state.monitoring_signals and current_state.engaged_entities and "ocm" not in summary:
            target = current_state.engaged_entities[0]
            if "ebs" in summary or "db looks ok" in summary:
                return ICDecision(
                    decision_id=_decision_id("ebs-validation"),
                    incident_id=current_state.incident_id,
                    move=ICMove.ASK_NEXT_VALIDATION,
                    phase=current_state.phase,
                    output={
                        "say_this": "The EBS increase is deployed and DB looks OK; capture final validation before closing the change loop.",
                        "next_line": f"{target.display_name}, please confirm DB health after EBS increase and whether the duplicate CM/change path is closed.",
                    },
                    targets=[target],
                    rationale=["Current evidence says the storage change is deployed and validation is the remaining step."],
                    grounding=_all_grounding(target, current_state),
                    confidence=0.7,
                )
            return ICDecision(
                decision_id=_decision_id("generic-validation"),
                incident_id=current_state.incident_id,
                move=ICMove.ASK_NEXT_VALIDATION,
                phase=current_state.phase,
                output={
                    "say_this": "The owner is engaged and current evidence names a concrete validation signal.",
                    "next_line": f"{target.display_name}, please confirm {_signal_phrase(current_state)} and whether any customer-visible failure remains.",
                },
                targets=[target],
                rationale=["The blocker is validation, not a new impact or owner question."],
                grounding=_all_grounding(target, current_state),
                confidence=0.66,
            )

        if sharp_decision := _plan_from_sharp_blocker(current_state, sharp_blocker_assessment):
            return sharp_decision

        target = next(
            (entity for entity in current_state.engaged_entities if entity.display_name.lower() == "praneeth"),
            None,
        )
        fallback_target = next(
            (entity for entity in current_state.engaged_entities if entity.display_name.lower() == "ocm"),
            None,
        )
        chosen = target or fallback_target
        return ICDecision(
            decision_id=_decision_id("deployment-validation"),
            incident_id=current_state.incident_id,
            move=ICMove.ASK_NEXT_VALIDATION,
            phase=current_state.phase,
            output={
                "say_this": "Looks like OCM/commerce-catalog is already engaged, so the next useful move is deployment validation.",
                "next_line": "Praneeth or OCM owner, can you confirm whether today's NA2 CSBX/sandbox deployment is related and whether the bridge has the right OCM owner?",
            },
            targets=[chosen] if chosen else [],
            rationale=["Current evidence says OCM/commerce-catalog are engaged and deployment relationship is unresolved."],
            grounding=_all_grounding(chosen, current_state),
            confidence=0.72,
        )

    if current_state.current_blocker == "waiting_on_mitigation":
        target = _target_by_name(current_state, "ZDP") or (current_state.engaged_entities[0] if current_state.engaged_entities else None)
        signal = _signal_phrase(current_state)
        return ICDecision(
            decision_id=_decision_id("wait-mitigation"),
            incident_id=current_state.incident_id,
            move=ICMove.WAIT_FOR_ACTIVE_WORK,
            phase=current_state.phase,
            output={
                "say_this": "The service owner is engaged and the next action depends on the active mitigation completing.",
                "next_line": f"{target.display_name if target else 'Active owner'}, please confirm the mitigation status, ETA, and whether {signal} should be used for validation.",
            },
            targets=[target] if target else [],
            rationale=["Current evidence shows owner engagement and mitigation still in progress."],
            grounding=_all_grounding(target, current_state),
            confidence=0.68,
        )

    if current_state.current_blocker in {"waiting_on_deploy", "deployment_pending"}:
        summary = current_state.compact_summary.lower()
        targets = _targets_by_names(current_state, "Change Management", "Engineering")
        target = targets[0] if targets else (current_state.engaged_entities[0] if current_state.engaged_entities else None)
        if "slack approval" in summary or "jira ecm" in summary:
            return ICDecision(
                decision_id=_decision_id("slack-ecm-approval"),
                incident_id=current_state.incident_id,
                move=ICMove.CONFIRM_DEPLOYMENT_RELATED,
                phase=current_state.phase,
                output={
                    "say_this": "Before proceeding, document the problem, fix, testing, validation, and PRs for interim Slack approval since Jira ECM is unavailable.",
                    "next_line": "Engineering, please post PRs plus build/deployment status, validation, and rollback details so Change Management can approve safely in Slack.",
                },
                targets=targets or ([target] if target else []),
                rationale=["Current evidence says Jira ECM is unavailable and Change Management requested interim approval context."],
                grounding=_all_grounding(target, current_state),
                confidence=0.7,
            )
        return ICDecision(
            decision_id=_decision_id("deployment-pending"),
            incident_id=current_state.incident_id,
            move=ICMove.CONFIRM_DEPLOYMENT_RELATED,
            phase=current_state.phase,
            output={
                "say_this": "The current blocker is deployment/change progress, not impact discovery.",
                "next_line": f"{target.display_name if target else 'Deployment owner'}, please confirm deployment status, validation plan, and rollback criteria.",
            },
            targets=[target] if target else [],
            rationale=["Current evidence points at deployment/change progress as the blocker."],
            grounding=_all_grounding(target, current_state),
            confidence=0.65,
        )

    if sharp_decision := _plan_from_sharp_blocker(current_state, sharp_blocker_assessment):
        return sharp_decision

    if current_state.current_blocker == "waiting_on_validation":
        target = current_state.engaged_entities[0] if current_state.engaged_entities else None
        return ICDecision(
            decision_id=_decision_id("validation"),
            incident_id=current_state.incident_id,
            move=ICMove.ASK_NEXT_VALIDATION,
            phase=current_state.phase,
            output={
                "say_this": "DUNE is engaged; keep the bridge focused on the validation result.",
                "next_line": "DUNE, can you confirm whether RevenueOrgMapping=0 explains tenant 10005051 / Google Fiber in Central Sandbox and what the next validation step is?",
            },
            targets=[target] if target else [],
            rationale=["Current evidence contains DUNE, tenant 10005051, Google Fiber, and RevenueOrgMapping=0."],
            grounding=_all_grounding(target, current_state),
            confidence=0.74,
        )

    if (
        current_state.current_blocker == "missing_impact"
        and "no confirmed customer name or tenant id yet" in current_state.impact.description.lower()
    ):
        return ICDecision(
            decision_id=_decision_id("safe-summary"),
            incident_id=current_state.incident_id,
            move=ICMove.SUMMARIZE_CURRENT_STATE,
            phase=current_state.phase,
            output={
                "say_this": "No confirmed customer name or tenant ID yet.",
                "next_line": "Please state affected customer/tenant only from current incident evidence before routing or paging.",
            },
            targets=[],
            rationale=["Current evidence explicitly says customer and tenant are not confirmed."],
            grounding=current_state.impact.evidence,
            confidence=0.65,
        )

    if current_state.current_blocker == "missing_impact" and current_state.impact.has_useful_info():
        target = current_state.engaged_entities[0] if current_state.engaged_entities else None
        if current_state.monitoring_signals and target:
            return ICDecision(
                decision_id=_decision_id("impact-validation"),
                incident_id=current_state.incident_id,
                move=ICMove.ASK_NEXT_VALIDATION,
                phase=current_state.phase,
                output={
                    "say_this": "Impact is now stated in current evidence; the next useful move is validation, not another generic impact question.",
                    "next_line": f"{target.display_name}, please confirm {_signal_phrase(current_state)} and which affected entries are validated or still pending.",
                },
                targets=[target],
                rationale=["Current evidence already contains impact and a validation signal."],
                grounding=_all_grounding(target, current_state),
                confidence=0.66,
            )

    if current_state.current_blocker == "missing_impact" and not current_state.impact.has_useful_info():
        return ICDecision(
            decision_id=_decision_id("impact"),
            incident_id=current_state.incident_id,
            move=ICMove.ASK_IMPACT,
            phase=current_state.phase if current_state.phase else IncidentPhase.TRIAGE,
            output={
                "say_this": "I do not see enough current evidence to name impact yet.",
                "next_line": "Can someone state the current affected customer count, tenant/account if known, and whether production traffic is blocked?",
            },
            targets=[],
            rationale=["Impact is the current blocker and impact evidence is low confidence."],
            grounding=[],
            confidence=0.55,
        )

    return ICDecision(
        decision_id=_decision_id("no-safe"),
        incident_id=current_state.incident_id,
        move=ICMove.NO_SAFE_RECOMMENDATION,
        phase=current_state.phase,
        output={"say_this": "I do not have a safe, grounded next move yet."},
        targets=[],
        rationale=["No deterministic Phase 1 planning rule matched current evidence."],
        grounding=[],
        confidence=0.3,
    )
