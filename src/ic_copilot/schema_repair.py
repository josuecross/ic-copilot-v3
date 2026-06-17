from __future__ import annotations

import copy
import re
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from ic_copilot.schemas import ICDecision, ICMove, IncidentBrief, IncidentPhase, Severity, StateDelta
from ic_copilot.schemas import IncidentReadAndWhisperV2


ModelT = TypeVar("ModelT", bound=BaseModel)


class ModelOutputValidationError(ValueError):
    def __init__(
        self,
        *,
        context: str,
        model_name: str,
        original_move: str | None = None,
        raw_error: Exception | None = None,
    ) -> None:
        self.context = context
        self.model_name = model_name
        self.original_move = original_move
        self.raw_error = raw_error
        if original_move:
            message = (
                f"Model output did not match the {model_name} schema. "
                f"The model suggested an unsupported move: {original_move}. "
                "A safe fallback should be used."
            )
        else:
            message = f"Model output did not match the {model_name} schema. A safe fallback should be used."
        super().__init__(message)


def _label(value: Any) -> str:
    raw = getattr(value, "value", value)
    return re.sub(r"[^a-z0-9]+", "_", str(raw).strip().lower()).strip("_")


PHASE_ALIASES = {
    "acknowledgement": IncidentPhase.ENGAGEMENT.value,
    "acknowledge": IncidentPhase.ENGAGEMENT.value,
    "acknowledged": IncidentPhase.ENGAGEMENT.value,
    "phase_1_acknowledge": IncidentPhase.ENGAGEMENT.value,
    "phase_1_acknowledgement": IncidentPhase.ENGAGEMENT.value,
    "engage": IncidentPhase.ENGAGEMENT.value,
    "owner_engagement": IncidentPhase.ENGAGEMENT.value,
    "initial_investigation": IncidentPhase.INVESTIGATION.value,
    "investigation_in_progress": IncidentPhase.INVESTIGATION.value,
    "investigating": IncidentPhase.INVESTIGATION.value,
    "active_mitigation": IncidentPhase.MITIGATION.value,
    "mitigation_in_progress": IncidentPhase.MITIGATION.value,
    "mitigating": IncidentPhase.MITIGATION.value,
    "observe": IncidentPhase.MONITORING.value,
    "observing": IncidentPhase.MONITORING.value,
    "watching": IncidentPhase.MONITORING.value,
    "validation": IncidentPhase.MONITORING.value,
    "validating": IncidentPhase.MONITORING.value,
    "post_mitigation_validation": IncidentPhase.MONITORING.value,
    "verified": IncidentPhase.VERIFICATION.value,
    "validation_complete": IncidentPhase.VERIFICATION.value,
    "resolution": IncidentPhase.RESOLVED.value,
    "closed": IncidentPhase.CLOSED.value,
    "closure": IncidentPhase.CLOSED.value,
}

MOVE_ALIASES = {
    "ask_validation": ICMove.ASK_NEXT_VALIDATION.value,
    "validation_request": ICMove.ASK_NEXT_VALIDATION.value,
    "next_validation": ICMove.ASK_NEXT_VALIDATION.value,
    "request_mapping_confirmation": ICMove.ASK_NEXT_VALIDATION.value,
    "investigate_mapping_behavior": ICMove.ASK_NEXT_VALIDATION.value,
    "request_details_from_researcher": ICMove.ASK_NEXT_VALIDATION.value,
    "request_security_details": ICMove.ASK_NEXT_VALIDATION.value,
    "request_vulnerability_details": ICMove.ASK_NEXT_VALIDATION.value,
    "request_vulnerability_report_details": ICMove.ASK_NEXT_VALIDATION.value,
    "request_researcher_details": ICMove.ASK_NEXT_VALIDATION.value,
    "request_security_triage_details": ICMove.ASK_NEXT_VALIDATION.value,
    "request_validation_step": ICMove.ASK_NEXT_VALIDATION.value,
    "ask_validation_owner": ICMove.ASK_NEXT_VALIDATION.value,
    "request_next_validation": ICMove.ASK_NEXT_VALIDATION.value,
    "request_vulnerability_scope": ICMove.ASK_IMPACT.value,
    "assess_security_impact": ICMove.ASK_IMPACT.value,
    "confirm_security_owner": ICMove.CONFIRM_OWNERSHIP.value,
    "engage_security_owner": ICMove.ENGAGE_OWNER.value,
    "request_containment_plan": ICMove.REQUEST_MITIGATION_OPTION.value,
    "request_security_mitigation": ICMove.REQUEST_MITIGATION_OPTION.value,
    "ask_eta": ICMove.REQUEST_STATUS_OR_ETA.value,
    "status_eta": ICMove.REQUEST_STATUS_OR_ETA.value,
    "request_eta": ICMove.REQUEST_STATUS_OR_ETA.value,
    "ask_status_update": ICMove.REQUEST_STATUS_OR_ETA.value,
    "ask_owner_update": ICMove.REQUEST_STATUS_OR_ETA.value,
    "request_owner_status": ICMove.REQUEST_STATUS_OR_ETA.value,
    "request_owner_update": ICMove.REQUEST_STATUS_OR_ETA.value,
    "request_status_update": ICMove.REQUEST_STATUS_OR_ETA.value,
    "request_status": ICMove.REQUEST_STATUS_OR_ETA.value,
    "ask_status": ICMove.REQUEST_STATUS_OR_ETA.value,
    "ask_for_status_update": ICMove.REQUEST_STATUS_OR_ETA.value,
    "status_check": ICMove.REQUEST_STATUS_OR_ETA.value,
    "ask_trust_post_confirmation": ICMove.CONFIRM_CUSTOMER_COMMS.value,
    "confirm_trust_post": ICMove.CONFIRM_CUSTOMER_COMMS.value,
    "ask_trust_post_needed": ICMove.CONFIRM_CUSTOMER_COMMS.value,
    "ask_customer_comms_status": ICMove.CONFIRM_CUSTOMER_COMMS.value,
    "ask_customer_comms_confirmation": ICMove.CONFIRM_CUSTOMER_COMMS.value,
    "confirm_customer_communication": ICMove.CONFIRM_CUSTOMER_COMMS.value,
    "confirm_customer_comms_status": ICMove.CONFIRM_CUSTOMER_COMMS.value,
    "ask_zoom_bridge_confirmation": ICMove.ASK_NEXT_VALIDATION.value,
    "ask_phase_update": ICMove.SUMMARIZE_CURRENT_STATE.value,
    "ask_for_code_fix_status_and_eta": ICMove.ASK_CODE_FIX_STATUS.value,
    "monitor_signal": ICMove.REQUEST_MONITORING_SIGNAL.value,
    "monitoring_signal": ICMove.REQUEST_MONITORING_SIGNAL.value,
    "monitor": ICMove.MONITOR_NEXT.value,
    "monitoring": ICMove.MONITOR_NEXT.value,
    "whisper": ICMove.NO_SAFE_RECOMMENDATION.value,
    "suggest_engagement": ICMove.ENGAGE_OWNER.value,
    "suggest_owner_engagement": ICMove.ENGAGE_OWNER.value,
    "engage": ICMove.ENGAGE_OWNER.value,
    "engage_target": ICMove.ENGAGE_OWNER.value,
    "engage_service_owner": ICMove.ENGAGE_OWNER.value,
    "engage_incident_owner": ICMove.ENGAGE_OWNER.value,
    "engage_team": ICMove.ENGAGE_OWNER.value,
    "engage_support_team": ICMove.ENGAGE_OWNER.value,
    "escalate_to_revpro_support": ICMove.ENGAGE_OWNER.value,
    "suggest_oncall_notification": ICMove.ENGAGE_OWNER.value,
    "suggest_engagement_check": ICMove.ENGAGE_OWNER.value,
    "page_owner": ICMove.ENGAGE_OWNER.value,
    "route_owner": ICMove.ENGAGE_OWNER.value,
    "wait_for_owner_confirmation": ICMove.CONFIRM_OWNERSHIP.value,
    "owner_confirmation": ICMove.CONFIRM_OWNERSHIP.value,
    "confirm_owner": ICMove.CONFIRM_OWNERSHIP.value,
    "check_ownership": ICMove.CONFIRM_OWNERSHIP.value,
    "check_owner": ICMove.CONFIRM_OWNERSHIP.value,
    "request_ownership_confirmation": ICMove.CONFIRM_OWNERSHIP.value,
    "ownership_confirmation": ICMove.CONFIRM_OWNERSHIP.value,
    "inform": ICMove.SUMMARIZE_CURRENT_STATE.value,
    "inform_waiting_for_owner_confirmation": ICMove.SUMMARIZE_CURRENT_STATE.value,
    "inform_no_trust_post_needed": ICMove.SUMMARIZE_CURRENT_STATE.value,
    "summarize_waiting_for_owner_confirmation": ICMove.SUMMARIZE_CURRENT_STATE.value,
    "no_recommendation": ICMove.NO_SAFE_RECOMMENDATION.value,
    "no_safe_move": ICMove.NO_SAFE_RECOMMENDATION.value,
}

SEVERITY_ALIASES = {
    "sev1": Severity.P1.value,
    "sev_1": Severity.P1.value,
    "p1": Severity.P1.value,
    "sev2": Severity.P2.value,
    "sev_2": Severity.P2.value,
    "p2": Severity.P2.value,
    "sev3": Severity.P3.value,
    "sev_3": Severity.P3.value,
    "p3": Severity.P3.value,
    "sev4": Severity.P4.value,
    "sev_4": Severity.P4.value,
    "p4": Severity.P4.value,
    "l3_escalation": Severity.L3.value,
    "l3": Severity.L3.value,
}

INCIDENT_BRIEF_BLOCKER_ALIASES = {
    "confirm_ownership": "missing_owner",
    "confirm_owner": "missing_owner",
    "request_ownership_confirmation": "missing_owner",
    "ownership_confirmation": "missing_owner",
    "engage_owner": "missing_owner",
    "engage_team": "missing_owner",
    "ask_next_validation": "validation_needed",
    "request_validation_step": "validation_needed",
    "request_next_validation": "validation_needed",
    "request_status_or_eta": "status_eta_needed",
    "ask_status_eta": "status_eta_needed",
    "request_status": "status_eta_needed",
    "request_mitigation_option": "mitigation_status_needed",
    "request_monitoring_signal": "monitoring_needed",
    "monitor_next": "monitoring_needed",
    "ask_code_fix_status": "code_fix_status_needed",
    "confirm_deployment_related": "deployment_validation_needed",
    "handoff_or_assign_dri": "handoff_needed",
}

V2_BLOCKER_ALIASES = {
    "owner_routing": "missing_owner",
    "awaiting_owner_routing": "missing_owner",
    "owner_route": "missing_owner",
    "routing_owner": "missing_owner",
    "routing_owner_missing": "missing_owner",
    "awaiting_routing_owner": "missing_owner",
    "owner_routing_pending": "missing_owner",
    "missing_owner_routing": "missing_owner",
    "service_owner_routing": "awaiting_service_owner_status",
    "owner_status": "awaiting_service_owner_status",
    "validation_needed": "awaiting_validation_signal",
    "missing_validation": "awaiting_validation_signal",
    "status_eta_needed": "awaiting_service_owner_status",
    "waiting_on_status": "awaiting_service_owner_status",
}

V2_WHISPER_MOVE_ALIASES = {
    "owner_routing": "confirm_ownership",
    "route_owner": "engage_owner",
    "engage_revpro_support": "engage_owner",
    "engage_support": "engage_owner",
    "request_owner_engagement": "engage_owner",
    "request_customer_impact": "ask_impact",
    "request_customer_scope": "ask_impact",
    "request_validation": "ask_next_validation",
    "validation_request": "ask_next_validation",
}


def normalize_phase(value: Any) -> Any:
    if value is None:
        return value
    label = _label(value)
    if label in {item.value for item in IncidentPhase}:
        return label
    return PHASE_ALIASES.get(label, value)


def normalize_move(value: Any) -> Any:
    if value is None:
        return value
    label = _label(value)
    if label in {item.value for item in ICMove}:
        return label
    return MOVE_ALIASES.get(label, value)


def normalize_severity(value: Any) -> Any:
    if value is None:
        return value
    label = _label(value)
    if label == "unknown":
        return Severity.UNKNOWN.value
    return SEVERITY_ALIASES.get(label, value)


def normalize_incident_brief_blocker(value: Any) -> Any:
    if value is None:
        return value
    label = _label(value)
    valid = {
        "missing_owner",
        "validation_needed",
        "rca_owner_needed",
        "monitoring_needed",
        "mitigation_status_needed",
        "customer_scope_needed",
        "status_eta_needed",
        "code_fix_status_needed",
        "deployment_validation_needed",
        "waiting_on_active_work",
        "handoff_needed",
        "unknown",
    }
    if label in valid:
        return label
    return INCIDENT_BRIEF_BLOCKER_ALIASES.get(label, value)


def normalize_v2_blocker(value: Any) -> Any:
    if value is None:
        return value
    label = _label(value)
    valid = {
        "missing_impact_scope",
        "missing_escalation_type",
        "missing_owner",
        "awaiting_reporter_details",
        "awaiting_service_owner_status",
        "awaiting_validation_signal",
        "awaiting_customer_confirmation",
        "trust_post_decision",
        "mitigation_done_need_verification",
        "no_safe_next_move",
    }
    if label in valid:
        return label
    return V2_BLOCKER_ALIASES.get(label, value)


def normalize_v2_whisper_move(value: Any) -> Any:
    if value is None:
        return value
    label = _label(value)
    valid = {
        "engage_owner",
        "confirm_ownership",
        "ask_next_validation",
        "request_status_or_eta",
        "request_mitigation_option",
        "request_monitoring_signal",
        "summarize_current_state",
        "prevent_stale_question",
        "escalate_severity_or_owner",
        "handoff_or_assign_dri",
        "wait_for_active_work",
        "ask_code_fix_status",
        "ask_status_eta",
        "ask_impact",
        "confirm_deployment_related",
        "confirm_customer_comms",
        "monitor_next",
        "ask_impact_scope",
        "ask_escalation_type",
        "ask_owner_routing",
        "ask_status_or_eta",
        "ask_validation_signal",
        "ask_customer_confirmation",
        "ask_trust_post_decision",
        "no_safe_recommendation",
    }
    if label in valid:
        return label
    return V2_WHISPER_MOVE_ALIASES.get(label, value)


def repair_state_delta_payload(payload: dict[str, Any]) -> dict[str, Any]:
    repaired = copy.deepcopy(payload)
    if "phase" in repaired:
        repaired["phase"] = normalize_phase(repaired.get("phase"))
    severity = repaired.get("severity")
    if isinstance(severity, dict) and "value" in severity:
        severity["value"] = normalize_severity(severity.get("value"))
    return repaired


def repair_ic_decision_payload(payload: dict[str, Any]) -> dict[str, Any]:
    repaired = copy.deepcopy(payload)
    if "move" in repaired:
        original_move = repaired.get("move")
        normalized_move = normalize_move(original_move)
        if normalized_move != original_move:
            original_text = str(getattr(original_move, "value", original_move))
            repaired["move"] = normalized_move
            repaired.setdefault("domain_intent", original_text)
            metadata = dict(repaired.get("model_metadata") or {})
            metadata.setdefault("original_move", original_text)
            metadata.setdefault(
                "normalized_move_reason",
                f"Normalized model move alias '{_label(original_move)}' to canonical ICMove '{normalized_move}'.",
            )
            repaired["model_metadata"] = metadata
        else:
            repaired["move"] = normalized_move
    if "phase" in repaired:
        repaired["phase"] = normalize_phase(repaired.get("phase"))
    return repaired


def repair_incident_brief_payload(payload: dict[str, Any]) -> dict[str, Any]:
    repaired = copy.deepcopy(payload)
    phase = repaired.get("phase")
    if isinstance(phase, dict) and "primary" in phase:
        phase["primary"] = normalize_phase(phase.get("primary"))
    blocker = repaired.get("latest_blocker")
    if isinstance(blocker, dict) and "blocker_type" in blocker:
        blocker["blocker_type"] = normalize_incident_brief_blocker(blocker.get("blocker_type"))
    focus = repaired.get("recommended_ic_focus")
    if isinstance(focus, dict) and isinstance(focus.get("acceptable_move_types"), list):
        focus["acceptable_move_types"] = [normalize_move(move) for move in focus["acceptable_move_types"]]
    return repaired


def repair_incident_read_v2_payload(payload: dict[str, Any]) -> dict[str, Any]:
    repaired = copy.deepcopy(payload)
    recovered: list[dict[str, str]] = []
    blocker = repaired.get("next_blocker")
    if isinstance(blocker, dict) and "blocker_type" in blocker:
        original = blocker.get("blocker_type")
        normalized = normalize_v2_blocker(original)
        if normalized != original:
            blocker["blocker_type"] = normalized
            recovered.append(
                {
                    "field": "next_blocker.blocker_type",
                    "original": str(original),
                    "normalized": str(normalized),
                }
            )
    whisper = repaired.get("whisper")
    if isinstance(whisper, dict) and "selected_move" in whisper:
        original = whisper.get("selected_move")
        normalized = normalize_v2_whisper_move(original)
        if normalized != original:
            whisper["selected_move"] = normalized
            recovered.append(
                {
                    "field": "whisper.selected_move",
                    "original": str(original),
                    "normalized": str(normalized),
                }
            )
    if recovered:
        notes = [str(item) for item in repaired.get("safety_notes") or []]
        notes.append("recovered_schema_synonym:" + json_safe_label(recovered))
        repaired["safety_notes"] = notes
    return repaired


def json_safe_label(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value)).strip()[:500]


def validate_with_repair(payload: Any, model: type[ModelT], *, context: str) -> ModelT:
    if isinstance(payload, model):
        return payload
    if isinstance(payload, BaseModel):
        payload = payload.model_dump(mode="json")
    original_payload = payload
    if isinstance(payload, dict):
        if model is StateDelta:
            payload = repair_state_delta_payload(payload)
        elif model is ICDecision:
            payload = repair_ic_decision_payload(payload)
        elif model is IncidentBrief:
            payload = repair_incident_brief_payload(payload)
        elif model is IncidentReadAndWhisperV2:
            payload = repair_incident_read_v2_payload(payload)
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        if model is ICDecision:
            original_move = None
            if isinstance(original_payload, dict):
                raw_move = original_payload.get("move")
                if raw_move is not None:
                    original_move = str(getattr(raw_move, "value", raw_move))
            raise ModelOutputValidationError(
                context=context,
                model_name=model.__name__,
                original_move=original_move,
                raw_error=exc,
            ) from exc
        raise
