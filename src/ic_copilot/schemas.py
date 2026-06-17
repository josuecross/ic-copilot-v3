from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


Confidence = float


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class StrictBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)


class IncidentPhase(str, Enum):
    UNKNOWN = "unknown"
    DETECTION = "detection"
    TRIAGE = "triage"
    ENGAGEMENT = "engagement"
    INVESTIGATION = "investigation"
    MITIGATION = "mitigation"
    MONITORING = "monitoring"
    VERIFICATION = "verification"
    CUSTOMER_COMMS = "customer_comms"
    HANDOFF = "handoff"
    CLOSED = "closed"
    RESOLVED = "resolved"


class ICMove(str, Enum):
    ENGAGE_OWNER = "engage_owner"
    CONFIRM_OWNERSHIP = "confirm_ownership"
    ASK_NEXT_VALIDATION = "ask_next_validation"
    REQUEST_STATUS_OR_ETA = "request_status_or_eta"
    REQUEST_MITIGATION_OPTION = "request_mitigation_option"
    REQUEST_MONITORING_SIGNAL = "request_monitoring_signal"
    SUMMARIZE_CURRENT_STATE = "summarize_current_state"
    PREVENT_STALE_QUESTION = "prevent_stale_question"
    ESCALATE_SEVERITY_OR_OWNER = "escalate_severity_or_owner"
    HANDOFF_OR_ASSIGN_DRI = "handoff_or_assign_dri"
    WAIT_FOR_ACTIVE_WORK = "wait_for_active_work"
    ASK_CODE_FIX_STATUS = "ask_code_fix_status"
    ASK_STATUS_ETA = "ask_status_eta"
    ASK_IMPACT = "ask_impact"
    CONFIRM_DEPLOYMENT_RELATED = "confirm_deployment_related"
    CONFIRM_CUSTOMER_COMMS = "confirm_customer_comms"
    MONITOR_NEXT = "monitor_next"
    NO_SAFE_RECOMMENDATION = "no_safe_recommendation"


class EntityType(str, Enum):
    SERVICE = "service"
    TEAM = "team"
    PERSON = "person"
    CUSTOMER = "customer"
    TENANT = "tenant"
    ENVIRONMENT = "environment"
    REGION = "region"
    ACCOUNT = "account"
    JIRA = "jira"
    DASHBOARD = "dashboard"
    RUNBOOK = "runbook"
    COMMAND = "command"
    LINK = "link"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    L3 = "L3"
    UNKNOWN = "unknown"


class EvidenceRef(StrictBaseModel):
    event_id: str
    quote: str = ""
    source: str = "slack"
    confidence: Confidence = Field(default=0.8, ge=0.0, le=1.0)


class EvidenceBackedFact(StrictBaseModel):
    value: str
    evidence: list[EvidenceRef] = Field(default_factory=list)
    confidence: Confidence = Field(default=0.7, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EntityRef(StrictBaseModel):
    entity_type: EntityType
    display_name: str
    canonical_id: str | None = None
    status: str = "mentioned"
    evidence: list[EvidenceRef] = Field(default_factory=list)
    confidence: Confidence = Field(default=0.7, ge=0.0, le=1.0)
    source: Literal["current_evidence", "catalog", "memory"] = "current_evidence"


class ImpactState(StrictBaseModel):
    description: str = ""
    affected_customers: list[EvidenceBackedFact] = Field(default_factory=list)
    affected_tenants: list[EvidenceBackedFact] = Field(default_factory=list)
    affected_count: int | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)
    confidence: Confidence = Field(default=0.0, ge=0.0, le=1.0)

    def has_useful_info(self) -> bool:
        return bool(
            self.description
            or self.affected_count is not None
            or self.affected_customers
            or self.affected_tenants
        )


class QuestionRecord(StrictBaseModel):
    question_id: str
    intent: str
    text: str
    target: str | None = None
    status: Literal["open", "answered", "stale"] = "open"
    answer: str | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)
    answered_evidence: list[EvidenceRef] = Field(default_factory=list)


class ActionRecord(StrictBaseModel):
    action_id: str
    action_type: str
    summary: str
    actor: str | None = None
    target: str | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)
    confidence: Confidence = Field(default=0.7, ge=0.0, le=1.0)


class CommandCandidate(StrictBaseModel):
    command: str
    target: str | None = None
    requires_human_approval: bool = True
    source: Literal["current_evidence", "catalog"] = "current_evidence"
    evidence: list[EvidenceRef] = Field(default_factory=list)


class LinkRef(StrictBaseModel):
    url: str
    evidence: list[EvidenceRef] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CleanContextFact(StrictBaseModel):
    fact_type: str
    value: str
    confidence: Confidence = Field(default=0.7, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)


class CleanContextEntity(StrictBaseModel):
    name: str
    entity_type: EntityType = EntityType.UNKNOWN
    status: Literal[
        "joined",
        "mentioned",
        "asked",
        "responded",
        "active",
        "engaged",
        "working",
        "actively_working",
        "suggested_not_engaged",
        "system_or_bot",
        "unknown",
    ] = "unknown"
    targetable: bool = False
    confidence: Confidence = Field(default=0.7, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)


class CleanContextBlocker(StrictBaseModel):
    blocker_type: str = "unknown"
    summary: str = ""
    confidence: Confidence = Field(default=0.0, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)


class CleanContextValue(StrictBaseModel):
    value: str = "unknown"
    confidence: Confidence = Field(default=0.0, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)


class CleanQuestionLedger(StrictBaseModel):
    open_questions: list[QuestionRecord] = Field(default_factory=list)
    answered_questions: list[QuestionRecord] = Field(default_factory=list)
    stale_question_intents: list[str] = Field(default_factory=list)


class CleanRejectedEntity(StrictBaseModel):
    text: str
    rejected_entity_type: EntityType = EntityType.UNKNOWN
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)


class CleanIncidentContext(StrictBaseModel):
    schema_version: Literal["1.0"] = "1.0"
    incident_id: str
    based_on_event_ids: list[str] = Field(default_factory=list)
    source_summary: str = ""
    clean_summary: str = ""
    phase: CleanContextValue = Field(default_factory=CleanContextValue)
    severity: CleanContextValue = Field(default_factory=CleanContextValue)
    current_blocker: CleanContextBlocker = Field(default_factory=CleanContextBlocker)
    incident_kind: list[CleanContextFact] = Field(default_factory=list)
    facts: list[CleanContextFact] = Field(default_factory=list)
    candidate_services: list[CleanContextEntity] = Field(default_factory=list)
    engaged_entities: list[CleanContextEntity] = Field(default_factory=list)
    suggested_but_not_engaged: list[CleanContextEntity] = Field(default_factory=list)
    question_ledger: CleanQuestionLedger = Field(default_factory=CleanQuestionLedger)
    actions_completed: list[ActionRecord] = Field(default_factory=list)
    monitoring_signals: list[EvidenceBackedFact] = Field(default_factory=list)
    rejected_entities: list[CleanRejectedEntity] = Field(default_factory=list)
    do_not_invent: list[str] = Field(default_factory=list)
    uncertainty_notes: list[str] = Field(default_factory=list)


class SlackConversationTurn(StrictBaseModel):
    turn_id: str
    speaker: str
    speaker_type: Literal["human", "bot", "system", "unknown"] = "unknown"
    text: str
    approximate_time: str | None = None
    source_event_ids: list[str] = Field(default_factory=list)
    confidence: Confidence = Field(default=0.6, ge=0.0, le=1.0)
    uncertainty_notes: list[str] = Field(default_factory=list)


class SlackTurnReconstruction(StrictBaseModel):
    schema_version: Literal["1.0"] = "1.0"
    incident_id: str
    source_event_ids: list[str] = Field(default_factory=list)
    turns: list[SlackConversationTurn] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class InputSizeAssessment(StrictBaseModel):
    event_count: int = 0
    character_count: int = 0
    estimated_token_count: int = 0
    long_event_count: int = 0
    url_count: int = 0
    code_or_log_block_count: int = 0
    bot_or_system_event_count: int = 0
    likely_too_large_for_single_pass: bool = False
    recommended_strategy: Literal[
        "single_pass",
        "compact_then_single_pass",
        "chunked_clean_context",
        "latest_window_only_with_summary",
    ] = "single_pass"
    reasons: list[str] = Field(default_factory=list)


class LatestWindowSelection(StrictBaseModel):
    event_ids: list[str] = Field(default_factory=list)
    reason: str = ""
    dropped_event_count: int = 0
    kept_event_count: int = 0
    contains_latest_human_evidence: bool = False
    contains_latest_bot_summary: bool = False
    contains_latest_actions: bool = False
    contains_latest_questions: bool = False
    contains_latest_validation_or_monitoring: bool = False
    contains_latest_customer_or_support_update: bool = False


class EventQuality(StrictBaseModel):
    event_id: str
    sequence: int = 0
    author: str | None = None
    author_type: Literal["human", "bot", "system", "unknown"] = "unknown"
    event_kind: Literal[
        "human_operator_message",
        "human_question",
        "human_status_update",
        "human_validation_or_monitoring",
        "human_mitigation_or_action",
        "human_diagnostic_evidence",
        "bot_system_message",
        "bot_diagnostic_evidence",
        "bot_lifecycle",
        "bot_owner_request",
        "bot_summary",
        "preview_card",
        "pagerduty_card",
        "jira_card",
        "zoom_card",
        "slack_lifecycle",
        "log_or_code_block",
        "table_or_log_diagnostic",
        "table_or_log_label_noise",
        "table_row",
        "table_header",
        "generated_summary_fragment",
        "continuation_line",
        "low_signal_noise",
        "unknown",
    ] = "unknown"
    evidence_quality: Literal["high", "medium", "low", "invalid"] = "medium"
    target_source_quality: Literal["high", "medium", "low", "invalid"] = "medium"
    is_target_source_allowed: bool = True
    is_blocker_evidence_allowed: bool = True
    is_planner_grounding_allowed: bool = True
    reasons: list[str] = Field(default_factory=list)


class AllowedTarget(StrictBaseModel):
    target_id: str
    display_name: str
    target_type: Literal["person", "team", "service", "bot_system", "non_targetable_noise"] = "person"
    source: Literal[
        "slack_author",
        "explicit_mention",
        "catalog",
        "current_evidence",
        "service_alias",
        "command_registry",
    ] = "current_evidence"
    role_hint: Literal[
        "ic_or_coordinator",
        "reporter_or_validator",
        "technical_investigator",
        "owner_team",
        "support_team",
        "observer",
        "unknown",
    ] = "unknown"
    targetable: bool = True
    evidence_ids: list[str] = Field(default_factory=list)
    reason: str = ""
    canonical_id: str | None = None
    target_quality: Literal["high", "medium", "low", "rejected"] = "medium"
    source_event_kind: str | None = None
    rejection_reason: str | None = None
    normalized_display_name: str | None = None
    raw_display_name: str | None = None
    is_selected_for_planning: bool = False


class RawMentionCandidate(StrictBaseModel):
    display_name: str
    source: Literal[
        "slack_author",
        "explicit_mention",
        "catalog",
        "command_registry",
        "current_evidence_phrase",
    ] = "current_evidence_phrase"
    evidence_ids: list[str] = Field(default_factory=list)
    candidate_type_guess: str = "unknown"
    targetable_initially: bool = False
    rejection_reason: str | None = None


class TargetShortlistItem(StrictBaseModel):
    target_id: str
    display_name: str
    target_type: Literal["person", "team", "service", "bot_system", "non_targetable_noise"] = "person"
    role_hint: Literal[
        "ic_or_coordinator",
        "reporter_or_validator",
        "technical_investigator",
        "owner_team",
        "support_team",
        "observer",
        "unknown",
    ] = "unknown"
    why_targetable: str = ""
    latest_evidence_ids: list[str] = Field(default_factory=list)
    rank: int = 0
    score: float = 0.0
    target_quality: Literal["high", "medium", "low", "rejected"] = "medium"
    target_score_breakdown: dict[str, float] = Field(default_factory=dict)
    target_evidence_age_rank: int = 0
    target_selected_because: str = ""
    target_penalties: list[str] = Field(default_factory=list)
    target_role_alignment: str = ""


class SemanticQuality(StrictBaseModel):
    status: Literal["sufficient", "degraded", "insufficient"] = "insufficient"
    can_plan: bool = False
    can_render_normal_recommendation: bool = False
    failed_readers: list[str] = Field(default_factory=list)
    successful_readers: list[str] = Field(default_factory=list)
    required_reader_success: bool = False
    question_only_success: bool = False
    human_operator_evidence_count: int = 0
    preview_card_evidence_count: int = 0
    blocker_evidence_quality: Literal["high", "medium", "low", "invalid"] = "invalid"
    target_quality_summary: dict[str, int] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class BriefQualityResult(StrictBaseModel):
    passed: bool = False
    status: Literal["high", "medium", "low", "invalid"] = "invalid"
    current_summary_quality: Literal["high", "medium", "low", "invalid"] = "invalid"
    latest_blocker_quality: Literal["high", "medium", "low", "invalid"] = "invalid"
    target_reference_quality: Literal["high", "medium", "low", "invalid"] = "invalid"
    blocked_reasons: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class AuthoritativeBlockerSelection(StrictBaseModel):
    status: Literal["no_repair_needed", "repaired", "insufficient"] = "insufficient"
    selected_blocker_type: str = "unknown"
    selected_blocker_summary: str = ""
    selected_evidence_ids: list[str] = Field(default_factory=list)
    selected_evidence_kinds: list[str] = Field(default_factory=list)
    selected_target_ids: list[str] = Field(default_factory=list)
    selected_target_names: list[str] = Field(default_factory=list)
    selected_workstream_type: str = "unknown"
    selected_workstream_status: str = "unknown"
    source: Literal[
        "incident_brief",
        "actor_workstream_ledger",
        "incident_fact_ledger",
        "question_intent_ledger",
        "deterministic_latest_human",
        "none",
    ] = "none"
    rejected_blocker_summary: str = ""
    rejected_blocker_evidence_ids: list[str] = Field(default_factory=list)
    rejected_reason: str = ""
    confidence: Confidence = Field(default=0.0, ge=0.0, le=1.0)
    can_plan: bool = False
    stale_blocker_superseded: bool = False
    superseded_blocker_summary: str = ""
    superseding_event_ids: list[str] = Field(default_factory=list)
    selected_latest_human_event_ids: list[str] = Field(default_factory=list)
    selected_blocker_evidence_quality: Literal["high", "medium", "low", "invalid"] = "invalid"
    stale_question_intents_added: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class IncidentBriefValue(StrictBaseModel):
    primary: IncidentPhase = IncidentPhase.UNKNOWN
    confidence: Confidence = Field(default=0.0, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)


class IncidentBriefBlocker(StrictBaseModel):
    blocker_type: Literal[
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
    ] = "unknown"
    summary: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: Confidence = Field(default=0.0, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _evidence_for_known_blocker(self):
        if self.blocker_type != "unknown" and self.summary and not self.evidence_ids:
            raise ValueError("known IncidentBrief blocker requires evidence_ids")
        return self


class IncidentBriefCompletedAction(StrictBaseModel):
    action_type: str
    summary: str
    actor_target_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _requires_evidence(self):
        if not self.evidence_ids:
            raise ValueError("IncidentBrief completed action requires evidence_ids")
        return self


class IncidentBriefWorkstream(StrictBaseModel):
    workstream_type: Literal[
        "owner_engagement",
        "investigation",
        "mitigation",
        "validation",
        "monitoring",
        "rca_followup",
        "customer_support_validation",
        "change_deployment_check",
        "trust_post_or_comms",
        "other",
    ] = "other"
    status: Literal["proposed", "active", "waiting", "completed", "blocked", "unknown"] = "unknown"
    summary: str = ""
    owner_target_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class IncidentBriefEntity(StrictBaseModel):
    target_id: str
    name: str
    target_type: Literal["person", "team", "service", "bot_system", "non_targetable_noise"] = "person"
    role_hint: Literal[
        "ic_or_coordinator",
        "reporter_or_validator",
        "technical_investigator",
        "owner_team",
        "support_team",
        "observer",
        "bot_system",
        "unknown",
    ] = "unknown"
    status: str = "mentioned"
    evidence_ids: list[str] = Field(default_factory=list)


class IncidentBriefRoleCandidate(StrictBaseModel):
    target_id: str
    name: str
    role_hint: Literal[
        "ic_or_coordinator",
        "reporter_or_validator",
        "technical_investigator",
        "owner_team",
        "support_team",
        "observer",
        "bot_system",
        "unknown",
    ] = "unknown"
    confidence: Confidence = Field(default=0.0, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)


class IncidentBriefDoNotAsk(StrictBaseModel):
    intent: str
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)


class IncidentBriefRejectedOrNoise(StrictBaseModel):
    text: str
    reason: Literal[
        "url_path_number",
        "url_domain",
        "log_fragment",
        "code_fragment",
        "table_fragment",
        "bot_system_placeholder",
        "generated_summary_fragment",
        "unsupported_entity",
        "other",
    ] = "other"
    evidence_ids: list[str] = Field(default_factory=list)


class IncidentBriefFocus(StrictBaseModel):
    summary: str = ""
    preferred_target_ids: list[str] = Field(default_factory=list)
    acceptable_move_types: list[ICMove] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class IncidentBriefUncertainty(StrictBaseModel):
    item: str
    why_it_matters: str
    evidence_ids: list[str] = Field(default_factory=list)


class IncidentBrief(StrictBaseModel):
    schema_version: Literal["1.0"] = "1.0"
    incident_id: str
    based_on_event_ids: list[str] = Field(default_factory=list)
    latest_window_event_ids: list[str] = Field(default_factory=list)
    full_context_used: bool = True
    latest_window_used: bool = False
    partial_context: bool = False
    current_summary: str = ""
    phase: IncidentBriefValue = Field(default_factory=IncidentBriefValue)
    latest_blocker: IncidentBriefBlocker = Field(default_factory=IncidentBriefBlocker)
    completed_actions: list[IncidentBriefCompletedAction] = Field(default_factory=list)
    active_workstreams: list[IncidentBriefWorkstream] = Field(default_factory=list)
    engaged_entities: list[IncidentBriefEntity] = Field(default_factory=list)
    role_candidates: list[IncidentBriefRoleCandidate] = Field(default_factory=list)
    do_not_ask: list[IncidentBriefDoNotAsk] = Field(default_factory=list)
    rejected_or_noise: list[IncidentBriefRejectedOrNoise] = Field(default_factory=list)
    recommended_ic_focus: IncidentBriefFocus = Field(default_factory=IncidentBriefFocus)
    uncertainty: list[IncidentBriefUncertainty] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _role_targets_need_allowed_ids(self):
        engaged_ids = {entity.target_id for entity in self.engaged_entities}
        focus_ids = set(self.recommended_ic_focus.preferred_target_ids)
        for candidate in self.role_candidates:
            if not candidate.target_id:
                raise ValueError("IncidentBrief role candidate requires target_id")
            engaged_ids.add(candidate.target_id)
        for workstream in self.active_workstreams:
            focus_ids.update(workstream.owner_target_ids)
        missing = [target_id for target_id in focus_ids if not target_id]
        if missing:
            raise ValueError("IncidentBrief references empty target_id")
        return self


class SemanticDetectedIntent(StrictBaseModel):
    intent: str
    confidence: Confidence = Field(default=0.0, ge=0.0, le=1.0)
    evidence_or_text: str = ""


class SemanticStaleIntentMatch(StrictBaseModel):
    candidate_intent: str
    matched_stale_intent: str
    confidence: Confidence = Field(default=0.0, ge=0.0, le=1.0)
    reason: str = ""


class SemanticIntentAssessment(StrictBaseModel):
    schema_version: Literal["1.0"] = "1.0"
    incident_id: str
    candidate_output_text: str = ""
    detected_intents: list[SemanticDetectedIntent] = Field(default_factory=list)
    stale_intent_matches: list[SemanticStaleIntentMatch] = Field(default_factory=list)
    unsafe_or_repeated_questions: list[str] = Field(default_factory=list)
    allowed_next_step_intents: list[str] = Field(default_factory=list)
    recommended_repair_direction: str | None = None


class PipelineStepArtifact(StrictBaseModel):
    run_id: str = "manual"
    step: str
    artifact_type: str
    summary_json: dict[str, Any] = Field(default_factory=dict)
    payload_json: dict[str, Any] = Field(default_factory=dict)
    redacted: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    warnings: list[str] = Field(default_factory=list)
    error: str | None = None


class CleanTurn(StrictBaseModel):
    turn_id: str
    speaker: str = "unknown"
    speaker_type: Literal["human", "bot", "system", "unknown"] = "unknown"
    event_ids: list[str] = Field(default_factory=list)
    time_hint: str | None = None
    message_type: Literal[
        "incident_created",
        "phase_update",
        "human_status",
        "question",
        "answer",
        "command",
        "command_output",
        "dashboard_link",
        "ticket_link",
        "diagnostic_log",
        "customer_impact",
        "mitigation",
        "monitoring",
        "noise",
        "other",
    ] = "other"
    summary: str = ""
    key_values: dict[str, str] = Field(default_factory=dict)
    is_noise: bool = False
    uncertainty: list[str] = Field(default_factory=list)


class CleanTurnLedger(StrictBaseModel):
    schema_version: Literal["1.0"] = "1.0"
    incident_id: str
    clean_turns: list[CleanTurn] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ActorLedgerItem(StrictBaseModel):
    name: str
    actor_type: Literal["person", "team", "service", "bot", "system", "unknown"] = "unknown"
    role_hint: Literal[
        "ic_or_coordinator",
        "reporter_or_validator",
        "technical_investigator",
        "owner_team",
        "support_team",
        "bot_system",
        "unknown",
    ] = "unknown"
    current_status: Literal[
        "joined",
        "mentioned",
        "asked",
        "responded",
        "actively_working",
        "paged",
        "unavailable",
        "unknown",
    ] = "unknown"
    last_visible_action: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    targetable: bool = False
    not_targetable_reason: str = ""


class WorkstreamLedgerItem(StrictBaseModel):
    type: Literal[
        "owner_engagement",
        "investigation",
        "mitigation",
        "monitoring",
        "validation",
        "customer_comms",
        "trust_post",
        "deployment_or_change",
        "unknown",
    ] = "unknown"
    status: Literal["not_started", "in_progress", "completed", "blocked", "unknown"] = "unknown"
    owner_or_actor_names: list[str] = Field(default_factory=list)
    summary: str = ""
    evidence_ids: list[str] = Field(default_factory=list)


class ActorWorkstreamLedger(StrictBaseModel):
    schema_version: Literal["1.0"] = "1.0"
    incident_id: str
    actors: list[ActorLedgerItem] = Field(default_factory=list)
    workstreams: list[WorkstreamLedgerItem] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class LedgerFact(StrictBaseModel):
    value: str = ""
    summary: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: Confidence = Field(default=0.0, ge=0.0, le=1.0)


class IncidentFactLedger(StrictBaseModel):
    schema_version: Literal["1.0"] = "1.0"
    incident_id: str
    severity: LedgerFact | None = None
    phase: LedgerFact | None = None
    impact: list[LedgerFact] = Field(default_factory=list)
    services_or_components: list[LedgerFact] = Field(default_factory=list)
    environments: list[LedgerFact] = Field(default_factory=list)
    customers: list[LedgerFact] = Field(default_factory=list)
    tenants: list[LedgerFact] = Field(default_factory=list)
    symptoms: list[LedgerFact] = Field(default_factory=list)
    diagnostic_signals: list[LedgerFact] = Field(default_factory=list)
    completed_actions: list[LedgerFact] = Field(default_factory=list)
    current_blocker: LedgerFact | None = None
    uncertainty: list[LedgerFact] = Field(default_factory=list)
    rejected_noise: list[IncidentBriefRejectedOrNoise] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class QuestionIntentItem(StrictBaseModel):
    intent: str
    summary: str = ""
    evidence_ids: list[str] = Field(default_factory=list)


class QuestionIntentLedger(StrictBaseModel):
    schema_version: Literal["1.0"] = "1.0"
    incident_id: str
    open_questions: list[QuestionIntentItem] = Field(default_factory=list)
    answered_questions: list[QuestionIntentItem] = Field(default_factory=list)
    stale_question_intents: list[str] = Field(default_factory=list)
    wrong_next_moves: list[QuestionIntentItem] = Field(default_factory=list)
    do_not_ask: list[QuestionIntentItem] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class VisibleWorkstream(StrictBaseModel):
    workstream_type: Literal[
        "owner_engagement",
        "investigation",
        "rollback_or_disable",
        "mitigation",
        "cleanup",
        "code_fix",
        "deployment_or_hotfix",
        "monitoring",
        "validation",
        "customer_comms",
        "trust_post",
        "other",
    ] = "other"
    summary: str = ""
    status: Literal[
        "requested_not_confirmed",
        "in_progress",
        "completed",
        "discussed_not_started",
        "blocked",
        "unknown",
    ] = "unknown"
    owner_candidates: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    unsafe_to_execute: bool = False


class GroundedOwnerCandidate(StrictBaseModel):
    name: str
    entity_type: Literal["person", "team", "service"] = "person"
    source: Literal["current_evidence", "catalog"] = "current_evidence"
    status: Literal["mentioned", "asked", "responded", "assigned", "actively_working", "unknown"] = "unknown"
    confidence: Confidence = Field(default=0.6, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)


class RoleCandidate(StrictBaseModel):
    name: str
    role_type: Literal[
        "reporter_validator",
        "technical_investigator",
        "owner_team",
        "support_team",
        "ic_or_coordinator",
        "duty_manager",
        "bot_or_system",
        "unknown",
    ] = "unknown"
    status: Literal[
        "asked",
        "responded",
        "actively_working",
        "validating",
        "paged",
        "mentioned",
        "unknown",
    ] = "unknown"
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: Confidence = Field(default=0.6, ge=0.0, le=1.0)


class WrongNextMove(StrictBaseModel):
    move_or_intent: str
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)


class SharpBlockerAssessment(StrictBaseModel):
    schema_version: Literal["1.0"] = "1.0"
    incident_id: str
    based_on_event_ids: list[str] = Field(default_factory=list)
    phase: IncidentPhase = IncidentPhase.UNKNOWN
    blocker_type: Literal[
        "missing_owner",
        "missing_impact",
        "missing_validation",
        "missing_mitigation",
        "mitigation_status_or_validation",
        "rollback_or_disable_status",
        "waiting_on_code_fix",
        "waiting_on_deploy",
        "waiting_on_owner_status",
        "waiting_on_monitoring",
        "customer_comms_status",
        "trust_post_status",
        "handoff_or_dri_assignment",
        "unclear",
        "none",
    ] = "unclear"
    blocker_summary: str = ""
    confidence: Confidence = Field(default=0.0, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    visible_workstreams: list[VisibleWorkstream] = Field(default_factory=list)
    active_owner_candidates: list[GroundedOwnerCandidate] = Field(default_factory=list)
    role_candidates: list[RoleCandidate] = Field(default_factory=list)
    latest_workstream_owner_candidates: list[str] = Field(default_factory=list)
    validation_request_targets: list[str] = Field(default_factory=list)
    technical_status_targets: list[str] = Field(default_factory=list)
    customer_or_reporter_validation_targets: list[str] = Field(default_factory=list)
    should_not_target_for_fix_status: list[str] = Field(default_factory=list)
    should_not_ask_yet: list[str] = Field(default_factory=list)
    already_done: list[EvidenceBackedFact] = Field(default_factory=list)
    not_confirmed_yet: list[EvidenceBackedFact] = Field(default_factory=list)
    wrong_next_moves: list[WrongNextMove] = Field(default_factory=list)
    recommended_move_families: list[ICMove] = Field(default_factory=list)
    recommended_ask_slots: list[str] = Field(default_factory=list)
    no_invention_constraints: list[str] = Field(default_factory=list)


class IncidentEvent(StrictBaseModel):
    event_id: str
    incident_id: str
    ts: str | None = None
    sequence: int
    source: str = "slack_paste"
    author: str | None = None
    message: str
    extracted_tokens: dict[str, Any] = Field(default_factory=dict)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
    hash: str


class CurrentIncidentState(StrictBaseModel):
    incident_id: str
    state_version: int = 0
    updated_at: datetime = Field(default_factory=utc_now)
    source_progress: dict[str, Any] = Field(default_factory=dict)
    severity: EvidenceBackedFact | None = None
    phase: IncidentPhase = IncidentPhase.UNKNOWN
    impact: ImpactState = Field(default_factory=ImpactState)
    candidate_services: list[EntityRef] = Field(default_factory=list)
    engaged_entities: list[EntityRef] = Field(default_factory=list)
    suggested_but_not_engaged: list[EntityRef] = Field(default_factory=list)
    actions_completed: list[ActionRecord] = Field(default_factory=list)
    open_questions: list[QuestionRecord] = Field(default_factory=list)
    answered_questions: list[QuestionRecord] = Field(default_factory=list)
    stale_question_intents: list[str] = Field(default_factory=list)
    current_blocker: str | None = None
    monitoring_signals: list[EvidenceBackedFact] = Field(default_factory=list)
    commands_seen: list[CommandCandidate] = Field(default_factory=list)
    links_seen: list[LinkRef] = Field(default_factory=list)
    rejected_entities: list[EntityRef] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    safety_flags: list[str] = Field(default_factory=list)
    compact_summary: str = ""


class DecisionMoment(StrictBaseModel):
    decision_id: str
    source_incident_id: str
    review_status: Literal[
        "draft",
        "approved",
        "human_reviewed",
        "externally_reviewed",
        "approved_for_product",
        "deprecated",
        "rejected",
    ]
    quality_score: Confidence = Field(ge=0.0, le=1.0)
    phase_before: IncidentPhase
    phase_after: IncidentPhase
    move: ICMove
    situation_before: str
    trigger: str
    ic_action: str
    why_it_worked: str
    applicability: dict[str, Any] = Field(default_factory=dict)
    forbidden_fact_leakage: list[str] = Field(default_factory=list)
    outcome: str = ""
    labels: list[str] = Field(default_factory=list)
    embedding_text: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    reviewed_at: datetime | None = None
    reviewed_by: str | None = None


class ServiceCatalogEntry(StrictBaseModel):
    service_id: str
    canonical_name: str
    aliases: list[str] = Field(default_factory=list)
    kind: EntityType = EntityType.SERVICE
    status: str = "active"
    criticality: str = "unknown"
    ownership: dict[str, Any] = Field(default_factory=dict)
    slack: dict[str, Any] = Field(default_factory=dict)
    oncall: dict[str, Any] = Field(default_factory=dict)
    runbooks: list[Any] = Field(default_factory=list)
    dashboards: list[Any] = Field(default_factory=list)
    known_commands: list[dict[str, Any]] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    environments: list[str] = Field(default_factory=list)
    known_signals: list[str] = Field(default_factory=list)
    unsafe_assumptions: list[str] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=utc_now)


class ICDecision(StrictBaseModel):
    decision_id: str
    incident_id: str
    generated_at: datetime = Field(default_factory=utc_now)
    move: ICMove
    phase: IncidentPhase
    domain_intent: str | None = None
    model_metadata: dict[str, Any] = Field(default_factory=dict)
    output: dict[str, Any] = Field(default_factory=dict)
    target_ids: list[str] = Field(default_factory=list)
    targets: list[EntityRef] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
    grounding: list[EvidenceRef] = Field(default_factory=list)
    confidence: Confidence = Field(default=0.6, ge=0.0, le=1.0)
    expiration: str = "PT15M"
    verifier_result: "VerifierResult | None" = None


class WhisperCommandSuggestion(StrictBaseModel):
    command_text: str
    registry_command_id: str | None = None
    requires_human_approval: bool = True


class WhisperEvidenceRef(StrictBaseModel):
    event_id: str
    quote: str
    confidence: Confidence = Field(default=0.7, ge=0.0, le=1.0)


class IncidentReadAndWhisper(StrictBaseModel):
    schema_version: Literal["1.0"] = "1.0"
    incident_id: str
    current_read: str
    latest_open_loop: str
    already_answered: list[str] = Field(default_factory=list)
    selected_move: ICMove
    selected_target_id: str | None = None
    selected_target_display_name: str | None = None
    say_this: str
    next_line: str | None = None
    command: WhisperCommandSuggestion | None = None
    evidence: list[WhisperEvidenceRef] = Field(default_factory=list)
    uncertainty: str | None = None
    confidence: Confidence = Field(default=0.6, ge=0.0, le=1.0)


QuestionTypeV2 = Literal[
    "impact_scope",
    "owner_routing",
    "trust_post",
    "escalation_type",
    "status_or_eta",
    "validation_signal",
    "customer_confirmation",
    "unknown",
]

BlockerTypeV2 = Literal[
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
]

TargetTypeV2 = Literal["person", "team", "service", "none"]

WhisperMoveV2 = Literal[
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
]


class OpenQuestionV2(StrictBaseModel):
    event_id: str
    asked_by: str | None = None
    asked_to: list[str] = Field(default_factory=list)
    question_text: str
    question_type: QuestionTypeV2 = "unknown"
    answered: bool = False
    answered_by: str | None = None
    answer_event_id: str | None = None
    answer_summary: str | None = None


class AnsweredQuestionV2(StrictBaseModel):
    question_text: str
    answer_summary: str
    question_type: QuestionTypeV2 = "unknown"
    asked_by: str | None = None
    answered_by: str | None = None
    evidence_event_ids: list[str] = Field(default_factory=list)


class IncidentStateV2(StrictBaseModel):
    incident_id: str
    incident_title: str | None = None
    severity: str | None = None
    channel_name: str | None = None
    current_phase: str | None = None
    incident_commander: str | None = None
    duty_manager: str | None = None
    reporters: list[str] = Field(default_factory=list)
    support_contacts: list[str] = Field(default_factory=list)
    active_humans: list[str] = Field(default_factory=list)
    active_teams: list[str] = Field(default_factory=list)
    known_impact: list[str] = Field(default_factory=list)
    affected_customers_or_tenants: list[str] = Field(default_factory=list)
    known_services_or_components: list[str] = Field(default_factory=list)
    diagnostic_signals: list[str] = Field(default_factory=list)
    open_questions: list[OpenQuestionV2] = Field(default_factory=list)
    answered_questions: list[AnsweredQuestionV2] = Field(default_factory=list)
    latest_human_updates: list[str] = Field(default_factory=list)
    do_not_ask: list[str] = Field(default_factory=list)
    uncertainty_notes: list[str] = Field(default_factory=list)


class RejectedTargetV2(StrictBaseModel):
    display_name: str
    reason: str
    evidence_event_ids: list[str] = Field(default_factory=list)


class NextBlockerV2(StrictBaseModel):
    blocker_type: BlockerTypeV2
    blocker_summary: str
    best_target_display_name: str | None = None
    best_target_type: TargetTypeV2 = "none"
    best_target_reason: str = ""
    evidence_event_ids: list[str] = Field(default_factory=list)
    rejected_targets: list[RejectedTargetV2] = Field(default_factory=list)
    confidence: Confidence = Field(default=0.6, ge=0.0, le=1.0)


class WhisperV2(StrictBaseModel):
    selected_move: WhisperMoveV2
    selected_target_display_name: str | None = None
    selected_target_id: str | None = None
    say_this: str
    next_line: str | None = None
    command: None = None
    evidence: list[WhisperEvidenceRef] = Field(default_factory=list)


class IncidentReadAndWhisperV2(StrictBaseModel):
    schema_version: Literal["2.0"] = "2.0"
    incident_id: str
    incident_state: IncidentStateV2
    next_blocker: NextBlockerV2
    whisper: WhisperV2
    evidence: list[WhisperEvidenceRef] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)
    uncertainty: list[str] = Field(default_factory=list)
    confidence: Confidence = Field(default=0.6, ge=0.0, le=1.0)


class VerifierResult(StrictBaseModel):
    passed: bool = False
    final_status: Literal["pass", "rewrite_required", "blocked", "fallback_required"] = "blocked"
    checks: dict[str, bool] = Field(default_factory=dict)
    blocked_claims: list[str] = Field(default_factory=list)
    allowed_claims: list[str] = Field(default_factory=list)
    rewrite_instructions: list[str] = Field(default_factory=list)
    fallback_decision: ICDecision | None = None


class StateDelta(StrictBaseModel):
    incident_id: str
    source_progress: dict[str, Any] = Field(default_factory=dict)
    severity: EvidenceBackedFact | None = None
    phase: IncidentPhase | None = None
    impact: ImpactState | None = None
    candidate_services: list[EntityRef] = Field(default_factory=list)
    engaged_entities: list[EntityRef] = Field(default_factory=list)
    suggested_but_not_engaged: list[EntityRef] = Field(default_factory=list)
    actions_completed: list[ActionRecord] = Field(default_factory=list)
    open_questions: list[QuestionRecord] = Field(default_factory=list)
    answered_questions: list[QuestionRecord] = Field(default_factory=list)
    stale_question_intents: list[str] = Field(default_factory=list)
    current_blocker: str | None = None
    monitoring_signals: list[EvidenceBackedFact] = Field(default_factory=list)
    commands_seen: list[CommandCandidate] = Field(default_factory=list)
    links_seen: list[LinkRef] = Field(default_factory=list)
    rejected_entities: list[EntityRef] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    safety_flags: list[str] = Field(default_factory=list)
    compact_summary: str = ""


class TriggerDecision(StrictBaseModel):
    level: Literal["ingest_only", "extract_state", "full_planning"] = "ingest_only"
    reasons: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    should_extract: bool = False
    should_plan: bool = False


class MemoryQuery(StrictBaseModel):
    incident_id: str
    phase: IncidentPhase = IncidentPhase.UNKNOWN
    current_blocker: str | None = None
    service_ids: list[str] = Field(default_factory=list)
    entity_names: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    evidence_terms: list[str] = Field(default_factory=list)


class MemoryApplicabilityResult(StrictBaseModel):
    decision_id: str
    accepted: bool
    score: Confidence = Field(default=0.0, ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    restrictions: list[str] = Field(default_factory=list)
    allowed_patterns: list[str] = Field(default_factory=list)
    forbidden_fact_leakage: list[str] = Field(default_factory=list)
    required_current_evidence_satisfied: list[str] = Field(default_factory=list)
    required_current_evidence_missing: list[str] = Field(default_factory=list)
    hard_requirements_satisfied: list[str] = Field(default_factory=list)
    hard_requirements_missing: list[str] = Field(default_factory=list)
    soft_signals_satisfied: list[str] = Field(default_factory=list)
    soft_signals_missing: list[str] = Field(default_factory=list)
    phase_signals_satisfied: list[str] = Field(default_factory=list)
    phase_signals_missing: list[str] = Field(default_factory=list)
    anti_leakage_guards: list[str] = Field(default_factory=list)
    rejected_because_already_engaged: bool = False
    rejected_because_wrong_phase: bool = False
    rejected_because_wrong_blocker: bool = False
    rejected_because_historical_leakage_risk: bool = False


class ReplayEvalExpected(StrictBaseModel):
    phase: IncidentPhase | None = None
    blocker_type: str | None = None
    acceptable_moves: list[ICMove] = Field(default_factory=list)
    acceptable_targets: list[str] = Field(default_factory=list)
    acceptable_commands: list[str] = Field(default_factory=list)
    minimum_required_claims: list[str] = Field(default_factory=list)
    forbidden_question_intents: list[str] = Field(default_factory=list)
    forbidden_entities: list[str] = Field(default_factory=list)
    forbidden_historical_facts: list[str] = Field(default_factory=list)
    expected_verifier_status: str | None = None
    allow_fallback: bool = False
    require_verifier_pass: bool = True
    expected_blocked_claim_substrings: list[str] = Field(default_factory=list)
    expected_absent_substrings: list[str] = Field(default_factory=list)
    expected_present_substrings: list[str] = Field(default_factory=list)


class ReplayEvalCase(StrictBaseModel):
    case_id: str
    incident_id: str
    title: str
    visible_events: list[str] = Field(default_factory=list)
    incident_file: str | None = None
    hidden_future_event_ids: list[str] = Field(default_factory=list)
    service_catalog_snapshot_ids: list[str] = Field(default_factory=list)
    memory_snapshot_ids: list[str] = Field(default_factory=list)
    expected_state_file: str | None = None
    expected_decision_file: str | None = None
    expected: ReplayEvalExpected


class ReplayEvalResult(StrictBaseModel):
    case_id: str
    passed: bool = False
    state_scores: dict[str, Any] = Field(default_factory=dict)
    decision_scores: dict[str, Any] = Field(default_factory=dict)
    safety_scores: dict[str, Any] = Field(default_factory=dict)
    latency_ms: int = 0
    final_output: str = ""
    verifier_result: VerifierResult | None = None
    used_fallback: bool = False
    verifier_status: str | None = None
    failure_reasons: list[str] = Field(default_factory=list)
    case_type: Literal["positive", "negative", "unknown"] = "unknown"


class CommandRegistryEntry(StrictBaseModel):
    command: str
    target: str
    source_service_id: str
    requires_human_approval: bool = True
    allowed_prefixes: list[str] = Field(default_factory=list)
    command_id: str | None = None
    command_type: str = "exact"
    pattern: str | None = None
    requires_catalog_target: bool = False
    danger_level: str = "read_only_lookup"
    exact: bool = True

    @field_validator("command")
    @classmethod
    def normalize_command(cls, value: str) -> str:
        return " ".join(value.split())


class TraceRecord(StrictBaseModel):
    trace_id: str
    incident_id: str
    created_at: datetime = Field(default_factory=utc_now)
    pipeline_version: str = "phase-1.6"
    input_event_ids: list[str] = Field(default_factory=list)
    trigger: TriggerDecision
    current_state: CurrentIncidentState
    memory_query: MemoryQuery | None = None
    retrieved_memory_ids: list[str] = Field(default_factory=list)
    hydrated_memory_ids: list[str] = Field(default_factory=list)
    applicability_results: list[MemoryApplicabilityResult] = Field(default_factory=list)
    accepted_memory_ids: list[str] = Field(default_factory=list)
    catalog_match_ids: list[str] = Field(default_factory=list)
    command_registry_size: int = 0
    input_size_assessment: InputSizeAssessment | None = None
    latest_window_selection: LatestWindowSelection | None = None
    processing_strategy: str | None = None
    chunk_count: int = 0
    chunk_ids: list[str] = Field(default_factory=list)
    chunk_success_count: int = 0
    chunk_failure_count: int = 0
    provider_timeout_stage: str | None = None
    retry_attempted: bool = False
    retry_strategy: str | None = None
    incident_brief_attempt_count: int = 0
    incident_brief_attempts: list[dict[str, Any]] = Field(default_factory=list)
    compact_payload_event_count: int = 0
    compact_payload_char_count: int = 0
    ultra_compact_payload_event_count: int = 0
    ultra_compact_payload_char_count: int = 0
    terminal_failure_reason: str | None = None
    slack_turn_reconstruction: SlackTurnReconstruction | None = None
    reconstructed_turn_count: int = 0
    reconstructed_turns_used: bool = False
    turn_reconstruction_warnings: list[str] = Field(default_factory=list)
    step_artifacts: list[dict[str, Any]] = Field(default_factory=list)
    event_quality: list[EventQuality] = Field(default_factory=list)
    context_pack_summary: dict[str, Any] = Field(default_factory=dict)
    incident_read_and_whisper: IncidentReadAndWhisper | None = None
    semantic_quality: SemanticQuality | None = None
    incident_brief_quality: BriefQualityResult | None = None
    original_incident_brief_quality: BriefQualityResult | None = None
    blocker_reselection: AuthoritativeBlockerSelection | None = None
    clean_turn_ledger: CleanTurnLedger | None = None
    actor_workstream_ledger: ActorWorkstreamLedger | None = None
    incident_fact_ledger: IncidentFactLedger | None = None
    question_intent_ledger: QuestionIntentLedger | None = None
    allowed_targets: list[AllowedTarget] = Field(default_factory=list)
    target_shortlist: list[TargetShortlistItem] = Field(default_factory=list)
    incident_brief: IncidentBrief | None = None
    selected_target_ids: list[str] = Field(default_factory=list)
    rejected_non_targetable_candidates: list[AllowedTarget] = Field(default_factory=list)
    latest_window_event_ids: list[str] = Field(default_factory=list)
    clean_context: CleanIncidentContext | None = None
    sharp_blocker_assessment: SharpBlockerAssessment | None = None
    semantic_intent_assessment: SemanticIntentAssessment | None = None
    repair_result: dict[str, Any] = Field(default_factory=dict)
    raw_decision: ICDecision
    verifier_result: VerifierResult
    rendered_decision: ICDecision
    final_output: str = ""
    run_diagnosis: dict[str, Any] = Field(default_factory=dict)
    safety_summary: dict[str, Any] = Field(default_factory=dict)
    latency_ms: int | None = None
    errors: list[str] = Field(default_factory=list)


class ShadowLLMCall(StrictBaseModel):
    call_id: str
    prompt_name: str
    provider: str
    model: str | None = None
    prompt_version: str | None = None
    prompt_hash: str | None = None
    prompt_variant_id: str | None = None
    prompt_variant_hash: str | None = None
    response_model: str
    started_at: datetime = Field(default_factory=utc_now)
    latency_ms: int | None = None
    success: bool = False
    error: str | None = None
    output_validated: bool = False
    output_summary: dict[str, Any] = Field(default_factory=dict)
    redacted_payload_used: bool = True
    provider_response_id: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    model_used: str | None = None
    raw_usage: dict[str, Any] = Field(default_factory=dict)


class ShadowComparison(StrictBaseModel):
    baseline_decision_id: str | None = None
    shadow_decision_id: str | None = None
    baseline_move: str | None = None
    shadow_move: str | None = None
    move_match: bool | None = None
    baseline_targets: list[str] = Field(default_factory=list)
    shadow_targets: list[str] = Field(default_factory=list)
    target_overlap: bool | None = None
    baseline_command: str | None = None
    shadow_command: str | None = None
    command_match: bool | None = None
    baseline_verifier_passed: bool | None = None
    shadow_verifier_passed: bool | None = None
    shadow_fallback_used: bool = False
    shadow_safe: bool = False
    notes: list[str] = Field(default_factory=list)


class ShadowRunResult(StrictBaseModel):
    shadow_id: str
    incident_id: str
    provider: str
    model: str | None = None
    prompt_version: str | None = None
    prompt_hashes: dict[str, str] = Field(default_factory=dict)
    prompt_variant_id: str | None = None
    prompt_variant_hash: str | None = None
    run_id: str | None = None
    enabled: bool = False
    baseline_trace: TraceRecord
    shadow_state: CurrentIncidentState | None = None
    shadow_decision: ICDecision | None = None
    shadow_verifier_result: VerifierResult | None = None
    shadow_final_output: str | None = None
    calls: list[ShadowLLMCall] = Field(default_factory=list)
    comparison: ShadowComparison
    errors: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
