from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from ic_copilot.schemas import CurrentIncidentState, IncidentEvent, TriggerDecision


class EventSignal(BaseModel):
    event_id: str
    low_value_ack: bool = False
    new_question: bool = False
    possible_answer: bool = False
    service_team_person_mention: bool = False
    impact_signal: bool = False
    severity_signal: bool = False
    deployment_signal: bool = False
    mitigation_signal: bool = False
    monitoring_signal: bool = False
    command_candidate: bool = False
    important_link: bool = False
    owner_acknowledgement: bool = False
    eta_status_update: bool = False
    reasons: list[str] = Field(default_factory=list)


LOW_VALUE_ACKS = {"ok", "okay", "ack", "thanks", "thank you", "+1", "sgtm", "done"}
SERVICE_WORDS = (
    "support",
    "team",
    "owner",
    "oncall",
    "revpro",
    "uno",
    "dune",
    "psg",
    "stripe",
    "ocm",
    "commerce-catalog",
    "revenue",
)
IMPACT_WORDS = ("customer", "customers", "tenant", "tenants", "affected", "blocked", "loss", "impact")
DEPLOY_WORDS = ("deploy", "deployment", "release", "version", "hotfix", "rollback", "rolled back")
MITIGATION_WORDS = ("mitigation", "mitigated", "workaround", "rollback", "hotfix", "fix forward", "code fix")
MONITOR_WORDS = ("monitor", "monitoring", "dashboard", "signal", "success criteria", "watching")
ETA_WORDS = ("eta", "status", "update", "blocked on", "blocker", "working on", "coordinating")
OWNER_ACK_WORDS = ("i can take", "i'm on it", "im on it", "working on", "owning", "taking this")


def _has_any(text: str, words: tuple[str, ...]) -> bool:
    return any(word in text for word in words)


def compute_event_signal(event: IncidentEvent, current_state: CurrentIncidentState) -> EventSignal:
    del current_state
    text = event.message.strip()
    lower = text.lower()
    tokens: dict[str, Any] = event.extracted_tokens
    signal = EventSignal(event_id=event.event_id)

    signal.low_value_ack = lower in LOW_VALUE_ACKS or bool(re.fullmatch(r"[\u2705👍🙏. ]+", lower))
    if signal.low_value_ack:
        signal.reasons.append("low_value_ack")

    if "?" in text:
        signal.new_question = True
        signal.reasons.append("new_question")
    if any(word in lower for word in ("yes", "no", "confirmed", "confirming", "looks like", "it is", "it's")):
        signal.possible_answer = True
        signal.reasons.append("possible_answer")
    if _has_any(lower, SERVICE_WORDS) or tokens.get("slack_mentions"):
        signal.service_team_person_mention = True
        signal.reasons.append("service_team_person_mention")
    if _has_any(lower, IMPACT_WORDS) or re.search(r"\b\d+\s+customers?\b", lower):
        signal.impact_signal = True
        signal.reasons.append("impact_signal")
    if re.search(r"\b(?:p[1-4]|l3)\b", lower):
        signal.severity_signal = True
        signal.reasons.append("severity_signal")
    if _has_any(lower, DEPLOY_WORDS):
        signal.deployment_signal = True
        signal.reasons.append("deployment_signal")
    if _has_any(lower, MITIGATION_WORDS):
        signal.mitigation_signal = True
        signal.reasons.append("mitigation_signal")
    if _has_any(lower, MONITOR_WORDS):
        signal.monitoring_signal = True
        signal.reasons.append("monitoring_signal")
    if tokens.get("command_candidates"):
        signal.command_candidate = True
        signal.reasons.append("command_candidate")
    if tokens.get("urls"):
        signal.important_link = True
        signal.reasons.append("important_link")
    if _has_any(lower, OWNER_ACK_WORDS):
        signal.owner_acknowledgement = True
        signal.reasons.append("owner_acknowledgement")
    if _has_any(lower, ETA_WORDS):
        signal.eta_status_update = True
        signal.reasons.append("eta_status_update")

    return signal


def decide_trigger(
    events: list[IncidentEvent],
    current_state: CurrentIncidentState,
    previous_decision: object | None = None,
    manual_refresh: bool = False,
) -> TriggerDecision:
    signals = [compute_event_signal(event, current_state) for event in events]
    reasons: list[str] = []
    event_ids: list[str] = []
    should_extract = False
    should_plan = False

    for signal in signals:
        if signal.low_value_ack and len(signal.reasons) == 1:
            continue
        extract_reasons = {
            "new_question",
            "possible_answer",
            "service_team_person_mention",
            "impact_signal",
            "severity_signal",
            "deployment_signal",
            "mitigation_signal",
            "monitoring_signal",
            "command_candidate",
            "important_link",
            "owner_acknowledgement",
            "eta_status_update",
        }
        if extract_reasons.intersection(signal.reasons):
            should_extract = True
            event_ids.append(signal.event_id)
            reasons.extend(reason for reason in signal.reasons if reason not in reasons)

        plan_reasons = {
            "service_team_person_mention",
            "impact_signal",
            "deployment_signal",
            "mitigation_signal",
            "monitoring_signal",
            "owner_acknowledgement",
            "eta_status_update",
        }
        if plan_reasons.intersection(signal.reasons):
            should_plan = True

    if manual_refresh:
        should_extract = True
        should_plan = True
        reasons.append("manual_refresh")

    if previous_decision is not None and getattr(previous_decision, "expired", False):
        should_plan = True
        reasons.append("last_decision_expired")

    if should_plan:
        level = "full_planning"
    elif should_extract:
        level = "extract_state"
    else:
        level = "ingest_only"

    return TriggerDecision(
        level=level,
        reasons=reasons,
        event_ids=event_ids,
        should_extract=should_extract,
        should_plan=should_plan,
    )

