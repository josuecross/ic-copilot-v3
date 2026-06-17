from __future__ import annotations

import re
from dataclasses import dataclass

from ic_copilot.evidence_quality import event_quality_by_id, validate_incident_brief_quality
from ic_copilot.schemas import (
    ActorWorkstreamLedger,
    AllowedTarget,
    AuthoritativeBlockerSelection,
    BriefQualityResult,
    CleanTurnLedger,
    EventQuality,
    ICMove,
    IncidentBrief,
    IncidentBriefBlocker,
    IncidentBriefDoNotAsk,
    IncidentBriefFocus,
    IncidentBriefRejectedOrNoise,
    IncidentBriefWorkstream,
    IncidentEvent,
    IncidentFactLedger,
    QuestionIntentLedger,
    SemanticQuality,
)
from ic_copilot.semantic_read import ParallelSemanticReadResult


NOISY_BLOCKER_TEXT = (
    "please join to slack channel",
    "incident in pagerduty",
    "preview in slack",
    "status triggered",
    "urgency high",
    "created",
    "refresh",
    "latest blocker is unclear",
    "semantic ledgers",
)
TRUST_POST_NO_NEED = ("trust post no need", "trust post not needed", "trust post: no need", "no need")
WAITING_CONFIRMATION_TERMS = (
    "awaiting customer confirmation",
    "await customer confirmation",
    "waiting on customer confirmation",
    "waiting for customer confirmation",
    "awaiting confirmation",
)
CONFIRMATION_SUPERSEDED_TERMS = (
    "got reply",
    "confirmed",
    "customer said",
    "they are doing",
    "they have been",
    "we found",
    "asking if",
    "can stop",
    "can pause",
    "stop the process",
    "pause",
    "paused",
    "stopped",
)
SUMMARY_MATCH_STOPWORDS = {
    "about",
    "after",
    "before",
    "blocker",
    "confirm",
    "confirmed",
    "current",
    "incident",
    "latest",
    "please",
    "status",
    "summary",
    "track",
    "visible",
}


@dataclass(frozen=True)
class _Candidate:
    source: str
    blocker_type: str
    summary: str
    evidence_ids: list[str]
    target_ids: list[str]
    workstream_type: str
    workstream_status: str
    confidence: float


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _blocker_type(summary: str, workstream_type: str = "") -> str:
    text = _norm(f"{summary} {workstream_type}")
    if any(term in text for term in ("acknowledg", "customer confirmation", "customer validation")):
        return "validation_needed"
    if any(term in text for term in ("code fix", "hotfix", "fix status")):
        return "code_fix_status_needed"
    if any(term in text for term in ("deploy", "deployment", "release")):
        return "deployment_validation_needed"
    if any(term in text for term in ("monitor", "metric", "dashboard", "signal", "stable", "health", "lag")):
        return "monitoring_needed"
    if any(term in text for term in ("mitigation", "rollback", "disable", "restart", "workaround", "queue")):
        return "mitigation_status_needed"
    if any(term in text for term in ("status", "eta", "waiting", "active work", "checking", "investigat")):
        return "status_eta_needed"
    if any(term in text for term in ("validate", "validation", "confirm", "result")):
        return "validation_needed"
    if any(term in text for term in ("owner", "dri", "engage")):
        return "missing_owner"
    return "unknown"


def _move_types(blocker_type: str) -> list[ICMove]:
    return {
        "missing_owner": [ICMove.CONFIRM_OWNERSHIP, ICMove.ENGAGE_OWNER],
        "validation_needed": [ICMove.ASK_NEXT_VALIDATION],
        "monitoring_needed": [ICMove.REQUEST_MONITORING_SIGNAL, ICMove.REQUEST_STATUS_OR_ETA],
        "mitigation_status_needed": [ICMove.REQUEST_STATUS_OR_ETA, ICMove.REQUEST_MITIGATION_OPTION],
        "status_eta_needed": [ICMove.REQUEST_STATUS_OR_ETA, ICMove.ASK_NEXT_VALIDATION],
        "code_fix_status_needed": [ICMove.REQUEST_STATUS_OR_ETA],
        "deployment_validation_needed": [ICMove.CONFIRM_DEPLOYMENT_RELATED, ICMove.ASK_NEXT_VALIDATION],
    }.get(blocker_type, [ICMove.ASK_NEXT_VALIDATION])


def _incident_workstream_type(raw_type: str) -> str:
    return {
        "customer_comms": "trust_post_or_comms",
        "trust_post": "trust_post_or_comms",
        "deployment_or_change": "change_deployment_check",
        "human_status": "investigation",
        "question": "investigation",
        "answer": "investigation",
        "diagnostic_log": "investigation",
        "customer_impact": "customer_support_validation",
        "fact_current_blocker": "investigation",
        "open_question": "investigation",
    }.get(raw_type, raw_type)


def _quality_for_ids(event_ids: list[str], quality_by_id: dict[str, EventQuality]) -> list[EventQuality]:
    return [quality_by_id[event_id] for event_id in event_ids if event_id in quality_by_id]


def _human_blocker_ids(event_ids: list[str], quality_by_id: dict[str, EventQuality]) -> list[str]:
    return [
        event_id
        for event_id in dict.fromkeys(event_ids)
        if (quality := quality_by_id.get(event_id)) and quality.is_blocker_evidence_allowed
    ]


def _event_kinds(event_ids: list[str], quality_by_id: dict[str, EventQuality]) -> list[str]:
    return [quality.event_kind for quality in _quality_for_ids(event_ids, quality_by_id)]


def _valid_targets(allowed_targets: list[AllowedTarget]) -> dict[str, AllowedTarget]:
    return {
        target.target_id: target
        for target in allowed_targets
        if target.targetable and target.target_quality in {"high", "medium"}
    }


def _target_ids_for_names(names: list[str], allowed_targets: list[AllowedTarget]) -> list[str]:
    by_name = {_norm(target.display_name): target for target in allowed_targets if target.targetable}
    ids: list[str] = []
    for name in names:
        target = by_name.get(_norm(name))
        if target and target.target_quality in {"high", "medium"}:
            ids.append(target.target_id)
    return list(dict.fromkeys(ids))


def _target_ids_from_evidence(event_ids: list[str], allowed_targets: list[AllowedTarget]) -> list[str]:
    ids = [
        target.target_id
        for target in allowed_targets
        if target.targetable
        and target.target_quality in {"high", "medium"}
        and set(target.evidence_ids).intersection(event_ids)
    ]
    return list(dict.fromkeys(ids))


def _is_noisy_text(text: str) -> bool:
    normalized = _norm(text)
    return any(term in normalized for term in NOISY_BLOCKER_TEXT)


def _trust_post_no_need(events: list[IncidentEvent], questions: QuestionIntentLedger | None) -> list[str]:
    ids: list[str] = []
    for event in events:
        text = _norm(f"{event.author}\n{event.message}")
        if "trust post" in text and any(term in text for term in TRUST_POST_NO_NEED):
            ids.append(event.event_id)
    if questions:
        for item in [*questions.answered_questions, *questions.do_not_ask]:
            text = _norm(f"{item.intent} {item.summary}")
            if "trust" in text and any(term in text for term in TRUST_POST_NO_NEED):
                ids.extend(item.evidence_ids)
    return list(dict.fromkeys(ids))


def _candidate_from_clean_turns(
    ledger: CleanTurnLedger | None,
    quality_by_id: dict[str, EventQuality],
    allowed_targets: list[AllowedTarget],
    *,
    message_types: set[str] | None = None,
) -> _Candidate | None:
    if ledger is None:
        return None
    message_types = message_types or {
        "question",
        "human_status",
        "mitigation",
        "monitoring",
        "diagnostic_log",
        "customer_impact",
    }
    for turn in reversed(ledger.clean_turns[-14:]):
        if turn.is_noise or turn.speaker_type != "human" or turn.message_type not in message_types:
            continue
        evidence_ids = _human_blocker_ids(turn.event_ids, quality_by_id)
        if not evidence_ids:
            continue
        summary = turn.summary.strip()
        if not summary or _is_noisy_text(summary):
            continue
        target_ids = _target_ids_for_names([turn.speaker], allowed_targets) or _target_ids_from_evidence(evidence_ids, allowed_targets)
        return _Candidate(
            source="deterministic_latest_human",
            blocker_type=_blocker_type(summary, turn.message_type),
            summary=summary[:260],
            evidence_ids=evidence_ids,
            target_ids=target_ids[:3],
            workstream_type=turn.message_type,
            workstream_status="active",
            confidence=0.78,
        )
    return None


def _brief_waits_on_confirmation(brief: IncidentBrief) -> bool:
    text = _norm(f"{brief.latest_blocker.summary} {brief.recommended_ic_focus.summary}")
    return any(term in text for term in WAITING_CONFIRMATION_TERMS)


def _is_later_evidence(
    candidate_ids: list[str],
    blocker_ids: list[str],
    events: list[IncidentEvent],
) -> bool:
    if not candidate_ids:
        return False
    order = {event.event_id: index for index, event in enumerate(events)}
    latest_candidate = max((order.get(event_id, -1) for event_id in candidate_ids), default=-1)
    latest_blocker = max((order.get(event_id, -1) for event_id in blocker_ids), default=-1)
    return latest_candidate > latest_blocker


def _candidate_from_superseding_confirmation(
    brief: IncidentBrief,
    ledger: CleanTurnLedger | None,
    quality_by_id: dict[str, EventQuality],
    allowed_targets: list[AllowedTarget],
    events: list[IncidentEvent],
) -> _Candidate | None:
    if not _brief_waits_on_confirmation(brief):
        return None
    if ledger is not None:
        for turn in reversed(ledger.clean_turns[-16:]):
            if turn.is_noise or turn.speaker_type != "human":
                continue
            if turn.message_type not in {"answer", "human_status", "question", "mitigation", "monitoring", "customer_impact"}:
                continue
            summary = turn.summary.strip()
            summary_norm = _norm(summary)
            if not summary or _is_noisy_text(summary):
                continue
            if not any(term in summary_norm for term in CONFIRMATION_SUPERSEDED_TERMS):
                continue
            evidence_ids = _human_blocker_ids(turn.event_ids, quality_by_id)
            if not evidence_ids or not _is_later_evidence(evidence_ids, brief.latest_blocker.evidence_ids, events):
                continue
            target_ids = _target_ids_for_names([turn.speaker], allowed_targets) or _target_ids_from_evidence(evidence_ids, allowed_targets)
            blocker_type = "mitigation_status_needed" if any(term in summary_norm for term in ("stop", "pause")) else _blocker_type(summary, turn.message_type)
            return _Candidate(
                source="deterministic_latest_human",
                blocker_type=blocker_type,
                summary=summary[:260],
                evidence_ids=evidence_ids,
                target_ids=target_ids[:3],
                workstream_type=turn.message_type,
                workstream_status="active",
                confidence=0.82,
            )
    for event in reversed(events[-16:]):
        quality = quality_by_id.get(event.event_id)
        if not quality or not quality.is_blocker_evidence_allowed or not event.author:
            continue
        summary = " ".join(event.message.split())
        summary_norm = _norm(summary)
        if not summary or _is_noisy_text(summary):
            continue
        if not any(term in summary_norm for term in CONFIRMATION_SUPERSEDED_TERMS):
            continue
        if not _is_later_evidence([event.event_id], brief.latest_blocker.evidence_ids, events):
            continue
        target_ids = _target_ids_for_names([event.author], allowed_targets) or _target_ids_from_evidence([event.event_id], allowed_targets)
        blocker_type = "mitigation_status_needed" if any(term in summary_norm for term in ("stop", "pause")) else _blocker_type(summary, "human_status")
        return _Candidate(
            source="deterministic_latest_human",
            blocker_type=blocker_type,
            summary=summary[:260],
            evidence_ids=[event.event_id],
            target_ids=target_ids[:3],
            workstream_type="human_status",
            workstream_status="active",
            confidence=0.82,
        )
    return None


def _candidate_from_latest_unresolved_action(
    brief: IncidentBrief,
    quality_by_id: dict[str, EventQuality],
    allowed_targets: list[AllowedTarget],
    events: list[IncidentEvent],
) -> _Candidate | None:
    for event in reversed(events[-12:]):
        quality = quality_by_id.get(event.event_id)
        if not quality or not quality.is_blocker_evidence_allowed or not event.author:
            continue
        summary = " ".join(event.message.split())
        summary_norm = _norm(summary)
        if not summary or _is_noisy_text(summary):
            continue
        if not any(term in summary_norm for term in ("can we stop", "can they stop", "stop the process", "pause", "same activity", "sandboxes", "confirm whether ongoing")):
            continue
        if event.event_id in brief.latest_blocker.evidence_ids and any(term in _norm(brief.latest_blocker.summary) for term in ("stop", "pause", "same activity", "sandbox")):
            return None
        if brief.latest_blocker.evidence_ids and not _is_later_evidence([event.event_id], brief.latest_blocker.evidence_ids, events):
            continue
        target_ids = _target_ids_for_names([event.author], allowed_targets) or _target_ids_from_evidence([event.event_id], allowed_targets)
        blocker_type = "mitigation_status_needed" if any(term in summary_norm for term in ("stop", "pause", "process")) else "validation_needed"
        return _Candidate(
            source="deterministic_latest_human",
            blocker_type=blocker_type,
            summary=summary[:260],
            evidence_ids=[event.event_id],
            target_ids=target_ids[:3],
            workstream_type="human_status",
            workstream_status="active",
            confidence=0.8,
        )
    return None


def _do_not_ask_with_superseded_confirmation(brief: IncidentBrief, candidate: _Candidate | None) -> list[IncidentBriefDoNotAsk]:
    do_not = list(brief.do_not_ask)
    if candidate and _brief_waits_on_confirmation(brief):
        if all(item.intent != "ask_customer_confirmation" for item in do_not):
            do_not.append(
                IncidentBriefDoNotAsk(
                    intent="ask_customer_confirmation",
                    reason="Later human evidence answered the earlier customer confirmation blocker.",
                    evidence_ids=candidate.evidence_ids,
                )
            )
    return do_not


def _candidate_from_workstreams(
    ledger: ActorWorkstreamLedger | None,
    quality_by_id: dict[str, EventQuality],
    allowed_targets: list[AllowedTarget],
) -> _Candidate | None:
    if ledger is None:
        return None
    status_score = {"blocked": 3, "in_progress": 2, "unknown": 1, "completed": 0, "not_started": 0}
    candidates: list[tuple[int, int, _Candidate]] = []
    for index, workstream in enumerate(ledger.workstreams):
        if workstream.type == "trust_post" and workstream.status == "completed":
            continue
        if workstream.status not in {"in_progress", "blocked", "unknown"}:
            continue
        evidence_ids = _human_blocker_ids(workstream.evidence_ids, quality_by_id)
        if not evidence_ids:
            continue
        summary = workstream.summary.strip()
        if not summary or _is_noisy_text(summary):
            continue
        target_ids = _target_ids_for_names(workstream.owner_or_actor_names, allowed_targets)
        if not target_ids:
            target_ids = _target_ids_from_evidence(evidence_ids, allowed_targets)
        candidates.append(
            (
                status_score.get(workstream.status, 0),
                index,
                _Candidate(
                    source="actor_workstream_ledger",
                    blocker_type=_blocker_type(summary, workstream.type),
                    summary=summary[:260],
                    evidence_ids=evidence_ids,
                    target_ids=target_ids[:3],
                    workstream_type=workstream.type,
                    workstream_status=workstream.status,
                    confidence=0.74,
                ),
            )
        )
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return candidates[0][2]


def _candidate_from_fact(
    ledger: IncidentFactLedger | None,
    quality_by_id: dict[str, EventQuality],
    allowed_targets: list[AllowedTarget],
) -> _Candidate | None:
    if ledger is None or ledger.current_blocker is None:
        return None
    evidence_ids = _human_blocker_ids(ledger.current_blocker.evidence_ids, quality_by_id)
    summary = (ledger.current_blocker.summary or ledger.current_blocker.value).strip()
    if not evidence_ids or not summary or _is_noisy_text(summary):
        return None
    return _Candidate(
        source="incident_fact_ledger",
        blocker_type=_blocker_type(summary),
        summary=summary[:260],
        evidence_ids=evidence_ids,
        target_ids=_target_ids_from_evidence(evidence_ids, allowed_targets)[:3],
        workstream_type="fact_current_blocker",
        workstream_status="active",
        confidence=max(0.65, ledger.current_blocker.confidence),
    )


def _candidate_from_questions(
    ledger: QuestionIntentLedger | None,
    quality_by_id: dict[str, EventQuality],
    allowed_targets: list[AllowedTarget],
) -> _Candidate | None:
    if ledger is None:
        return None
    for item in reversed(ledger.open_questions[-6:]):
        evidence_ids = _human_blocker_ids(item.evidence_ids, quality_by_id)
        summary = item.summary.strip()
        if not evidence_ids or not summary or _is_noisy_text(summary):
            continue
        return _Candidate(
            source="question_intent_ledger",
            blocker_type=_blocker_type(summary),
            summary=summary[:260],
            evidence_ids=evidence_ids,
            target_ids=_target_ids_from_evidence(evidence_ids, allowed_targets)[:3],
            workstream_type="open_question",
            workstream_status="active",
            confidence=0.66,
        )
    return None


def _candidate_from_brief_summary(
    brief: IncidentBrief,
    events: list[IncidentEvent],
    quality_by_id: dict[str, EventQuality],
    allowed_targets: list[AllowedTarget],
) -> _Candidate | None:
    summary = (brief.latest_blocker.summary or brief.recommended_ic_focus.summary or "").strip()
    if not summary or _is_noisy_text(summary) or "unclear" in _norm(summary):
        return None
    summary_tokens = {
        token
        for token in re.findall(r"[a-z0-9][a-z0-9_-]{3,}", _norm(summary))
        if token not in SUMMARY_MATCH_STOPWORDS
    }
    if not summary_tokens:
        return None
    evidence_ids: list[str] = []
    for event in events:
        quality = quality_by_id.get(event.event_id)
        if not quality or not quality.is_blocker_evidence_allowed:
            continue
        event_text = _norm(f"{event.author or ''} {event.message}")
        if any(token in event_text for token in summary_tokens):
            evidence_ids.append(event.event_id)
    evidence_ids = list(dict.fromkeys(evidence_ids))[:6]
    if not evidence_ids:
        return None
    return _Candidate(
        source="incident_brief",
        blocker_type=_blocker_type(summary),
        summary=summary[:260],
        evidence_ids=evidence_ids,
        target_ids=_target_ids_from_evidence(evidence_ids, allowed_targets)[:3],
        workstream_type="fact_current_blocker",
        workstream_status="active",
        confidence=max(0.68, min(0.82, brief.latest_blocker.confidence or 0.68)),
    )


def _selection_from_candidate(
    candidate: _Candidate,
    *,
    status: str,
    brief: IncidentBrief,
    brief_quality: BriefQualityResult,
    quality_by_id: dict[str, EventQuality],
    allowed_targets: list[AllowedTarget],
) -> AuthoritativeBlockerSelection:
    valid = _valid_targets(allowed_targets)
    selected_target_ids = [target_id for target_id in candidate.target_ids if target_id in valid]
    qualities = _quality_for_ids(candidate.evidence_ids, quality_by_id)
    evidence_quality = "invalid"
    if any(quality.evidence_quality == "high" for quality in qualities):
        evidence_quality = "high"
    elif any(quality.evidence_quality == "medium" for quality in qualities):
        evidence_quality = "medium"
    elif qualities:
        evidence_quality = "low"
    superseded = _brief_waits_on_confirmation(brief) and candidate.source == "deterministic_latest_human"
    return AuthoritativeBlockerSelection(
        status=status,  # type: ignore[arg-type]
        selected_blocker_type=candidate.blocker_type,
        selected_blocker_summary=candidate.summary,
        selected_evidence_ids=candidate.evidence_ids,
        selected_evidence_kinds=_event_kinds(candidate.evidence_ids, quality_by_id),
        selected_target_ids=selected_target_ids,
        selected_target_names=[valid[target_id].display_name for target_id in selected_target_ids],
        selected_workstream_type=candidate.workstream_type,
        selected_workstream_status=candidate.workstream_status,
        source=candidate.source,  # type: ignore[arg-type]
        rejected_blocker_summary=brief.latest_blocker.summary,
        rejected_blocker_evidence_ids=brief.latest_blocker.evidence_ids,
        rejected_reason="; ".join(brief_quality.blocked_reasons),
        confidence=candidate.confidence,
        can_plan=candidate.blocker_type != "unknown" and bool(candidate.evidence_ids),
        stale_blocker_superseded=superseded,
        superseded_blocker_summary=brief.latest_blocker.summary if superseded else "",
        superseding_event_ids=candidate.evidence_ids if candidate.source == "deterministic_latest_human" else [],
        selected_latest_human_event_ids=candidate.evidence_ids if candidate.source == "deterministic_latest_human" else [],
        selected_blocker_evidence_quality=evidence_quality,  # type: ignore[arg-type]
        stale_question_intents_added=["ask_customer_confirmation"] if superseded else [],
    )


def _apply_trust_post_no_need(brief: IncidentBrief, evidence_ids: list[str]) -> IncidentBrief:
    if not evidence_ids:
        return brief
    do_not = list(brief.do_not_ask)
    if all(item.intent != "ask_if_trust_post_needed" for item in do_not):
        do_not.append(
            IncidentBriefDoNotAsk(
                intent="ask_if_trust_post_needed",
                reason="Trust Post was already marked no need in current evidence.",
                evidence_ids=evidence_ids,
            )
        )
    workstreams = [
        item.model_copy(update={"status": "completed"})
        if item.workstream_type == "trust_post_or_comms"
        else item
        for item in brief.active_workstreams
    ]
    return brief.model_copy(update={"do_not_ask": do_not, "active_workstreams": workstreams})


def select_authoritative_blocker(
    *,
    brief: IncidentBrief,
    brief_quality: BriefQualityResult,
    semantic_quality: SemanticQuality,
    semantic_read: ParallelSemanticReadResult,
    events: list[IncidentEvent],
    event_quality: list[EventQuality],
    allowed_targets: list[AllowedTarget],
) -> tuple[AuthoritativeBlockerSelection, IncidentBrief, BriefQualityResult]:
    quality_by_id = event_quality_by_id(event_quality)
    trust_no_need_ids = _trust_post_no_need(events, semantic_read.question_intent_ledger)
    brief = _apply_trust_post_no_need(brief, trust_no_need_ids)
    superseding_candidate = _candidate_from_superseding_confirmation(
        brief,
        semantic_read.clean_turn_ledger,
        quality_by_id,
        allowed_targets,
        events,
    )
    if superseding_candidate is None:
        superseding_candidate = _candidate_from_latest_unresolved_action(
            brief,
            quality_by_id,
            allowed_targets,
            events,
        )

    if brief_quality.passed and superseding_candidate is None:
        original_qualities = _quality_for_ids(brief.latest_blocker.evidence_ids, quality_by_id)
        original_evidence_quality = (
            "high"
            if any(quality.evidence_quality == "high" for quality in original_qualities)
            else "medium"
            if any(quality.evidence_quality == "medium" for quality in original_qualities)
            else "low"
            if original_qualities
            else "invalid"
        )
        selection = AuthoritativeBlockerSelection(
            status="no_repair_needed",
            selected_blocker_type=brief.latest_blocker.blocker_type,
            selected_blocker_summary=brief.latest_blocker.summary,
            selected_evidence_ids=brief.latest_blocker.evidence_ids,
            selected_evidence_kinds=_event_kinds(brief.latest_blocker.evidence_ids, quality_by_id),
            selected_target_ids=brief.recommended_ic_focus.preferred_target_ids,
            selected_target_names=[
                target.display_name
                for target in allowed_targets
                if target.target_id in set(brief.recommended_ic_focus.preferred_target_ids)
            ],
            source="incident_brief",
            confidence=brief.latest_blocker.confidence,
            can_plan=semantic_quality.can_plan,
            selected_blocker_evidence_quality=original_evidence_quality,  # type: ignore[arg-type]
        )
        repaired_quality = validate_incident_brief_quality(brief, events, allowed_targets, semantic_quality)
        return selection, brief, repaired_quality

    candidates = [superseding_candidate] if superseding_candidate is not None else [
        _candidate_from_brief_summary(brief, events, quality_by_id, allowed_targets),
        _candidate_from_workstreams(semantic_read.actor_workstream_ledger, quality_by_id, allowed_targets),
        _candidate_from_fact(semantic_read.incident_fact_ledger, quality_by_id, allowed_targets),
        _candidate_from_clean_turns(
            semantic_read.clean_turn_ledger,
            quality_by_id,
            allowed_targets,
            message_types={"question"},
        ),
        _candidate_from_clean_turns(
            semantic_read.clean_turn_ledger,
            quality_by_id,
            allowed_targets,
            message_types={"human_status", "mitigation", "monitoring", "diagnostic_log", "customer_impact"},
        ),
    ]
    if superseding_candidate is None and not semantic_quality.question_only_success:
        candidates.append(_candidate_from_questions(semantic_read.question_intent_ledger, quality_by_id, allowed_targets))
    candidate = next((item for item in candidates if item and item.blocker_type != "unknown"), None)
    if candidate is None:
        selection = AuthoritativeBlockerSelection(
            status="insufficient",
            rejected_blocker_summary=brief.latest_blocker.summary,
            rejected_blocker_evidence_ids=brief.latest_blocker.evidence_ids,
            rejected_reason="No high-quality current human/operator blocker survived the evidence quality gate.",
            can_plan=False,
            warnings=[*brief_quality.blocked_reasons],
        )
        repaired_quality = validate_incident_brief_quality(brief, events, allowed_targets, semantic_quality)
        return selection, brief, repaired_quality

    selection = _selection_from_candidate(
        candidate,
        status="repaired",
        brief=brief,
        brief_quality=brief_quality,
        quality_by_id=quality_by_id,
        allowed_targets=allowed_targets,
    )
    rejected = [
        *brief.rejected_or_noise,
        IncidentBriefRejectedOrNoise(
            text=brief.latest_blocker.summary or "original latest_blocker",
            reason="generated_summary_fragment" if _is_noisy_text(brief.latest_blocker.summary) else "other",
            evidence_ids=brief.latest_blocker.evidence_ids,
        ),
    ]
    workstreams = list(brief.active_workstreams)
    if selection.selected_workstream_type != "unknown":
        workstreams.append(
            IncidentBriefWorkstream(
                workstream_type=_incident_workstream_type(selection.selected_workstream_type),  # type: ignore[arg-type]
                status="active" if selection.selected_workstream_status in {"in_progress", "active"} else "waiting",
                summary=selection.selected_blocker_summary,
                owner_target_ids=selection.selected_target_ids,
                evidence_ids=selection.selected_evidence_ids,
            )
        )
    repaired = brief.model_copy(
        update={
            "latest_blocker": IncidentBriefBlocker(
                blocker_type=selection.selected_blocker_type,  # type: ignore[arg-type]
                summary=selection.selected_blocker_summary,
                evidence_ids=selection.selected_evidence_ids,
                confidence=selection.confidence,
            ),
            "active_workstreams": workstreams,
            "rejected_or_noise": rejected,
            "do_not_ask": _do_not_ask_with_superseded_confirmation(brief, candidate),
            "recommended_ic_focus": IncidentBriefFocus(
                summary=selection.selected_blocker_summary,
                preferred_target_ids=selection.selected_target_ids,
                acceptable_move_types=_move_types(selection.selected_blocker_type),
                evidence_ids=selection.selected_evidence_ids,
            ),
            "warnings": [
                *brief.warnings,
                f"latest_blocker repaired from {selection.source}; original rejected: {selection.rejected_reason}",
            ],
        }
    )
    repaired_quality = validate_incident_brief_quality(repaired, events, allowed_targets, semantic_quality)
    selection = selection.model_copy(update={"can_plan": repaired_quality.passed and semantic_quality.can_plan})
    return selection, repaired, repaired_quality
