from __future__ import annotations

import re
from typing import Any

from ic_copilot.action_state import infer_action_state_transitions
from ic_copilot.actionability import analyze_visible_actionability
from ic_copilot.llm.redaction import redact_for_llm
from ic_copilot.schemas import EventQuality, ICDecision, IncidentEvent, IncidentReadAndWhisper, VerifierResult


ANSWERED_OPEN_LOOP_SCHEMA_VERSION = "1.0"


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").lower()).strip()


def _compact_quote(value: str | None, *, limit: int = 180) -> str:
    text = " ".join(str(redact_for_llm(value or "")).split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "..."


def _event_quality_by_id(event_quality: list[EventQuality] | list[dict[str, Any]] | None) -> dict[str, EventQuality]:
    quality_by_id: dict[str, EventQuality] = {}
    for item in event_quality or []:
        quality = item if isinstance(item, EventQuality) else EventQuality.model_validate(item)
        quality_by_id[quality.event_id] = quality
    return quality_by_id


def _is_high_signal_human(event: IncidentEvent, quality_by_id: dict[str, EventQuality]) -> bool:
    quality = quality_by_id.get(event.event_id)
    if quality is not None:
        return (
            quality.author_type == "human"
            and quality.evidence_quality in {"high", "medium"}
            and quality.event_kind
            not in {
                "preview_card",
                "pagerduty_card",
                "jira_card",
                "zoom_card",
                "slack_lifecycle",
                "bot_system_message",
                "bot_summary",
                "log_or_code_block",
                "table_row",
                "table_header",
                "generated_summary_fragment",
                "low_signal_noise",
            }
        )
    tokens = event.extracted_tokens or {}
    return not bool(tokens.get("is_bot") or tokens.get("is_system"))


def classify_open_question_intent(text: str) -> str | None:
    text_norm = _norm(text)
    if not text_norm:
        return None
    has_question_shape = "?" in text or any(
        phrase in text_norm
        for phrase in (
            "can you",
            "could you",
            "do we",
            "do you know",
            "need",
            "what is",
            "what's",
            "who is",
            "who owns",
            "please confirm",
            "confirm whether",
            "confirm if",
        )
    )
    if not has_question_shape:
        return None
    if any(
        phrase in text_norm
        for phrase in (
            "multiple customers",
            "how many customers",
            "more customers",
            "more production customers",
            "one or more customers",
            "only customer",
            "isolated to",
            "customer impact",
            "scope of impact",
            "affected customers",
        )
    ) or (
        any(phrase in text_norm for phrase in ("why do you say", "why do we say", "why is this", "why p1", "why p2"))
        and any(phrase in text_norm for phrase in ("p1", "p2", "severity", "priority"))
    ):
        return "impact_scope"
    if any(phrase in text_norm for phrase in ("p0", "p1", "p2", "severity", "priority", "sev")):
        return "severity_scope"
    if any(
        phrase in text_norm
        for phrase in ("current status", "status recap", "recap", "what did we discuss", "what was discussed")
    ):
        return "status_recap"
    if "zoom" in text_norm or "bridge" in text_norm:
        return "zoom_bridge"
    if "trust post" in text_norm or "trust posting" in text_norm or "trust update" in text_norm:
        return "trust_post"
    if any(
        phrase in text_norm
        for phrase in (
            "who owns",
            "owner",
            "eta",
            "checking",
            "work item",
            "next action",
            "page engineering",
            "page team",
            "paged the team",
            "engage engineering",
            "engage support",
        )
    ):
        return "owner_status"
    if any(
        phrase in text_norm
        for phrase in ("validate", "validation", "row-count", "row count", "pipeline", "iceberg", "root cause", "rca")
    ):
        return "technical_validation"
    if any(
        phrase in text_norm
        for phrase in ("monitor", "monitoring", "signal", "catch up", "catch-up", "drain", "recovery", "lag")
    ):
        return "monitoring_signal"
    if any(phrase in text_norm for phrase in ("customer confirmed", "customer validation", "reporter", "symptoms")):
        return "customer_validation"
    return "unknown"


def _answer_candidate_for_intent(question_intent: str, event_text: str) -> tuple[float, str] | None:
    text_norm = _norm(event_text)
    if question_intent == "impact_scope":
        strong_phrases = (
            "only one customer",
            "one customer affected",
            "single customer",
            "isolated to one customer",
            "only toast reported",
            "only toast has reported",
            "reported is only for",
            "no other customer",
            "no other customers",
            "only reported it",
            "only live customers",
            "only have 2 live customers",
            "only have two live customers",
            "only two live customers",
        )
        if any(phrase in text_norm for phrase in strong_phrases):
            return 0.9, "scope answer"
        if "only" in text_norm and "reported" in text_norm and "customer" in text_norm:
            return 0.78, "scope answer"
    if question_intent == "severity_scope":
        if any(phrase in text_norm for phrase in ("confirmed p1", "set to p1", "priority is", "severity is", "sev is")):
            return 0.82, "severity answer"
    if question_intent == "status_recap":
        status_markers = ("current status", "findings", "next steps", "summary:", "update:", "status:")
        if sum(1 for phrase in status_markers if phrase in text_norm) >= 2:
            return 0.86, "status update"
        if "next steps" in text_norm and len(text_norm) > 120:
            return 0.76, "status update"
    if question_intent == "trust_post":
        if any(phrase in text_norm for phrase in ("trust post no need", "no trust post", "no trust", "trust not needed")):
            return 0.9, "trust decision"
    if question_intent == "zoom_bridge":
        if any(phrase in text_norm for phrase in ("zoom bridge opened", "bridge opened", "meeting started", "joined zoom")):
            return 0.88, "zoom bridge answer"
    if question_intent in {"owner_status", "technical_validation"}:
        if any(
            phrase in text_norm
            for phrase in (
                "owner:",
                "owner is",
                " is checking ",
                " is validating ",
                "next action",
                "next step",
                "pipeline owner",
                "row-count",
                "row count",
                "iceberg",
                "validation",
            )
        ):
            return 0.78, "owner/action answer" if question_intent == "owner_status" else "technical validation answer"
    if question_intent == "monitoring_signal":
        if any(
            phrase in text_norm
            for phrase in ("monitoring", "signal", "catch-up", "catch up", "draining", "recovered", "lag is", "trend")
        ):
            return 0.78, "monitoring answer"
    if question_intent == "customer_validation":
        if any(
            phrase in text_norm
            for phrase in ("customer confirmed", "reported", "no other customer", "symptoms", "customer-side")
        ):
            return 0.76, "customer validation answer"
    return None


def diagnose_open_loops(
    events: list[IncidentEvent] | list[dict[str, Any]],
    event_quality: list[EventQuality] | list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    normalized_events = [event if isinstance(event, IncidentEvent) else IncidentEvent.model_validate(event) for event in events]
    quality_by_id = _event_quality_by_id(event_quality)
    open_questions: list[dict[str, Any]] = []
    later_answer_candidates: list[dict[str, Any]] = []
    answered_ids: set[str] = set()
    action_state = infer_action_state_transitions(normalized_events, event_quality)

    for idx, event in enumerate(normalized_events):
        if not _is_high_signal_human(event, quality_by_id):
            continue
        intent = classify_open_question_intent(event.message)
        if intent is None:
            continue
        question = {
            "event_id": event.event_id,
            "author": event.author,
            "question_intent": intent,
            "question_text": _compact_quote(event.message),
        }
        open_questions.append(question)
        if intent == "unknown":
            continue
        for answer in normalized_events[idx + 1 :]:
            if not _is_high_signal_human(answer, quality_by_id):
                continue
            candidate = _answer_candidate_for_intent(intent, answer.message)
            if candidate is None:
                continue
            confidence, reason = candidate
            row = {
                "question_event_id": event.event_id,
                "question_intent": intent,
                "answer_event_id": answer.event_id,
                "answer_author": answer.author,
                "answer_quote": _compact_quote(answer.message),
                "answer_confidence": confidence,
                "answer_reason": reason,
            }
            later_answer_candidates.append(row)
            if confidence >= 0.75:
                answered_ids.add(event.event_id)
                break

    for action_answer in action_state.get("answered_questions", []):
        question_event_id = str(action_answer.get("question_event_id") or "")
        if not question_event_id:
            continue
        if all(question.get("event_id") != question_event_id for question in open_questions):
            source = next((event for event in normalized_events if event.event_id == question_event_id), None)
            open_questions.append(
                {
                    "event_id": question_event_id,
                    "author": source.author if source else None,
                    "question_intent": str(action_answer.get("question_intent") or "owner_status"),
                    "question_text": str(action_answer.get("question_text") or ""),
                }
            )
        later_answer_candidates.append(
            {
                "question_event_id": question_event_id,
                "question_intent": str(action_answer.get("question_intent") or "owner_status"),
                "answer_event_id": str(action_answer.get("answer_event_id") or ""),
                "answer_author": None,
                "answer_quote": str(action_answer.get("answer_summary") or ""),
                "answer_confidence": float(action_answer.get("answer_confidence") or 0.8),
                "answer_reason": str(action_answer.get("answer_reason") or "operational action completion"),
            }
        )
        if float(action_answer.get("answer_confidence") or 0.0) >= 0.75:
            answered_ids.add(question_event_id)

    answered_open_loops = [question for question in open_questions if question["event_id"] in answered_ids]
    unresolved_open_loops = [question for question in open_questions if question["event_id"] not in answered_ids]

    all_later_text = "\n".join(event.message for event in normalized_events if _is_high_signal_human(event, quality_by_id))
    if answered_open_loops and any(item.get("question_intent") == "impact_scope" for item in answered_open_loops):
        text_norm = _norm(all_later_text)
        if any(phrase in text_norm for phrase in ("row-count", "row count", "iceberg", "pipeline", "validation")):
            unresolved_open_loops.append(
                {
                    "event_id": "derived:technical_validation",
                    "author": None,
                    "question_intent": "technical_validation",
                    "question_text": "pipeline / row-count mismatch owner validation remains unresolved",
                }
            )

    return {
        "open_questions": open_questions,
        "later_answer_candidates": later_answer_candidates,
        "answered_open_loops": answered_open_loops,
        "unresolved_open_loops": unresolved_open_loops,
        "stale_output_risks": [],
        "action_state_transitions": action_state.get("action_loops", []),
        "do_not_ask_from_actions": action_state.get("do_not_ask", []),
    }


def stale_output_risks_for_output(
    output_text: str,
    events: list[IncidentEvent] | list[dict[str, Any]],
    event_quality: list[EventQuality] | list[dict[str, Any]] | dict[str, EventQuality] | None = None,
) -> list[dict[str, Any]]:
    if isinstance(event_quality, dict):
        quality_rows: list[EventQuality] = list(event_quality.values())
    else:
        quality_rows = list(event_quality or [])
    open_loop = diagnose_open_loops(events, quality_rows)
    text_norm = _norm(output_text)
    risks: list[dict[str, Any]] = []

    def _first_answered(intent: str) -> dict[str, Any] | None:
        for candidate in open_loop["later_answer_candidates"]:
            if candidate.get("question_intent") == intent and candidate.get("answer_confidence", 0.0) >= 0.75:
                return candidate
        return None

    scope_answer = _first_answered("impact_scope")
    if scope_answer and any(
        phrase in text_norm
        for phrase in (
            "confirm whether this is isolated",
            "confirm whether it is isolated",
            "confirm whether this is limited",
            "confirm whether toast is the only",
            "one or more customers",
            "more production customers",
            "multiple customers",
            "how many customers",
            "only impacted customer",
        )
    ):
        risks.append(
            {
                "risk_type": "scope_question_after_scope_answer",
                "output_phrase": _compact_quote(output_text),
                "answered_by_event_id": scope_answer["answer_event_id"],
                "severity": "error",
            }
        )
    status_answer = _first_answered("status_recap")
    if status_answer and any(phrase in text_norm for phrase in ("recap current status", "what did we discuss on zoom")):
        risks.append(
            {
                "risk_type": "status_recap_after_update",
                "output_phrase": _compact_quote(output_text),
                "answered_by_event_id": status_answer["answer_event_id"],
                "severity": "error",
            }
        )
    trust_answer = _first_answered("trust_post")
    if trust_answer and "trust post" in text_norm and any(phrase in text_norm for phrase in ("need", "needed", "post")):
        risks.append(
            {
                "risk_type": "asks_already_answered_question",
                "output_phrase": _compact_quote(output_text),
                "answered_by_event_id": trust_answer["answer_event_id"],
                "severity": "error",
            }
        )
    zoom_answer = _first_answered("zoom_bridge")
    if zoom_answer and "zoom" in text_norm and any(phrase in text_norm for phrase in ("need", "open", "start")):
        risks.append(
            {
                "risk_type": "asks_already_answered_question",
                "output_phrase": _compact_quote(output_text),
                "answered_by_event_id": zoom_answer["answer_event_id"],
                "severity": "warning",
            }
        )
    action_state = infer_action_state_transitions(
        [event if isinstance(event, IncidentEvent) else IncidentEvent.model_validate(event) for event in events],
        quality_rows,
    )
    for loop in action_state.get("action_loops", []):
        if not loop.get("closed"):
            continue
        if any(
            phrase in text_norm
            for phrase in (
                "did you page",
                "have you paged",
                "if you paged",
                "whether you paged",
                "confirm if you paged",
                "confirm whether you paged",
                "confirm engineering was paged",
                "confirm whether engineering was paged",
            )
        ):
            final_transition = (loop.get("transitions") or [{}])[-1]
            risks.append(
                {
                    "risk_type": "asks_already_answered_question",
                    "output_phrase": _compact_quote(output_text),
                    "answered_by_event_id": final_transition.get("event_id"),
                    "severity": "error",
                }
            )
            break
    return risks


def _event_by_id(events: list[IncidentEvent]) -> dict[str, IncidentEvent]:
    return {event.event_id: event for event in events}


def _used_evidence(
    incident_read: IncidentReadAndWhisper | dict[str, Any] | None,
    events_by_id: dict[str, IncidentEvent],
) -> list[dict[str, Any]]:
    if incident_read is None:
        return []
    read = incident_read if isinstance(incident_read, dict) else incident_read.model_dump(mode="json")
    used = []
    for item in read.get("evidence", []) or []:
        event_id = item.get("event_id")
        event = events_by_id.get(event_id)
        used.append(
            {
                "event_id": event_id,
                "author": event.author if event else None,
                "timestamp": event.ts if event else None,
                "quote": _compact_quote(item.get("quote") or (event.message if event else "")),
                "why_used": "model grounding evidence",
            }
        )
    return used


def _memory_funnel(
    *,
    loaded_count: int,
    retrieved_memory_ids: list[str],
    applicability_results: list[Any],
    accepted_memory_ids: list[str],
    current_events: list[IncidentEvent],
) -> dict[str, Any]:
    current_text = "\n".join(event.message for event in current_events)
    current_text_norm = _norm(current_text)
    accepted_set = set(accepted_memory_ids)
    accepted = []
    rejected = []
    possible_gaps = []
    for raw in applicability_results:
        item = raw if isinstance(raw, dict) else raw.model_dump(mode="json")
        decision_id = item.get("decision_id")
        if decision_id in accepted_set or item.get("accepted"):
            accepted.append(
                {
                    "decision_id": decision_id,
                    "behavior_hint": (item.get("allowed_patterns") or [""])[0],
                    "matched_evidence": item.get("required_current_evidence_satisfied", []),
                }
            )
            continue
        rejected.append(
            {
                "decision_id": decision_id,
                "reasons": item.get("reasons", []),
                "missing_required_current_evidence": item.get("required_current_evidence_missing", []),
            }
        )
        for missing in item.get("required_current_evidence_missing", []) or []:
            missing_norm = _norm(missing)
            nearby = []
            if missing_norm == "report failure":
                for phrase in ("reports are erroring out", "reports erroring out", "not able to run reports"):
                    if phrase in current_text_norm:
                        nearby.append(phrase)
            if nearby:
                possible_gaps.append(
                    {
                        "decision_id": decision_id,
                        "missing_phrase": missing,
                        "nearby_current_evidence": nearby,
                        "suggested_fix_category": "memory evidence synonym",
                    }
                )

    return {
        "loaded_count": loaded_count,
        "retrieved": [{"decision_id": item, "why_retrieved": "matched current evidence terms"} for item in retrieved_memory_ids],
        "accepted": accepted,
        "rejected": rejected,
        "possible_semantic_gaps": possible_gaps,
    }


def _verifier_summary(verifier_result: VerifierResult | dict[str, Any] | None) -> dict[str, Any]:
    if verifier_result is None:
        return {"status": "unknown", "meaningful_checks": [], "failed_checks": []}
    verifier = (
        verifier_result
        if isinstance(verifier_result, dict)
        else verifier_result.model_dump(mode="json", exclude={"fallback_decision": {"verifier_result": True}})
    )
    checks = verifier.get("checks") or {}
    meaningful = []
    for name in (
        "no_stale_question",
        "stale_open_loop_contradiction",
        "stale_answered_open_loop",
        "stale_visible_status_recap",
        "severity_claim_confirmed",
        "action_owner_aligned",
        "role_target_aligned",
        "target_in_allowed_targets",
        "no_private_identifier_in_visible_output",
        "no_executable_action_wording",
        "no_passive_we_need_owner_statement",
        "visible_output_is_direct_ask",
        "selected_move_matches_visible_intent",
        "no_low_quality_named_person_as_owner",
        "unresolved_loop_requires_question",
        "no_safe_despite_accepted_memory",
        "accepted_memory_target_class_satisfied",
        "accepted_memory_visible_intent_satisfied",
        "no_safe_despite_diagnostic_signal",
        "reporter_not_owner_when_owner_candidate_exists",
        "bot_diagnostic_context_preserved",
        "raw_paste_evidence_preservation",
    ):
        if name in checks:
            meaningful.append({"check": name, "passed": bool(checks[name]), "detail": ""})
    failed = [{"check": name, "detail": ""} for name, passed in checks.items() if not passed]
    return {
        "status": verifier.get("final_status") or ("pass" if verifier.get("passed") else "fail"),
        "meaningful_checks": meaningful,
        "failed_checks": failed,
    }


def _selected_output(
    *,
    decision: ICDecision | dict[str, Any] | None,
    incident_read: IncidentReadAndWhisper | dict[str, Any] | None,
    final_output: str,
    fallback_used: bool,
    verifier_result: VerifierResult | dict[str, Any] | None,
) -> dict[str, Any]:
    decision_dict = (
        decision.model_dump(mode="json", exclude={"verifier_result": {"fallback_decision": {"verifier_result": True}}})
        if isinstance(decision, ICDecision)
        else (decision or {})
    )
    read = incident_read.model_dump(mode="json") if isinstance(incident_read, IncidentReadAndWhisper) else (incident_read or {})
    verifier = (
        verifier_result.model_dump(mode="json", exclude={"fallback_decision": {"verifier_result": True}})
        if isinstance(verifier_result, VerifierResult)
        else (verifier_result or {})
    )
    raw_target_names = [
        target.get("display_name") for target in decision_dict.get("targets", []) if target.get("display_name")
    ] or ([read.get("selected_target_display_name")] if read.get("selected_target_display_name") else [])
    target_display_names = _dedup_strings([str(name) for name in raw_target_names if name])
    return {
        "move": decision_dict.get("move") or read.get("selected_move"),
        "say_this": decision_dict.get("output", {}).get("say_this") or read.get("say_this") or _compact_quote(final_output),
        "target_ids": decision_dict.get("target_ids", []),
        "target_display_names": target_display_names,
        "target_dedup_applied": len(target_display_names) < len(raw_target_names),
        "fallback_used": fallback_used,
        "verifier_status": verifier.get("final_status") or ("pass" if verifier.get("passed") else "fail"),
    }


def _dedup_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        key = _norm(value)
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(value)
    return deduped


def _move_normalization_metadata(decision: ICDecision | dict[str, Any] | None) -> dict[str, Any]:
    if decision is None:
        return {}
    data = (
        decision.model_dump(mode="json", exclude={"verifier_result": {"fallback_decision": {"verifier_result": True}}})
        if isinstance(decision, ICDecision)
        else decision
    )
    metadata = data.get("model_metadata") or {}
    normalization = metadata.get("actionability_move_normalization")
    return normalization if isinstance(normalization, dict) else {}


def build_run_diagnosis(
    *,
    incident_id: str,
    events: list[IncidentEvent] | list[dict[str, Any]],
    event_quality: list[EventQuality] | list[dict[str, Any]] | None = None,
    latest_window_selection: Any | None = None,
    context_pack: dict[str, Any] | None = None,
    allowed_targets: list[Any] | None = None,
    current_work_items: list[dict[str, Any]] | None = None,
    loaded_memory_count: int = 0,
    retrieved_memory_ids: list[str] | None = None,
    applicability_results: list[Any] | None = None,
    accepted_memory_ids: list[str] | None = None,
    incident_read: IncidentReadAndWhisper | dict[str, Any] | None = None,
    decision: ICDecision | dict[str, Any] | None = None,
    candidate_decision: ICDecision | dict[str, Any] | None = None,
    verifier_result: VerifierResult | dict[str, Any] | None = None,
    final_output: str = "",
    fallback_used: bool = False,
    planning_failure: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_events = [event if isinstance(event, IncidentEvent) else IncidentEvent.model_validate(event) for event in events]
    quality_by_id = _event_quality_by_id(event_quality)
    events_by_id = _event_by_id(normalized_events)
    latest_kept = latest_window_selection.event_ids if hasattr(latest_window_selection, "event_ids") else []
    selected_output = _selected_output(
        decision=decision,
        incident_read=incident_read,
        final_output=final_output,
        fallback_used=fallback_used,
        verifier_result=verifier_result,
    )
    open_loop = diagnose_open_loops(normalized_events, event_quality)
    stale_risks = stale_output_risks_for_output(selected_output.get("say_this") or final_output, normalized_events, event_quality)
    selected_actionability = analyze_visible_actionability(
        decision or {"output": {"say_this": selected_output.get("say_this") or final_output}},
        allowed_targets=allowed_targets or [],
        unresolved_open_loops=open_loop.get("unresolved_open_loops", []),
    )
    move_normalization = _move_normalization_metadata(decision)
    candidate_stale_risks: list[dict[str, Any]] = []
    candidate_actionability: dict[str, Any] = {}
    if candidate_decision is not None:
        candidate = (
            candidate_decision.model_dump(
                mode="json",
                exclude={"verifier_result": {"fallback_decision": {"verifier_result": True}}},
            )
            if isinstance(candidate_decision, ICDecision)
            else candidate_decision
        )
        candidate_text = (candidate.get("output") or {}).get("say_this") or ""
        candidate_stale_risks = stale_output_risks_for_output(candidate_text, normalized_events, event_quality)
        candidate_actionability = analyze_visible_actionability(
            candidate,
            allowed_targets=allowed_targets or [],
            unresolved_open_loops=open_loop.get("unresolved_open_loops", []),
        )
    open_loop["stale_output_risks"] = stale_risks
    open_loop["model_candidate_stale_output_risks"] = candidate_stale_risks
    used = _used_evidence(incident_read, events_by_id)
    used_ids = {item.get("event_id") for item in used}
    ignored = []
    for candidate in open_loop["later_answer_candidates"]:
        event_id = candidate.get("answer_event_id")
        if event_id in used_ids:
            continue
        ignored.append(
            {
                "event_id": event_id,
                "author": candidate.get("answer_author"),
                "quote": candidate.get("answer_quote"),
                "why_relevant": candidate.get("answer_reason"),
            }
        )
    latest_high_signal = [
        {
            "event_id": event.event_id,
            "author": event.author,
            "quote": _compact_quote(event.message),
        }
        for event in normalized_events
        if _is_high_signal_human(event, quality_by_id)
    ][-8:]
    quality_rows = list(quality_by_id.values())
    human_operator_count = sum(1 for quality in quality_rows if quality.event_kind.startswith("human_"))
    planner_grounding_count = sum(1 for quality in quality_rows if quality.is_planner_grounding_allowed)
    human_diagnostic_count = sum(
        1 for quality in quality_rows if quality.event_kind == "human_diagnostic_evidence"
    )
    retained_diagnostic_ids = list((context_pack or {}).get("retained_high_signal_diagnostic_event_ids") or [])
    dropped_diagnostic_ids = list((context_pack or {}).get("dropped_high_signal_diagnostic_event_ids") or [])
    detected_diagnostic_facts = list((context_pack or {}).get("detected_diagnostic_facts") or [])
    retained_diagnostic_facts = list((context_pack or {}).get("retained_diagnostic_facts") or [])
    dropped_diagnostic_facts = list((context_pack or {}).get("dropped_diagnostic_facts") or [])
    recovered_compact_author_count = sum(
        1 for event in normalized_events if (event.raw_metadata or {}).get("compact_author_recovered")
    )
    compact_author_examples = [
        str(event.author or "unknown")
        for event in normalized_events
        if (event.raw_metadata or {}).get("compact_author_recovered")
    ][:6]
    memory_funnel = _memory_funnel(
        loaded_count=loaded_memory_count,
        retrieved_memory_ids=list(retrieved_memory_ids or []),
        applicability_results=list(applicability_results or []),
        accepted_memory_ids=list(accepted_memory_ids or []),
        current_events=normalized_events,
    )
    asks_answered = bool(stale_risks or candidate_stale_risks)
    is_restatement_only = bool(
        re.match(r"^\s*@?[\w .-]+,?\s*(?:noted|you said|this is)\b", selected_output.get("say_this") or "", re.I)
    )
    is_actionable = bool(selected_actionability.get("direct_ask"))
    candidate_category = candidate_actionability.get("actionability_failure_category", "none")
    selected_category = selected_actionability.get("actionability_failure_category", "none")
    actionability_category = selected_category if selected_category != "none" else candidate_category
    no_safe_wording_quality = str(
        selected_actionability.get("no_safe_wording_quality")
        or candidate_actionability.get("no_safe_wording_quality")
        or "not_applicable"
    )
    passive_owner_statement = bool(
        selected_actionability.get("passive_owner_statement")
        or candidate_actionability.get("passive_owner_statement")
    )
    low_quality_owner_terms = list(
        dict.fromkeys(
            [
                *selected_actionability.get("low_quality_named_owner_terms", []),
                *candidate_actionability.get("low_quality_named_owner_terms", []),
            ]
        )
    )
    move_visible_intent_mismatch = bool(
        selected_actionability.get("move_visible_intent_mismatch")
        or candidate_actionability.get("move_visible_intent_mismatch")
    )
    planning_failure = planning_failure or {}
    planner_output_invalid = bool(planning_failure.get("provider_output_was_invalid"))
    safe_but_weak = asks_answered or is_restatement_only or not is_actionable
    safe_but_weak = safe_but_weak or actionability_category != "none"
    safe_but_weak = safe_but_weak or planner_output_invalid
    weakness_reasons = []
    if planner_output_invalid:
        weakness_reasons.append("one-call IncidentReadAndWhisper output did not validate cleanly")
    if asks_answered:
        weakness_reasons.append("visible output asks an earlier broad question already answered by later human evidence")
    if is_restatement_only:
        weakness_reasons.append("visible output appears to restate current facts instead of asking for next validation")
    if not is_actionable:
        weakness_reasons.append("visible output does not ask a concrete owner-aligned next question")
    if passive_owner_statement:
        weakness_reasons.append("visible output uses passive owner wording instead of a direct IC ask")
    if low_quality_owner_terms:
        weakness_reasons.append("visible output assigns owner/action to an unselected or low-quality named person")
    if no_safe_wording_quality == "weak_finality":
        weakness_reasons.append("no_safe_recommendation wording implies closure without grounded closure evidence")
    lost_high_signal_diagnostics = bool(dropped_diagnostic_ids) or (
        human_diagnostic_count > 0 and not retained_diagnostic_ids
    )
    lost_required_diagnostic_facts = bool(detected_diagnostic_facts) and not retained_diagnostic_facts
    checks = {}
    if isinstance(verifier_result, VerifierResult):
        checks = verifier_result.checks
    elif isinstance(verifier_result, dict):
        checks = verifier_result.get("checks") or {}
    if planner_output_invalid:
        likely_failure = str(planning_failure.get("planning_failure_category") or "planning_model_schema_invalid")
    elif recovered_compact_author_count == 0 and human_operator_count == 0 and normalized_events:
        likely_failure = "normalization_compact_timestamp_parse_failed"
    elif human_operator_count == 0 and normalized_events:
        likely_failure = "normalization_no_human_operator_events"
    elif lost_high_signal_diagnostics or lost_required_diagnostic_facts:
        likely_failure = "context_pack_lost_high_signal_diagnostic_evidence"
    elif asks_answered:
        likely_failure = "open_loop_supersedence"
    elif checks.get("accepted_memory_target_class_satisfied") is False:
        likely_failure = "accepted_memory_target_class_mismatch"
    elif checks.get("accepted_memory_visible_intent_satisfied") is False:
        likely_failure = "accepted_memory_visible_intent_mismatch"
    elif checks.get("no_safe_despite_diagnostic_signal") is False:
        likely_failure = "no_safe_despite_diagnostic_signal"
    elif (
        memory_funnel.get("rejected")
        and human_diagnostic_count == 0
        and planner_grounding_count == 0
    ):
        likely_failure = "memory_applicability_missing_evidence_due_context_loss"
    elif actionability_category != "none":
        likely_failure = "model_choice"
    elif fallback_used and not is_actionable:
        likely_failure = "safe_but_weak_no_actionable_evidence"
    else:
        likely_failure = "none"

    parsing_quality = {
        "normalized_event_count": len(normalized_events),
        "recovered_compact_author_count": recovered_compact_author_count,
        "compact_author_recovery_examples": compact_author_examples,
        "human_operator_event_count": human_operator_count,
        "planner_grounding_event_count": planner_grounding_count,
        "human_diagnostic_grounding_count": human_diagnostic_count,
        "retained_high_signal_diagnostic_event_ids": retained_diagnostic_ids,
        "dropped_high_signal_diagnostic_event_ids": dropped_diagnostic_ids,
        "detected_diagnostic_facts": detected_diagnostic_facts[:12],
        "retained_diagnostic_facts": retained_diagnostic_facts[:12],
        "dropped_diagnostic_facts": dropped_diagnostic_facts[:12],
        "detected_diagnostic_fact_ids": [fact.get("fact_id") for fact in detected_diagnostic_facts[:24]],
        "retained_diagnostic_fact_ids": [fact.get("fact_id") for fact in retained_diagnostic_facts[:24]],
        "dropped_diagnostic_fact_ids": [fact.get("fact_id") for fact in dropped_diagnostic_facts[:24]],
        "likely_failure_category": likely_failure,
    }

    return {
        "schema_version": ANSWERED_OPEN_LOOP_SCHEMA_VERSION,
        "incident_id": incident_id,
        "selected_output": selected_output,
        "evidence_chain": {
            "used_evidence": used,
            "latest_high_signal_events_kept": latest_high_signal,
            "latest_high_signal_events_dropped": [],
            "ignored_but_relevant_evidence": ignored,
        },
        "open_loop_diagnosis": open_loop,
        "memory_funnel": memory_funnel,
        "planning_failure": planning_failure,
        "parsing_quality": parsing_quality,
        "model_candidate_actionability": candidate_actionability,
        "final_output_quality": {
            "is_safe": _verifier_summary(verifier_result).get("status") == "pass" and not any(
                risk.get("severity") == "error" for risk in stale_risks
            ),
            "is_actionable": is_actionable,
            "direct_ask": is_actionable,
            "passive_owner_statement": passive_owner_statement,
            "low_quality_named_owner_terms": low_quality_owner_terms,
            "move_visible_intent_mismatch": move_visible_intent_mismatch,
            "unresolved_loop_without_question": bool(
                selected_actionability.get("unresolved_loop_without_question")
                or candidate_actionability.get("unresolved_loop_without_question")
            ),
            "actionability_failure_category": actionability_category,
            "no_safe_wording_quality": no_safe_wording_quality,
            "provider_output_was_invalid": planner_output_invalid,
            "provider_output_invalid_reason": planning_failure.get("provider_output_invalid_reason"),
            "planning_failure_category": planning_failure.get("planning_failure_category"),
            "target_dedup_applied": bool(selected_output.get("target_dedup_applied")),
            "move_normalized_from": move_normalization.get("from_move"),
            "move_normalized_to": move_normalization.get("to_move"),
            "is_restatement_only": is_restatement_only,
            "asks_already_answered_question": asks_answered,
            "target_has_latest_relevant_evidence": True,
            "safe_but_weak": safe_but_weak,
            "weakness_reasons": weakness_reasons,
            "likely_failure_category": likely_failure,
        },
        "verifier_summary": _verifier_summary(verifier_result),
        "current_work_item_count": len(current_work_items or []),
        "context_pack_summary": {
            "model_event_count": (context_pack or {}).get("model_event_count"),
            "work_item_count": len((context_pack or {}).get("current_work_items", [])),
        },
        "latest_window_event_ids": latest_kept,
    }


def summarize_run_diagnosis(diagnosis: dict[str, Any] | None) -> dict[str, Any]:
    diagnosis = diagnosis or {}
    open_loop = diagnosis.get("open_loop_diagnosis") or {}
    memory = diagnosis.get("memory_funnel") or {}
    quality = diagnosis.get("final_output_quality") or {}
    verifier = diagnosis.get("verifier_summary") or {}
    parsing = diagnosis.get("parsing_quality") or {}
    return {
        "answered_open_loop_count": len(open_loop.get("answered_open_loops") or []),
        "unresolved_open_loop_count": len(open_loop.get("unresolved_open_loops") or []),
        "stale_output_risk_count": len(open_loop.get("stale_output_risks") or []),
        "accepted_memory_ids": [
            item.get("decision_id") for item in memory.get("accepted", []) if isinstance(item, dict)
        ],
        "rejected_memory_ids": [
            {
                "decision_id": item.get("decision_id"),
                "reasons": item.get("reasons", []),
            }
            for item in memory.get("rejected", [])
            if isinstance(item, dict)
        ],
        "possible_semantic_gaps": memory.get("possible_semantic_gaps", []),
        "safe_but_weak": bool(quality.get("safe_but_weak")),
        "likely_failure_category": quality.get("likely_failure_category", "none"),
        "direct_ask": bool(quality.get("direct_ask")),
        "passive_owner_statement": bool(quality.get("passive_owner_statement")),
        "low_quality_named_owner_terms": quality.get("low_quality_named_owner_terms", []),
        "move_visible_intent_mismatch": bool(quality.get("move_visible_intent_mismatch")),
        "actionability_failure_category": quality.get("actionability_failure_category", "none"),
        "no_safe_wording_quality": quality.get("no_safe_wording_quality", "not_applicable"),
        "provider_output_was_invalid": bool(quality.get("provider_output_was_invalid")),
        "provider_output_invalid_reason": quality.get("provider_output_invalid_reason"),
        "planning_failure_category": quality.get("planning_failure_category"),
        "planner_validation_error": (diagnosis.get("planning_failure") or {}).get("planner_validation_error"),
        "provider_schema_error": bool((diagnosis.get("planning_failure") or {}).get("provider_schema_error")),
        "target_dedup_applied": bool(quality.get("target_dedup_applied")),
        "move_normalized_from": quality.get("move_normalized_from"),
        "move_normalized_to": quality.get("move_normalized_to"),
        "verifier_status": verifier.get("status"),
        "meaningful_verifier_checks": verifier.get("meaningful_checks", []),
        "parsing_quality": parsing,
        "recovered_compact_author_count": parsing.get("recovered_compact_author_count", 0),
        "compact_author_recovery_examples": parsing.get("compact_author_recovery_examples", []),
        "human_operator_event_count": parsing.get("human_operator_event_count", 0),
        "planner_grounding_event_count": parsing.get("planner_grounding_event_count", 0),
        "human_diagnostic_grounding_count": parsing.get("human_diagnostic_grounding_count", 0),
        "retained_high_signal_diagnostic_event_ids": parsing.get("retained_high_signal_diagnostic_event_ids", []),
        "dropped_high_signal_diagnostic_event_ids": parsing.get("dropped_high_signal_diagnostic_event_ids", []),
        "detected_diagnostic_fact_ids": parsing.get("detected_diagnostic_fact_ids", []),
        "retained_diagnostic_fact_ids": parsing.get("retained_diagnostic_fact_ids", []),
        "dropped_diagnostic_fact_ids": parsing.get("dropped_diagnostic_fact_ids", []),
    }
