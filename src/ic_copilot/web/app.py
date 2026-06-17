from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from ic_copilot.error_sanitizer import sanitize_user_facing_error
from ic_copilot.incident_loader import incident_id_from_path, load_incident_events
from ic_copilot.input_processing import assess_input_size, select_latest_window
from ic_copilot.llm.product_client import ProductConfigurationError
from ic_copilot.llm.providers.base_json import ProviderJSONError
from ic_copilot.product_knowledge import ProductKnowledgeError, product_knowledge_status, validate_product_knowledge
from ic_copilot.provider_health import check_product_provider_health
from ic_copilot.run_diagnosis import summarize_run_diagnosis
from ic_copilot.runtime_config import load_product_runtime_config
from ic_copilot.runtime_diagnostics import collect_provider_runtime_diagnostics, format_provider_diagnostics_for_ui
from ic_copilot.storage import init_db
from ic_copilot.web.models import (
    FeedbackRequest,
    PipelineStepEvent,
    RunRequest,
    RunResultView,
)
from ic_copilot.web.pipeline_events import STEP_ORDER, run_pipeline_with_progress
from ic_copilot.web.run_store import (
    add_step_event,
    create_run,
    delete_all_runs,
    delete_run,
    get_step_artifact,
    get_run,
    init_web_db,
    list_feedback,
    list_runs,
    list_step_artifacts,
    list_step_events,
    mark_stale_running_runs,
    save_feedback,
    save_step_artifact,
    update_run,
)


ROOT = Path(__file__).resolve().parents[3]
WEB_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = Path(".ic_copilot/web.sqlite3")
DEFAULT_INPUT_DIR = Path(".ic_copilot/web_inputs")
SECRET_PATTERNS = (
    re.compile(r"bearer\s+[a-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"api[_-]?key\s*[:=]\s*[a-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"sk-[a-z0-9]{20,}", re.IGNORECASE),
)
ALLOWED_PATH_ROOTS = (
    "data/sample",
    "data/contract",
    ".ic_copilot/web_inputs",
)


def _as_path(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    return Path(value)


def _safe_filename(name: str | None) -> str:
    raw = Path(name or "upload.txt").name
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._")
    return safe or "upload.txt"


def _redact_text(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED_SECRET]", redacted)
    return redacted


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_value(item) for key, item in value.items()}
    return value


def _allowed_roots(input_dir: Path) -> list[Path]:
    roots = [ROOT / root for root in ALLOWED_PATH_ROOTS]
    roots.append(input_dir)
    return [root.resolve() for root in roots]


def _resolve_allowed_path(path_value: str | Path, input_dir: Path, label: str = "path") -> Path:
    path = Path(path_value)
    if not path.is_absolute():
        path = ROOT / path
    resolved = path.resolve()
    if os.environ.get("IC_COPILOT_WEB_ALLOW_ARBITRARY_PATHS") == "1":
        return resolved
    if not any(resolved == root or root in resolved.parents for root in _allowed_roots(input_dir)):
        raise HTTPException(status_code=400, detail=f"{label} is outside allowed local roots")
    return resolved


def _extract_section(output: str, label: str) -> str | None:
    pattern = re.compile(rf"{re.escape(label)}:\n(.*?)(?:\n\n[A-Z ]+:\n|\Z)", re.DOTALL)
    match = pattern.search(output)
    return match.group(1).strip() if match else None


def _run_result_view(run: dict[str, Any]) -> RunResultView | None:
    result = run.get("result_json") or {}
    trace = result.get("trace") or {}
    final_output = run.get("final_output") or trace.get("final_output") or ""
    if not final_output:
        return None
    state = result.get("state") or trace.get("current_state") or {}
    verifier = result.get("verifier_result") or trace.get("verifier_result") or {}
    incident_brief = trace.get("incident_brief") or result.get("incident_brief") or {}
    incident_read = trace.get("incident_read_and_whisper") or result.get("incident_read_and_whisper") or {}
    incident_read_v2 = (
        (trace.get("safety_summary") or {}).get("incident_read_and_whisper_v2")
        or result.get("incident_read_and_whisper_v2")
        or {}
    )
    latest_window_selection = trace.get("latest_window_selection") or result.get("latest_window_selection") or {}
    clean_context = trace.get("clean_context") or result.get("clean_context") or {}
    sharp_blocker = trace.get("sharp_blocker_assessment") or result.get("sharp_blocker_assessment") or {}
    safety = trace.get("safety_summary") or result.get("safety_summary") or {}
    run_diagnosis = trace.get("run_diagnosis") or result.get("run_diagnosis") or {}
    diagnosis_summary = summarize_run_diagnosis(run_diagnosis)
    return RunResultView(
        run_id=run["run_id"],
        final_output=final_output,
        say_this=_extract_section(final_output, "SAY THIS"),
        next_line=_extract_section(final_output, "NEXT LINE"),
        command=_extract_section(final_output, "COMMAND"),
        do_not_ask=_do_not_ask_items(state, verifier, safety),
        why={
            "phase": state.get("phase"),
            "current_blocker": state.get("current_blocker"),
            "compact_summary": state.get("compact_summary"),
            "incident_brief_summary": incident_brief.get("current_summary"),
            "incident_brief_latest_blocker": (incident_brief.get("latest_blocker") or {}).get("blocker_type"),
            "current_read": incident_read.get("current_read"),
            "latest_open_loop": incident_read.get("latest_open_loop"),
            "v2_blocker_type": ((incident_read_v2.get("next_blocker") or {}).get("blocker_type")),
            "v2_blocker_summary": ((incident_read_v2.get("next_blocker") or {}).get("blocker_summary")),
            "v2_target_reason": ((incident_read_v2.get("next_blocker") or {}).get("best_target_reason")),
            "usefulness_status": safety.get("usefulness_status"),
            "state_quality_status": safety.get("state_quality_status"),
            "parser_quality_status": safety.get("parser_quality_status"),
            "latest_window_reason": latest_window_selection.get("reason"),
            "selected_target_ids": trace.get("selected_target_ids", []),
            "allowed_target_count": len(trace.get("allowed_targets") or result.get("allowed_targets") or []),
            "clean_summary": clean_context.get("clean_summary"),
            "sharp_blocker": sharp_blocker.get("blocker_type"),
            "sharp_blocker_summary": sharp_blocker.get("blocker_summary"),
            "visible_workstreams": [
                item.get("summary") for item in sharp_blocker.get("visible_workstreams", []) if isinstance(item, dict)
            ],
            "role_candidates": [
                f"{item.get('name')}:{item.get('role_type')}"
                for item in sharp_blocker.get("role_candidates", [])
                if isinstance(item, dict)
            ],
            "technical_status_targets": sharp_blocker.get("technical_status_targets", []),
            "validation_targets": sharp_blocker.get("customer_or_reporter_validation_targets", []),
            "engaged_entities": [entity.get("display_name") for entity in state.get("engaged_entities", [])],
            "suggested_but_not_engaged": [
                entity.get("display_name") for entity in state.get("suggested_but_not_engaged", [])
            ],
            "input_event_ids": trace.get("input_event_ids", []),
            "retrieved_memory_ids": trace.get("retrieved_memory_ids", []),
            "accepted_memory_ids": trace.get("accepted_memory_ids", []),
            "runtime_knowledge_counts": safety.get("runtime_knowledge_counts")
            or (trace.get("context_pack_summary") or {}).get("runtime_knowledge_counts")
            or {},
            "catalog_match_ids": trace.get("catalog_match_ids", []),
            "blocked_claims": verifier.get("blocked_claims", []),
            "original_blocked_claims": safety.get("original_blocked_claims", []),
            "failed_checks": safety.get("failed_checks", []),
            "repair_reason": safety.get("repair_reason"),
            "answered_open_loop_count": diagnosis_summary.get("answered_open_loop_count"),
            "unresolved_open_loop_count": diagnosis_summary.get("unresolved_open_loop_count"),
            "safe_but_weak": diagnosis_summary.get("safe_but_weak"),
            "likely_failure_category": diagnosis_summary.get("likely_failure_category"),
            "direct_ask": diagnosis_summary.get("direct_ask"),
            "passive_owner_statement": diagnosis_summary.get("passive_owner_statement"),
            "low_quality_named_owner_terms": diagnosis_summary.get("low_quality_named_owner_terms", []),
            "move_visible_intent_mismatch": diagnosis_summary.get("move_visible_intent_mismatch"),
            "actionability_failure_category": diagnosis_summary.get("actionability_failure_category"),
            "no_safe_wording_quality": diagnosis_summary.get("no_safe_wording_quality"),
            "target_dedup_applied": diagnosis_summary.get("target_dedup_applied"),
            "move_normalized_from": diagnosis_summary.get("move_normalized_from"),
            "move_normalized_to": diagnosis_summary.get("move_normalized_to"),
        },
        verifier_status=verifier.get("final_status") or safety.get("verifier_status"),
        verifier_passed=bool(verifier.get("passed") or safety.get("verifier_passed")),
        fallback_used=bool(safety.get("fallback_used")),
        trace_id=run.get("trace_id") or trace.get("trace_id"),
        total_elapsed_ms=run.get("total_elapsed_ms"),
    )


def _do_not_ask_items(
    state: dict[str, Any],
    verifier: dict[str, Any],
    safety: dict[str, Any] | None = None,
) -> list[str]:
    items: list[str] = []
    safety = safety or {}
    items.extend(state.get("stale_question_intents", []))
    for question in state.get("answered_questions", []):
        intent = question.get("intent")
        if intent:
            items.append(intent)
    for claim in verifier.get("blocked_claims", []):
        lowered = str(claim).lower()
        if "stale" in lowered or "already" in lowered:
            items.append(str(claim))
    if safety.get("fallback_used"):
        for claim in safety.get("original_blocked_claims", []):
            lowered = str(claim).lower()
            if "stale" in lowered or "already" in lowered:
                items.append(str(claim))
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def _debug_summary_from_run(run: dict[str, Any]) -> dict[str, Any]:
    result = run.get("result_json") or {}
    trace = result.get("trace") or {}
    state = result.get("state") or trace.get("current_state") or {}
    verifier = result.get("verifier_result") or trace.get("verifier_result") or {}
    incident_brief = trace.get("incident_brief") or result.get("incident_brief") or {}
    incident_read = trace.get("incident_read_and_whisper") or result.get("incident_read_and_whisper") or {}
    safety = trace.get("safety_summary") or result.get("safety_summary") or {}
    incident_read_v2 = safety.get("incident_read_and_whisper_v2") or result.get("incident_read_and_whisper_v2") or {}
    v2_quality_gate = safety.get("v2_quality_gate") or {}
    latest_window_selection = trace.get("latest_window_selection") or result.get("latest_window_selection") or {}
    allowed_targets = trace.get("allowed_targets") or result.get("allowed_targets") or []
    rejected_non_targetable = (
        trace.get("rejected_non_targetable_candidates") or result.get("rejected_non_targetable_candidates") or []
    )
    clean_context = trace.get("clean_context") or result.get("clean_context") or {}
    sharp_blocker = trace.get("sharp_blocker_assessment") or result.get("sharp_blocker_assessment") or {}
    semantic = trace.get("semantic_intent_assessment") or result.get("semantic_intent_assessment") or {}
    raw_decision = trace.get("raw_decision") or result.get("raw_decision") or {}
    rendered = trace.get("rendered_decision") or result.get("decision") or {}
    run_diagnosis = trace.get("run_diagnosis") or result.get("run_diagnosis") or {}
    diagnosis_summary = summarize_run_diagnosis(run_diagnosis)
    clean_turn_ledger = trace.get("clean_turn_ledger") or result.get("clean_turn_ledger") or {}
    actor_ledger = trace.get("actor_workstream_ledger") or result.get("actor_workstream_ledger") or {}
    fact_ledger = trace.get("incident_fact_ledger") or result.get("incident_fact_ledger") or {}
    question_ledger = trace.get("question_intent_ledger") or result.get("question_intent_ledger") or {}
    metadata = raw_decision.get("model_metadata") or {}
    fallback_events = []
    fallback_input_assessment = None
    fallback_latest_window_selection = None
    if not result.get("events") and run.get("input_path"):
        try:
            input_path = Path(run["input_path"])
            fallback_events = load_incident_events(input_path, incident_id=incident_id_from_path(input_path))
            fallback_input_assessment = assess_input_size(input_path.read_text(errors="replace"), fallback_events)
            fallback_latest_window_selection = select_latest_window(fallback_events, max_events=35)
        except Exception:
            fallback_events = []
    original_blocked_claims = safety.get("original_blocked_claims") or verifier.get("blocked_claims", [])
    semantic_stale = semantic.get("stale_intent_matches") or safety.get("semantic_stale_matches") or []
    blocked_stale_intents = sorted(
        {
            match.group(1)
            for claim in original_blocked_claims
            for match in [re.search(r"stale question intent:\s*([A-Za-z0-9_-]+)", str(claim))]
            if match
        }
        .union(set(state.get("stale_question_intents", [])))
        .union(
            {
                match.get("matched_stale_intent")
                for match in semantic_stale
                if isinstance(match, dict) and match.get("matched_stale_intent")
            }
        )
    )

    def _rejected_entity_label(entity: dict[str, Any]) -> str:
        name = entity.get("display_name") or "unknown"
        entity_type = entity.get("entity_type") or "unknown"
        status = str(entity.get("status") or "rejected")
        reason = status.removeprefix("rejected:")
        if reason == "url_path_number":
            entity_type = "tenant"
        return f"{name} ({entity_type}:{reason})"

    return {
        "run_id": run["run_id"],
        "status": run.get("status"),
        "error": _redact_text(run.get("error") or ""),
        "normalized_event_count": len(result.get("events") or trace.get("input_event_ids", []) or fallback_events),
        "first_event_id": (
            (result.get("events") or [{}])[0].get("event_id")
            if result.get("events")
            else (trace.get("input_event_ids") or [None])[0]
            if trace.get("input_event_ids")
            else fallback_events[0].event_id
            if fallback_events
            else None
        ),
        "last_event_id": (
            (result.get("events") or [{}])[-1].get("event_id")
            if result.get("events")
            else (trace.get("input_event_ids") or [None])[-1]
            if trace.get("input_event_ids")
            else fallback_events[-1].event_id
            if fallback_events
            else None
        ),
        "input_size_assessment": safety.get("input_size_assessment")
        or trace.get("input_size_assessment")
        or (fallback_input_assessment.model_dump(mode="json") if fallback_input_assessment else None),
        "latest_window_selection": latest_window_selection
        or safety.get("latest_window_selection")
        or (fallback_latest_window_selection.model_dump(mode="json") if fallback_latest_window_selection else None),
        "latest_window_reason": latest_window_selection.get("reason")
        or (safety.get("latest_window_selection") or {}).get("reason")
        or (fallback_latest_window_selection.reason if fallback_latest_window_selection else None),
        "processing_strategy": safety.get("processing_strategy") or trace.get("processing_strategy"),
        "chunk_count": safety.get("chunk_count") or trace.get("chunk_count"),
        "chunk_success_count": safety.get("chunk_success_count") or trace.get("chunk_success_count"),
        "chunk_failure_count": safety.get("chunk_failure_count") or trace.get("chunk_failure_count"),
        "provider_timeout_stage": safety.get("provider_timeout_stage") or trace.get("provider_timeout_stage"),
        "retry_attempted": safety.get("retry_attempted") or trace.get("retry_attempted"),
        "retry_strategy": safety.get("retry_strategy") or trace.get("retry_strategy"),
        "incident_brief_attempt_count": safety.get("incident_brief_attempt_count")
        or trace.get("incident_brief_attempt_count"),
        "incident_brief_attempts": safety.get("incident_brief_attempts")
        or trace.get("incident_brief_attempts", []),
        "compact_payload_event_count": safety.get("compact_payload_event_count")
        or trace.get("compact_payload_event_count"),
        "compact_payload_char_count": safety.get("compact_payload_char_count")
        or trace.get("compact_payload_char_count"),
        "ultra_compact_payload_event_count": safety.get("ultra_compact_payload_event_count")
        or trace.get("ultra_compact_payload_event_count"),
        "ultra_compact_payload_char_count": safety.get("ultra_compact_payload_char_count")
        or trace.get("ultra_compact_payload_char_count"),
        "terminal_failure_reason": safety.get("terminal_failure_reason")
        or trace.get("terminal_failure_reason"),
        "state_delta_status": safety.get("state_delta_status"),
        "full_context_enrichment_status": safety.get("full_context_enrichment_status"),
        "reconstructed_turn_count": safety.get("reconstructed_turn_count") or trace.get("reconstructed_turn_count"),
        "reconstructed_turns_used": bool(safety.get("reconstructed_turns_used") or trace.get("reconstructed_turns_used")),
        "turn_reconstruction_warnings": safety.get("turn_reconstruction_warnings")
        or trace.get("turn_reconstruction_warnings", []),
        "semantic_read": {
            "success_count": safety.get("semantic_read_success_count"),
            "failed_readers": safety.get("semantic_read_failed_readers", []),
            "clean_turns": len(clean_turn_ledger.get("clean_turns", []))
            if isinstance(clean_turn_ledger, dict)
            else 0,
            "actors": len(actor_ledger.get("actors", [])) if isinstance(actor_ledger, dict) else 0,
            "workstreams": len(actor_ledger.get("workstreams", []))
            if isinstance(actor_ledger, dict)
            else 0,
            "fact_phase": (fact_ledger.get("phase") or {}).get("value")
            if isinstance(fact_ledger, dict)
            else None,
            "question_do_not_ask": [
                item.get("intent")
                for item in question_ledger.get("do_not_ask", [])
                if isinstance(item, dict)
            ]
            if isinstance(question_ledger, dict)
            else [],
        },
        "incident_read_and_whisper": {
            "current_read": incident_read.get("current_read"),
            "latest_open_loop": incident_read.get("latest_open_loop"),
            "selected_move": incident_read.get("selected_move"),
            "selected_target_id": incident_read.get("selected_target_id"),
            "selected_target_display_name": incident_read.get("selected_target_display_name"),
            "already_answered": incident_read.get("already_answered", []),
            "evidence_count": len(incident_read.get("evidence", [])) if isinstance(incident_read, dict) else 0,
            "confidence": incident_read.get("confidence"),
        },
        "incident_read_and_whisper_v2": incident_read_v2,
        "v2_quality_gate": v2_quality_gate,
        "product_path": safety.get("processing_strategy") or v2_quality_gate.get("product_path"),
        "safety_status": safety.get("safety_status") or v2_quality_gate.get("safety_status"),
        "usefulness_status": safety.get("usefulness_status") or v2_quality_gate.get("usefulness_status"),
        "state_quality_status": safety.get("state_quality_status") or v2_quality_gate.get("state_quality_status"),
        "parser_quality_status": safety.get("parser_quality_status") or v2_quality_gate.get("parser_quality_status"),
        "v2_blocker_type": safety.get("v2_blocker_type") or v2_quality_gate.get("blocker_type"),
        "v2_state_summary": safety.get("v2_state_summary") or v2_quality_gate.get("state_summary"),
        "context_pack_summary": trace.get("context_pack_summary") or safety.get("context_pack_summary"),
        "parsing_quality": {
            "normalized_event_count": diagnosis_summary.get("parsing_quality", {}).get(
                "normalized_event_count",
                len(result.get("events") or trace.get("input_event_ids", []) or fallback_events),
            ),
            "recovered_compact_author_count": safety.get("recovered_compact_author_count")
            or diagnosis_summary.get("recovered_compact_author_count", 0),
            "compact_author_recovery_examples": safety.get("compact_author_recovery_examples")
            or diagnosis_summary.get("compact_author_recovery_examples", []),
            "human_operator_event_count": diagnosis_summary.get("human_operator_event_count", 0),
            "planner_grounding_event_count": diagnosis_summary.get("planner_grounding_event_count", 0),
            "human_diagnostic_grounding_count": safety.get("human_diagnostic_grounding_count")
            or diagnosis_summary.get("human_diagnostic_grounding_count", 0),
            "retained_high_signal_diagnostic_event_ids": safety.get("retained_high_signal_diagnostic_event_ids")
            or diagnosis_summary.get("retained_high_signal_diagnostic_event_ids", []),
            "dropped_high_signal_diagnostic_event_ids": safety.get("dropped_high_signal_diagnostic_event_ids")
            or diagnosis_summary.get("dropped_high_signal_diagnostic_event_ids", []),
            "diagnostic_fact_classifications": safety.get("diagnostic_fact_classifications")
            or (trace.get("context_pack_summary") or {}).get("diagnostic_fact_classifications", []),
            "diagnostic_behavior_contracts": safety.get("diagnostic_behavior_contracts")
            or (trace.get("context_pack_summary") or {}).get("diagnostic_behavior_contracts", []),
            "diagnostic_actionability": safety.get("diagnostic_actionability")
            or (trace.get("context_pack_summary") or {}).get("diagnostic_actionability", []),
            "likely_failure_category": diagnosis_summary.get("likely_failure_category"),
        },
        "work_item_count": safety.get("work_item_count"),
        "work_item_labels": safety.get("work_item_labels", []),
        "permission_denied_work_items": safety.get("permission_denied_work_items", []),
        "json_log_pseudo_author_count": safety.get("json_log_pseudo_author_count", 0),
        "rejected_json_log_target_examples": safety.get("rejected_json_log_target_examples", []),
        "accepted_sync_latency_memory_ids": safety.get("accepted_sync_latency_memory_ids", []),
        "permission_denied_wrong_owner_check": safety.get("permission_denied_wrong_owner_check"),
        "permission_denied_wrong_owner_detail": safety.get("permission_denied_wrong_owner_detail"),
        "no_private_identifier_in_visible_output": safety.get("no_private_identifier_in_visible_output"),
        "no_json_log_target": safety.get("no_json_log_target"),
        "candidate_targets": safety.get("candidate_targets", []),
        "rejected_targets": safety.get("rejected_targets", []),
        "phase": state.get("phase"),
        "blocker": state.get("current_blocker"),
        "incident_brief_summary": incident_brief.get("current_summary"),
        "incident_brief_phase": (incident_brief.get("phase") or {}).get("primary"),
        "incident_brief_latest_blocker": incident_brief.get("latest_blocker"),
        "incident_brief_do_not_ask": [
            item.get("intent") for item in incident_brief.get("do_not_ask", []) if isinstance(item, dict)
        ],
        "recommended_ic_focus": incident_brief.get("recommended_ic_focus"),
        "allowed_target_count": len(allowed_targets),
        "target_shortlist": trace.get("target_shortlist") or safety.get("target_shortlist", []),
        "preferred_target_ids": (incident_brief.get("recommended_ic_focus") or {}).get("preferred_target_ids", []),
        "selected_target_ids": trace.get("selected_target_ids", []),
        "latest_window_event_ids": trace.get("latest_window_event_ids", [])
        or latest_window_selection.get("event_ids", [])
        or (fallback_latest_window_selection.event_ids if fallback_latest_window_selection else []),
        "rejected_non_targetable_candidates": [
            {
                "target_id": item.get("target_id"),
                "display_name": item.get("display_name"),
                "reason": item.get("reason"),
            }
            for item in rejected_non_targetable
            if isinstance(item, dict)
        ],
        "clean_summary": clean_context.get("clean_summary"),
        "clean_phase": (clean_context.get("phase") or {}).get("value"),
        "clean_blocker": (clean_context.get("current_blocker") or {}).get("blocker_type"),
        "sharp_blocker": sharp_blocker.get("blocker_type"),
        "sharp_blocker_summary": sharp_blocker.get("blocker_summary"),
        "visible_workstreams": [
            {
                "type": item.get("workstream_type"),
                "status": item.get("status"),
                "summary": item.get("summary"),
            }
            for item in sharp_blocker.get("visible_workstreams", [])
            if isinstance(item, dict)
        ],
        "role_candidates": [
            {
                "name": item.get("name"),
                "role_type": item.get("role_type"),
                "status": item.get("status"),
            }
            for item in sharp_blocker.get("role_candidates", [])
            if isinstance(item, dict)
        ],
        "technical_status_targets": sharp_blocker.get("technical_status_targets", []),
        "validation_targets": sharp_blocker.get("customer_or_reporter_validation_targets", []),
        "wrong_next_moves": [
            item.get("move_or_intent") for item in sharp_blocker.get("wrong_next_moves", []) if isinstance(item, dict)
        ],
        "engaged_entities": [entity.get("display_name") for entity in state.get("engaged_entities", [])],
        "suggested_but_not_engaged": [
            entity.get("display_name") for entity in state.get("suggested_but_not_engaged", [])
        ],
        "stale_question_intents": state.get("stale_question_intents", []),
        "blocked_stale_intents": blocked_stale_intents,
        "semantic_stale_matches": semantic_stale,
        "rejected_entities": [_rejected_entity_label(entity) for entity in state.get("rejected_entities", [])],
        "retrieved_memory_ids": trace.get("retrieved_memory_ids", []),
        "accepted_memory_ids": trace.get("accepted_memory_ids", []),
        "run_diagnosis": run_diagnosis,
        "run_diagnosis_summary": diagnosis_summary,
        "answered_open_loop_count": diagnosis_summary.get("answered_open_loop_count"),
        "unresolved_open_loop_count": diagnosis_summary.get("unresolved_open_loop_count"),
        "safe_but_weak": diagnosis_summary.get("safe_but_weak"),
        "likely_failure_category": diagnosis_summary.get("likely_failure_category"),
        "direct_ask": diagnosis_summary.get("direct_ask"),
        "passive_owner_statement": diagnosis_summary.get("passive_owner_statement"),
        "low_quality_named_owner_terms": diagnosis_summary.get("low_quality_named_owner_terms", []),
        "move_visible_intent_mismatch": diagnosis_summary.get("move_visible_intent_mismatch"),
        "actionability_failure_category": diagnosis_summary.get("actionability_failure_category"),
        "no_safe_wording_quality": diagnosis_summary.get("no_safe_wording_quality"),
        "target_dedup_applied": diagnosis_summary.get("target_dedup_applied"),
        "move_normalized_from": diagnosis_summary.get("move_normalized_from"),
        "move_normalized_to": diagnosis_summary.get("move_normalized_to"),
        "provider_output_was_invalid": diagnosis_summary.get("provider_output_was_invalid")
        or safety.get("provider_output_was_invalid"),
        "provider_output_invalid_reason": diagnosis_summary.get("provider_output_invalid_reason")
        or safety.get("provider_output_invalid_reason"),
        "planning_failure_category": diagnosis_summary.get("planning_failure_category")
        or safety.get("planning_failure_category"),
        "provider_schema_error": diagnosis_summary.get("provider_schema_error") or safety.get("provider_schema_error"),
        "provider_json_parse_error": safety.get("provider_json_parse_error"),
        "provider_invalid_fields": safety.get("provider_invalid_fields", []),
        "provider_raw_output_redacted_excerpt": safety.get("provider_raw_output_redacted_excerpt"),
        "rejected_memory_ids_with_reasons": diagnosis_summary.get("rejected_memory_ids", []),
        "possible_semantic_gaps": diagnosis_summary.get("possible_semantic_gaps", []),
        "verifier_status": verifier.get("final_status") or safety.get("verifier_status"),
        "failed_verifier_checks": safety.get("failed_checks", []),
        "stale_status_recap_check": safety.get("stale_status_recap_check"),
        "stale_status_recap_check_detail": safety.get("stale_status_recap_check_detail"),
        "no_premature_rca": (verifier.get("checks") or {}).get("no_premature_rca"),
        "role_target_aligned": (verifier.get("checks") or {}).get("role_target_aligned"),
        "fallback_used": bool(safety.get("fallback_used")),
        "planner_fallback_used": bool(safety.get("planner_fallback_used") or metadata.get("planner_fallback_used")),
        "repair_attempted": bool(safety.get("repair_attempted")),
        "repair_used": bool(safety.get("repair_used")),
        "repair_reason": safety.get("repair_reason"),
        "repair_verifier_status": safety.get("repair_verifier_status"),
        "repair_selected_target_ids": safety.get("repair_selected_target_ids", []),
        "why_no_safe_recommendation": safety.get("why_no_safe_recommendation"),
        "repaired_from_move": (rendered.get("model_metadata") or {}).get("repaired_from_move")
        or safety.get("original_model_move")
        or metadata.get("original_move"),
        "repaired_to_move": (rendered.get("model_metadata") or {}).get("repaired_to_move") or rendered.get("move"),
        "domain_intent": raw_decision.get("domain_intent") or safety.get("domain_intent"),
        "original_model_move": metadata.get("original_move") or safety.get("original_model_move"),
        "planner_validation_error": metadata.get("planner_validation_error")
        or diagnosis_summary.get("planner_validation_error")
        or safety.get("planner_validation_error"),
        "command_suggestion": _extract_section(run.get("final_output") or "", "COMMAND"),
        "trace_id": run.get("trace_id") or trace.get("trace_id"),
        "total_elapsed_ms": run.get("total_elapsed_ms"),
        "output_move": rendered.get("move"),
    }


def _result_payload(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "events": [event.model_dump(mode="json") for event in result.get("events", [])],
        "trigger": result["trigger"].model_dump(mode="json"),
        "slack_turn_reconstruction": (
            result["slack_turn_reconstruction"].model_dump(mode="json")
            if result.get("slack_turn_reconstruction")
            else None
        ),
        "allowed_targets": [target.model_dump(mode="json") for target in result.get("allowed_targets", [])],
        "latest_window_selection": (
            result["latest_window_selection"].model_dump(mode="json")
            if result.get("latest_window_selection")
            else None
        ),
        "context_pack_summary": result.get("context_pack_summary", {}),
        "incident_read_and_whisper": (
            result["incident_read_and_whisper"].model_dump(mode="json")
            if result.get("incident_read_and_whisper")
            else None
        ),
        "incident_read_and_whisper_v2": (
            result["incident_read_and_whisper_v2"].model_dump(mode="json")
            if result.get("incident_read_and_whisper_v2")
            else None
        ),
        "step_artifacts": result.get("step_artifacts", []),
        "clean_turn_ledger": (
            result["clean_turn_ledger"].model_dump(mode="json")
            if result.get("clean_turn_ledger")
            else None
        ),
        "actor_workstream_ledger": (
            result["actor_workstream_ledger"].model_dump(mode="json")
            if result.get("actor_workstream_ledger")
            else None
        ),
        "incident_fact_ledger": (
            result["incident_fact_ledger"].model_dump(mode="json")
            if result.get("incident_fact_ledger")
            else None
        ),
        "question_intent_ledger": (
            result["question_intent_ledger"].model_dump(mode="json")
            if result.get("question_intent_ledger")
            else None
        ),
        "incident_brief": result["incident_brief"].model_dump(mode="json") if result.get("incident_brief") else None,
        "clean_context": result["clean_context"].model_dump(mode="json") if result.get("clean_context") else None,
        "sharp_blocker_assessment": (
            result["sharp_blocker_assessment"].model_dump(mode="json")
            if result.get("sharp_blocker_assessment")
            else None
        ),
        "state": result["state"].model_dump(mode="json"),
        "memory_ids": result.get("memory_ids", []),
        "accepted_memories": [item.model_dump(mode="json") for item in result.get("accepted_memories", [])],
        "decision": result["decision"].model_dump(mode="json"),
        "raw_decision": result["raw_decision"].model_dump(mode="json"),
        "verifier_result": result["verifier_result"].model_dump(mode="json"),
        "semantic_intent_assessment": (
            result["semantic_intent_assessment"].model_dump(mode="json")
            if result.get("semantic_intent_assessment")
            else None
        ),
        "final_output": result["final_output"],
        "trace": result["trace"].model_dump(mode="json"),
        "latency_ms": result.get("latency_ms"),
    }


def _run_list_item(run: dict[str, Any]) -> dict[str, Any]:
    result = run.get("result_json") or {}
    trace = result.get("trace") or {}
    verifier = result.get("verifier_result") or trace.get("verifier_result") or {}
    final_output = run.get("final_output") or ""
    return {
        "run_id": run["run_id"],
        "created_at": run.get("created_at"),
        "updated_at": run.get("updated_at"),
        "status": run.get("status"),
        "input_kind": run.get("input_kind"),
        "input_name": run.get("input_name"),
        "total_elapsed_ms": run.get("total_elapsed_ms"),
        "verifier_status": verifier.get("final_status") or (trace.get("safety_summary") or {}).get("verifier_status"),
        "trace_id": run.get("trace_id"),
        "final_output_preview": final_output[:240],
    }


def _feedback_jsonl(rows: list[dict[str, Any]]) -> str:
    clean_rows = []
    for row in rows:
        clean = {
            "label_id": row.get("label_id"),
            "run_id": row.get("run_id"),
            "created_at": row.get("created_at"),
            "usefulness": row.get("usefulness"),
            "failure_tags": row.get("failure_tags_json") or [],
            "reviewer_notes": _redact_text(row.get("reviewer_notes") or ""),
            "final_output_snapshot": _redact_text(row.get("final_output_snapshot") or ""),
        }
        clean_rows.append(clean)
    return "".join(json.dumps(row, default=str) + "\n" for row in clean_rows)


def _safe_read_text(path: Path) -> str:
    return _redact_text(path.read_text(errors="replace"))


def _mark_stale_runs(path: Path) -> None:
    try:
        config = load_product_runtime_config()
        threshold = int(config.timeouts.total_pipeline_hard_timeout_seconds + 15)
    except Exception:
        threshold = 90
    mark_stale_running_runs(path, older_than_seconds=threshold)


def _run_pipeline_background(
    run_id: str,
    incident_file: Path,
    request: RunRequest,
    db_path: Path,
    input_dir: Path,
    llm_client: Any | None = None,
) -> None:
    started = time.perf_counter()
    update_run(run_id, path=db_path, status="running")

    def on_event(event: PipelineStepEvent) -> None:
        add_step_event(event, path=db_path)

    def on_artifact(artifact: Any) -> None:
        save_step_artifact(
            run_id=run_id,
            step=artifact.step,
            artifact_type=artifact.artifact_type,
            summary_json=artifact.summary_json,
            payload_json=artifact.payload_json,
            redacted=artifact.redacted,
            warnings=artifact.warnings,
            error=artifact.error,
            path=db_path,
        )

    def add_failure_complete_event(error: str) -> None:
        if any(event["step"] == "complete" and event["status"] == "failed" for event in list_step_events(run_id, db_path)):
            return
        add_step_event(
            PipelineStepEvent(run_id=run_id, step="complete", status="failed", message="Pipeline failed", error=error),
            path=db_path,
        )

    try:
        result = run_pipeline_with_progress(
            incident_file=incident_file,
            catalog_path=None,
            memory_path=None,
            command_registry_path=None,
            save_trace=request.save_trace,
            on_event=on_event,
            on_artifact=on_artifact,
            run_id=run_id,
            llm_client=llm_client,
        )
        payload = _result_payload(result)
        update_run(
            run_id,
            path=db_path,
            status="succeeded",
            total_elapsed_ms=result.get("latency_ms"),
            final_output=result["final_output"],
            trace_id=result["trace"].trace_id,
            result_json=payload,
        )
    except (ProductConfigurationError, ProductKnowledgeError, ProviderJSONError) as exc:
        error = sanitize_user_facing_error(exc)
        add_failure_complete_event(error)
        partial_result = getattr(exc, "debug_payload", None)
        update_run(
            run_id,
            path=db_path,
            status="failed",
            error=error,
            total_elapsed_ms=int((time.perf_counter() - started) * 1000),
            result_json=_redact_value(partial_result) if partial_result else None,
        )
    except Exception as exc:
        error = sanitize_user_facing_error(exc)
        add_failure_complete_event(error)
        partial_result = getattr(exc, "debug_payload", None)
        update_run(
            run_id,
            path=db_path,
            status="failed",
            error=error,
            total_elapsed_ms=int((time.perf_counter() - started) * 1000),
            result_json=_redact_value(partial_result) if partial_result else None,
        )


def _start_background_run(
    run_id: str,
    incident_file: Path,
    request: RunRequest,
    db_path: Path,
    input_dir: Path,
    llm_client: Any | None = None,
) -> None:
    thread = threading.Thread(
        target=_run_pipeline_background,
        args=(run_id, incident_file, request, db_path, input_dir, llm_client),
        daemon=True,
    )
    thread.start()


def _delete_trace(trace_id: str | None) -> None:
    if not trace_id:
        return
    db_path = Path(os.environ.get("IC_COPILOT_DB_PATH", ".ic_copilot/traces.sqlite3"))
    if not db_path.exists():
        return
    conn = init_db(db_path)
    conn.execute("DELETE FROM traces WHERE trace_id = ?", (trace_id,))
    conn.commit()
    conn.close()


def create_app(
    db_path: str | Path = DEFAULT_DB_PATH,
    input_dir: str | Path = DEFAULT_INPUT_DIR,
    llm_client: Any | None = None,
    **_legacy_kwargs: Any,
) -> FastAPI:
    app = FastAPI(title="IC Copilot Local Web Console")
    if str(db_path) == str(DEFAULT_DB_PATH):
        db_path = os.environ.get("IC_COPILOT_WEB_DB_PATH", str(DEFAULT_DB_PATH))
    app.state.db_path = Path(db_path)
    app.state.input_dir = Path(input_dir)
    app.state.llm_client = llm_client
    app.state.provider_health = None
    init_web_db(app.state.db_path)
    _mark_stale_runs(app.state.db_path)
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return (WEB_DIR / "templates" / "index.html").read_text()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "bind": "localhost-only"}

    @app.get("/api/config")
    def config() -> dict[str, Any]:
        product_config = load_product_runtime_config()
        diagnostics = collect_provider_runtime_diagnostics()
        health = app.state.provider_health
        return {
            "runtime": "verified_ai_product",
            "provider": product_config.llm.provider,
            "model": product_config.llm.model,
            "api_key_env": product_config.llm.api_key_env,
            "api_key_configured": diagnostics.credential.present,
            "api_key_present": diagnostics.credential.present,
            "api_key_fingerprint": diagnostics.effective_key_fingerprint,
            "api_key_validated_status": health.status if health else "unknown",
            "last_provider_check_at": health.checked_at.isoformat() if health else None,
            "config_path_used": diagnostics.config_path_used,
            "setup_warnings": diagnostics.warnings + diagnostics.errors,
            "diagnostics": format_provider_diagnostics_for_ui(diagnostics),
            "product_knowledge": product_knowledge_status(product_config.product_knowledge_path),
            "localhost_only": True,
            "verifier_required": product_config.runtime.require_verifier_pass,
            "fail_closed": product_config.runtime.fail_closed,
            "action_execution": product_config.runtime.command_execution_enabled,
            "slack_posting": product_config.runtime.slack_posting_enabled,
            "paging": product_config.runtime.paging_enabled,
            "runtime_knowledge_source": "local_knowledge",
            "commands": "manual copy only; not executed",
        }

    @app.get("/api/knowledge/status")
    def knowledge_status() -> dict[str, Any]:
        product_config = load_product_runtime_config()
        return {"knowledge": product_knowledge_status(product_config.product_knowledge_path)}

    @app.post("/api/knowledge/validate")
    def knowledge_validate() -> dict[str, Any]:
        product_config = load_product_runtime_config()
        return {"validation": validate_product_knowledge(product_config.product_knowledge_path).model_dump(mode="json")}

    @app.get("/api/provider/health")
    def provider_health() -> dict[str, Any]:
        health = check_product_provider_health()
        app.state.provider_health = health
        return {"health": health.model_dump(mode="json")}

    @app.post("/api/provider/check")
    def provider_check() -> dict[str, Any]:
        return provider_health()

    @app.get("/api/samples")
    def samples() -> dict[str, list[dict[str, str]]]:
        rows: list[dict[str, str]] = []
        for path in sorted((ROOT / "data/sample/incidents").glob("*.txt")):
            rows.append(
                {
                    "name": path.name,
                    "display_name": path.stem.replace("_", " "),
                    "path": str(path.relative_to(ROOT)),
                    "kind": "sample",
                    "source": "sample",
                    "label": "Sample incident",
                }
            )
        return {"samples": rows}

    @app.post("/api/runs")
    def create_run_from_request(request: RunRequest) -> dict[str, str]:
        if not request.pasted_text and not request.sample_path:
            raise HTTPException(status_code=400, detail="Provide pasted_text or sample_path")
        if request.sample_path:
            incident_file = _resolve_allowed_path(request.sample_path, app.state.input_dir, "sample_path")
            if not incident_file.exists():
                raise HTTPException(status_code=404, detail="sample_path not found")
            input_kind = "jsonl" if incident_file.suffix == ".jsonl" else "sample"
            run_id = create_run(input_kind, incident_file.name, str(incident_file), app.state.db_path)
        else:
            run_id = create_run("paste", "pasted incident", None, app.state.db_path)
            app.state.input_dir.mkdir(parents=True, exist_ok=True)
            incident_file = app.state.input_dir / f"{run_id}.txt"
            incident_file.write_text(_redact_text(request.pasted_text or ""))
            update_run(run_id, path=app.state.db_path, input_path=str(incident_file))
        _start_background_run(run_id, incident_file, request, app.state.db_path, app.state.input_dir, app.state.llm_client)
        return {"run_id": run_id}

    @app.post("/api/runs/upload")
    async def upload_run(
        file: UploadFile = File(...),
        save_trace: bool = True,
    ) -> dict[str, str]:
        filename = _safe_filename(file.filename)
        input_kind = "jsonl" if filename.endswith(".jsonl") else "upload"
        run_id = create_run(input_kind, filename, None, app.state.db_path)
        app.state.input_dir.mkdir(parents=True, exist_ok=True)
        incident_file = app.state.input_dir / f"{run_id}_{filename}"
        incident_file.write_text(_redact_text((await file.read()).decode("utf-8", errors="replace")))
        update_run(run_id, path=app.state.db_path, input_path=str(incident_file))
        request = RunRequest(
            sample_path=str(incident_file),
            save_trace=save_trace,
        )
        _start_background_run(run_id, incident_file, request, app.state.db_path, app.state.input_dir, app.state.llm_client)
        return {"run_id": run_id}

    @app.get("/api/runs")
    def api_list_runs(limit: int = 50) -> dict[str, Any]:
        _mark_stale_runs(app.state.db_path)
        return {"runs": [_run_list_item(run) for run in list_runs(limit=limit, path=app.state.db_path)]}

    @app.get("/api/runs/{run_id}")
    def api_get_run(run_id: str) -> dict[str, Any]:
        _mark_stale_runs(app.state.db_path)
        run = get_run(run_id, app.state.db_path)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        result_view = _run_result_view(run)
        return {"run": _redact_value(run), "result": result_view.model_dump(mode="json") if result_view else None}

    @app.get("/api/runs/{run_id}/events")
    def events(run_id: str) -> StreamingResponse:
        _mark_stale_runs(app.state.db_path)
        if get_run(run_id, app.state.db_path) is None:
            raise HTTPException(status_code=404, detail="run not found")

        def stream():
            sent: set[int] = set()
            while True:
                for event in list_step_events(run_id, app.state.db_path):
                    event_id = int(event["id"])
                    if event_id in sent:
                        continue
                    sent.add(event_id)
                    yield "event: step\n"
                    yield f"data: {json.dumps(event, default=str)}\n\n"
                run = get_run(run_id, app.state.db_path)
                if run and run["status"] in {"succeeded", "failed"}:
                    event_name = "complete" if run["status"] == "succeeded" else "error"
                    yield f"event: {event_name}\n"
                    yield f"data: {json.dumps({'run_id': run_id, 'status': run['status'], 'error': run.get('error')})}\n\n"
                    break
                time.sleep(0.1)

        return StreamingResponse(stream(), media_type="text/event-stream")

    @app.get("/api/runs/{run_id}/steps")
    def run_steps(run_id: str) -> dict[str, Any]:
        if get_run(run_id, app.state.db_path) is None:
            raise HTTPException(status_code=404, detail="run not found")
        artifacts = list_step_artifacts(run_id, app.state.db_path)
        by_step: dict[str, list[dict[str, Any]]] = {}
        for artifact in artifacts:
            by_step.setdefault(artifact["step"], []).append(artifact)
        return {
            "steps": list_step_events(run_id, app.state.db_path),
            "artifacts_by_step": by_step,
        }

    @app.get("/api/runs/{run_id}/step-artifacts")
    def step_artifacts(run_id: str) -> dict[str, Any]:
        if get_run(run_id, app.state.db_path) is None:
            raise HTTPException(status_code=404, detail="run not found")
        return {"artifacts": list_step_artifacts(run_id, app.state.db_path)}

    @app.get("/api/runs/{run_id}/step-artifacts/{artifact_id}")
    def step_artifact(run_id: str, artifact_id: int) -> dict[str, Any]:
        run = get_run(run_id, app.state.db_path)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        artifact = get_step_artifact(artifact_id, app.state.db_path)
        if artifact is None or artifact["run_id"] != run_id:
            raise HTTPException(status_code=404, detail="artifact not found")
        return {"artifact": artifact}

    @app.get("/api/runs/{run_id}/trace")
    def trace(run_id: str) -> dict[str, Any]:
        run = get_run(run_id, app.state.db_path)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        result = run.get("result_json") or {}
        trace_payload = result.get("trace")
        if not trace_payload:
            raise HTTPException(status_code=404, detail="trace not available")
        return _redact_value(trace_payload)

    @app.get("/api/runs/{run_id}/debug-summary")
    def debug_summary(run_id: str) -> dict[str, Any]:
        run = get_run(run_id, app.state.db_path)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        return _redact_value(_debug_summary_from_run(run))

    @app.get("/api/runs/{run_id}/download-trace")
    def download_trace(run_id: str) -> Response:
        trace_payload = trace(run_id)
        body = json.dumps(trace_payload, indent=2, default=str)
        return Response(
            content=body,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{run_id}-trace.json"'},
        )

    @app.get("/api/runs/{run_id}/download-input")
    def download_input(run_id: str) -> Response:
        run = get_run(run_id, app.state.db_path)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        input_path = Path(run["input_path"]) if run.get("input_path") else None
        if not input_path or not input_path.exists():
            raise HTTPException(status_code=404, detail="input not available")
        resolved = _resolve_allowed_path(input_path, app.state.input_dir, "input_path")
        body = _safe_read_text(resolved)
        return Response(
            content=body,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{run_id}-input.txt"'},
        )

    @app.post("/api/runs/{run_id}/feedback")
    def feedback(run_id: str, request: FeedbackRequest) -> dict[str, str]:
        run = get_run(run_id, app.state.db_path)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        label_id = save_feedback(
            run_id,
            FeedbackRequest(
                usefulness=request.usefulness,
                failure_tags=request.failure_tags,
                reviewer_notes=_redact_text(request.reviewer_notes),
            ),
            final_output_snapshot=_redact_text(run.get("final_output") or ""),
            path=app.state.db_path,
        )
        return {"label_id": label_id, "status": "saved"}

    @app.get("/api/feedback/export")
    def feedback_export(
        format: str = "jsonl",
        run_id: str | None = None,
    ) -> Response:
        if format != "jsonl":
            raise HTTPException(status_code=400, detail="Only jsonl export is supported")
        body = _feedback_jsonl(list_feedback(run_id=run_id, path=app.state.db_path))
        return Response(
            content=body,
            media_type="application/x-ndjson",
            headers={"Content-Disposition": 'attachment; filename="web_feedback.jsonl"'},
        )

    @app.delete("/api/runs/{run_id}")
    def api_delete_run(run_id: str, delete_trace: bool = True) -> dict[str, Any]:
        existing = delete_run(run_id, app.state.db_path)
        if existing is None:
            raise HTTPException(status_code=404, detail="run not found")
        input_path = Path(existing["input_path"]) if existing.get("input_path") else None
        warnings: list[str] = []
        if input_path and input_path.exists() and app.state.input_dir.resolve() in input_path.resolve().parents:
            input_path.unlink()
        if delete_trace:
            try:
                _delete_trace(existing.get("trace_id"))
            except Exception as exc:
                warnings.append(f"trace deletion failed: {exc.__class__.__name__}: {exc}")
        return {"deleted": True, "run_id": run_id, "warnings": warnings}

    @app.delete("/api/runs")
    def api_delete_all_runs(confirm: bool = Query(False), delete_traces: bool = Query(True)) -> dict[str, Any]:
        if not confirm:
            raise HTTPException(status_code=400, detail="confirm=true is required")
        existing = delete_all_runs(app.state.db_path)
        warnings: list[str] = []
        for run in existing:
            input_path = Path(run["input_path"]) if run.get("input_path") else None
            if input_path and input_path.exists() and app.state.input_dir.resolve() in input_path.resolve().parents:
                input_path.unlink()
            if delete_traces:
                try:
                    _delete_trace(run.get("trace_id"))
                except Exception as exc:
                    warnings.append(f"{run.get('run_id')}: trace deletion failed: {exc.__class__.__name__}: {exc}")
        return {"deleted": len(existing), "warnings": warnings}

    @app.get("/api/steps")
    def steps() -> dict[str, list[str]]:
        return {"steps": STEP_ORDER}

    return app


app = create_app()
