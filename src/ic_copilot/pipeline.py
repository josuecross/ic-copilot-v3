from __future__ import annotations

import json
import os
import re
import time
import ast
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from ic_copilot.clean_context import extract_clean_incident_context
from ic_copilot.actionability import normalize_move_for_visible_ask
from ic_copilot.catalog import build_command_registry, load_command_registry, load_service_catalog, resolve_service_or_team
from ic_copilot.blocker_reselection import select_authoritative_blocker
from ic_copilot.decision_metadata import normalize_decision_expiration, only_expiration_failed
from ic_copilot.decision_output import formatting_only_repair, lint_manual_copy_output
from ic_copilot.decision_repair import repair_blocked_decision
from ic_copilot.error_sanitizer import classify_provider_error, sanitize_provider_error, sanitize_user_facing_error
from ic_copilot.evidence_quality import (
    assess_semantic_quality,
    classify_events_quality,
    event_quality_summary,
    target_quality_summary,
    validate_incident_brief_quality,
)
from ic_copilot.extractor import extract_state_delta
from ic_copilot.input_processing import (
    assess_input_size,
    latest_window_events,
    merge_clean_contexts,
    select_chunks,
    select_latest_window,
    split_event_chunks,
)
from ic_copilot.incident_brief import (
    augment_allowed_targets_from_state,
    build_allowed_targets,
    build_incident_brief_payload,
    build_target_shortlist,
    clean_context_from_incident_brief,
    extract_incident_brief,
    incident_brief_payload_stats,
    sharp_blocker_from_incident_brief,
    state_delta_from_incident_brief,
)
from ic_copilot.incident_loader import incident_id_from_path, load_incident_events
from ic_copilot.incident_read_v2 import (
    build_incident_read_v2_context_pack,
    decision_from_incident_read_v2,
    evaluate_incident_read_v2_quality,
    extract_incident_read_and_whisper_v2,
    incident_read_v2_context_pack_summary,
)
from ic_copilot.llm.base import LLMClient
from ic_copilot.llm.product_client import create_product_llm_client
from ic_copilot.llm.redaction import redact_for_llm
from ic_copilot.memory import (
    build_memory_query,
    hydrate_decision_moments,
    judge_applicability,
    load_decision_moments,
    retrieve_decision_moment_ids,
)
from ic_copilot.planner import plan_ic_decision
from ic_copilot.read_and_whisper import (
    build_incident_read_context_pack,
    build_ultra_compact_incident_read_context_pack,
    context_pack_summary,
    decision_from_incident_read,
    extract_incident_read_and_whisper,
    normalize_incident_read_envelope,
)
from ic_copilot.render import render_ic_whisper
from ic_copilot.run_diagnosis import build_run_diagnosis, summarize_run_diagnosis
from ic_copilot.runtime_config import ProductRuntimeConfig, load_product_runtime_config
from ic_copilot.runtime_resources import (
    load_product_catalog,
    load_product_command_registry,
    load_product_decision_moments,
)
from ic_copilot.schemas import (
    ActorWorkstreamLedger,
    AllowedTarget,
    AuthoritativeBlockerSelection,
    CleanIncidentContext,
    CleanTurnLedger,
    CurrentIncidentState,
    EvidenceBackedFact,
    EvidenceRef,
    BriefQualityResult,
    ICDecision,
    ICMove,
    IncidentReadAndWhisper,
    IncidentReadAndWhisperV2,
    IncidentBrief,
    IncidentEvent,
    IncidentFactLedger,
    InputSizeAssessment,
    LatestWindowSelection,
    PipelineStepArtifact,
    QuestionIntentLedger,
    SemanticQuality,
    SemanticIntentAssessment,
    SharpBlockerAssessment,
    SlackTurnReconstruction,
    TargetShortlistItem,
    TraceRecord,
    VerifierResult,
    WhisperEvidenceRef,
)
from ic_copilot.semantic_read import (
    ParallelSemanticReadResult,
    build_deterministic_actor_workstream_ledger,
    build_deterministic_clean_turn_ledger,
    build_deterministic_incident_fact_ledger,
    build_deterministic_question_intent_ledger,
    build_fallback_workstream_ledger,
    build_semantic_read_payload,
    extract_clean_turn_ledger,
    reduce_ledgers_to_incident_brief,
    run_parallel_semantic_read,
)
from ic_copilot.semantic_intent import (
    assess_output_intent,
    build_deterministic_semantic_intent_assessment,
    high_confidence_stale_matches,
)
from ic_copilot.sharp_blocker import assess_sharp_blocker, build_deterministic_sharp_blocker_assessment
from ic_copilot.slack_turns import reconstruct_slack_turns
from ic_copilot.state_merge import merge_state_delta
from ic_copilot.storage import init_db, save_payload
from ic_copilot.trigger import decide_trigger
from ic_copilot.verifier import verify_ic_decision
from ic_copilot.work_items import extract_current_work_items


PipelineEventCallback = Callable[[str, str, str, int | None, str | None], None]
PipelineArtifactCallback = Callable[[PipelineStepArtifact], None]


class LargeInputProcessingError(RuntimeError):
    def __init__(self, message: str, *, debug_payload: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.debug_payload = debug_payload or {}


class ProviderTimeoutProcessingError(TimeoutError):
    def __init__(self, message: str, *, debug_payload: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.debug_payload = debug_payload or {}


def _planner_failure_object(exc: Exception) -> dict[str, Any]:
    error_type = classify_provider_error(exc)
    safe_message = sanitize_user_facing_error(exc)
    raw_excerpt = " ".join(sanitize_provider_error(getattr(exc, "raw_error_redacted", None) or exc).split())
    if len(raw_excerpt) > 480:
        raw_excerpt = raw_excerpt[:477].rstrip() + "..."
    invalid_fields = sorted(
        {
            match
            for match in re.findall(
                r"(?:\n|^|\s)([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)\s+(?:Field required|Input should be|Extra inputs)",
                raw_excerpt,
            )
            if match not in {"Input", "Field", "Extra"}
        }
    )
    return {
        "provider_output_was_invalid": True,
        "provider_output_invalid_reason": safe_message,
        "planning_failure_category": "planning_model_schema_invalid"
        if error_type == "schema_error"
        else "planning_model_provider_error",
        "planner_validation_error": safe_message,
        "provider_json_parse_error": "invalid json" in raw_excerpt.lower() or "json response" in raw_excerpt.lower(),
        "provider_schema_error": error_type == "schema_error",
        "provider_invalid_fields": invalid_fields[:12],
        "provider_raw_output_redacted_excerpt": raw_excerpt,
    }


@dataclass(frozen=True)
class PipelineStep:
    step: str
    status: str
    message: str = ""
    elapsed_ms: int | None = None
    error: str | None = None


def catalog_matches_for_state(state: CurrentIncidentState, catalog):
    matches = []
    for entity in state.candidate_services + state.engaged_entities + state.suggested_but_not_engaged:
        for match in resolve_service_or_team(entity.display_name, catalog):
            if match.service_id not in {entry.service_id for entry in matches}:
                matches.append(match)
    return matches or catalog


def _semantic_fallback_decision(decision: ICDecision) -> ICDecision:
    metadata = dict(decision.model_metadata)
    metadata["semantic_fallback_reason"] = "semantic_intent_stale_question"
    return ICDecision(
        decision_id=f"fallback-{decision.decision_id}",
        incident_id=decision.incident_id,
        move=ICMove.NO_SAFE_RECOMMENDATION,
        phase=decision.phase,
        domain_intent=decision.domain_intent,
        model_metadata=metadata,
        output={
            "say_this": "I do not have a safe, grounded next move yet.",
            "next_line": "Hold until the current owner, scope, or validation signal is explicit in the incident thread.",
        },
        rationale=["Semantic intent assessment detected a stale or repeated question."],
        grounding=decision.grounding,
        confidence=0.2,
    )


def _apply_semantic_intent_blocks(
    decision: ICDecision,
    verifier_result: VerifierResult,
    assessment: SemanticIntentAssessment | None,
) -> VerifierResult:
    if assessment is None:
        return verifier_result
    stale_matches = high_confidence_stale_matches(assessment)
    if not stale_matches:
        return verifier_result

    checks = dict(verifier_result.checks)
    checks["no_stale_question"] = False
    blocked = list(verifier_result.blocked_claims)
    for match in stale_matches:
        blocked.append(
            "semantic stale question intent: "
            f"{match.matched_stale_intent} "
            f"candidate={match.candidate_intent} "
            f"confidence={match.confidence:.2f} "
            f"reason={match.reason}"
        )
    return VerifierResult(
        passed=False,
        final_status="fallback_required",
        checks=checks,
        blocked_claims=blocked,
        allowed_claims=verifier_result.allowed_claims,
        rewrite_instructions=[
            *verifier_result.rewrite_instructions,
            assessment.recommended_repair_direction
            or "Rewrite to a grounded owner, scope, containment, mitigation, or validation step.",
        ],
        fallback_decision=verifier_result.fallback_decision or _semantic_fallback_decision(decision),
    )


def _apply_sharp_blocker_blocks(
    verifier_result: VerifierResult,
    sharp_blocker: SharpBlockerAssessment | None,
) -> VerifierResult:
    if sharp_blocker is None or verifier_result.checks.get("sharp_blocker_aligned", True):
        return verifier_result
    blocked = list(verifier_result.blocked_claims)
    blocked.append(
        "sharp blocker mismatch: "
        f"{sharp_blocker.blocker_type} summary={sharp_blocker.blocker_summary}"
    )
    return VerifierResult(
        passed=False,
        final_status="fallback_required",
        checks=dict(verifier_result.checks),
        blocked_claims=blocked,
        allowed_claims=verifier_result.allowed_claims,
        rewrite_instructions=[
            *verifier_result.rewrite_instructions,
            "Rewrite to the sharp blocker: mitigation/status/ETA/remaining scope/validation.",
        ],
        fallback_decision=verifier_result.fallback_decision,
    )


def _emit(
    on_step: PipelineEventCallback | None,
    step: str,
    status: str,
    message: str = "",
    elapsed_ms: int | None = None,
    error: str | None = None,
) -> None:
    if on_step is not None:
        on_step(step, status, message, elapsed_ms, error)


def _emit_artifact(
    on_artifact: PipelineArtifactCallback | None,
    *,
    run_id: str,
    step: str,
    artifact_type: str,
    summary_json: dict[str, Any],
    payload_json: dict[str, Any],
    warnings: list[str] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    summary_json = redact_for_llm(summary_json)
    payload_json = redact_for_llm(payload_json)
    warnings = redact_for_llm(warnings or [])
    error = redact_for_llm(error) if error else None
    artifact = PipelineStepArtifact(
        run_id=run_id,
        step=step,
        artifact_type=artifact_type,
        summary_json=summary_json,
        payload_json=payload_json,
        warnings=warnings,
        error=error,
    )
    if on_artifact is not None:
        on_artifact(artifact)
    return {
        "step": step,
        "artifact_type": artifact_type,
        "summary_json": summary_json,
        "warnings": warnings,
        "error": error,
    }


def _event_artifact_rows(events: list[IncidentEvent], *, limit: int = 40) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in events[:limit]:
        tokens = event.extracted_tokens or {}
        rows.append(
            {
                "event_id": event.event_id,
                "sequence": event.sequence,
                "author": event.author,
                "is_bot": bool(tokens.get("is_bot")),
                "is_system": bool(tokens.get("is_system")),
                "url_count": len(tokens.get("urls", [])),
                "command_candidate_count": len(tokens.get("command_candidates", [])),
                "message_preview": " ".join(event.message.split())[:180],
            }
        )
    return rows


def _normalizer_artifact_summary(events: list[IncidentEvent], event_quality: list[Any] | None = None) -> dict[str, Any]:
    warnings: list[str] = []
    continuation_count = 0
    suspicious_examples: list[str] = []
    compact_author_examples: list[str] = []
    for event in events:
        metadata = event.raw_metadata or {}
        event_warnings = [str(item) for item in metadata.get("parser_warnings", [])]
        warnings.extend(event_warnings)
        continuation_count += int(metadata.get("non_author_continuation_lines", 0) or 0)
        if event_warnings and len(suspicious_examples) < 6:
            suspicious_examples.append(event.message.splitlines()[-1][:80])
        if metadata.get("compact_author_recovered") and len(compact_author_examples) < 6:
            compact_author_examples.append(str(event.author or "unknown"))
    bot_system_count = sum(
        1
        for event in events
        if (event.extracted_tokens or {}).get("is_bot") or (event.extracted_tokens or {}).get("is_system")
    )
    url_count = sum(len((event.extracted_tokens or {}).get("urls", [])) for event in events)
    summary = {
        "events": len(events),
        "bot_system": bot_system_count,
        "urls": url_count,
        "first_event_id": events[0].event_id if events else None,
        "latest_event_id": events[-1].event_id if events else None,
        "author_recovery_warnings": len(warnings),
        "non_author_continuation_lines": continuation_count,
        "bot_system_event_count": bot_system_count,
        "suspicious_author_count": len(warnings),
        "suspicious_author_examples": suspicious_examples,
        "recovered_compact_author_count": sum(
            1 for event in events if (event.raw_metadata or {}).get("compact_author_recovered")
        ),
        "compact_author_recovery_examples": compact_author_examples,
    }
    if event_quality is not None:
        quality_summary = event_quality_summary(event_quality)
        human_diagnostic_count = sum(
            1 for quality in event_quality if getattr(quality, "event_kind", "") == "human_diagnostic_evidence"
        )
        summary.update(
            {
                "human_operator_events": quality_summary["human_operator_events"],
                "preview_card_events": quality_summary["preview_card_events"],
                "log_table_events": quality_summary["log_table_events"],
                "planner_grounding_allowed": quality_summary["planner_grounding_allowed"],
                "target_source_allowed": quality_summary["target_source_allowed"],
                "human_diagnostic_grounding_count": human_diagnostic_count,
            }
        )
    return summary


def _allowed_target_counts(allowed_targets: list[AllowedTarget]) -> dict[str, int]:
    quality_counts = target_quality_summary(allowed_targets)
    return {
        "allowed": len([target for target in allowed_targets if target.targetable]),
        "rejected": len([target for target in allowed_targets if not target.targetable]),
        "total": len(allowed_targets),
        "allowed_high": quality_counts.get("high", 0),
        "allowed_medium": quality_counts.get("medium", 0),
        "allowed_low": quality_counts.get("low", 0),
        "rejected_noise": quality_counts.get("rejected_total", 0),
    }


def _jsonl_record_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text().splitlines() if line.strip())


def _runtime_knowledge_counts(
    *,
    catalog: list[Any],
    command_registry: list[Any],
    moments: list[Any],
    memory_path: str | Path,
) -> dict[str, int]:
    knowledge_dir = Path(memory_path).parent
    return {
        "services": len(catalog),
        "commands": len(command_registry),
        "decision_moments": len(moments),
        "verifier_regressions": _jsonl_record_count(knowledge_dir / "verifier_regressions.jsonl"),
        "rejected_entities": _jsonl_record_count(knowledge_dir / "rejected_entities.jsonl"),
        "stale_question_patterns": _jsonl_record_count(knowledge_dir / "stale_question_patterns.jsonl"),
    }


def _clean_turn_ledger_summary(ledger: CleanTurnLedger) -> dict[str, Any]:
    speaker_names = [turn.speaker for turn in ledger.clean_turns if turn.speaker and turn.speaker != "unknown"]
    return {
        "turns": len(ledger.clean_turns),
        "human_turns": sum(1 for turn in ledger.clean_turns if turn.speaker_type == "human"),
        "bot_system_turns": sum(1 for turn in ledger.clean_turns if turn.speaker_type in {"bot", "system"}),
        "noise_turns": sum(1 for turn in ledger.clean_turns if turn.is_noise),
        "speakers": list(dict.fromkeys(speaker_names))[:8],
        "warnings": len(ledger.warnings),
    }


def _actor_workstream_ledger_summary(ledger: ActorWorkstreamLedger) -> dict[str, Any]:
    return {
        "actors": len(ledger.actors),
        "targetable_actors": sum(1 for actor in ledger.actors if actor.targetable),
        "technical_investigators": [
            actor.name for actor in ledger.actors if actor.role_hint == "technical_investigator"
        ][:6],
        "workstreams": len(ledger.workstreams),
        "active_workstreams": [
            workstream.type for workstream in ledger.workstreams if workstream.status == "in_progress"
        ][:6],
        "warnings": len(ledger.warnings),
    }


def _incident_fact_ledger_summary(ledger: IncidentFactLedger) -> dict[str, Any]:
    return {
        "severity": ledger.severity.value if ledger.severity else None,
        "phase": ledger.phase.value if ledger.phase else None,
        "current_blocker": ledger.current_blocker.summary if ledger.current_blocker else None,
        "services_or_components": [fact.value for fact in ledger.services_or_components[:6]],
        "customers": [fact.value for fact in ledger.customers[:6]],
        "tenants": [fact.value for fact in ledger.tenants[:6]],
        "rejected_noise": [item.text for item in ledger.rejected_noise[:8]],
        "warnings": len(ledger.warnings),
    }


def _question_intent_ledger_summary(ledger: QuestionIntentLedger) -> dict[str, Any]:
    return {
        "open_questions": len(ledger.open_questions),
        "answered_questions": len(ledger.answered_questions),
        "stale_question_intents": ledger.stale_question_intents[:8],
        "do_not_ask": [item.intent for item in ledger.do_not_ask[:8]],
        "wrong_next_moves": [item.intent for item in ledger.wrong_next_moves[:8]],
        "warnings": len(ledger.warnings),
    }


def _semantic_ledger_artifacts(
    semantic_read_result: ParallelSemanticReadResult,
) -> list[tuple[str, dict[str, Any], dict[str, Any], list[str]]]:
    artifacts: list[tuple[str, dict[str, Any], dict[str, Any], list[str]]] = []
    if semantic_read_result.clean_turn_ledger is not None:
        ledger = semantic_read_result.clean_turn_ledger
        artifacts.append(
            (
                "clean_turn_ledger",
                _clean_turn_ledger_summary(ledger),
                ledger.model_dump(mode="json"),
                ledger.warnings,
            )
        )
    if semantic_read_result.actor_workstream_ledger is not None:
        ledger = semantic_read_result.actor_workstream_ledger
        artifacts.append(
            (
                "actor_workstream_ledger",
                _actor_workstream_ledger_summary(ledger),
                ledger.model_dump(mode="json"),
                ledger.warnings,
            )
        )
    if semantic_read_result.incident_fact_ledger is not None:
        ledger = semantic_read_result.incident_fact_ledger
        artifacts.append(
            (
                "incident_fact_ledger",
                _incident_fact_ledger_summary(ledger),
                ledger.model_dump(mode="json"),
                ledger.warnings,
            )
        )
    if semantic_read_result.question_intent_ledger is not None:
        ledger = semantic_read_result.question_intent_ledger
        artifacts.append(
            (
                "question_intent_ledger",
                _question_intent_ledger_summary(ledger),
                ledger.model_dump(mode="json"),
                ledger.warnings,
            )
        )
    return artifacts


def _clean_turns_show_operator_intent(ledger: CleanTurnLedger | None) -> bool:
    if ledger is None:
        return False
    intent_terms = (
        "can you",
        "could you",
        "please confirm",
        "confirm if",
        "confirm whether",
        "await",
        "need",
        "next action",
        "next steps",
        "checking",
        "status",
        "validation",
        "validate",
    )
    for turn in ledger.clean_turns[-12:]:
        text = " ".join((turn.summary, " ".join(turn.key_values.values()))).lower()
        if turn.message_type in {"question", "answer", "human_status", "mitigation", "monitoring"} and any(
            term in text for term in intent_terms
        ):
            return True
    return False


def _is_timeout_error(exc: Exception) -> bool:
    text = f"{exc.__class__.__name__}: {exc}".lower()
    return any(term in text for term in ("timed out", "timeout", "read operation timed out"))


@contextmanager
def _stage_timeout(llm_client: LLMClient, seconds: float | None):
    config = getattr(llm_client, "config", None)
    if seconds is None or config is None or not hasattr(config, "model_copy"):
        yield
        return
    original = config
    try:
        setattr(llm_client, "config", config.model_copy(update={"timeout_seconds": seconds}))
        yield
    finally:
        setattr(llm_client, "config", original)


def _timeout(product_config: ProductRuntimeConfig | None, name: str) -> float | None:
    if product_config is None:
        return None
    return float(getattr(product_config.timeouts, name))


def _total_run_timeout(product_config: ProductRuntimeConfig | None) -> float | None:
    if product_config is None:
        return None
    return float(product_config.timeouts.total_run_timeout_seconds)


def _ensure_run_budget(started: float, product_config: ProductRuntimeConfig | None, stage: str) -> None:
    timeout = _total_run_timeout(product_config)
    if timeout is None:
        return
    elapsed = time.perf_counter() - started
    if elapsed > timeout:
        raise LargeInputProcessingError(
            f"Product run exceeded the {int(timeout)}s runtime budget before {stage}. "
            "Try rerun; if it repeats, paste the latest 30-50 messages around the current blocker."
        )


def _events_by_selection(events: list[IncidentEvent], selection: LatestWindowSelection) -> list[IncidentEvent]:
    selected = set(selection.event_ids)
    return [event for event in events if event.event_id in selected]


def _trace_legacy_debug_summary() -> dict[str, Any]:
    return {
        "normal_product_path": "incident_read_and_whisper",
        "legacy_debug_only": [
            "semantic_read",
            "incident_brief",
            "clean_context",
            "state_extraction",
            "state_merge",
            "sharp_blocker_assessment",
            "semantic_intent_check",
            "blocker_reselection",
            "target_shortlist",
        ],
        "note": "Legacy semantic fields are retained for compatibility/debug only and are not product truth in the normal path.",
    }


def _simplified_verifier_checks(result: VerifierResult) -> dict[str, bool]:
    checks = result.checks
    return {
        "schema_valid": checks.get("schema_valid", True),
        "evidence_grounded": checks.get("evidence_grounded", True),
        "selected_target_allowed": checks.get("target_in_allowed_targets", True)
        and checks.get("target_exists", True),
        "selected_target_not_noise": checks.get("no_non_targetable_target", True)
        and checks.get("selected_target_quality", True)
        and checks.get("no_noise_targets", True),
        "no_fake_customer": checks.get("no_fake_customer", True),
        "no_fake_tenant": checks.get("no_fake_tenant", True),
        "no_fake_person": checks.get("no_fake_person", True),
        "no_fake_team": checks.get("no_fake_team", True),
        "no_fake_service": checks.get("no_fake_service", True),
        "no_historical_fact_leakage": checks.get("no_historical_fact_leakage", True),
        "no_stale_question": checks.get("no_stale_question", True),
        "stale_open_loop_contradiction": checks.get("stale_open_loop_contradiction", True),
        "stale_answered_open_loop": checks.get("stale_answered_open_loop", True),
        "stale_visible_status_recap": checks.get("stale_visible_status_recap", True),
        "action_owner_aligned": checks.get("action_owner_aligned", True),
        "command_registry_valid": checks.get("valid_command", True),
        "no_unsafe_action_wording": checks.get("no_executable_action_wording", True),
        "no_private_identifier_in_visible_output": checks.get("no_private_identifier_in_visible_output", True),
        "permission_denied_wrong_owner_loop": checks.get("permission_denied_wrong_owner_loop", True),
        "no_json_log_target": checks.get("no_json_log_target", True),
        "severity_claim_confirmed": checks.get("severity_claim_confirmed", True),
        "no_useless_self_summary": checks.get("no_useless_self_summary", True),
        "no_passive_we_need_owner_statement": checks.get("no_passive_we_need_owner_statement", True),
        "visible_output_is_direct_ask": checks.get("visible_output_is_direct_ask", True),
        "selected_move_matches_visible_intent": checks.get("selected_move_matches_visible_intent", True),
        "no_low_quality_named_person_as_owner": checks.get("no_low_quality_named_person_as_owner", True),
        "unresolved_loop_requires_question": checks.get("unresolved_loop_requires_question", True),
        "no_safe_despite_accepted_memory": checks.get("no_safe_despite_accepted_memory", True),
        "accepted_memory_target_class_satisfied": checks.get("accepted_memory_target_class_satisfied", True),
        "accepted_memory_visible_intent_satisfied": checks.get("accepted_memory_visible_intent_satisfied", True),
        "no_safe_despite_diagnostic_signal": checks.get("no_safe_despite_diagnostic_signal", True),
        "reporter_not_owner_when_owner_candidate_exists": checks.get(
            "reporter_not_owner_when_owner_candidate_exists",
            True,
        ),
        "bot_diagnostic_context_preserved": checks.get("bot_diagnostic_context_preserved", True),
        "raw_paste_evidence_preservation": checks.get("raw_paste_evidence_preservation", True),
        "output_length_ok": checks.get("not_too_generic", True),
        "expiration_or_metadata_ok": checks.get("expires_correctly", True),
    }


def _legacy_verifier_checks(result: VerifierResult) -> dict[str, bool]:
    legacy_names = {
        "sharp_blocker_aligned",
        "incident_brief_quality_sufficient",
        "semantic_quality_sufficient",
        "generated_summary_as_evidence",
        "generated_summary_not_primary_evidence",
        "latest_blocker_respected",
        "monitoring_signal_supported",
    }
    return {name: passed for name, passed in result.checks.items() if name in legacy_names}


def _verifier_detail_claim(result: VerifierResult, prefix: str) -> dict[str, Any]:
    marker = f"{prefix}: "
    for claim in result.allowed_claims:
        if not str(claim).startswith(marker):
            continue
        try:
            value = ast.literal_eval(str(claim)[len(marker) :])
        except (SyntaxError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}
    return {}


def _verifier_has_allowed_claim(result: VerifierResult, claim: str) -> bool:
    return any(str(item) == claim for item in result.allowed_claims)


def _verifier_result_payload(result: VerifierResult) -> dict[str, Any]:
    return result.model_dump(mode="json", exclude={"fallback_decision": {"verifier_result": True}})


def _decision_payload(decision: ICDecision) -> dict[str, Any]:
    return decision.model_dump(mode="json", exclude={"verifier_result": {"fallback_decision": {"verifier_result": True}}})


def _trace_payload(trace: TraceRecord) -> dict[str, Any]:
    return trace.model_dump(
        mode="json",
        exclude={
            "raw_decision": {"verifier_result": {"fallback_decision": {"verifier_result": True}}},
            "rendered_decision": {"verifier_result": {"fallback_decision": {"verifier_result": True}}},
            "verifier_result": {"fallback_decision": {"verifier_result": True}},
        },
    )


def _allows_dev_schema_fallback(llm_client: LLMClient) -> bool:
    # Explicit test/dev clients often implement only a subset of prompt contracts. Real
    # product clients carry provider config and should fail closed on IncidentBrief schema errors.
    return getattr(llm_client, "config", None) is None


def _uses_exact_fixture_client(llm_client: LLMClient) -> bool:
    return llm_client.__class__.__name__ == "FixtureLLMClient"


def _semantic_errors_allow_dev_fallback(errors: dict[str, str] | None) -> bool:
    if not errors:
        return False
    joined = " ".join(errors.values()).lower()
    provider_failure_terms = (
        "timeout",
        "timed out",
        "read operation timed out",
        "authentication",
        "invalid_api_key",
        "rate limit",
        "providerjsonerror",
        "connect",
    )
    return not any(term in joined for term in provider_failure_terms)


def _allows_dev_state_delta_compatibility(llm_client: LLMClient) -> bool:
    return getattr(llm_client, "config", None) is None


def _events_text(events: list[IncidentEvent]) -> str:
    event_text = "\n\n".join(f"{event.event_id} {event.author or ''}: {event.message}" for event in events)
    work_items = extract_current_work_items(events)
    if not work_items:
        return event_text
    work_item_text = "\n".join(
        "current work item next action text; explicit owner marker: "
        f"{item.get('work_item_label')}; owners={','.join(item.get('owner_names', []) or [])}; "
        f"owner_group={item.get('owner_group') or ''}; action={item.get('status_or_action') or ''}"
        for item in work_items[:6]
    )
    return "\n\n".join(part for part in (event_text, work_item_text) if part)


def _owner_base(name: str) -> str:
    value = re.sub(r"\s+", " ", name.strip().lower())
    for suffix in (" team", " service"):
        if value.endswith(suffix):
            return value[: -len(suffix)].strip()
    return value


def _expand_shortlist_with_canonical_targets(
    allowed_targets: list[AllowedTarget],
    target_shortlist: list[TargetShortlistItem],
) -> list[AllowedTarget]:
    shortlist_ids = {target.target_id for target in target_shortlist}
    bases = {_owner_base(target.display_name) for target in target_shortlist if target.target_type in {"team", "service"}}
    canonical_ids = {
        target.target_id
        for target in allowed_targets
        if target.targetable
        and target.source in {"catalog", "service_alias", "command_registry"}
        and target.target_quality in {"high", "medium"}
        and _owner_base(target.display_name) in bases
    }
    ids = shortlist_ids | canonical_ids
    return [target for target in allowed_targets if target.target_id in ids]


def _incident_brief_attempt_record(
    *,
    attempt_name: str,
    events: list[IncidentEvent],
    current_state: CurrentIncidentState,
    allowed_targets: list[AllowedTarget],
    input_size_assessment: InputSizeAssessment,
    timeout_seconds: float,
    reconstructed_turns: SlackTurnReconstruction | None,
    max_chars_per_event: int,
    max_targets: int,
) -> dict[str, Any]:
    payload = build_incident_brief_payload(
        _events_text(events),
        events,
        current_state,
        allowed_targets,
        input_size_assessment,
        reconstructed_turns=reconstructed_turns,
        attempt_name=attempt_name,
        max_chars_per_event=max_chars_per_event,
        max_targets=max_targets,
    )
    stats = incident_brief_payload_stats(payload)
    return {
        "attempt_name": attempt_name,
        "event_count": stats["event_count"],
        "char_count": stats["char_count"],
        "estimated_token_count": stats["estimated_token_count"],
        "timeout_seconds": timeout_seconds,
        "status": "not_started",
        "error_type": None,
    }


def _failure_debug_payload(
    *,
    events: list[IncidentEvent],
    input_size_assessment: InputSizeAssessment,
    latest_window_selection: LatestWindowSelection,
    allowed_targets: list[AllowedTarget],
    processing_meta: dict[str, Any],
    terminal_failure_reason: str,
) -> dict[str, Any]:
    return {
        "events": [event.model_dump(mode="json") for event in events],
        "latest_window_selection": latest_window_selection.model_dump(mode="json"),
        "input_size_assessment": input_size_assessment.model_dump(mode="json"),
        "allowed_target_count": len(allowed_targets),
        "allowed_targets": [target.model_dump(mode="json") for target in allowed_targets],
        "safety_summary": {
            "latest_window_selection": latest_window_selection.model_dump(mode="json"),
            "input_size_assessment": input_size_assessment.model_dump(mode="json"),
            "provider_timeout_stage": processing_meta.get("provider_timeout_stage"),
            "retry_attempted": processing_meta.get("retry_attempted"),
            "retry_strategy": processing_meta.get("retry_strategy"),
            "incident_brief_attempt_count": len(processing_meta.get("incident_brief_attempts", [])),
            "incident_brief_attempts": processing_meta.get("incident_brief_attempts", []),
            "compact_payload_event_count": processing_meta.get("compact_payload_event_count"),
            "compact_payload_char_count": processing_meta.get("compact_payload_char_count"),
            "ultra_compact_payload_event_count": processing_meta.get("ultra_compact_payload_event_count"),
            "ultra_compact_payload_char_count": processing_meta.get("ultra_compact_payload_char_count"),
            "terminal_failure_reason": terminal_failure_reason,
            "processing_warnings": processing_meta.get("warnings", []),
        },
        "processing_strategy": processing_meta.get("processing_strategy"),
        "provider_timeout_stage": processing_meta.get("provider_timeout_stage"),
        "retry_attempted": processing_meta.get("retry_attempted"),
        "retry_strategy": processing_meta.get("retry_strategy"),
        "latest_window_event_ids": latest_window_selection.event_ids,
    }


def _context_pack_char_count(context_pack: dict[str, Any]) -> int:
    return len(json.dumps(context_pack, default=str))


def _simplified_failure_debug_payload(
    *,
    events: list[IncidentEvent],
    input_size_assessment: InputSizeAssessment,
    latest_window_selection: LatestWindowSelection,
    context_pack: dict[str, Any],
    pack_summary: dict[str, Any],
    processing_meta: dict[str, Any],
    terminal_failure_reason: str,
) -> dict[str, Any]:
    compact_candidates = context_pack.get("candidate_targets", [])[:10]
    compact_rejected = context_pack.get("do_not_target", [])[:10]
    latest_ids = latest_window_selection.event_ids
    payload = {
        "normalized_event_count": len(events),
        "latest_window_selection": latest_window_selection.model_dump(mode="json"),
        "latest_window_event_ids": latest_ids,
        "input_size_assessment": input_size_assessment.model_dump(mode="json"),
        "context_pack_summary": pack_summary,
        "candidate_targets": compact_candidates,
        "rejected_targets": compact_rejected,
        "target_aliases": context_pack.get("target_aliases", [])[:10],
        "mentionable_fact_count": len(context_pack.get("non_targetable_but_mentionable_facts", [])),
        "do_not_target_only_count": len(context_pack.get("do_not_target_only", [])),
        "forbidden_output_entity_count": len(context_pack.get("forbidden_output_entities", [])),
        "provider_timeout_stage": processing_meta.get("provider_timeout_stage"),
        "retry_attempted": processing_meta.get("retry_attempted"),
        "retry_strategy": processing_meta.get("retry_strategy"),
        "compact_payload_event_count": processing_meta.get("compact_payload_event_count"),
        "compact_payload_char_count": processing_meta.get("compact_payload_char_count"),
        "ultra_compact_payload_event_count": processing_meta.get("ultra_compact_payload_event_count"),
        "ultra_compact_payload_char_count": processing_meta.get("ultra_compact_payload_char_count"),
        "terminal_failure_reason": terminal_failure_reason,
        "processing_warnings": processing_meta.get("warnings", []),
        "safety_summary": {
            "context_pack_summary": pack_summary,
            "candidate_targets": compact_candidates,
            "rejected_targets": compact_rejected,
            "provider_timeout_stage": processing_meta.get("provider_timeout_stage"),
            "retry_attempted": processing_meta.get("retry_attempted"),
            "retry_strategy": processing_meta.get("retry_strategy"),
            "terminal_failure_reason": terminal_failure_reason,
        },
    }
    return redact_for_llm(payload)


EXPLICIT_TENANT_RE = re.compile(
    r"\b(?:tenant\s+id|tenant|account\s+id|account|org\s+id)\s*(?:[:=#-]|\bis\b)?\s*(\d{5,})\b",
    re.I,
)


def _apply_explicit_tenant_evidence_to_state(state: CurrentIncidentState, events: list[IncidentEvent]) -> CurrentIncidentState:
    tenant_events: dict[str, IncidentEvent] = {}
    for event in events:
        for match in EXPLICIT_TENANT_RE.finditer(event.message):
            tenant_events.setdefault(match.group(1), event)
    if not tenant_events:
        return state
    affected_tenants = list(state.impact.affected_tenants)
    known = {fact.value for fact in affected_tenants}
    for tenant_id, event in tenant_events.items():
        if tenant_id not in known:
            affected_tenants.append(
                EvidenceBackedFact(
                    value=tenant_id,
                    evidence=[EvidenceRef(event_id=event.event_id, quote=event.message, confidence=0.92)],
                    confidence=0.92,
                )
            )
            known.add(tenant_id)
    rejected_entities = [
        entity
        for entity in state.rejected_entities
        if not (
            entity.display_name in tenant_events
            and entity.status in {"rejected:url_path_number", "rejected:jira_issue_number_not_tenant"}
        )
    ]
    return state.model_copy(
        update={
            "impact": state.impact.model_copy(
                update={
                    "affected_tenants": affected_tenants,
                    "confidence": max(state.impact.confidence, 0.72),
                }
            ),
            "rejected_entities": rejected_entities,
        }
    )


def _extract_clean_context_chunks(
    *,
    events: list[IncidentEvent],
    state: CurrentIncidentState,
    llm_client: LLMClient,
    timeout: float | None,
    meta: dict[str, Any],
    max_chunk_chars: int,
    max_events_per_chunk: int,
    input_size_assessment: InputSizeAssessment,
    reconstructed_turns: SlackTurnReconstruction | None,
    turn_reconstruction_warning: str | None,
) -> CleanIncidentContext | None:
    chunks = select_chunks(
        split_event_chunks(
            events,
            max_chunk_chars=max_chunk_chars,
            max_events_per_chunk=max_events_per_chunk,
        )
    )
    meta["chunk_count"] = len(chunks)
    meta["chunk_ids"] = [chunk.chunk_id for chunk in chunks]
    contexts: list[CleanIncidentContext] = []
    failures: list[str] = []
    for chunk in chunks:
        try:
            with _stage_timeout(llm_client, timeout):
                contexts.append(
                    extract_clean_incident_context(
                        chunk.raw_text,
                        chunk.events,
                        state,
                        llm_client,
                        reconstructed_turns=reconstructed_turns,
                        input_size_assessment=input_size_assessment,
                        turn_reconstruction_warning=turn_reconstruction_warning,
                    )
                )
            meta["chunk_success_count"] += 1
        except Exception as exc:
            meta["chunk_failure_count"] += 1
            failures.append(f"{chunk.chunk_id}: {sanitize_user_facing_error(exc)}")
            if _is_timeout_error(exc):
                meta["provider_timeout_stage"] = "clean_context_chunk"
            continue
    meta["warnings"] = [*meta.get("warnings", []), *failures]
    if contexts:
        return merge_clean_contexts(contexts, state.incident_id)
    return None


def _extract_clean_context_resilient(
    *,
    raw_text: str,
    events: list[IncidentEvent],
    state: CurrentIncidentState,
    llm_client: LLMClient,
    product_config: ProductRuntimeConfig | None,
    assessment: InputSizeAssessment,
    reconstructed_turns: SlackTurnReconstruction | None = None,
    turn_reconstruction_warning: str | None = None,
) -> tuple[CleanIncidentContext, dict[str, Any]]:
    timeout = _timeout(product_config, "clean_context_timeout_seconds")
    meta: dict[str, Any] = {
        "processing_strategy": assessment.recommended_strategy,
        "chunk_count": 0,
        "chunk_ids": [],
        "chunk_success_count": 0,
        "chunk_failure_count": 0,
        "provider_timeout_stage": None,
        "retry_attempted": False,
        "retry_strategy": None,
        "warnings": [],
    }
    if assessment.recommended_strategy in {"single_pass", "compact_then_single_pass"}:
        try:
            with _stage_timeout(llm_client, timeout):
                return extract_clean_incident_context(
                    raw_text,
                    events,
                    state,
                    llm_client,
                    reconstructed_turns=reconstructed_turns,
                    input_size_assessment=assessment,
                    turn_reconstruction_warning=turn_reconstruction_warning,
                ), meta
        except Exception as exc:
            meta["provider_timeout_stage"] = "clean_context"
            meta["retry_attempted"] = True
            meta["retry_strategy"] = "chunked_clean_context_after_single_failure"
            meta["warnings"] = [
                *meta.get("warnings", []),
                f"clean_context_single_pass: {sanitize_user_facing_error(exc)}",
            ]
            chunked = _extract_clean_context_chunks(
                events=events,
                state=state,
                llm_client=llm_client,
                timeout=timeout,
                meta=meta,
                max_chunk_chars=4000,
                max_events_per_chunk=4,
                input_size_assessment=assessment,
                reconstructed_turns=reconstructed_turns,
                turn_reconstruction_warning=turn_reconstruction_warning,
            )
            if chunked is not None:
                return chunked, meta
            meta["retry_strategy"] = "latest_window_clean_context_after_chunk_failures"
            window = latest_window_events(events)
            with _stage_timeout(llm_client, timeout):
                return extract_clean_incident_context(
                    _events_text(window),
                    window,
                    state,
                    llm_client,
                    reconstructed_turns=reconstructed_turns,
                    input_size_assessment=assessment,
                    turn_reconstruction_warning=turn_reconstruction_warning,
                ), meta

    chunk_max_chars = 6000 if assessment.code_or_log_block_count >= 4 else 14000
    chunk_max_events = 12 if assessment.code_or_log_block_count >= 4 else 40
    chunked = _extract_clean_context_chunks(
        events=events,
        state=state,
        llm_client=llm_client,
        timeout=timeout,
        meta=meta,
        max_chunk_chars=chunk_max_chars,
        max_events_per_chunk=chunk_max_events,
        input_size_assessment=assessment,
        reconstructed_turns=reconstructed_turns,
        turn_reconstruction_warning=turn_reconstruction_warning,
    )
    if chunked is not None:
        return chunked, meta

    meta["retry_attempted"] = True
    meta["retry_strategy"] = "latest_window_clean_context_after_chunk_failures"
    window = latest_window_events(events)
    try:
        with _stage_timeout(llm_client, timeout):
            return extract_clean_incident_context(
                _events_text(window),
                window,
                state,
                llm_client,
                reconstructed_turns=reconstructed_turns,
                input_size_assessment=assessment,
                turn_reconstruction_warning=turn_reconstruction_warning,
            ), meta
    except Exception as exc:
        if _is_timeout_error(exc):
            raise LargeInputProcessingError(
                "Provider timed out while processing a large Slack paste. Try rerun; if it repeats, "
                "paste the latest 30-50 messages around the current blocker."
            ) from exc
        raise


@contextmanager
def _step(on_step: PipelineEventCallback | None, name: str, message: str = ""):
    started = time.perf_counter()
    _emit(on_step, name, "running", message)
    try:
        yield
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        _emit(on_step, name, "failed", message, elapsed_ms, sanitize_user_facing_error(exc))
        raise
    else:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        _emit(on_step, name, "succeeded", message, elapsed_ms)


def _run_incident_read_and_whisper_path(
    *,
    incident_id: str,
    events: list[IncidentEvent],
    state: CurrentIncidentState,
    trigger,
    catalog,
    command_registry,
    allowed_targets: list[AllowedTarget],
    latest_window_selection: LatestWindowSelection,
    latest_window: list[IncidentEvent],
    input_size_assessment: InputSizeAssessment,
    event_quality: list[Any],
    product_config: ProductRuntimeConfig | None,
    product_resource_mode: bool,
    effective_memory_path,
    llm_client: LLMClient,
    started: float,
    save_trace: bool,
    on_step: PipelineEventCallback | None,
    on_artifact: PipelineArtifactCallback | None,
    run_id: str,
    step_artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    processing_meta: dict[str, Any] = {
        "processing_strategy": "incident_read_and_whisper_v2"
        if os.environ.get("IC_COPILOT_INCIDENT_READ_LEGACY_V1") != "1"
        else "incident_read_and_whisper",
        "provider_timeout_stage": None,
        "retry_attempted": False,
        "retry_strategy": None,
        "warnings": [],
        "state_delta_status": "legacy_debug_only_not_run",
        "full_context_enrichment_status": "skipped",
        "terminal_failure_reason": None,
        "compact_payload_event_count": 0,
        "compact_payload_char_count": 0,
        "ultra_compact_payload_event_count": 0,
        "ultra_compact_payload_char_count": 0,
    }
    errors: list[str] = []
    use_v2 = os.environ.get("IC_COPILOT_INCIDENT_READ_LEGACY_V1") != "1"
    incident_read_v2: IncidentReadAndWhisperV2 | None = None
    decision: ICDecision | None = None
    normalizer_summary = _normalizer_artifact_summary(events, event_quality)
    catalog_matches = catalog_matches_for_state(state, catalog)

    _emit(on_step, "slack_turn_reconstruction", "skipped", "Not used by simplified normal product path", 0)
    _emit(on_step, "semantic_read", "skipped", "Legacy semantic ledgers are debug-only in normal path", 0)
    _emit(on_step, "incident_brief", "skipped", "IncidentReadAndWhisper replaced IncidentBrief in normal path", 0)
    _emit(on_step, "clean_context", "skipped", "Legacy compatibility clean context not used", 0)
    _emit(on_step, "state_extraction", "skipped", "StateDelta compatibility is not used before rendering", 0)
    _emit(on_step, "state_merge", "skipped", "Compatibility state merge is not product truth", 0)

    with _step(on_step, "memory_load", "Loaded structured DecisionMoment memory"):
        moments = (
            load_product_decision_moments(product_config)
            if product_resource_mode and product_config is not None
            else load_decision_moments(effective_memory_path)
        )
        runtime_knowledge_counts = _runtime_knowledge_counts(
            catalog=catalog,
            command_registry=command_registry,
            moments=moments,
            memory_path=effective_memory_path,
        )
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="memory_load",
                artifact_type="memory_load_summary",
                summary_json={"decision_moments": len(moments), "runtime_knowledge_counts": runtime_knowledge_counts},
                payload_json={"decision_moment_ids": [moment.decision_id for moment in moments[:80]]},
            )
        )

    with _step(on_step, "memory_retrieval", "Retrieved memory IDs only"):
        latest_window_evidence_text = _events_text(latest_window)
        query = build_memory_query(state, current_evidence_text=latest_window_evidence_text)
        memory_ids = retrieve_decision_moment_ids(query, moments)
        hydrated = hydrate_decision_moments(memory_ids, moments)
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="memory_retrieval",
                artifact_type="memory_retrieval_summary",
                summary_json={"retrieved": len(memory_ids), "query_phase": query.phase},
                payload_json={"memory_query": query.model_dump(mode="json"), "memory_ids": memory_ids},
            )
        )

    with _step(on_step, "applicability_gate", "Applied deterministic memory relevance gate"):
        applicability = judge_applicability(
            state,
            hydrated,
            llm_client=None,
            current_evidence_text=latest_window_evidence_text,
        )
        accepted = [item for item in applicability if item.accepted]
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="applicability_gate",
                artifact_type="memory_applicability_summary",
                summary_json={"accepted": len(accepted), "evaluated": len(applicability)},
                payload_json={
                    "applicability": [item.model_dump(mode="json") for item in applicability],
                    "accepted_ids": [item.decision_id for item in accepted],
                },
            )
        )

    _emit(on_step, "sharp_blocker_assessment", "skipped", "Legacy sharp blocker is not used by normal path", 0)

    with _step(on_step, "context_pack", "Packed latest-window evidence for one AI read"):
        hydrated_by_id = {moment.decision_id: moment for moment in hydrated}
        accepted_moments = [
            hydrated_by_id[item.decision_id]
            for item in accepted
            if item.decision_id in hydrated_by_id
        ]
        base_context_pack = build_incident_read_context_pack(
            incident_id=incident_id,
            latest_window_events=latest_window,
            input_size_assessment=input_size_assessment,
            latest_window_selection=latest_window_selection,
            allowed_targets=allowed_targets,
            command_registry=command_registry,
            catalog=catalog,
            accepted_memories=accepted_moments,
            event_quality=event_quality,
        )
        context_pack = (
            build_incident_read_v2_context_pack(
                base_context_pack=base_context_pack,
                allowed_targets=allowed_targets,
            )
            if use_v2
            else base_context_pack
        )
        pack_summary = context_pack_summary(context_pack)
        if use_v2:
            pack_summary = {
                **pack_summary,
                **incident_read_v2_context_pack_summary(context_pack),
                "source_context_pack": context_pack_summary(base_context_pack),
            }
        pack_summary["runtime_knowledge_counts"] = runtime_knowledge_counts
        processing_meta["compact_payload_event_count"] = len(context_pack.get("latest_window_events", []))
        processing_meta["compact_payload_char_count"] = _context_pack_char_count(context_pack)
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="context_pack",
                artifact_type="incident_read_v2_context_pack_summary" if use_v2 else "incident_read_context_pack_summary",
                summary_json=pack_summary,
                payload_json={
                    **context_pack,
                    **({"legacy_v1_context_pack_summary": context_pack_summary(base_context_pack)} if use_v2 else {}),
                },
            )
        )

    with _step(on_step, "planning", "Read incident and planned one manual-copy whisper"):
        _ensure_run_budget(started, product_config, "planning")
        try:
            with _stage_timeout(llm_client, _timeout(product_config, "planner_timeout_seconds")):
                if use_v2:
                    incident_read_v2 = extract_incident_read_and_whisper_v2(context_pack, llm_client)
                    decision, incident_read = decision_from_incident_read_v2(
                        incident_read_v2,
                        context_pack=context_pack,
                        allowed_targets=allowed_targets,
                        current_events=latest_window,
                    )
                else:
                    incident_read = extract_incident_read_and_whisper(context_pack, llm_client)
                    decision = decision_from_incident_read(
                        incident_read,
                        allowed_targets=allowed_targets,
                        current_events=latest_window,
                    )
        except Exception as exc:
            retry_succeeded = False
            if _is_timeout_error(exc):
                processing_meta["provider_timeout_stage"] = (
                    "incident_read_and_whisper_v2" if use_v2 else "incident_read_and_whisper"
                )
                processing_meta["retry_attempted"] = True
                processing_meta["retry_strategy"] = "ultra_compact_incident_read_and_whisper"
                processing_meta["warnings"].append(
                    f"incident_read_and_whisper_first_attempt: {sanitize_user_facing_error(exc)}"
                )
                ultra_context_pack = build_ultra_compact_incident_read_context_pack(
                    incident_id=incident_id,
                    latest_window_events=latest_window,
                    input_size_assessment=input_size_assessment,
                    latest_window_selection=latest_window_selection,
                    allowed_targets=allowed_targets,
                    command_registry=command_registry,
                    catalog=catalog,
                    accepted_memories=[],
                    event_quality=event_quality,
                )
                if use_v2:
                    ultra_context_pack = build_incident_read_v2_context_pack(
                        base_context_pack=ultra_context_pack,
                        allowed_targets=allowed_targets,
                    )
                ultra_pack_summary = context_pack_summary(ultra_context_pack)
                if use_v2:
                    ultra_pack_summary = {
                        **ultra_pack_summary,
                        **incident_read_v2_context_pack_summary(ultra_context_pack),
                    }
                processing_meta["ultra_compact_payload_event_count"] = len(
                    ultra_context_pack.get("latest_window_events", [])
                )
                processing_meta["ultra_compact_payload_char_count"] = _context_pack_char_count(ultra_context_pack)
                step_artifacts.append(
                    _emit_artifact(
                        on_artifact,
                        run_id=run_id,
                        step="context_pack",
                        artifact_type="ultra_compact_incident_read_context_pack_summary",
                        summary_json=ultra_pack_summary,
                        payload_json=ultra_context_pack,
                        warnings=["First IncidentReadAndWhisper call timed out; retried with ultra-compact context."],
                    )
                )
                try:
                    with _stage_timeout(llm_client, _timeout(product_config, "latest_window_retry_timeout_seconds")):
                        if use_v2:
                            incident_read_v2 = extract_incident_read_and_whisper_v2(ultra_context_pack, llm_client)
                            decision, incident_read = decision_from_incident_read_v2(
                                incident_read_v2,
                                context_pack=ultra_context_pack,
                                allowed_targets=allowed_targets,
                                current_events=latest_window,
                            )
                        else:
                            incident_read = extract_incident_read_and_whisper(ultra_context_pack, llm_client)
                            decision = decision_from_incident_read(
                                incident_read,
                                allowed_targets=allowed_targets,
                                current_events=latest_window,
                            )
                except Exception as retry_exc:
                    terminal_failure_reason = (
                        "Provider timed out while reading the incident. The app retried with compact context "
                        "and still failed after a read operation timed out. Try again or paste the latest "
                        "20-30 messages around the current blocker."
                    )
                    processing_meta["terminal_failure_reason"] = terminal_failure_reason
                    processing_meta["warnings"].append(
                        f"incident_read_and_whisper_retry: {sanitize_user_facing_error(retry_exc)}"
                    )
                    raise ProviderTimeoutProcessingError(
                        terminal_failure_reason,
                        debug_payload=_simplified_failure_debug_payload(
                            events=events,
                            input_size_assessment=input_size_assessment,
                            latest_window_selection=latest_window_selection,
                            context_pack=context_pack,
                            pack_summary=pack_summary,
                            processing_meta=processing_meta,
                            terminal_failure_reason=terminal_failure_reason,
                        ),
                    ) from retry_exc
                context_pack = ultra_context_pack
                pack_summary = ultra_pack_summary
                retry_succeeded = True
            if retry_succeeded:
                pass
            elif classify_provider_error(exc) in {"auth_error", "model_error", "rate_limit", "network_error"}:
                processing_meta["terminal_failure_reason"] = sanitize_user_facing_error(exc)
                raise
            else:
                planning_failure = _planner_failure_object(exc)
                processing_meta["planning_failure"] = planning_failure
                processing_meta["provider_output_was_invalid"] = True
                processing_meta["planning_failure_category"] = planning_failure["planning_failure_category"]
                processing_meta["warnings"].append(f"incident_read_schema_or_provider_error: {sanitize_user_facing_error(exc)}")
                source_event = latest_window[-1] if latest_window else None
                incident_read = IncidentReadAndWhisper(
                    incident_id=incident_id,
                    current_read="The one-call incident read did not validate cleanly.",
                    latest_open_loop="insufficient validated model output",
                    already_answered=[],
                    selected_move=ICMove.NO_SAFE_RECOMMENDATION,
                    selected_target_id=None,
                    selected_target_display_name=None,
                    say_this="I do not have a safe, grounded next move yet.",
                    next_line="The model output did not validate cleanly; retry or paste the latest messages around the current blocker.",
                    evidence=[
                        WhisperEvidenceRef(
                            event_id=source_event.event_id,
                            quote=str(redact_for_llm(" ".join(source_event.message.split())[:240])),
                            confidence=0.4,
                        )
                    ]
                    if source_event is not None
                    else [],
                    uncertainty=sanitize_user_facing_error(exc),
                    confidence=0.2,
                )
        original_incident_read = incident_read
        incident_read, envelope_normalization = normalize_incident_read_envelope(
            incident_read,
            context_pack=context_pack,
            latest_window_events=latest_window,
        )
        if (
            envelope_normalization.get("target_id_canonicalized")
            or envelope_normalization.get("evidence_quote_canonicalized")
        ):
            processing_meta["envelope_normalization"] = envelope_normalization
        if not use_v2:
            decision = decision_from_incident_read(
                incident_read,
                allowed_targets=allowed_targets,
                current_events=latest_window,
            )
        else:
            # Rebuild after metadata-only target/quote canonicalization so the legacy verifier sees
            # the normalized compatibility envelope, while the semantic source remains V2.
            previous_metadata = decision.model_metadata if decision is not None else {}
            decision = decision_from_incident_read(
                incident_read,
                allowed_targets=allowed_targets,
                current_events=latest_window,
            ).model_copy(
                update={
                    "model_metadata": {
                        "product_path": "incident_read_and_whisper_v2",
                        **previous_metadata,
                    }
                }
            )
        if planning_failure := processing_meta.get("planning_failure"):
            decision = decision.model_copy(
                update={
                    "model_metadata": {
                        **decision.model_metadata,
                        "planning_failure": planning_failure,
                        "planner_validation_error": planning_failure.get("planner_validation_error"),
                        "provider_output_was_invalid": True,
                        "planning_failure_category": planning_failure.get("planning_failure_category"),
                    }
                }
            )
        decision = decision.model_copy(
            update={
                "model_metadata": {
                    **decision.model_metadata,
                    "current_work_items": context_pack.get("current_work_items", []),
                    "detected_diagnostic_facts": context_pack.get("detected_diagnostic_facts", []),
                    "retained_diagnostic_facts": context_pack.get("retained_diagnostic_facts", []),
                    "dropped_diagnostic_facts": context_pack.get("dropped_diagnostic_facts", []),
                    "diagnostic_fact_classifications": context_pack.get("diagnostic_fact_classifications", []),
                    "diagnostic_behavior_contracts": context_pack.get("diagnostic_behavior_contracts", []),
                    "diagnostic_actionability": context_pack.get("diagnostic_actionability", []),
                    "candidate_target_classes": context_pack.get("candidate_target_classes", []),
                    "service_team_owner_candidates": context_pack.get("service_team_owner_candidates", []),
                    "accepted_memory_behavior_contracts": context_pack.get(
                        "accepted_memory_behavior_contracts",
                        [],
                    ),
                    "incident_read_and_whisper_v2": (
                        incident_read_v2.model_dump(mode="json") if incident_read_v2 is not None else None
                    ),
                    "next_blocker_v2": (
                        incident_read_v2.next_blocker.model_dump(mode="json") if incident_read_v2 is not None else None
                    ),
                    "incident_state_v2": (
                        incident_read_v2.incident_state.model_dump(mode="json") if incident_read_v2 is not None else None
                    ),
                }
            }
        )
        if processing_meta.get("envelope_normalization"):
            decision = decision.model_copy(
                update={
                    "model_metadata": {
                        **decision.model_metadata,
                        "envelope_normalization": processing_meta["envelope_normalization"],
                    }
                }
            )
        decision, wording_lint_changed, wording_lint_reason = lint_manual_copy_output(decision)
        if wording_lint_changed:
            processing_meta["wording_lint_reason"] = wording_lint_reason
        decision, move_normalized, move_normalization_reason = normalize_move_for_visible_ask(decision)
        if move_normalized:
            processing_meta["metadata_repair_reason"] = move_normalization_reason
            processing_meta["actionability_move_normalized"] = True
            processing_meta["actionability_move_normalization_reason"] = move_normalization_reason
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="planning",
                artifact_type="incident_read_and_whisper_summary",
                summary_json={
                    "move": incident_read.selected_move,
                    "selected_target_id": incident_read.selected_target_id,
                    "selected_target_display_name": incident_read.selected_target_display_name,
                    "evidence_count": len(incident_read.evidence),
                    "confidence": incident_read.confidence,
                    "wording_lint_reason": processing_meta.get("wording_lint_reason"),
                    "move_normalization_reason": move_normalization_reason,
                    "target_id_canonicalized": envelope_normalization.get("target_id_canonicalized"),
                    "evidence_quote_canonicalized": envelope_normalization.get("evidence_quote_canonicalized"),
                    "planning_failure_category": (processing_meta.get("planning_failure") or {}).get(
                        "planning_failure_category"
                    ),
                    "provider_output_was_invalid": bool(processing_meta.get("provider_output_was_invalid")),
                    "product_path": "incident_read_and_whisper_v2" if use_v2 else "incident_read_and_whisper",
                    "v2_blocker_type": incident_read_v2.next_blocker.blocker_type if incident_read_v2 is not None else None,
                },
                payload_json={
                    "original_incident_read_and_whisper": original_incident_read.model_dump(mode="json"),
                    "incident_read_and_whisper": incident_read.model_dump(mode="json"),
                    "incident_read_and_whisper_v2": (
                        incident_read_v2.model_dump(mode="json") if incident_read_v2 is not None else None
                    ),
                    "envelope_normalization": envelope_normalization,
                    "decision": _decision_payload(decision),
                    "planning_failure": processing_meta.get("planning_failure"),
                },
            )
        )

    _emit(on_step, "semantic_intent_check", "skipped", "Legacy semantic intent checker is not used by normal path", 0)

    with _step(on_step, "verification", "Ran deterministic safety verifier"):
        verifier_result = verify_ic_decision(
            decision=decision,
            current_state=state,
            catalog=catalog,
            accepted_memories=accepted,
            command_registry=command_registry,
            allowed_targets=allowed_targets,
            event_quality=event_quality,
            current_events=latest_window,
            current_work_items=context_pack.get("current_work_items", []),
        )
        original_verifier_result = verifier_result
        repair_attempted = False
        repair_used = False
        repair_reason = None
        repair_verifier_status = None
        repair_blocked_claims: list[str] = []
        metadata_repair_used = False
        render_decision = decision
        if not verifier_result.passed and only_expiration_failed(verifier_result.checks):
            normalized_decision, changed, expiration_reason = normalize_decision_expiration(decision)
            if changed:
                repair_attempted = True
                metadata_repair_used = True
                repair_reason = "expiration_normalized"
                normalized_verifier = verify_ic_decision(
                    decision=normalized_decision,
                    current_state=state,
                    catalog=catalog,
                    accepted_memories=accepted,
                    command_registry=command_registry,
                    allowed_targets=allowed_targets,
                    event_quality=event_quality,
                    current_events=latest_window,
                    current_work_items=context_pack.get("current_work_items", []),
                )
                normalized_decision.verifier_result = normalized_verifier
                repair_verifier_status = normalized_verifier.final_status
                repair_blocked_claims = normalized_verifier.blocked_claims
                if normalized_verifier.passed:
                    verifier_result = normalized_verifier
                    render_decision = normalized_decision
                    processing_meta["metadata_repair_reason"] = expiration_reason
        if not verifier_result.passed:
            repaired, changed, formatting_reason = formatting_only_repair(render_decision, verifier_result)
            if changed:
                repair_attempted = True
                repair_reason = repair_reason or formatting_reason
                repaired_verifier = verify_ic_decision(
                    decision=repaired,
                    current_state=state,
                    catalog=catalog,
                    accepted_memories=accepted,
                    command_registry=command_registry,
                    allowed_targets=allowed_targets,
                    event_quality=event_quality,
                    current_events=latest_window,
                    current_work_items=context_pack.get("current_work_items", []),
                )
                repaired.verifier_result = repaired_verifier
                repair_verifier_status = repaired_verifier.final_status
                repair_blocked_claims = repaired_verifier.blocked_claims
                if repaired_verifier.passed:
                    verifier_result = repaired_verifier
                    render_decision = repaired
                    repair_used = True
        if not verifier_result.passed and verifier_result.fallback_decision is not None:
            render_decision = verifier_result.fallback_decision
            fallback_verifier = verify_ic_decision(
                decision=render_decision,
                current_state=state,
                catalog=catalog,
                accepted_memories=accepted,
                command_registry=command_registry,
                allowed_targets=allowed_targets,
                event_quality=event_quality,
                current_events=latest_window,
                current_work_items=context_pack.get("current_work_items", []),
            )
            render_decision.verifier_result = fallback_verifier
            if fallback_verifier.passed:
                verifier_result = fallback_verifier
        if metadata_repair_used and render_decision is not decision:
            repair_used = True
        decision.verifier_result = original_verifier_result
        render_decision.verifier_result = verifier_result
        no_safe_fallback_used = render_decision.decision_id.startswith("fallback-")
        fallback_used = no_safe_fallback_used
        why_no_safe_recommendation = None
        if render_decision.move == ICMove.NO_SAFE_RECOMMENDATION:
            why_no_safe_recommendation = "The one-call read did not produce a verifier-safe grounded normal recommendation."
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="verification",
                artifact_type="verifier_summary",
                summary_json={
                    "status": verifier_result.final_status,
                    "passed": verifier_result.passed,
                    "failed_checks": [
                        name for name, passed in verifier_result.checks.items() if not passed
                    ],
                    "repair_attempted": repair_attempted,
                    "repair_used": repair_used,
                    "render_move": render_decision.move,
                    "metadata_repair_reason": processing_meta.get("metadata_repair_reason"),
                    "simplified_failed_checks": [
                        name
                        for name, passed in _simplified_verifier_checks(original_verifier_result).items()
                        if not passed
                    ],
                },
                payload_json={
                    "original_verifier_result": _verifier_result_payload(original_verifier_result),
                    "final_verifier_result": _verifier_result_payload(verifier_result),
                    "simplified_checks": _simplified_verifier_checks(original_verifier_result),
                    "final_simplified_checks": _simplified_verifier_checks(verifier_result),
                    "legacy_noop_checks": _legacy_verifier_checks(original_verifier_result),
                    "repair": {
                        "repair_attempted": repair_attempted,
                        "repair_used": repair_used,
                        "repair_reason": repair_reason,
                        "repair_verifier_status": repair_verifier_status,
                        "repair_blocked_claims": repair_blocked_claims,
                        "metadata_repair_used": metadata_repair_used,
                        "metadata_repair_reason": processing_meta.get("metadata_repair_reason"),
                    },
                },
                warnings=verifier_result.blocked_claims,
            )
        )
        if repair_attempted:
            step_artifacts.append(
                _emit_artifact(
                    on_artifact,
                    run_id=run_id,
                    step="repair",
                    artifact_type="repair_summary",
                    summary_json={
                        "repair_used": repair_used,
                        "repair_reason": repair_reason,
                        "repair_verifier_status": repair_verifier_status,
                        "selected_target_ids": list(render_decision.target_ids),
                        "metadata_repair_used": metadata_repair_used,
                    },
                    payload_json={
                        "render_decision": _decision_payload(render_decision),
                        "blocked_claims": repair_blocked_claims,
                    },
                    warnings=repair_blocked_claims,
                )
            )

    _emit(
        on_step,
        "repair",
        "succeeded" if repair_attempted else "skipped",
        "Formatting/metadata repair used" if repair_used else "No formatting repair needed",
        0,
    )

    with _step(on_step, "rendering", "Rendered manual-copy IC whisper"):
        final_output = render_ic_whisper(render_decision)
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="rendering",
                artifact_type="final_output_summary",
                summary_json={
                    "move": render_decision.move,
                    "target_ids": render_decision.target_ids,
                    "has_command": bool(render_decision.output.get("command")),
                },
                payload_json={
                    "final_output": final_output,
                    "rendered_decision": _decision_payload(render_decision),
                },
            )
        )

    latency_ms = int((time.perf_counter() - started) * 1000)
    action_owner_alignment_detail = _verifier_detail_claim(
        original_verifier_result,
        "action_owner_alignment_detail",
    )
    stale_superseded_question_detail = _verifier_detail_claim(
        original_verifier_result,
        "stale_superseded_question_detail",
    )
    stale_status_recap_detail = _verifier_detail_claim(
        original_verifier_result,
        "stale_status_recap_detail",
    )
    permission_denied_wrong_owner_detail = _verifier_detail_claim(
        original_verifier_result,
        "permission_denied_wrong_owner_detail",
    )
    metadata_only_stale_repair = _verifier_has_allowed_claim(
        original_verifier_result,
        "metadata_only_stale_open_loop_repaired",
    )
    visible_metadata_repair_used = metadata_repair_used or metadata_only_stale_repair
    visible_metadata_repair_reason = processing_meta.get("metadata_repair_reason")
    if metadata_only_stale_repair:
        visible_metadata_repair_reason = "stale_open_loop_metadata_only"
    safety_summary = {
        "fallback_used": fallback_used,
        "planner_fallback_used": False,
        "repair_attempted": repair_attempted,
        "repair_used": repair_used,
        "repair_reason": repair_reason,
        "repair_verifier_status": repair_verifier_status,
        "repair_blocked_claims": repair_blocked_claims,
        "repair_selected_target_ids": list(render_decision.target_ids) if repair_used else [],
        "metadata_repair_used": visible_metadata_repair_used,
        "metadata_repair_reason": visible_metadata_repair_reason,
        "actionability_move_normalized": bool(processing_meta.get("actionability_move_normalized")),
        "actionability_move_normalization_reason": processing_meta.get("actionability_move_normalization_reason"),
        "envelope_normalization": processing_meta.get("envelope_normalization"),
        "target_id_canonicalized": bool(
            (processing_meta.get("envelope_normalization") or {}).get("target_id_canonicalized")
        ),
        "evidence_quote_canonicalized": bool(
            (processing_meta.get("envelope_normalization") or {}).get("evidence_quote_canonicalized")
        ),
        "wording_lint_reason": processing_meta.get("wording_lint_reason"),
        "original_decision_move": decision.move,
        "repaired_decision_move": render_decision.move if repair_used else None,
        "why_no_safe_recommendation": why_no_safe_recommendation,
        "planning_failure": processing_meta.get("planning_failure"),
        "planner_validation_error": (processing_meta.get("planning_failure") or {}).get("planner_validation_error"),
        "provider_json_parse_error": (processing_meta.get("planning_failure") or {}).get("provider_json_parse_error"),
        "provider_schema_error": (processing_meta.get("planning_failure") or {}).get("provider_schema_error"),
        "provider_invalid_fields": (processing_meta.get("planning_failure") or {}).get("provider_invalid_fields", []),
        "provider_raw_output_redacted_excerpt": (processing_meta.get("planning_failure") or {}).get(
            "provider_raw_output_redacted_excerpt"
        ),
        "provider_output_was_invalid": bool(processing_meta.get("provider_output_was_invalid")),
        "provider_output_invalid_reason": (processing_meta.get("planning_failure") or {}).get(
            "provider_output_invalid_reason"
        ),
        "planning_failure_category": (processing_meta.get("planning_failure") or {}).get("planning_failure_category"),
        "domain_intent": decision.domain_intent,
        "original_verifier_status": original_verifier_result.final_status,
        "original_blocked_claims": original_verifier_result.blocked_claims,
        "verifier_status": verifier_result.final_status,
        "verifier_passed": verifier_result.passed,
        "blocked_claims": verifier_result.blocked_claims,
        "failed_checks": [name for name, passed in verifier_result.checks.items() if not passed],
        "simplified_verifier_checks": _simplified_verifier_checks(original_verifier_result),
        "final_simplified_verifier_checks": _simplified_verifier_checks(verifier_result),
        "legacy_noop_verifier_checks": _legacy_verifier_checks(original_verifier_result),
        "input_size_assessment": input_size_assessment.model_dump(mode="json"),
        "latest_window_selection": latest_window_selection.model_dump(mode="json"),
        "processing_strategy": processing_meta.get("processing_strategy"),
        "provider_timeout_stage": processing_meta.get("provider_timeout_stage"),
        "retry_attempted": processing_meta.get("retry_attempted"),
        "retry_strategy": processing_meta.get("retry_strategy"),
        "compact_payload_event_count": processing_meta.get("compact_payload_event_count"),
        "compact_payload_char_count": processing_meta.get("compact_payload_char_count"),
        "ultra_compact_payload_event_count": processing_meta.get("ultra_compact_payload_event_count"),
        "ultra_compact_payload_char_count": processing_meta.get("ultra_compact_payload_char_count"),
        "terminal_failure_reason": processing_meta.get("terminal_failure_reason"),
        "state_delta_status": processing_meta.get("state_delta_status"),
        "full_context_enrichment_status": processing_meta.get("full_context_enrichment_status"),
        "processing_warnings": processing_meta.get("warnings", []),
        "event_quality_summary": event_quality_summary(event_quality),
        "recovered_compact_author_count": normalizer_summary.get("recovered_compact_author_count", 0),
        "compact_author_recovery_examples": normalizer_summary.get("compact_author_recovery_examples", []),
        "human_diagnostic_grounding_count": normalizer_summary.get("human_diagnostic_grounding_count", 0),
        "retained_high_signal_diagnostic_event_ids": pack_summary.get(
            "retained_high_signal_diagnostic_event_ids",
            [],
        ),
        "dropped_high_signal_diagnostic_event_ids": pack_summary.get(
            "dropped_high_signal_diagnostic_event_ids",
            [],
        ),
        "detected_diagnostic_facts": pack_summary.get("detected_diagnostic_facts", []),
        "retained_diagnostic_facts": pack_summary.get("retained_diagnostic_facts", []),
        "dropped_diagnostic_facts": pack_summary.get("dropped_diagnostic_facts", []),
        "diagnostic_fact_classifications": pack_summary.get("diagnostic_fact_classifications", []),
        "detected_diagnostic_fact_ids": pack_summary.get("detected_diagnostic_fact_ids", []),
        "retained_diagnostic_fact_ids": pack_summary.get("retained_diagnostic_fact_ids", []),
        "dropped_diagnostic_fact_ids": pack_summary.get("dropped_diagnostic_fact_ids", []),
        "candidate_target_classes": pack_summary.get("candidate_target_classes", []),
        "service_team_owner_candidates": pack_summary.get("service_team_owner_candidates", []),
        "accepted_memory_behavior_contracts": pack_summary.get("accepted_memory_behavior_contracts", []),
        "action_state_transitions": context_pack.get("action_state_transitions", []),
        "answered_questions_from_actions": context_pack.get("answered_questions_from_actions", []),
        "do_not_ask_from_actions": context_pack.get("do_not_ask_from_actions", []),
        "runtime_knowledge_counts": pack_summary.get("runtime_knowledge_counts", {}),
        "diagnostic_behavior_contracts": pack_summary.get("diagnostic_behavior_contracts", []),
        "diagnostic_actionability": pack_summary.get("diagnostic_actionability", []),
        "context_pack_summary": pack_summary,
        "model_payload_char_count": pack_summary.get("model_payload_char_count"),
        "model_event_count": pack_summary.get("model_event_count"),
        "work_item_count": pack_summary.get("work_item_count"),
        "work_item_labels": pack_summary.get("work_item_labels"),
        "action_owner_alignment_check": original_verifier_result.checks.get("action_owner_aligned", True),
        "action_owner_alignment_check_detail": action_owner_alignment_detail,
        "stale_open_loop_contradiction_check": original_verifier_result.checks.get(
            "stale_open_loop_contradiction", True
        ),
        "stale_superseded_question_check": stale_superseded_question_detail,
        "stale_status_recap_check": original_verifier_result.checks.get("stale_visible_status_recap", True),
        "stale_status_recap_check_detail": stale_status_recap_detail,
        "permission_denied_wrong_owner_check": original_verifier_result.checks.get(
            "permission_denied_wrong_owner_loop", True
        ),
        "permission_denied_wrong_owner_detail": permission_denied_wrong_owner_detail,
        "accepted_memory_target_class_satisfied": original_verifier_result.checks.get(
            "accepted_memory_target_class_satisfied",
            True,
        ),
        "accepted_memory_visible_intent_satisfied": original_verifier_result.checks.get(
            "accepted_memory_visible_intent_satisfied",
            True,
        ),
        "no_safe_despite_diagnostic_signal": original_verifier_result.checks.get(
            "no_safe_despite_diagnostic_signal",
            True,
        ),
        "reporter_not_owner_when_owner_candidate_exists": original_verifier_result.checks.get(
            "reporter_not_owner_when_owner_candidate_exists",
            True,
        ),
        "bot_diagnostic_context_preserved": original_verifier_result.checks.get(
            "bot_diagnostic_context_preserved",
            True,
        ),
        "raw_paste_evidence_preservation": original_verifier_result.checks.get(
            "raw_paste_evidence_preservation",
            True,
        ),
        "no_private_identifier_in_visible_output": original_verifier_result.checks.get(
            "no_private_identifier_in_visible_output", True
        ),
        "no_json_log_target": original_verifier_result.checks.get("no_json_log_target", True),
        "metadata_only_stale_open_loop_repaired": metadata_only_stale_repair,
        "model_payload_hard_cap": pack_summary.get("model_payload_hard_cap"),
        "model_payload_over_cap": pack_summary.get("model_payload_over_cap"),
        "provider_payload_char_count": pack_summary.get("provider_payload_char_count"),
        "excluded_human_mention_count": pack_summary.get("excluded_human_mention_count", 0),
        "observed_bot_command_candidate_count": pack_summary.get("observed_bot_command_candidate_count", 0),
        "model_exposed_command_count": pack_summary.get("model_exposed_command_count", 0),
        "url_slash_false_positive_count": pack_summary.get("url_slash_false_positive_count", 0),
        "candidate_targets": context_pack.get("candidate_targets", []),
        "rejected_targets": context_pack.get("do_not_target", []),
        "json_log_pseudo_author_count": sum(
            1
            for event in latest_window
            for warning in (event.raw_metadata or {}).get("parser_warnings", [])
            if "json" in str(warning).lower() or "diagnostic" in str(warning).lower()
        ),
        "rejected_json_log_target_examples": [
            target.get("display_name")
            for target in context_pack.get("do_not_target", [])
            if "json" in str(target.get("rejection_reason") or "").lower()
            or "diagnostic" in str(target.get("rejection_reason") or "").lower()
        ][:8],
        "permission_denied_work_items": [
            item
            for item in context_pack.get("current_work_items", [])
            if item.get("work_item_type") == "permission_blocked_operational_attempt"
        ],
        "accepted_sync_latency_memory_ids": [
            item.decision_id
            for item in accepted
            if str(item.decision_id).startswith("DM_")
            and any(term in str(item.decision_id).lower() for term in ("bottleneck", "tenant", "customer", "service_owner"))
        ],
        "selected_target_ids": list(render_decision.target_ids),
        "selected_move": render_decision.move,
        "incident_read_and_whisper": incident_read.model_dump(mode="json"),
        "legacy_debug_only": _trace_legacy_debug_summary(),
    }
    run_diagnosis = build_run_diagnosis(
        incident_id=incident_id,
        events=latest_window,
        event_quality=event_quality,
        latest_window_selection=latest_window_selection,
        context_pack=context_pack,
        allowed_targets=allowed_targets,
        current_work_items=context_pack.get("current_work_items", []),
        loaded_memory_count=len(hydrated),
        retrieved_memory_ids=memory_ids,
        applicability_results=applicability,
        accepted_memory_ids=[item.decision_id for item in accepted],
        incident_read=incident_read,
        decision=render_decision,
        candidate_decision=decision,
        verifier_result=verifier_result,
        final_output=final_output,
        fallback_used=fallback_used,
        planning_failure=processing_meta.get("planning_failure"),
    )
    run_diagnosis_summary = summarize_run_diagnosis(run_diagnosis)
    safety_summary["run_diagnosis_summary"] = run_diagnosis_summary
    v2_quality_gate = evaluate_incident_read_v2_quality(
        read_v2=incident_read_v2,
        diagnosis_summary=run_diagnosis_summary,
    )
    if incident_read_v2 is not None:
        safety_summary["incident_read_and_whisper_v2"] = incident_read_v2.model_dump(mode="json")
        safety_summary["v2_quality_gate"] = v2_quality_gate
        safety_summary["safety_status"] = v2_quality_gate.get("safety_status")
        safety_summary["usefulness_status"] = v2_quality_gate.get("usefulness_status")
        safety_summary["state_quality_status"] = v2_quality_gate.get("state_quality_status")
        safety_summary["parser_quality_status"] = v2_quality_gate.get("parser_quality_status")
        safety_summary["v2_blocker_type"] = v2_quality_gate.get("blocker_type")
        safety_summary["v2_state_summary"] = v2_quality_gate.get("state_summary")
    with _step(on_step, "run_diagnosis", "Built run diagnosis"):
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="run_diagnosis",
                artifact_type="run_diagnosis_summary",
                summary_json=run_diagnosis_summary,
                payload_json=run_diagnosis,
            )
        )
    trace = TraceRecord(
        trace_id=f"{incident_id}:{uuid4().hex[:12]}",
        incident_id=incident_id,
        pipeline_version="phase-2.0-state-first" if use_v2 else "phase-1.36-simplified",
        input_event_ids=[event.event_id for event in events],
        trigger=trigger,
        current_state=state,
        memory_query=query,
        retrieved_memory_ids=memory_ids,
        hydrated_memory_ids=[moment.decision_id for moment in hydrated],
        applicability_results=applicability,
        accepted_memory_ids=[item.decision_id for item in accepted],
        catalog_match_ids=[entry.service_id for entry in catalog_matches],
        command_registry_size=len(command_registry),
        input_size_assessment=input_size_assessment,
        latest_window_selection=latest_window_selection,
        processing_strategy=processing_meta.get("processing_strategy"),
        provider_timeout_stage=processing_meta.get("provider_timeout_stage"),
        retry_attempted=bool(processing_meta.get("retry_attempted")),
        retry_strategy=processing_meta.get("retry_strategy"),
        terminal_failure_reason=processing_meta.get("terminal_failure_reason"),
        step_artifacts=step_artifacts,
        event_quality=event_quality,
        context_pack_summary=pack_summary,
        incident_read_and_whisper=incident_read,
        allowed_targets=allowed_targets,
        selected_target_ids=list(render_decision.target_ids),
        rejected_non_targetable_candidates=[target for target in allowed_targets if not target.targetable],
        latest_window_event_ids=latest_window_selection.event_ids,
        repair_result={
            "repair_attempted": repair_attempted,
            "repair_used": repair_used,
            "repair_reason": repair_reason,
            "repair_verifier_status": repair_verifier_status,
            "repair_blocked_claims": repair_blocked_claims,
        },
        raw_decision=decision,
        verifier_result=verifier_result,
        rendered_decision=render_decision,
        final_output=final_output,
        run_diagnosis=run_diagnosis,
        safety_summary=safety_summary,
        latency_ms=latency_ms,
        errors=errors,
    )

    if save_trace:
        with _step(on_step, "trace_saved", "Saved trace locally"):
            db_path = os.environ.get("IC_COPILOT_DB_PATH", ".ic_copilot/traces.sqlite3")
            conn = init_db(db_path)
            save_payload(conn, trace_id=trace.trace_id, kind="run", payload=_trace_payload(trace))
            conn.close()
    else:
        _emit(on_step, "trace_saved", "skipped", "Trace saving disabled", 0)

    _emit(on_step, "complete", "succeeded", "Pipeline complete", 0)
    return {
        "events": events,
        "event_quality": event_quality,
        "trigger": trigger,
        "allowed_targets": allowed_targets,
        "target_shortlist": [],
        "latest_window_selection": latest_window_selection,
        "context_pack": context_pack,
        "context_pack_summary": pack_summary,
        "incident_read_and_whisper": incident_read,
        "incident_read_and_whisper_v2": incident_read_v2,
        "incident_brief": None,
        "clean_turn_ledger": None,
        "actor_workstream_ledger": None,
        "incident_fact_ledger": None,
        "question_intent_ledger": None,
        "semantic_quality": None,
        "original_incident_brief_quality": None,
        "incident_brief_quality": None,
        "blocker_reselection": None,
        "step_artifacts": step_artifacts,
        "clean_context": None,
        "slack_turn_reconstruction": None,
        "sharp_blocker_assessment": None,
        "state": state,
        "memory_ids": memory_ids,
        "accepted_memories": accepted,
        "decision": render_decision,
        "raw_decision": decision,
        "verifier_result": verifier_result,
        "semantic_intent_assessment": None,
        "final_output": final_output,
        "trace": trace,
        "latency_ms": latency_ms,
    }


def run_pipeline(
    incident_file: str | Path,
    catalog_path: str | Path | None = None,
    memory_dir: str | Path | None = None,
    memory_path: str | Path | None = None,
    command_registry_path: str | Path | None = None,
    save_trace: bool = True,
    on_step: PipelineEventCallback | None = None,
    on_artifact: PipelineArtifactCallback | None = None,
    run_id: str = "manual",
    planner_func: Callable[..., Any] | None = None,
    llm_client: LLMClient | None = None,
    runtime_config: ProductRuntimeConfig | None = None,
    config_path: str | Path | None = None,
    use_product_defaults: bool = True,
) -> dict[str, Any]:
    started = time.perf_counter()
    errors: list[str] = []
    incident_id = incident_id_from_path(incident_file)
    step_artifacts: list[dict[str, Any]] = []

    with _step(on_step, "normalize_input", "Loaded incident events"):
        events = load_incident_events(incident_file, incident_id=incident_id)
        raw_text = Path(incident_file).read_text(errors="replace")
        event_quality = classify_events_quality(events)
        normalizer_summary = _normalizer_artifact_summary(events, event_quality)
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="normalize_input",
                artifact_type="normalized_events_summary",
                summary_json=normalizer_summary,
                payload_json={
                    "events": _event_artifact_rows(events),
                    "event_quality": [quality.model_dump(mode="json") for quality in event_quality],
                },
            )
        )

    state = CurrentIncidentState(incident_id=incident_id)
    with _step(on_step, "input_assessment", "Assessed input size and processing strategy"):
        input_size_assessment = assess_input_size(raw_text, events)
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="input_assessment",
                artifact_type="input_size_assessment_summary",
                summary_json={
                    "events": input_size_assessment.event_count,
                    "estimated_tokens": input_size_assessment.estimated_token_count,
                    "strategy": input_size_assessment.recommended_strategy,
                    "bot_system": input_size_assessment.bot_or_system_event_count,
                    "urls": input_size_assessment.url_count,
                    "log_table_blocks": input_size_assessment.code_or_log_block_count,
                },
                payload_json=input_size_assessment.model_dump(mode="json"),
            )
        )

    with _step(on_step, "trigger_decision", "Evaluated whether the incident needs planning"):
        trigger = decide_trigger(events, state)
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="trigger_decision",
                artifact_type="trigger_summary",
                summary_json={"should_extract": trigger.should_extract, "should_plan": trigger.should_plan, "reasons": trigger.reasons},
                payload_json=trigger.model_dump(mode="json"),
            )
        )

    product_config = runtime_config
    product_resource_mode = False
    if llm_client is None:
        with _step(on_step, "product_runtime_config", "Loaded product AI runtime configuration"):
            product_config = product_config or load_product_runtime_config(config_path)
            llm_client = create_product_llm_client(product_config)
            product_resource_mode = (
                use_product_defaults
                and catalog_path is None
                and command_registry_path is None
                and memory_dir is None
                and memory_path is None
            )
            step_artifacts.append(
                _emit_artifact(
                    on_artifact,
                    run_id=run_id,
                    step="product_runtime_config",
                    artifact_type="runtime_config_summary",
                    summary_json={
                        "provider": product_config.llm.provider,
                        "model": product_config.llm.model,
                        "knowledge_source": product_config.product_knowledge_path,
                        "verifier_required": product_config.runtime.require_verifier_pass,
                    },
                    payload_json={
                        "provider": product_config.llm.provider,
                        "model": product_config.llm.model,
                        "api_key_env": product_config.llm.api_key_env,
                        "product_knowledge_path": product_config.product_knowledge_path,
                        "timeouts": product_config.timeouts.model_dump(mode="json"),
                    },
                )
            )
    else:
        _emit(on_step, "product_runtime_config", "skipped", "Explicit LLM client injected for test/eval/dev run", 0)

    if product_config is not None and not product_resource_mode:
        product_resource_mode = (
            use_product_defaults
            and catalog_path is None
            and command_registry_path is None
            and memory_dir is None
            and memory_path is None
        )

    effective_memory_path = memory_path if memory_path is not None else memory_dir
    if product_config is not None:
        effective_catalog_path = catalog_path or product_config.paths.catalog
        effective_command_registry_path = command_registry_path or product_config.paths.command_registry
        effective_memory_path = effective_memory_path or product_config.paths.memory
    else:
        effective_catalog_path = catalog_path or "data/sample/service_catalog.yaml"
        effective_command_registry_path = command_registry_path
        effective_memory_path = effective_memory_path or "data/sample/decision_moments"

    with _step(on_step, "catalog_lookup", "Loaded service catalog"):
        catalog = (
            load_product_catalog(product_config)
            if product_resource_mode and product_config is not None
            else load_service_catalog(effective_catalog_path)
        )
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="catalog_lookup",
                artifact_type="catalog_summary",
                summary_json={"services": len(catalog)},
                payload_json={
                    "service_ids": [entry.service_id for entry in catalog],
                    "visible_names": [entry.canonical_name for entry in catalog[:40]],
                },
            )
        )

    with _step(on_step, "command_registry_load", "Loaded command registry for suggestion validation"):
        if product_resource_mode and product_config is not None:
            command_registry = load_product_command_registry(product_config, catalog)
        else:
            command_registry = (
                load_command_registry(effective_command_registry_path, catalog)
                if effective_command_registry_path
                else build_command_registry(catalog)
            )
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="command_registry_load",
                artifact_type="command_registry_summary",
                summary_json={"commands": len(command_registry)},
                payload_json={
                    "commands": [
                        {
                            "command_id": command.command_id,
                            "target": command.target,
                            "danger_level": command.danger_level,
                            "requires_human_approval": command.requires_human_approval,
                        }
                        for command in command_registry
                    ]
                },
            )
        )

    with _step(on_step, "allowed_targets", "Built deterministic allowed target candidates"):
        allowed_targets = build_allowed_targets(events, catalog, command_registry)
        counts = _allowed_target_counts(allowed_targets)
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="allowed_targets",
                artifact_type="allowed_targets_summary",
                summary_json={
                    **counts,
                    "sample_allowed": [
                        target.display_name
                        for target in allowed_targets
                        if target.targetable and target.target_quality in {"high", "medium"}
                    ][:8],
                    "sample_rejected": [
                        target.display_name
                        for target in allowed_targets
                        if not target.targetable or target.target_quality in {"low", "rejected"}
                    ][:8],
                    "rejected_preview_card": len(
                        [
                            target
                            for target in allowed_targets
                            if target.source_event_kind in {"preview_card", "pagerduty_card", "jira_card", "zoom_card"}
                            and not target.targetable
                        ]
                    ),
                    "rejected_log_table": len(
                        [
                            target
                            for target in allowed_targets
                            if target.source_event_kind in {"log_or_code_block", "table_row", "table_header"}
                            and not target.targetable
                        ]
                    ),
                },
                payload_json={"allowed_targets": [target.model_dump(mode="json") for target in allowed_targets]},
            )
        )
    target_shortlist: list[TargetShortlistItem] = []
    planner_allowed_targets = allowed_targets

    with _step(on_step, "latest_window_selection", "Selected latest high-signal incident window"):
        latest_window_selection = select_latest_window(events, max_events=35)
        latest_window = _events_by_selection(events, latest_window_selection)
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="latest_window_selection",
                artifact_type="latest_window_selection",
                summary_json={
                    "kept": latest_window_selection.kept_event_count,
                    "dropped": latest_window_selection.dropped_event_count,
                    "reason": latest_window_selection.reason,
                    "latest_human_evidence": latest_window_selection.contains_latest_human_evidence,
                    "latest_validation_or_monitoring": latest_window_selection.contains_latest_validation_or_monitoring,
                },
                payload_json=latest_window_selection.model_dump(mode="json"),
            )
        )

    if planner_func is None:
        return _run_incident_read_and_whisper_path(
            incident_id=incident_id,
            events=events,
            state=state,
            trigger=trigger,
            catalog=catalog,
            command_registry=command_registry,
            allowed_targets=allowed_targets,
            latest_window_selection=latest_window_selection,
            latest_window=latest_window,
            input_size_assessment=input_size_assessment,
            event_quality=event_quality,
            product_config=product_config,
            product_resource_mode=product_resource_mode,
            effective_memory_path=effective_memory_path,
            llm_client=llm_client,
            started=started,
            save_trace=save_trace,
            on_step=on_step,
            on_artifact=on_artifact,
            run_id=run_id,
            step_artifacts=step_artifacts,
        )

    slack_turn_reconstruction = None
    turn_reconstruction_warnings: list[str] = []
    with _step(on_step, "slack_turn_reconstruction", "Reconstructed collapsed Slack speaker turns when needed"):
        slack_turn_reconstruction, turn_reconstruction_warnings = reconstruct_slack_turns(
            raw_text=raw_text,
            events=events,
            assessment=input_size_assessment,
            incident_id=incident_id,
            llm_client=llm_client,
        )
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="slack_turn_reconstruction",
                artifact_type="turn_reconstruction_summary",
                summary_json={
                    "turns": len(slack_turn_reconstruction.turns) if slack_turn_reconstruction else 0,
                    "used": slack_turn_reconstruction is not None,
                    "warnings": len(turn_reconstruction_warnings),
                },
                payload_json=(
                    slack_turn_reconstruction.model_dump(mode="json") if slack_turn_reconstruction else {"warnings": turn_reconstruction_warnings}
                ),
                warnings=turn_reconstruction_warnings,
            )
        )

    clean_context = None
    processing_meta: dict[str, Any] = {
        "processing_strategy": "parallel_semantic_read_incident_brief",
        "chunk_count": 0,
        "chunk_ids": [],
        "chunk_success_count": 0,
        "chunk_failure_count": 0,
        "provider_timeout_stage": None,
        "retry_attempted": False,
        "retry_strategy": None,
        "warnings": [],
        "state_delta_status": "not_started",
        "full_context_enrichment_status": "skipped",
        "incident_brief_attempts": [],
        "incident_brief_attempt_count": 0,
        "compact_payload_event_count": 0,
        "compact_payload_char_count": 0,
        "ultra_compact_payload_event_count": 0,
        "ultra_compact_payload_char_count": 0,
        "terminal_failure_reason": None,
    }
    if input_size_assessment.recommended_strategy in {"chunked_clean_context", "latest_window_only_with_summary"}:
        planned_chunks = select_chunks(
            split_event_chunks(
                events,
                max_chunk_chars=6000 if input_size_assessment.code_or_log_block_count >= 4 else 14000,
                max_events_per_chunk=12 if input_size_assessment.code_or_log_block_count >= 4 else 40,
            )
        )
        processing_meta["chunk_count"] = len(planned_chunks)
        processing_meta["chunk_ids"] = [chunk.chunk_id for chunk in planned_chunks]
    semantic_read_result = ParallelSemanticReadResult(errors={})
    incident_brief: IncidentBrief | None = None
    semantic_quality = SemanticQuality()
    incident_brief_quality = BriefQualityResult()
    original_incident_brief_quality = BriefQualityResult()
    blocker_reselection = AuthoritativeBlockerSelection()
    quality_gate_blocks_planning = False
    if trigger.should_extract or events:
        _ensure_run_budget(started, product_config, "semantic_read")
        with _step(on_step, "semantic_read", "Read latest incident window into parallel semantic ledgers"):
            semantic_timeout = _timeout(product_config, "latest_window_brief_timeout_seconds")
            try:
                with _stage_timeout(llm_client, semantic_timeout):
                    semantic_read_result, semantic_meta = run_parallel_semantic_read(
                        incident_id=incident_id,
                        events=latest_window,
                        allowed_targets=allowed_targets,
                        input_size_assessment=input_size_assessment,
                        current_state=state,
                        llm_client=llm_client,
                        max_workers=4,
                    )
                processing_meta["compact_payload_event_count"] = len(latest_window)
                processing_meta["compact_payload_char_count"] = len(str(semantic_meta.get("payload") or ""))
                step_artifacts.append(
                    _emit_artifact(
                        on_artifact,
                        run_id=run_id,
                        step="semantic_read",
                        artifact_type="semantic_read_summary",
                        summary_json=semantic_meta["summary"],
                        payload_json=semantic_meta["payload"],
                        warnings=[
                            f"{name}: {sanitize_user_facing_error(error)}"
                            for name, error in (semantic_read_result.errors or {}).items()
                        ],
                    )
                )
                if semantic_read_result.clean_turn_ledger is None:
                    processing_meta["retry_attempted"] = True
                    processing_meta["retry_strategy"] = "ultra_compact_clean_turn_ledger"
                    retry_events = latest_window[-18:] if len(latest_window) > 18 else latest_window
                    retry_payload = build_semantic_read_payload(
                        incident_id=incident_id,
                        events=retry_events,
                        allowed_targets=allowed_targets,
                        input_size_assessment=input_size_assessment,
                        current_state=state,
                        max_chars_per_event=360,
                        max_targets=8,
                    )
                    try:
                        retry_timeout = _timeout(product_config, "latest_window_retry_timeout_seconds")
                        if retry_timeout is not None and semantic_timeout is not None:
                            retry_timeout = min(retry_timeout, semantic_timeout)
                        elif retry_timeout is None:
                            retry_timeout = semantic_timeout
                        with _stage_timeout(
                            llm_client,
                            retry_timeout,
                        ):
                            semantic_read_result.clean_turn_ledger = extract_clean_turn_ledger(retry_payload, llm_client)
                        if semantic_read_result.errors:
                            semantic_read_result.errors.pop("clean_turn_ledger", None)
                        step_artifacts.append(
                            _emit_artifact(
                                on_artifact,
                                run_id=run_id,
                                step="semantic_read",
                                artifact_type="clean_turn_ledger_retry",
                                summary_json={
                                    "status": "succeeded",
                                    "event_count": len(retry_events),
                                    "payload_chars": len(str(retry_payload)),
                                },
                                payload_json={
                                    "event_ids": [event.event_id for event in retry_events],
                                    "payload_event_count": len(retry_payload.get("events", [])),
                                    "clean_turns": semantic_read_result.clean_turn_ledger.model_dump(mode="json"),
                                },
                            )
                        )
                    except Exception as retry_exc:
                        if _is_timeout_error(retry_exc):
                            processing_meta["provider_timeout_stage"] = "semantic_read.clean_turn_ledger_retry"
                        processing_meta["warnings"] = [
                            *processing_meta.get("warnings", []),
                            f"clean_turn_ledger_retry: {sanitize_user_facing_error(retry_exc)}",
                        ]
                        if semantic_read_result.errors is None:
                            semantic_read_result.errors = {}
                        semantic_read_result.errors["clean_turn_ledger_retry"] = f"{retry_exc.__class__.__name__}: {retry_exc}"
                        step_artifacts.append(
                            _emit_artifact(
                                on_artifact,
                                run_id=run_id,
                                step="semantic_read",
                                artifact_type="clean_turn_ledger_retry_error",
                                summary_json={"status": "failed", "error_type": type(retry_exc).__name__},
                                payload_json={"event_ids": [event.event_id for event in retry_events]},
                                error=sanitize_user_facing_error(retry_exc),
                            )
                        )
            except Exception as exc:
                if _is_timeout_error(exc):
                    processing_meta["provider_timeout_stage"] = "semantic_read"
                processing_meta["warnings"] = [
                    *processing_meta.get("warnings", []),
                    f"semantic_read: {sanitize_user_facing_error(exc)}",
                ]
                step_artifacts.append(
                    _emit_artifact(
                        on_artifact,
                        run_id=run_id,
                        step="semantic_read",
                        artifact_type="semantic_read_error",
                        summary_json={"status": "failed", "error_type": type(exc).__name__},
                        payload_json={"latest_window_event_ids": latest_window_selection.event_ids},
                        error=sanitize_user_facing_error(exc),
                    )
                )
                raise
            for artifact_type, summary_json, payload_json, warnings in _semantic_ledger_artifacts(
                semantic_read_result
            ):
                step_artifacts.append(
                    _emit_artifact(
                        on_artifact,
                        run_id=run_id,
                        step="semantic_read",
                        artifact_type=artifact_type,
                        summary_json=summary_json,
                        payload_json=payload_json,
                        warnings=warnings,
                    )
                )
            for reader_name, error in (semantic_read_result.errors or {}).items():
                step_artifacts.append(
                    _emit_artifact(
                        on_artifact,
                        run_id=run_id,
                        step="semantic_read",
                        artifact_type=f"{reader_name}_error",
                        summary_json={"reader": reader_name, "status": "failed"},
                        payload_json={"reader": reader_name},
                        error=sanitize_user_facing_error(error),
                    )
                )
            if semantic_read_result.success_count == 0:
                if _allows_dev_schema_fallback(llm_client) and _semantic_errors_allow_dev_fallback(
                    semantic_read_result.errors
                ):
                    processing_meta["warnings"] = [
                        *processing_meta.get("warnings", []),
                        "semantic_read_dev_compatibility: generated deterministic ledgers for a partial test client.",
                    ]
                    semantic_read_result = ParallelSemanticReadResult(
                        clean_turn_ledger=build_deterministic_clean_turn_ledger(
                            incident_id,
                            latest_window,
                        ),
                        actor_workstream_ledger=build_deterministic_actor_workstream_ledger(
                            incident_id,
                            latest_window,
                            allowed_targets,
                        ),
                        incident_fact_ledger=build_deterministic_incident_fact_ledger(
                            incident_id,
                            latest_window,
                        ),
                        question_intent_ledger=build_deterministic_question_intent_ledger(
                            incident_id,
                            latest_window,
                        ),
                        errors={},
                    )
                else:
                    first_error = next(iter((semantic_read_result.errors or {}).values()), "")
                    safe_error = sanitize_user_facing_error(first_error)
                    provider_failure = any(
                        term in safe_error.lower()
                        for term in ("authentication", "api key", "rate limit", "provider")
                    )
                    timeout_failure = _is_timeout_error(RuntimeError(safe_error))
                    if semantic_read_result.clean_turn_ledger is None and not (timeout_failure or provider_failure):
                        terminal_failure_reason = (
                            "Could not build a clean speaker/action ledger from this paste. "
                            "Try again or paste the latest 20-30 messages around the current blocker."
                        )
                        processing_meta["terminal_failure_reason"] = terminal_failure_reason
                        raise LargeInputProcessingError(
                            terminal_failure_reason,
                            debug_payload=_failure_debug_payload(
                                events=events,
                                input_size_assessment=input_size_assessment,
                                latest_window_selection=latest_window_selection,
                                allowed_targets=allowed_targets,
                                processing_meta=processing_meta,
                                terminal_failure_reason=terminal_failure_reason,
                            ),
                        )
                    if timeout_failure:
                        terminal_failure_reason = (
                            "Provider timed out while reading the incident. Try again or paste the latest "
                            "20-30 messages around the current blocker."
                        )
                    elif provider_failure:
                        terminal_failure_reason = safe_error
                    else:
                        terminal_failure_reason = (
                            "Provider could not produce a structured semantic read of the incident. "
                            "Try again or paste the latest 20-30 messages around the current blocker."
                        )
                    processing_meta["terminal_failure_reason"] = terminal_failure_reason
                    raise LargeInputProcessingError(
                        terminal_failure_reason,
                        debug_payload=_failure_debug_payload(
                            events=events,
                            input_size_assessment=input_size_assessment,
                            latest_window_selection=latest_window_selection,
                            allowed_targets=allowed_targets,
                            processing_meta=processing_meta,
                            terminal_failure_reason=terminal_failure_reason,
                        ),
                    )
            if (
                semantic_read_result.clean_turn_ledger is not None
                and semantic_read_result.incident_fact_ledger is None
                and semantic_read_result.actor_workstream_ledger is None
            ):
                if _clean_turns_show_operator_intent(semantic_read_result.clean_turn_ledger):
                    processing_meta["warnings"] = [
                        *processing_meta.get("warnings", []),
                        "semantic_read_partial: actor/fact readers failed; derived conservative ledgers from clean turns and current evidence.",
                    ]
                    semantic_read_result.actor_workstream_ledger = build_deterministic_actor_workstream_ledger(
                        incident_id,
                        latest_window,
                        allowed_targets,
                    )
                    semantic_read_result.incident_fact_ledger = build_deterministic_incident_fact_ledger(
                        incident_id,
                        latest_window,
                    )
                else:
                    terminal_failure_reason = (
                        "Semantic read did not produce enough actor/fact evidence for a grounded IC move."
                    )
                    processing_meta["terminal_failure_reason"] = terminal_failure_reason
                    raise LargeInputProcessingError(
                        terminal_failure_reason,
                        debug_payload=_failure_debug_payload(
                            events=events,
                            input_size_assessment=input_size_assessment,
                            latest_window_selection=latest_window_selection,
                            allowed_targets=allowed_targets,
                            processing_meta=processing_meta,
                            terminal_failure_reason=terminal_failure_reason,
                        ),
                    )

            active_workstream_count = (
                sum(
                    1
                    for workstream in semantic_read_result.actor_workstream_ledger.workstreams
                    if workstream.status in {"in_progress", "blocked", "unknown"}
                )
                if semantic_read_result.actor_workstream_ledger is not None
                else 0
            )
            if active_workstream_count == 0:
                fallback_ledger = build_fallback_workstream_ledger(incident_id, latest_window, allowed_targets)
                if fallback_ledger.workstreams:
                    existing_ledger = semantic_read_result.actor_workstream_ledger
                    existing_actor_names = {
                        str(actor.name).strip().lower()
                        for actor in (existing_ledger.actors if existing_ledger else [])
                    }
                    merged_actors = list(existing_ledger.actors if existing_ledger else [])
                    merged_actors.extend(
                        actor
                        for actor in fallback_ledger.actors
                        if str(actor.name).strip().lower() not in existing_actor_names
                    )
                    semantic_read_result.actor_workstream_ledger = ActorWorkstreamLedger(
                        incident_id=incident_id,
                        actors=merged_actors,
                        workstreams=[
                            *(existing_ledger.workstreams if existing_ledger else []),
                            *fallback_ledger.workstreams,
                        ],
                        warnings=[
                            *(existing_ledger.warnings if existing_ledger else []),
                            *fallback_ledger.warnings,
                        ],
                    )
                    processing_meta["fallback_workstream_builder_used"] = True
                    processing_meta["fallback_workstream_count"] = len(fallback_ledger.workstreams)
                    processing_meta["fallback_workstream_owner_candidates"] = [
                        name
                        for workstream in fallback_ledger.workstreams
                        for name in workstream.owner_or_actor_names
                    ][:8]
                    processing_meta["fallback_workstream_evidence_ids"] = [
                        event_id
                        for workstream in fallback_ledger.workstreams
                        for event_id in workstream.evidence_ids
                    ][:8]
                    step_artifacts.append(
                        _emit_artifact(
                            on_artifact,
                            run_id=run_id,
                            step="semantic_read",
                            artifact_type="fallback_workstream_summary",
                            summary_json={
                                "fallback_workstream_builder_used": True,
                                "fallback_workstream_count": len(fallback_ledger.workstreams),
                                "owner_candidates": processing_meta["fallback_workstream_owner_candidates"],
                                "evidence_ids": processing_meta["fallback_workstream_evidence_ids"],
                            },
                            payload_json=fallback_ledger.model_dump(mode="json"),
                            warnings=fallback_ledger.warnings,
                        )
                    )
                else:
                    processing_meta["fallback_workstream_builder_used"] = False
                    processing_meta["fallback_workstream_count"] = 0

            semantic_quality = assess_semantic_quality(semantic_read_result, latest_window, allowed_targets)
            step_artifacts.append(
                _emit_artifact(
                    on_artifact,
                    run_id=run_id,
                    step="semantic_read",
                    artifact_type="semantic_quality_summary",
                    summary_json={
                        "status": semantic_quality.status,
                        "can_plan": semantic_quality.can_plan,
                        "can_render_normal_recommendation": semantic_quality.can_render_normal_recommendation,
                        "success_count": len(semantic_quality.successful_readers),
                        "failed_readers": semantic_quality.failed_readers,
                        "question_only_success": semantic_quality.question_only_success,
                        "human_operator_evidence_count": semantic_quality.human_operator_evidence_count,
                        "preview_card_evidence_count": semantic_quality.preview_card_evidence_count,
                        "reasons": semantic_quality.reasons,
                    },
                    payload_json=semantic_quality.model_dump(mode="json"),
                    warnings=semantic_quality.warnings,
                )
            )

        _ensure_run_budget(started, product_config, "incident_brief")
        with _step(on_step, "incident_brief", "Reduced semantic ledgers into authoritative IncidentBrief"):
            processing_meta["incident_brief_attempts"] = [
                {
                    "attempt_name": "parallel_semantic_read_reducer",
                    "event_count": len(latest_window),
                    "char_count": len(_events_text(latest_window)),
                    "estimated_token_count": max(1, len(_events_text(latest_window)) // 4),
                    "timeout_seconds": 0,
                    "status": "succeeded",
                    "error_type": None,
                }
            ]
            processing_meta["incident_brief_attempt_count"] = 1
            if _uses_exact_fixture_client(llm_client):
                incident_brief = extract_incident_brief(
                    _events_text(latest_window),
                    latest_window,
                    state,
                    allowed_targets,
                    input_size_assessment,
                    llm_client,
                    reconstructed_turns=slack_turn_reconstruction,
                    attempt_name="dev_compat_incident_brief_after_semantic_read",
                    max_chars_per_event=700,
                    max_targets=16,
                )
                incident_brief = incident_brief.model_copy(
                    update={
                        "warnings": [
                            *incident_brief.warnings,
                            "Dev/test compatibility: direct IncidentBrief used after semantic read artifacts.",
                        ]
                    }
                )
            else:
                incident_brief = reduce_ledgers_to_incident_brief(
                    incident_id=incident_id,
                    events=latest_window,
                    allowed_targets=allowed_targets,
                    semantic_read=semantic_read_result,
                )
            incident_brief = incident_brief.model_copy(
                update={
                    "latest_window_event_ids": latest_window_selection.event_ids,
                    "latest_window_used": True,
                    "partial_context": latest_window_selection.dropped_event_count > 0,
                    "full_context_used": latest_window_selection.dropped_event_count == 0,
                }
            )
            incident_brief_quality = validate_incident_brief_quality(
                incident_brief,
                latest_window,
                allowed_targets,
                semantic_quality,
            )
            original_incident_brief_quality = incident_brief_quality
            blocker_reselection, incident_brief, incident_brief_quality = select_authoritative_blocker(
                brief=incident_brief,
                brief_quality=original_incident_brief_quality,
                semantic_quality=semantic_quality,
                semantic_read=semantic_read_result,
                events=latest_window,
                event_quality=event_quality,
                allowed_targets=allowed_targets,
            )
            quality_gate_blocks_planning = (not semantic_quality.can_plan) or (
                (not incident_brief_quality.passed) and not _allows_dev_schema_fallback(llm_client)
            )
            step_artifacts.append(
                _emit_artifact(
                    on_artifact,
                    run_id=run_id,
                    step="blocker_reselection",
                    artifact_type="blocker_reselection_summary",
                    summary_json={
                        "status": blocker_reselection.status,
                        "source": blocker_reselection.source,
                        "selected_blocker_type": blocker_reselection.selected_blocker_type,
                        "selected_evidence_ids": blocker_reselection.selected_evidence_ids,
                        "selected_evidence_kinds": blocker_reselection.selected_evidence_kinds,
                        "selected_target_ids": blocker_reselection.selected_target_ids,
                        "rejected_reason": blocker_reselection.rejected_reason,
                        "can_plan": blocker_reselection.can_plan,
                        "stale_blocker_superseded": blocker_reselection.stale_blocker_superseded,
                        "superseding_event_ids": blocker_reselection.superseding_event_ids,
                        "selected_latest_human_event_ids": blocker_reselection.selected_latest_human_event_ids,
                        "selected_blocker_evidence_quality": blocker_reselection.selected_blocker_evidence_quality,
                        "stale_question_intents_added": blocker_reselection.stale_question_intents_added,
                    },
                    payload_json=blocker_reselection.model_dump(mode="json"),
                    warnings=blocker_reselection.warnings,
                )
            )
            step_artifacts.append(
                _emit_artifact(
                    on_artifact,
                    run_id=run_id,
                    step="incident_brief",
                    artifact_type="incident_brief_summary",
                    summary_json={
                        "phase": incident_brief.phase.primary,
                        "blocker": incident_brief.latest_blocker.blocker_type,
                        "preferred_target_ids": incident_brief.recommended_ic_focus.preferred_target_ids,
                        "do_not_ask": [item.intent for item in incident_brief.do_not_ask[:8]],
                        "focus": incident_brief.recommended_ic_focus.summary,
                        "semantic_quality_status": semantic_quality.status,
                        "original_brief_quality_status": original_incident_brief_quality.status,
                        "brief_quality_status": incident_brief_quality.status,
                        "blocker_repair_status": blocker_reselection.status,
                        "rejected_blocker_reason": blocker_reselection.rejected_reason,
                        "final_blocker_evidence_ids": incident_brief.latest_blocker.evidence_ids,
                        "final_blocker_evidence_kinds": blocker_reselection.selected_evidence_kinds,
                        "stale_blocker_superseded": blocker_reselection.stale_blocker_superseded,
                        "superseded_blocker_summary": blocker_reselection.superseded_blocker_summary,
                        "superseding_event_ids": blocker_reselection.superseding_event_ids,
                        "selected_blocker_evidence_quality": blocker_reselection.selected_blocker_evidence_quality,
                        "can_plan": not quality_gate_blocks_planning,
                        "blocked_reasons": incident_brief_quality.blocked_reasons,
                    },
                    payload_json={
                        "incident_brief": incident_brief.model_dump(mode="json"),
                        "semantic_quality": semantic_quality.model_dump(mode="json"),
                        "original_incident_brief_quality": original_incident_brief_quality.model_dump(mode="json"),
                        "incident_brief_quality": incident_brief_quality.model_dump(mode="json"),
                        "blocker_reselection": blocker_reselection.model_dump(mode="json"),
                    },
                    warnings=[*incident_brief.warnings, *incident_brief_quality.warnings],
                )
            )
        with _step(on_step, "clean_context", "Derived compatibility clean context from IncidentBrief"):
            clean_context = clean_context_from_incident_brief(incident_brief, allowed_targets)
            step_artifacts.append(
                _emit_artifact(
                    on_artifact,
                    run_id=run_id,
                    step="clean_context",
                    artifact_type="compat_clean_context_summary",
                    summary_json={
                        "phase": clean_context.phase.value,
                        "blocker": clean_context.current_blocker.blocker_type,
                        "engaged_entities": len(clean_context.engaged_entities),
                        "stale_question_intents": clean_context.question_ledger.stale_question_intents[:8],
                    },
                    payload_json=clean_context.model_dump(mode="json"),
                    warnings=clean_context.uncertainty_notes,
                )
            )
        with _step(on_step, "state_extraction", "Used IncidentBrief as compatibility state; StateDelta is non-blocking"):
            baseline_delta = state_delta_from_incident_brief(incident_brief, allowed_targets)
            state = merge_state_delta(state, baseline_delta)
            state = _apply_explicit_tenant_evidence_to_state(state, latest_window)
            processing_meta["state_delta_status"] = "incident_brief_compatibility"
            processing_meta["full_context_enrichment_status"] = "skipped_non_blocking"
            processing_meta["warnings"] = [
                *processing_meta.get("warnings", []),
                "state_delta_enrichment_skipped: IncidentBrief is the operator-facing semantic source.",
            ]
            if _allows_dev_state_delta_compatibility(llm_client):
                try:
                    ai_delta = extract_state_delta(latest_window, state, llm_client, clean_context=clean_context)
                    state = merge_state_delta(state, ai_delta)
                    processing_meta["state_delta_status"] = "enriched_dev_compatibility"
                    processing_meta["full_context_enrichment_status"] = "dev_compatibility_only"
                except Exception as exc:
                    processing_meta["warnings"] = [
                        *processing_meta.get("warnings", []),
                        f"state_extraction_dev_compatibility: {sanitize_user_facing_error(exc)}",
                    ]
            step_artifacts.append(
                _emit_artifact(
                    on_artifact,
                    run_id=run_id,
                    step="state_extraction",
                    artifact_type="state_compatibility_summary",
                    summary_json={
                        "status": processing_meta["state_delta_status"],
                        "phase": state.phase,
                        "blocker": state.current_blocker,
                        "stale_question_intents": state.stale_question_intents[:8],
                    },
                    payload_json=state.model_dump(mode="json"),
                    warnings=processing_meta.get("warnings", []),
                )
            )
        with _step(on_step, "state_merge", "Merged extracted facts into the incident ledger"):
            allowed_targets = augment_allowed_targets_from_state(allowed_targets, state)
            target_shortlist = build_target_shortlist(allowed_targets, incident_brief, latest_window)
            planner_allowed_targets = _expand_shortlist_with_canonical_targets(allowed_targets, target_shortlist)
            step_artifacts.append(
                _emit_artifact(
                    on_artifact,
                    run_id=run_id,
                    step="state_merge",
                    artifact_type="state_merge_summary",
                    summary_json={
                        "phase": state.phase,
                        "blocker": state.current_blocker,
                        "target_shortlist": [target.display_name for target in target_shortlist[:8]],
                        "allowed_target_count": len(allowed_targets),
                        "fallback_workstream_builder_used": processing_meta.get("fallback_workstream_builder_used", False),
                        "fallback_workstream_count": processing_meta.get("fallback_workstream_count", 0),
                        "fallback_workstream_owner_candidates": processing_meta.get(
                            "fallback_workstream_owner_candidates",
                            [],
                        ),
                    },
                    payload_json={
                        "current_state": state.model_dump(mode="json"),
                        "target_shortlist": [target.model_dump(mode="json") for target in target_shortlist],
                    },
                )
            )
    else:
        _emit(on_step, "incident_brief", "skipped", "No incident evidence", 0)
        _emit(on_step, "clean_context", "skipped", "No incident brief", 0)
        _emit(on_step, "state_extraction", "skipped", "No extraction needed", 0)
        _emit(on_step, "state_merge", "skipped", "No state delta to merge", 0)

    catalog_matches = catalog_matches_for_state(state, catalog)

    with _step(on_step, "memory_load", "Loaded structured DecisionMoment memory"):
        moments = (
            load_product_decision_moments(product_config)
            if product_resource_mode and product_config is not None
            else load_decision_moments(effective_memory_path)
        )
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="memory_load",
                artifact_type="memory_load_summary",
                summary_json={"decision_moments": len(moments)},
                payload_json={"decision_moment_ids": [moment.decision_id for moment in moments[:80]]},
            )
        )

    with _step(on_step, "memory_retrieval", "Retrieved memory IDs only"):
        latest_window_evidence_text = _events_text(latest_window)
        query = build_memory_query(state, current_evidence_text=latest_window_evidence_text)
        memory_ids = retrieve_decision_moment_ids(query, moments)
        hydrated = hydrate_decision_moments(memory_ids, moments)
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="memory_retrieval",
                artifact_type="memory_retrieval_summary",
                summary_json={"retrieved": len(memory_ids), "query_phase": query.phase},
                payload_json={"memory_query": query.model_dump(mode="json"), "memory_ids": memory_ids},
            )
        )

    with _step(on_step, "applicability_gate", "Applied deterministic memory relevance gate"):
        applicability = judge_applicability(
            state,
            hydrated,
            llm_client=None,
            current_evidence_text=latest_window_evidence_text,
        )
        accepted = [item for item in applicability if item.accepted]
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="applicability_gate",
                artifact_type="memory_applicability_summary",
                summary_json={"accepted": len(accepted), "evaluated": len(applicability)},
                payload_json={
                    "applicability": [item.model_dump(mode="json") for item in applicability],
                    "accepted_ids": [item.decision_id for item in accepted],
                },
            )
        )

    sharp_blocker_assessment = None
    if incident_brief is not None:
        with _step(on_step, "sharp_blocker_assessment", "Derived compatibility sharp blocker from IncidentBrief"):
            sharp_blocker_assessment = sharp_blocker_from_incident_brief(incident_brief, allowed_targets)
            step_artifacts.append(
                _emit_artifact(
                    on_artifact,
                    run_id=run_id,
                    step="sharp_blocker_assessment",
                    artifact_type="sharp_blocker_summary",
                    summary_json={
                        "blocker_type": sharp_blocker_assessment.blocker_type,
                        "visible_workstreams": len(sharp_blocker_assessment.visible_workstreams),
                        "recommended_moves": [
                            str(getattr(move, "value", move))
                            for move in sharp_blocker_assessment.recommended_move_families[:6]
                        ],
                    },
                    payload_json=sharp_blocker_assessment.model_dump(mode="json"),
                )
            )
    elif clean_context is not None:
        with _step(on_step, "sharp_blocker_assessment", "Assessed the sharpest IC blocker"):
            try:
                with _stage_timeout(llm_client, _timeout(product_config, "sharp_blocker_timeout_seconds")):
                    sharp_blocker_assessment = assess_sharp_blocker(clean_context, state, catalog_matches, llm_client)
            except Exception as exc:
                if _is_timeout_error(exc):
                    processing_meta["provider_timeout_stage"] = "sharp_blocker_assessment"
                processing_meta["warnings"] = [
                    *processing_meta.get("warnings", []),
                    f"sharp_blocker_assessment: {sanitize_user_facing_error(exc)}",
                ]
                sharp_blocker_assessment = build_deterministic_sharp_blocker_assessment(
                    clean_context,
                    state,
                    catalog_matches,
                )
    else:
        _emit(on_step, "sharp_blocker_assessment", "skipped", "No clean context available", 0)

    with _step(on_step, "planning", "Planned one ICDecision"):
        _ensure_run_budget(started, product_config, "planning")
        if quality_gate_blocks_planning:
            reason = (
                "semantic quality insufficient"
                if not semantic_quality.can_plan
                else "IncidentBrief quality insufficient"
            )
            decision = ICDecision(
                decision_id=f"quality-gate-{incident_id}",
                incident_id=incident_id,
                move=ICMove.NO_SAFE_RECOMMENDATION,
                phase=incident_brief.phase.primary if incident_brief else state.phase,
                output={
                    "say_this": "I do not have enough clean current human/operator evidence to suggest a grounded next move.",
                    "next_line": "Try again with the latest 20-30 messages around the current blocker.",
                },
                rationale=[
                    reason,
                    *semantic_quality.reasons,
                    *incident_brief_quality.blocked_reasons,
                ],
                grounding=[],
                confidence=0.2,
                model_metadata={
                    "planner_skipped": True,
                    "planner_skip_reason": reason,
                    "semantic_quality_status": semantic_quality.status,
                    "incident_brief_quality_status": incident_brief_quality.status,
                },
            )
        else:
            try:
                with _stage_timeout(llm_client, _timeout(product_config, "planner_timeout_seconds")):
                    decision = (planner_func or plan_ic_decision)(
                        state,
                        catalog_matches,
                        accepted,
                        llm_client=llm_client,
                        command_registry=command_registry,
                        clean_context=clean_context,
                        sharp_blocker_assessment=sharp_blocker_assessment,
                        incident_brief=incident_brief,
                        allowed_targets=planner_allowed_targets,
                    )
            except Exception as exc:
                if not _is_timeout_error(exc):
                    raise
                processing_meta["provider_timeout_stage"] = "planning"
                processing_meta["retry_attempted"] = True
                processing_meta["retry_strategy"] = "deterministic_planner_after_timeout"
                decision = (planner_func or plan_ic_decision)(
                    state,
                    catalog_matches,
                    accepted,
                    llm_client=None,
                    command_registry=command_registry,
                    clean_context=clean_context,
                    sharp_blocker_assessment=sharp_blocker_assessment,
                    incident_brief=incident_brief,
                    allowed_targets=planner_allowed_targets,
                    semantic_quality=semantic_quality,
                    incident_brief_quality=incident_brief_quality,
                    event_quality=event_quality,
                )
        decision, wording_lint_changed, wording_lint_reason = lint_manual_copy_output(decision)
        if wording_lint_changed:
            processing_meta["wording_lint_reason"] = wording_lint_reason
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="planning",
                artifact_type="ic_decision_summary",
                summary_json={
                    "move": decision.move,
                    "target_ids": decision.target_ids,
                    "domain_intent": decision.domain_intent,
                    "command": decision.output.get("command") if isinstance(decision.output, dict) else None,
                    "skipped": bool(decision.model_metadata.get("planner_skipped")),
                    "skip_reason": decision.model_metadata.get("planner_skip_reason"),
                    "wording_lint_reason": processing_meta.get("wording_lint_reason"),
                },
                payload_json=_decision_payload(decision),
                warnings=[str(error) for error in errors],
            )
        )

    semantic_assessment = None
    if clean_context is not None:
        with _step(on_step, "semantic_intent_check", "Checked planner output intent against answered questions"):
            try:
                _ensure_run_budget(started, product_config, "semantic_intent_check")
                with _stage_timeout(llm_client, _timeout(product_config, "semantic_intent_timeout_seconds")):
                    semantic_assessment = assess_output_intent(decision, state, clean_context, llm_client)
            except Exception as exc:
                if _is_timeout_error(exc):
                    processing_meta["provider_timeout_stage"] = "semantic_intent_check"
                processing_meta["warnings"] = [
                    *processing_meta.get("warnings", []),
                    f"semantic_intent_check: {sanitize_user_facing_error(exc)}",
                ]
                semantic_assessment = build_deterministic_semantic_intent_assessment(
                    decision,
                    state,
                    clean_context,
                )
            step_artifacts.append(
                _emit_artifact(
                    on_artifact,
                    run_id=run_id,
                    step="semantic_intent_check",
                    artifact_type="semantic_intent_summary",
                    summary_json={
                        "detected_intents": [
                            item.intent for item in semantic_assessment.detected_intents[:8]
                        ],
                        "stale_matches": len(semantic_assessment.stale_intent_matches),
                        "recommended_repair_direction": semantic_assessment.recommended_repair_direction,
                    },
                    payload_json=semantic_assessment.model_dump(mode="json"),
                    warnings=semantic_assessment.unsafe_or_repeated_questions,
                )
            )
    else:
        _emit(on_step, "semantic_intent_check", "skipped", "No clean context available", 0)

    with _step(on_step, "verification", "Ran deterministic verifier"):
        deterministic_verifier_result = verify_ic_decision(
            decision=decision,
            current_state=state,
            catalog=catalog,
            accepted_memories=accepted,
            command_registry=command_registry,
            sharp_blocker_assessment=sharp_blocker_assessment,
            incident_brief=incident_brief,
            allowed_targets=planner_allowed_targets,
            semantic_quality=semantic_quality,
            incident_brief_quality=incident_brief_quality,
            event_quality=event_quality,
        )
        verifier_result = _apply_semantic_intent_blocks(decision, deterministic_verifier_result, semantic_assessment)
        verifier_result = _apply_sharp_blocker_blocks(verifier_result, sharp_blocker_assessment)
        decision.verifier_result = verifier_result
        original_verifier_result = verifier_result
        repair_attempted = False
        repair_reason = None
        repair_verifier_status = None
        repair_blocked_claims: list[str] = []
        metadata_repair_used = False
        render_decision = decision
        if not verifier_result.passed and only_expiration_failed(verifier_result.checks):
            normalized_decision, changed, expiration_reason = normalize_decision_expiration(decision)
            if changed:
                repair_attempted = True
                metadata_repair_used = True
                repair_reason = "expiration_normalized"
                normalized_verifier = verify_ic_decision(
                    decision=normalized_decision,
                    current_state=state,
                    catalog=catalog,
                    accepted_memories=accepted,
                    command_registry=command_registry,
                    sharp_blocker_assessment=sharp_blocker_assessment,
                    incident_brief=incident_brief,
                    allowed_targets=planner_allowed_targets,
                    semantic_quality=semantic_quality,
                    incident_brief_quality=incident_brief_quality,
                    event_quality=event_quality,
                )
                normalized_verifier = _apply_semantic_intent_blocks(
                    normalized_decision,
                    normalized_verifier,
                    semantic_assessment,
                )
                normalized_verifier = _apply_sharp_blocker_blocks(normalized_verifier, sharp_blocker_assessment)
                normalized_decision.verifier_result = normalized_verifier
                repair_verifier_status = normalized_verifier.final_status
                repair_blocked_claims = normalized_verifier.blocked_claims
                if normalized_verifier.passed:
                    verifier_result = normalized_verifier
                    render_decision = normalized_decision
                    processing_meta["metadata_repair_reason"] = expiration_reason
        if not verifier_result.passed:
            repaired = repair_blocked_decision(
                original_decision=decision,
                verifier_result=verifier_result,
                current_state=state,
                catalog_matches=catalog_matches,
                command_registry=command_registry,
                accepted_memories=accepted,
                sharp_blocker_assessment=sharp_blocker_assessment,
                incident_brief=incident_brief,
                allowed_targets=planner_allowed_targets,
            )
            repair_attempted = repaired is not None
            if repaired is not None:
                repair_reason = repaired.model_metadata.get("repair_reason")
                repaired_verifier = verify_ic_decision(
                    decision=repaired,
                    current_state=state,
                    catalog=catalog,
                    accepted_memories=accepted,
                    command_registry=command_registry,
                    sharp_blocker_assessment=sharp_blocker_assessment,
                    incident_brief=incident_brief,
                    allowed_targets=planner_allowed_targets,
                    semantic_quality=semantic_quality,
                    incident_brief_quality=incident_brief_quality,
                    event_quality=event_quality,
                )
                repaired.verifier_result = repaired_verifier
                repair_verifier_status = repaired_verifier.final_status
                repair_blocked_claims = repaired_verifier.blocked_claims
                if repaired_verifier.passed:
                    verifier_result = repaired_verifier
                    render_decision = repaired
                elif verifier_result.fallback_decision is not None:
                    render_decision = verifier_result.fallback_decision
                    fallback_verifier = verify_ic_decision(
                        decision=render_decision,
                        current_state=state,
                        catalog=catalog,
                        accepted_memories=accepted,
                        command_registry=command_registry,
                        sharp_blocker_assessment=sharp_blocker_assessment,
                        incident_brief=incident_brief,
                        allowed_targets=planner_allowed_targets,
                        semantic_quality=semantic_quality,
                        incident_brief_quality=incident_brief_quality,
                        event_quality=event_quality,
                    )
                    if fallback_verifier.passed:
                        verifier_result = fallback_verifier
            elif verifier_result.fallback_decision is not None:
                render_decision = verifier_result.fallback_decision
                fallback_verifier = verify_ic_decision(
                    decision=render_decision,
                    current_state=state,
                    catalog=catalog,
                    accepted_memories=accepted,
                    command_registry=command_registry,
                    sharp_blocker_assessment=sharp_blocker_assessment,
                    incident_brief=incident_brief,
                    allowed_targets=planner_allowed_targets,
                    semantic_quality=semantic_quality,
                    incident_brief_quality=incident_brief_quality,
                    event_quality=event_quality,
                )
                if fallback_verifier.passed:
                    verifier_result = fallback_verifier
            if not verifier_result.passed and incident_brief is not None:
                deterministic_retry = plan_ic_decision(
                    state,
                    catalog_matches,
                    accepted,
                    llm_client=None,
                    command_registry=command_registry,
                    clean_context=clean_context,
                    sharp_blocker_assessment=sharp_blocker_assessment,
                    incident_brief=incident_brief,
                    allowed_targets=planner_allowed_targets,
                )
                retry_metadata = dict(deterministic_retry.model_metadata)
                retry_metadata.setdefault("repair_reason", "incident_brief_deterministic_retry")
                deterministic_retry = deterministic_retry.model_copy(
                    update={
                        "decision_id": f"repair-{deterministic_retry.decision_id}",
                        "model_metadata": retry_metadata,
                    }
                )
                retry_quality_kwargs = (
                    {}
                    if _allows_dev_schema_fallback(llm_client)
                    else {
                        "semantic_quality": semantic_quality,
                        "incident_brief_quality": incident_brief_quality,
                        "event_quality": event_quality,
                    }
                )
                retry_verifier = verify_ic_decision(
                    decision=deterministic_retry,
                    current_state=state,
                    catalog=catalog,
                    accepted_memories=accepted,
                    command_registry=command_registry,
                    sharp_blocker_assessment=sharp_blocker_assessment,
                    incident_brief=incident_brief,
                    allowed_targets=planner_allowed_targets,
                    **retry_quality_kwargs,
                )
                deterministic_retry.verifier_result = retry_verifier
                repair_attempted = True
                repair_reason = repair_reason or deterministic_retry.model_metadata.get("repair_reason")
                repair_verifier_status = retry_verifier.final_status
                repair_blocked_claims = retry_verifier.blocked_claims
                if retry_verifier.passed:
                    verifier_result = retry_verifier
                    render_decision = deterministic_retry
        if (
            render_decision.move == ICMove.NO_SAFE_RECOMMENDATION
            and not verifier_result.passed
            and render_decision.decision_id.startswith("fallback-")
        ):
            fallback_verifier = verify_ic_decision(
                decision=render_decision,
                current_state=state,
                catalog=catalog,
                accepted_memories=accepted,
                command_registry=command_registry,
                sharp_blocker_assessment=sharp_blocker_assessment,
                allowed_targets=planner_allowed_targets,
            )
            if fallback_verifier.passed:
                verifier_result = fallback_verifier
        planner_fallback_used = bool(decision.model_metadata.get("planner_fallback_used"))
        content_repair_used = render_decision.decision_id.startswith("repair-")
        repair_used = metadata_repair_used or content_repair_used
        no_safe_fallback_used = render_decision.decision_id.startswith("fallback-")
        fallback_used = planner_fallback_used or content_repair_used or no_safe_fallback_used
        if planner_error := decision.model_metadata.get("planner_validation_error"):
            errors.append(str(planner_error))
        semantic_stale_matches = [
            match.model_dump(mode="json")
            for match in high_confidence_stale_matches(semantic_assessment)
        ] if semantic_assessment else []
        why_no_safe_recommendation = None
        if render_decision.move == ICMove.NO_SAFE_RECOMMENDATION:
            why_no_safe_recommendation = (
                "Verifier could not produce a grounded repair from the IncidentBrief, allowed target shortlist, "
                "and current evidence."
            )
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="verification",
                artifact_type="verifier_summary",
                summary_json={
                    "status": verifier_result.final_status,
                    "passed": verifier_result.passed,
                    "failed_checks": [
                        name for name, passed in verifier_result.checks.items() if not passed
                    ],
                    "repair_attempted": repair_attempted,
                    "repair_used": repair_used,
                    "render_move": render_decision.move,
                    "metadata_repair_reason": processing_meta.get("metadata_repair_reason"),
                },
                payload_json={
                    "deterministic_verifier_result": _verifier_result_payload(deterministic_verifier_result),
                    "final_verifier_result": _verifier_result_payload(verifier_result),
                    "repair": {
                        "repair_attempted": repair_attempted,
                        "repair_used": repair_used,
                        "repair_reason": repair_reason,
                        "repair_verifier_status": repair_verifier_status,
                        "repair_blocked_claims": repair_blocked_claims,
                        "metadata_repair_used": metadata_repair_used,
                        "metadata_repair_reason": processing_meta.get("metadata_repair_reason"),
                    },
                },
                warnings=verifier_result.blocked_claims,
            )
        )
        if repair_attempted:
            step_artifacts.append(
                _emit_artifact(
                    on_artifact,
                    run_id=run_id,
                    step="repair",
                    artifact_type="repair_summary",
                    summary_json={
                        "repair_used": repair_used,
                        "repair_reason": repair_reason,
                        "repair_verifier_status": repair_verifier_status,
                        "selected_target_ids": list(render_decision.target_ids),
                        "metadata_repair_used": metadata_repair_used,
                    },
                    payload_json={
                        "render_decision": _decision_payload(render_decision),
                        "blocked_claims": repair_blocked_claims,
                    },
                    warnings=repair_blocked_claims,
                )
            )

    _emit(
        on_step,
        "repair",
        "succeeded" if repair_attempted else "skipped",
        "Repair used" if repair_used else "No verifier-guided repair needed",
        0,
    )

    with _step(on_step, "rendering", "Rendered manual-copy IC whisper"):
        final_output = render_ic_whisper(render_decision)
        step_artifacts.append(
            _emit_artifact(
                on_artifact,
                run_id=run_id,
                step="rendering",
                artifact_type="final_output_summary",
                summary_json={
                    "move": render_decision.move,
                    "target_ids": render_decision.target_ids,
                    "has_command": bool(render_decision.output.get("command")),
                },
                payload_json={
                    "final_output": final_output,
                    "rendered_decision": _decision_payload(render_decision),
                },
            )
        )

    latency_ms = int((time.perf_counter() - started) * 1000)
    trace = TraceRecord(
        trace_id=f"{incident_id}:{uuid4().hex[:12]}",
        incident_id=incident_id,
        input_event_ids=[event.event_id for event in events],
        trigger=trigger,
        current_state=state,
        memory_query=query,
        retrieved_memory_ids=memory_ids,
        hydrated_memory_ids=[moment.decision_id for moment in hydrated],
        applicability_results=applicability,
        accepted_memory_ids=[item.decision_id for item in accepted],
        catalog_match_ids=[entry.service_id for entry in catalog_matches],
        command_registry_size=len(command_registry),
        input_size_assessment=input_size_assessment,
        latest_window_selection=latest_window_selection,
        processing_strategy=processing_meta.get("processing_strategy"),
        chunk_count=int(processing_meta.get("chunk_count") or 0),
        chunk_ids=list(processing_meta.get("chunk_ids") or []),
        chunk_success_count=int(processing_meta.get("chunk_success_count") or 0),
        chunk_failure_count=int(processing_meta.get("chunk_failure_count") or 0),
        provider_timeout_stage=processing_meta.get("provider_timeout_stage"),
        retry_attempted=bool(processing_meta.get("retry_attempted")),
        retry_strategy=processing_meta.get("retry_strategy"),
        incident_brief_attempt_count=int(processing_meta.get("incident_brief_attempt_count") or 0),
        incident_brief_attempts=list(processing_meta.get("incident_brief_attempts") or []),
        compact_payload_event_count=int(processing_meta.get("compact_payload_event_count") or 0),
        compact_payload_char_count=int(processing_meta.get("compact_payload_char_count") or 0),
        ultra_compact_payload_event_count=int(processing_meta.get("ultra_compact_payload_event_count") or 0),
        ultra_compact_payload_char_count=int(processing_meta.get("ultra_compact_payload_char_count") or 0),
        terminal_failure_reason=processing_meta.get("terminal_failure_reason"),
        slack_turn_reconstruction=slack_turn_reconstruction,
        reconstructed_turn_count=len(slack_turn_reconstruction.turns) if slack_turn_reconstruction else 0,
        reconstructed_turns_used=slack_turn_reconstruction is not None,
        turn_reconstruction_warnings=turn_reconstruction_warnings,
        step_artifacts=step_artifacts,
        event_quality=event_quality,
        semantic_quality=semantic_quality,
        incident_brief_quality=incident_brief_quality,
        original_incident_brief_quality=original_incident_brief_quality,
        blocker_reselection=blocker_reselection,
        clean_turn_ledger=semantic_read_result.clean_turn_ledger,
        actor_workstream_ledger=semantic_read_result.actor_workstream_ledger,
        incident_fact_ledger=semantic_read_result.incident_fact_ledger,
        question_intent_ledger=semantic_read_result.question_intent_ledger,
        allowed_targets=allowed_targets,
        target_shortlist=target_shortlist,
        incident_brief=incident_brief,
        selected_target_ids=list(render_decision.target_ids),
        rejected_non_targetable_candidates=[target for target in allowed_targets if not target.targetable],
        latest_window_event_ids=latest_window_selection.event_ids,
        clean_context=clean_context,
        sharp_blocker_assessment=sharp_blocker_assessment,
        semantic_intent_assessment=semantic_assessment,
        repair_result={
            "repair_attempted": repair_attempted,
            "repair_used": repair_used,
            "repair_reason": repair_reason,
            "repair_verifier_status": repair_verifier_status,
            "repair_blocked_claims": repair_blocked_claims,
        },
        raw_decision=decision,
        verifier_result=verifier_result,
        rendered_decision=render_decision,
        final_output=final_output,
        safety_summary={
            "fallback_used": fallback_used,
            "planner_fallback_used": planner_fallback_used,
            "repair_attempted": repair_attempted,
            "repair_used": repair_used,
            "repair_reason": repair_reason,
            "repair_verifier_status": repair_verifier_status,
            "repair_blocked_claims": repair_blocked_claims,
            "repair_selected_target_ids": list(render_decision.target_ids) if repair_used else [],
            "metadata_repair_used": metadata_repair_used,
            "metadata_repair_reason": processing_meta.get("metadata_repair_reason"),
            "wording_lint_reason": processing_meta.get("wording_lint_reason"),
            "original_decision_move": decision.move,
            "repaired_decision_move": render_decision.move if repair_used else None,
            "why_no_safe_recommendation": why_no_safe_recommendation,
            "domain_intent": decision.domain_intent,
            "original_model_move": decision.model_metadata.get("original_move"),
            "original_verifier_status": original_verifier_result.final_status,
            "original_blocked_claims": original_verifier_result.blocked_claims,
            "deterministic_verifier_status": deterministic_verifier_result.final_status,
            "semantic_stale_matches": semantic_stale_matches,
            "input_size_assessment": input_size_assessment.model_dump(mode="json"),
            "latest_window_selection": latest_window_selection.model_dump(mode="json"),
            "processing_strategy": processing_meta.get("processing_strategy"),
            "chunk_count": processing_meta.get("chunk_count"),
            "chunk_success_count": processing_meta.get("chunk_success_count"),
            "chunk_failure_count": processing_meta.get("chunk_failure_count"),
            "provider_timeout_stage": processing_meta.get("provider_timeout_stage"),
            "retry_attempted": processing_meta.get("retry_attempted"),
            "retry_strategy": processing_meta.get("retry_strategy"),
            "incident_brief_attempt_count": processing_meta.get("incident_brief_attempt_count"),
            "incident_brief_attempts": processing_meta.get("incident_brief_attempts", []),
            "compact_payload_event_count": processing_meta.get("compact_payload_event_count"),
            "compact_payload_char_count": processing_meta.get("compact_payload_char_count"),
            "ultra_compact_payload_event_count": processing_meta.get("ultra_compact_payload_event_count"),
            "ultra_compact_payload_char_count": processing_meta.get("ultra_compact_payload_char_count"),
            "terminal_failure_reason": processing_meta.get("terminal_failure_reason"),
            "state_delta_status": processing_meta.get("state_delta_status"),
            "full_context_enrichment_status": processing_meta.get("full_context_enrichment_status"),
            "processing_warnings": processing_meta.get("warnings", []),
            "reconstructed_turn_count": len(slack_turn_reconstruction.turns) if slack_turn_reconstruction else 0,
            "reconstructed_turns_used": slack_turn_reconstruction is not None,
            "turn_reconstruction_warnings": turn_reconstruction_warnings,
            "semantic_read_success_count": semantic_read_result.success_count,
            "semantic_read_failed_readers": sorted((semantic_read_result.errors or {}).keys()),
            "semantic_quality": semantic_quality.model_dump(mode="json"),
            "original_incident_brief_quality": original_incident_brief_quality.model_dump(mode="json"),
            "incident_brief_quality": incident_brief_quality.model_dump(mode="json"),
            "blocker_reselection": blocker_reselection.model_dump(mode="json"),
            "fallback_workstream_builder_used": processing_meta.get("fallback_workstream_builder_used", False),
            "fallback_workstream_count": processing_meta.get("fallback_workstream_count", 0),
            "fallback_workstream_owner_candidates": processing_meta.get("fallback_workstream_owner_candidates", []),
            "fallback_workstream_evidence_ids": processing_meta.get("fallback_workstream_evidence_ids", []),
            "event_quality_summary": event_quality_summary(event_quality),
            "clean_turn_ledger_summary": (
                _clean_turn_ledger_summary(semantic_read_result.clean_turn_ledger)
                if semantic_read_result.clean_turn_ledger
                else None
            ),
            "actor_workstream_ledger_summary": (
                _actor_workstream_ledger_summary(semantic_read_result.actor_workstream_ledger)
                if semantic_read_result.actor_workstream_ledger
                else None
            ),
            "incident_fact_ledger_summary": (
                _incident_fact_ledger_summary(semantic_read_result.incident_fact_ledger)
                if semantic_read_result.incident_fact_ledger
                else None
            ),
            "question_intent_ledger_summary": (
                _question_intent_ledger_summary(semantic_read_result.question_intent_ledger)
                if semantic_read_result.question_intent_ledger
                else None
            ),
            "incident_brief_summary": incident_brief.current_summary if incident_brief else None,
            "incident_brief_latest_blocker": (
                incident_brief.latest_blocker.model_dump(mode="json") if incident_brief else None
            ),
            "allowed_target_count": len(allowed_targets),
            "target_shortlist": [target.model_dump(mode="json") for target in target_shortlist],
            "selected_target_ids": list(render_decision.target_ids),
            "rejected_non_targetable_candidates": [
                target.model_dump(mode="json") for target in allowed_targets if not target.targetable
            ],
            "latest_window_event_ids": latest_window_selection.event_ids,
            "sharp_blocker_type": sharp_blocker_assessment.blocker_type if sharp_blocker_assessment else None,
            "sharp_blocker_summary": sharp_blocker_assessment.blocker_summary if sharp_blocker_assessment else None,
            "role_candidates": [
                item.model_dump(mode="json")
                for item in (sharp_blocker_assessment.role_candidates if sharp_blocker_assessment else [])
            ],
            "technical_status_targets": sharp_blocker_assessment.technical_status_targets if sharp_blocker_assessment else [],
            "validation_targets": (
                sharp_blocker_assessment.customer_or_reporter_validation_targets if sharp_blocker_assessment else []
            ),
            "sharp_blocker_wrong_next_moves": [
                item.model_dump(mode="json")
                for item in (sharp_blocker_assessment.wrong_next_moves if sharp_blocker_assessment else [])
            ],
            "sharp_blocker_recommended_moves": [
                str(getattr(move, "value", move))
                for move in (sharp_blocker_assessment.recommended_move_families if sharp_blocker_assessment else [])
            ],
            "verifier_status": verifier_result.final_status,
            "verifier_passed": verifier_result.passed,
            "blocked_claims": verifier_result.blocked_claims,
            "failed_checks": [name for name, passed in verifier_result.checks.items() if not passed],
        },
        latency_ms=latency_ms,
        errors=errors,
    )

    if save_trace:
        with _step(on_step, "trace_saved", "Saved trace locally"):
            db_path = os.environ.get("IC_COPILOT_DB_PATH", ".ic_copilot/traces.sqlite3")
            conn = init_db(db_path)
            save_payload(
                conn,
                trace_id=trace.trace_id,
                kind="run",
                payload=_trace_payload(trace),
            )
            conn.close()
    else:
        _emit(on_step, "trace_saved", "skipped", "Trace saving disabled", 0)

    _emit(on_step, "complete", "succeeded", "Pipeline complete", 0)
    return {
        "events": events,
        "event_quality": event_quality,
        "trigger": trigger,
        "allowed_targets": allowed_targets,
        "target_shortlist": target_shortlist,
        "latest_window_selection": latest_window_selection,
        "incident_brief": incident_brief,
        "clean_turn_ledger": semantic_read_result.clean_turn_ledger,
        "actor_workstream_ledger": semantic_read_result.actor_workstream_ledger,
        "incident_fact_ledger": semantic_read_result.incident_fact_ledger,
        "question_intent_ledger": semantic_read_result.question_intent_ledger,
        "semantic_quality": semantic_quality,
        "original_incident_brief_quality": original_incident_brief_quality,
        "incident_brief_quality": incident_brief_quality,
        "blocker_reselection": blocker_reselection,
        "step_artifacts": step_artifacts,
        "clean_context": clean_context,
        "slack_turn_reconstruction": slack_turn_reconstruction,
        "sharp_blocker_assessment": sharp_blocker_assessment,
        "state": state,
        "memory_ids": memory_ids,
        "accepted_memories": accepted,
        "decision": render_decision,
        "raw_decision": decision,
        "verifier_result": verifier_result,
        "semantic_intent_assessment": semantic_assessment,
        "final_output": final_output,
        "trace": trace,
        "latency_ms": latency_ms,
    }
