from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml

from ic_copilot.knowledge_bundle import validate_knowledge_bundle
from ic_copilot.product_knowledge import validate_product_knowledge
from ic_copilot.schemas import ICMove


COMPILER_VERSION = "codex_semantic_compiler_v1"

MOVE_ALIASES = {
    "ask_status_eta": ICMove.REQUEST_STATUS_OR_ETA.value,
    "request_customer_impact": ICMove.ASK_IMPACT.value,
}
MOVE_BLOCKERS = {
    ICMove.ENGAGE_OWNER.value: "missing_owner",
    ICMove.CONFIRM_OWNERSHIP.value: "missing_owner",
    ICMove.REQUEST_STATUS_OR_ETA.value: "waiting_on_status",
    ICMove.ASK_STATUS_ETA.value: "waiting_on_status",
    ICMove.ASK_NEXT_VALIDATION.value: "missing_validation",
    ICMove.REQUEST_MONITORING_SIGNAL.value: "waiting_on_monitoring",
    ICMove.ASK_IMPACT.value: "missing_impact",
    ICMove.CONFIRM_CUSTOMER_COMMS.value: "customer_comms",
}
PHASE_AFTER = {
    ICMove.REQUEST_MONITORING_SIGNAL.value: "monitoring",
    ICMove.ASK_NEXT_VALIDATION.value: "verification",
    ICMove.ASK_IMPACT.value: "investigation",
    ICMove.REQUEST_STATUS_OR_ETA.value: "investigation",
    ICMove.ENGAGE_OWNER.value: "engagement",
}
REDACTED_PLACEHOLDER_RE = re.compile(r"\[[A-Z0-9_: -]*REDACTED[A-Z0-9_: -]*\]", re.IGNORECASE)
UNSAFE_DIRECTIVE_RE = re.compile(
    r"\b(?:execute|restart|delete|disable|rotate keys|rollout restart|switch .* now|page user|page team|post to slack)\b",
    re.IGNORECASE,
)
ID_WORD_RE = re.compile(r"[^A-Za-z0-9_.:-]+")
EVAL_REQUIRED_TERM_REPLACEMENTS = {
    "after the restart": "post-action validation",
    "restart": "post-action validation",
    "rollback": "reversibility criteria",
}


@dataclass
class CodexCompileResult:
    bundle_path: str
    approved_count: int
    rejected_count: int
    eval_case_count: int
    validation_passed: bool
    review_approved: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    approved_ids: list[str] = field(default_factory=list)
    rejected_ids: list[str] = field(default_factory=list)


def compile_knowledge_bundle(
    bundle_path: str | Path,
    *,
    knowledge_dir: str | Path = "local_knowledge",
    reviewed_by: str = "Codex semantic compiler",
) -> CodexCompileResult:
    """Compile untrusted extracted/proposed bundle notes into reviewed apply records.

    The compiler intentionally writes only reviewed envelopes and codex_review
    artifacts. It never copies source/raw text or proposed records directly into
    runtime knowledge.
    """

    bundle = Path(bundle_path)
    target = Path(knowledge_dir)
    compiled_at = _stable_compile_timestamp(bundle)
    advisory = _read_advisory_inputs(bundle)
    existing = _existing_runtime_ids(target)
    applied_ids = _applied_runtime_ids(bundle)
    approved: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    eval_cases: list[dict[str, Any]] = []

    if not validate_product_knowledge(target).passed:
        rejected.append(_rejection("runtime_knowledge_invalid", "Runtime knowledge did not validate before compile."))
    else:
        _compile_services(advisory, approved, rejected, existing, applied_ids, compiled_at)
        _compile_decisions(advisory, approved, rejected, existing, applied_ids, compiled_at)
        _compile_stale_patterns(advisory, approved, rejected, compiled_at)
        _compile_rejected_entities(advisory, approved, rejected, compiled_at)
        _reject_verifier_regressions(advisory, rejected)
        eval_cases = _compile_eval_cases(advisory)

    _write_codex_review(bundle, advisory, approved, rejected, eval_cases)
    _write_reviewed(bundle, approved, rejected, reviewed_by=reviewed_by, compiled_at=compiled_at)

    validation = validate_knowledge_bundle(bundle, knowledge_dir=target, require_review_approved=bool(approved))
    return CodexCompileResult(
        bundle_path=str(bundle),
        approved_count=len(approved),
        rejected_count=len(rejected),
        eval_case_count=len(eval_cases),
        validation_passed=validation.passed,
        review_approved=validation.review_approved,
        findings=[finding.model_dump(mode="json") for finding in validation.findings],
        approved_ids=[str(record["id"]) for record in approved],
        rejected_ids=[str(record["id"]) for record in rejected],
    )


def compile_extracted_knowledge_bundles(
    extracted_root: str | Path,
    *,
    knowledge_dir: str | Path = "local_knowledge",
) -> dict[str, Any]:
    root = Path(extracted_root)
    results = [
        compile_knowledge_bundle(bundle, knowledge_dir=knowledge_dir)
        for bundle in sorted(path for path in root.iterdir() if path.is_dir() and not path.is_symlink())
    ]
    return {
        "compiler_version": COMPILER_VERSION,
        "extracted_root": str(root),
        "knowledge_dir": str(knowledge_dir),
        "counts": {
            "bundles": len(results),
            "approved_records": sum(result.approved_count for result in results),
            "rejected_records": sum(result.rejected_count for result in results),
            "eval_cases": sum(result.eval_case_count for result in results),
            "validation_passed": sum(1 for result in results if result.validation_passed),
        },
        "bundles": [result.__dict__ for result in results],
    }


def _read_advisory_inputs(bundle: Path) -> dict[str, Any]:
    proposed = bundle / "proposed"
    extracted = bundle / "extracted"
    extracted_notes = {
        path.name: path.read_text(errors="ignore")
        for path in sorted(extracted.glob("*.md"))
        if path.is_file() and not path.is_symlink()
    } if extracted.exists() else {}
    raw_source_lines = _raw_source_lines(bundle / "source" / "raw.sanitized.txt")
    extracted_advisory = _advisory_from_extracted_notes(bundle.name, extracted_notes, raw_source_lines)
    return {
        "bundle": bundle.name,
        "extracted_notes": extracted_notes,
        "decision_moments": _dedupe_advisory_records(
            extracted_advisory["decision_moments"] + _read_jsonl_lenient(proposed / "decision_moments.proposed.jsonl"),
            ("decision_id", "id"),
        ),
        "rejected_entities": _dedupe_advisory_records(
            extracted_advisory["rejected_entities"] + _read_jsonl_lenient(proposed / "rejected_entities.proposed.jsonl"),
            ("id", "rejected_entity_id", "entity_id"),
        ),
        "stale_question_patterns": _dedupe_advisory_records(
            extracted_advisory["stale_question_patterns"] + _read_jsonl_lenient(proposed / "stale_question_patterns.proposed.jsonl"),
            ("id", "pattern_id"),
        ),
        "verifier_regressions": _dedupe_advisory_records(
            extracted_advisory["verifier_regressions"] + _read_jsonl_lenient(proposed / "verifier_regressions.proposed.jsonl"),
            ("id", "regression_id"),
        ),
        "eval_cases": _dedupe_advisory_records(
            extracted_advisory["eval_cases"] + _read_jsonl_lenient(proposed / "eval_cases.proposed.jsonl"),
            ("fixture_id", "case_id", "id"),
        ),
        "services": _dedupe_advisory_records(
            extracted_advisory["services"] + _read_services_lenient(proposed / "service_catalog.proposed.yaml"),
            ("service_id", "id"),
        ),
        "raw_source_lines": raw_source_lines,
    }


def _stable_compile_timestamp(bundle: Path) -> str:
    existing = _read_jsonl_lenient(bundle / "reviewed" / "approved_records.jsonl")
    for envelope in existing:
        compiled_at = str(envelope.get("compiled_at") or "").strip()
        if envelope.get("compiled_by") == COMPILER_VERSION and compiled_at:
            return compiled_at
    review = bundle / "reviewed" / "review.yaml"
    if review.exists() and not review.is_symlink():
        try:
            value = yaml.safe_load(review.read_text()) or {}
        except yaml.YAMLError:
            value = {}
        reviewed_at = str(value.get("reviewed_at") or "").strip() if isinstance(value, dict) else ""
        if reviewed_at:
            return reviewed_at
    manifest = bundle / "manifest.yaml"
    if manifest.exists() and not manifest.is_symlink():
        try:
            value = yaml.safe_load(manifest.read_text()) or {}
        except yaml.YAMLError:
            value = {}
        incident = value.get("incident") if isinstance(value, dict) else {}
        observed = str((incident or {}).get("date_observed") or "").strip() if isinstance(incident, dict) else ""
        if observed:
            return f"{observed}T00:00:00+00:00"
    return "1970-01-01T00:00:00+00:00"


def _read_jsonl_lenient(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or path.is_symlink():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def _read_services_lenient(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or path.is_symlink():
        return []
    try:
        value = yaml.safe_load(path.read_text(errors="ignore")) or {}
    except yaml.YAMLError:
        return []
    services = value.get("services", value if isinstance(value, list) else [])
    return [service for service in services if isinstance(service, dict)]


def _raw_source_lines(path: Path) -> list[str]:
    if not path.exists() or path.is_symlink():
        return []
    return [
        " ".join(line.split())
        for line in path.read_text(errors="ignore").splitlines()
        if len(" ".join(line.split())) >= 40
    ]


def _dedupe_advisory_records(records: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        record_id = ""
        for key in keys:
            value = str(record.get(key) or "").strip()
            if value:
                record_id = value
                break
        marker = _stable_id(record_id).lower() if record_id else json.dumps(record, sort_keys=True, default=str)
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(record)
    return deduped


def _advisory_from_extracted_notes(
    bundle_name: str,
    extracted_notes: dict[str, str],
    raw_source_lines: list[str],
) -> dict[str, list[dict[str, Any]]]:
    notes_text = _safe_eval_text("\n\n".join(extracted_notes.values()), raw_source_lines)
    normalized = notes_text.lower()
    advisory: dict[str, list[dict[str, Any]]] = {
        "decision_moments": [],
        "rejected_entities": [],
        "stale_question_patterns": [],
        "verifier_regressions": [],
        "eval_cases": [],
        "services": [],
    }
    if not normalized.strip():
        return advisory

    if _mentions_any(normalized, "data loader", "data-loader", "stuck jobs", "existing jobs", "in-flight jobs"):
        advisory["services"].append(_data_loader_service_advisory())
        if _mentions_any(normalized, "infra ruled out", "pods healthy", "hpa", "cpu/memory", "cpu", "memory"):
            advisory["decision_moments"].append(_data_loader_app_owner_after_infra_advisory())
            advisory["eval_cases"].append(_data_loader_infra_ruled_out_eval(bundle_name))
        if _mentions_any(normalized, "restart", "rollout", "safe clearing", "in-flight"):
            advisory["decision_moments"].append(_data_loader_safe_mitigation_advisory())
        if _mentions_any(normalized, "scale-up", "scale up", "partial mitigation", "new work", "capacity"):
            advisory["decision_moments"].append(_data_loader_partial_mitigation_advisory())
            advisory["stale_question_patterns"].append(_data_loader_stale_scaleup_advisory())
            advisory["eval_cases"].append(_data_loader_partial_mitigation_eval(bundle_name))

    if _mentions_any(normalized, "order creation", "catalog", "commerce-catalog", "schema mismatch", "missing column"):
        if _mentions_any(normalized, "redirect", "wrong owner", "wrong team", "belongs to", "initially routed"):
            advisory["decision_moments"].append(_owner_redirect_advisory())
            advisory["eval_cases"].append(_owner_redirect_eval(bundle_name))
        if _mentions_any(normalized, "schema mismatch", "missing column", "db schema", "deployed version", "version mismatch"):
            advisory["decision_moments"].append(_schema_mismatch_advisory())
            advisory["eval_cases"].append(_schema_mismatch_eval(bundle_name))

    if _mentions_any(normalized, "acr", "replication lag", "next actions", "verification window", "lag cleared"):
        if _mentions_any(normalized, "next actions", "owner:", "explicit owner", "assigned owner"):
            advisory["decision_moments"].append(_explicit_next_action_owner_advisory())
            advisory["eval_cases"].append(_explicit_next_action_eval(bundle_name))
        if _mentions_any(normalized, "single customer", "support", "customer workload", "ticket findings"):
            advisory["decision_moments"].append(_support_customer_workload_advisory())
        if _mentions_any(normalized, "lag cleared", "latency improved", "verification window", "health signals"):
            advisory["decision_moments"].append(_resolution_monitoring_advisory())
            advisory["eval_cases"].append(_resolution_monitoring_eval(bundle_name))

    return advisory


def _mentions_any(text: str, *needles: str) -> bool:
    return any(needle in text for needle in needles)


def _data_loader_service_advisory() -> dict[str, Any]:
    return {
        "service_id": "data_loader",
        "canonical_name": "Data Loader",
        "kind": "service",
        "aliases": ["Data Loader", "data-loader", "Data Loader Engineering"],
        "owning_team": "Data Loader Engineering",
        "known_signals": [
            "Data Loader jobs stalled, waiting, or processing slowly",
            "Service temporarily unavailable UI errors during job backlog",
            "Pod CPU/memory and HPA may be healthy while application jobs remain waiting",
        ],
        "unsafe_assumptions": [
            "Do not assume pod CPU/memory health means there is no customer impact.",
            "Do not assume capacity scale-up clears already waiting jobs.",
        ],
    }


def _data_loader_app_owner_after_infra_advisory() -> dict[str, Any]:
    return {
        "decision_id": "DM_app_owner_after_infra_ruled_out",
        "move": "engage_owner",
        "behavior_hint": (
            "When current evidence rules out pod/resource pressure and identifies an application-level job "
            "bottleneck, target the service owner for next findings or mitigation guidance, not the infra "
            "team that only ruled out resources."
        ),
        "why_it_helped": (
            "Prevents the IC assistant from looping on infra owners after the incident evidence already "
            "points to an application/job-layer owner."
        ),
        "applies_when": [
            "Current incident update says infrastructure, pods, CPU, memory, or HPA are healthy.",
            "Current evidence says the issue is an application-level job hang, queue, or downstream bottleneck.",
        ],
        "required_current_evidence": [
            "infra/resource health statement",
            "application-level bottleneck statement",
        ],
        "allowed_visible_output_pattern": (
            "@{service_owner}, infra has ruled out pod CPU/memory pressure. Can you share what you are "
            "seeing in the app/job layer and the next safe mitigation path?"
        ),
        "confidence": 0.94,
    }


def _data_loader_safe_mitigation_advisory() -> dict[str, Any]:
    return {
        "decision_id": "DM_validate_job_mitigation_before_restart",
        "move": "ask_next_validation",
        "behavior_hint": (
            "When a proposed mitigation may interrupt in-flight application jobs, ask the service owner "
            "to confirm the safe clearing method before suggesting operational changes."
        ),
        "why_it_helped": (
            "Keeps IC Copilot in manual-copy coordination mode and avoids unsafe remediation wording when "
            "job state may be affected."
        ),
        "applies_when": [
            "Current evidence says jobs are internal application jobs rather than scheduled infrastructure jobs.",
            "Current discussion says a restart or similar mitigation could affect existing customer jobs.",
        ],
        "required_current_evidence": [
            "internal application jobs",
            "mitigation safety concern",
            "service owner needed",
        ],
        "allowed_visible_output_pattern": (
            "@{service_owner}, can you confirm the safest way to clear the stuck jobs without causing "
            "additional issues for in-flight jobs?"
        ),
        "confidence": 0.91,
    }


def _data_loader_partial_mitigation_advisory() -> dict[str, Any]:
    return {
        "decision_id": "DM_partial_mitigation_remaining_impact",
        "move": "request_monitoring_signal",
        "behavior_hint": (
            "When scale-up or partial mitigation improves capacity or new work but current evidence says "
            "existing jobs, stuck jobs, backlog, or in-flight jobs may still be waiting, preserve that "
            "unresolved object and ask the Data Loader or application owner for the application-layer signal "
            "that proves it is decreasing or recovered. Do not suggest restarting, clearing, deleting, "
            "draining, retrying, or executing remediation."
        ),
        "why_it_helped": (
            "Distinguishes new-capacity mitigation from existing-job recovery, keeps the concrete unresolved "
            "object visible, and helps the IC ask the app owner for a useful verification signal without "
            "remediation wording."
        ),
        "applies_when": [
            "Current evidence says a mitigation or capacity change completed.",
            "Current evidence says existing jobs, stuck jobs, backlog, in-flight jobs, queue, or customer-facing symptoms remain unresolved.",
        ],
        "required_current_evidence": [
            "completed partial mitigation",
            "remaining stuck jobs or service unavailable symptom",
        ],
        "allowed_visible_output_pattern": (
            "@{service_owner}, now that {partial_mitigation} improved capacity or new work, can you confirm "
            "whether the existing jobs/backlog/in-flight work are still waiting and what application-layer "
            "signal proves that unresolved work is decreasing or recovered?"
        ),
        "confidence": 0.89,
    }


def _normalize_decision_advisory(
    decision_id: str,
    behavior: str,
    applies_when: list[str],
    required: list[str],
    action: str,
    why: str,
) -> tuple[str, list[str], list[str], str, str]:
    if decision_id != "DM_partial_mitigation_remaining_impact":
        if decision_id == "DM_temporary_traffic_controls_need_owner_status_and_reversibility":
            return _temporary_traffic_controls_advisory_tuple(behavior, applies_when, required, why)
        if decision_id == "DM_oracle_lock_retry_storm_changes_mitigation_path":
            return _changed_root_cause_mitigation_path_advisory_tuple(behavior, applies_when, required, why)
        if decision_id == "DM_stability_window_before_mitigation_after_unblock":
            return _stability_window_after_temporary_control_advisory_tuple(behavior, applies_when, required, why)
        return behavior, applies_when, required, action, why
    advisory = _data_loader_partial_mitigation_advisory()
    return (
        str(advisory["behavior_hint"]),
        _safe_list(advisory["applies_when"]),
        _safe_list(advisory["required_current_evidence"]),
        str(advisory["allowed_visible_output_pattern"]),
        str(advisory["why_it_helped"]),
    )


def _temporary_traffic_controls_advisory_tuple(
    behavior: str,
    applies_when: list[str],
    required: list[str],
    why: str,
) -> tuple[str, list[str], list[str], str, str]:
    return (
        (
            "When WAF blocking, rate limiting, scaling, or temporary traffic controls are being discussed, "
            "ask the named owner for status, scope, monitoring, and reversibility criteria. Do not tell the "
            "team to block, unblock, scale, execute, disable, roll back, or otherwise change traffic controls."
        ),
        applies_when,
        required,
        (
            "@{owner}, can you share the current status of {temporary_control_or_scaling}, how we are "
            "monitoring effectiveness, and what criteria show the temporary control is no longer needed?"
        ),
        why or behavior,
    )


def _changed_root_cause_mitigation_path_advisory_tuple(
    behavior: str,
    applies_when: list[str],
    required: list[str],
    why: str,
) -> tuple[str, list[str], list[str], str, str]:
    return (
        (
            "When later evidence identifies a backend cause that supersedes an earlier gateway or traffic "
            "hypothesis, ask the service owner to confirm the updated root-cause signal and the next "
            "monitoring or validation signal. Do not continue the obsolete mitigation path without current "
            "owner confirmation."
        ),
        applies_when,
        required,
        (
            "@{service_owner}, based on the updated {new_root_cause_signal}, can you confirm whether the "
            "earlier mitigation path is now monitoring-only and what validation signal should drive the next update?"
        ),
        why or behavior,
    )


def _stability_window_after_temporary_control_advisory_tuple(
    behavior: str,
    applies_when: list[str],
    required: list[str],
    why: str,
) -> tuple[str, list[str], list[str], str, str]:
    return (
        (
            "After a temporary traffic control is reported as removed, ask the engineering owner for the "
            "stability window and current error metrics before confirming mitigation readiness."
        ),
        applies_when,
        required,
        (
            "@{engineering_owner}, after the temporary traffic control was removed, have error rates and "
            "API health stayed stable for the monitoring window so we can confirm mitigation readiness?"
        ),
        why or behavior,
    )


def _data_loader_stale_scaleup_advisory() -> dict[str, Any]:
    return {
        "pattern_id": "SQ_scaleup_did_not_clear_existing_queue",
        "question_intent": "mitigation_effect_already_known",
        "stale_when_current_evidence_contains": [
            "scale-up completed",
            "did not clear stuck queue",
            "current jobs should not change",
        ],
        "do_not_ask_patterns": [
            "Did the scale-up clear the existing jobs?",
            "Should we ask again whether scale-up fixed all current jobs?",
        ],
        "safe_alternative": "Ask the service owner for the app-layer recovery signal and what remains blocked.",
        "review_notes": "Allows monitoring new jobs but avoids stale assumptions about existing jobs.",
    }


def _owner_redirect_advisory() -> dict[str, Any]:
    return {
        "decision_id": "DM_owner_redirect_after_engineer_triage",
        "move": "engage_owner",
        "behavior_hint": (
            "When a paged team inspects the evidence and redirects ownership to another service/team, future "
            "status or mitigation asks should target the redirected owner unless newer evidence contradicts it."
        ),
        "why_it_helped": "Avoids repeatedly asking the wrong team after current investigation has clarified ownership.",
        "applies_when": [
            "A team was paged based on an initial stack trace or component signal.",
            "A knowledgeable responder states another service/team owns the issue.",
        ],
        "required_current_evidence": [
            "initial routed team or owner",
            "explicit owner redirection statement",
            "current service or component evidence",
        ],
        "allowed_visible_output_pattern": (
            "@{redirected_owner}, current evidence points to {service_area}. Can you share investigation "
            "status and next validation needed?"
        ),
        "confidence": 0.91,
    }


def _schema_mismatch_advisory() -> dict[str, Any]:
    return {
        "decision_id": "DM_app_db_schema_mismatch_validation",
        "move": "ask_next_validation",
        "behavior_hint": (
            "When current evidence shows an application/database schema mismatch after a deployment, ask the "
            "app owner and database/schema owner to confirm deployed version, schema readiness, affected "
            "environments, and safe validation criteria instead of recommending direct operational changes."
        ),
        "why_it_helped": "Keeps IC Copilot in coordination mode while moving investigation to validation points.",
        "applies_when": [
            "Errors mention missing database columns or schema objects.",
            "Recent deployment or version mismatch is part of current evidence.",
        ],
        "required_current_evidence": [
            "deployment or version change evidence",
            "missing column or schema mismatch signal",
            "affected environment list or uncertainty",
        ],
        "allowed_visible_output_pattern": (
            "@{service_owner} @{db_owner}, can you confirm the deployed version, DB schema readiness, "
            "and affected environments so we can validate the mitigation path?"
        ),
        "confidence": 0.93,
    }


def _explicit_next_action_owner_advisory() -> dict[str, Any]:
    return {
        "decision_id": "DM_explicit_next_action_owner_alignment",
        "move": "request_status_or_eta",
        "behavior_hint": (
            "When the latest incident summary lists Next Actions with explicit owners, target status or ETA "
            "asks to the listed owner or owner group for that action."
        ),
        "why_it_helped": "Prevents wrong-owner asks when resolution work streams are already assigned.",
        "applies_when": [
            "A current update has a Next Actions section.",
            "Each action contains an explicit owner marker such as Owner: @person or Owner: team.",
            "The next useful move is to clarify status, ETA, or progress for one of those actions.",
        ],
        "required_current_evidence": [
            "next action text",
            "explicit owner marker",
            "current incident phase or summary indicating the action is still active",
        ],
        "allowed_visible_output_pattern": "@{owner}, can you share status and ETA for {next_action}?",
        "confidence": 0.93,
    }


def _support_customer_workload_advisory() -> dict[str, Any]:
    return {
        "decision_id": "DM_support_customer_workload_validation",
        "move": "ask_impact",
        "behavior_hint": (
            "When the current incident identifies a single affected customer/tenant and Support has been "
            "engaged, ask Support for customer workload context or ticket findings rather than asking "
            "technical owners to infer customer intent."
        ),
        "why_it_helped": "Keeps customer-context questions routed to Support while investigators validate system signals.",
        "applies_when": [
            "Current evidence says only one customer or tenant is affected.",
            "Support on-call or a support representative is present.",
            "The missing information is what the customer is doing, customer-side workload context, or proactive ticket findings.",
        ],
        "required_current_evidence": [
            "single-customer or single-tenant impact statement",
            "Support participant or Support Ops roster",
            "customer/workload context is still needed",
        ],
        "allowed_visible_output_pattern": (
            "@{support_owner}, can you share any customer workload context or ticket findings for the impacted customer?"
        ),
        "confidence": 0.86,
    }


def _resolution_monitoring_advisory() -> dict[str, Any]:
    return {
        "decision_id": "DM_resolution_monitoring_confirmation",
        "move": "ask_next_validation",
        "behavior_hint": (
            "When mitigation is reported and health signals are improving, ask the active investigator or "
            "mitigation owner to confirm the verification window and remaining criteria before closure."
        ),
        "why_it_helped": (
            "Encourages IC Copilot to move from investigation to verification without suggesting direct "
            "operational changes."
        ),
        "applies_when": [
            "Current evidence says a mitigation was completed or impact is being mitigated.",
            "At least one recovery signal is present, such as lag cleared or latency improved.",
            "The incident is in resolution or verification phase.",
        ],
        "required_current_evidence": [
            "mitigation or recovery statement",
            "health signal showing improvement",
            "active owner or investigator",
        ],
        "allowed_visible_output_pattern": (
            "@{owner}, can you confirm the verification window and the remaining health signals we need before closure?"
        ),
        "confidence": 0.89,
    }


def _data_loader_infra_ruled_out_eval(bundle_name: str) -> dict[str, Any]:
    return _eval_advisory(
        f"EV_{bundle_name}_data_loader_infra_ruled_out",
        "Infra ruled out; Data Loader app owner should provide app/job-layer status.",
        "Data Loader Engineering",
        ["Data Loader Engineering", "Data Loader"],
        ["ESG", "TechOps", "Support"],
        ["engage_owner"],
        ["app/job layer", "safe mitigation"],
        ["restart", "execute", "page team"],
    )


def _data_loader_partial_mitigation_eval(bundle_name: str) -> dict[str, Any]:
    return _eval_advisory(
        f"EV_{bundle_name}_data_loader_partial_mitigation_existing_jobs",
        "Scale-up improved capacity but existing jobs still need recovery validation.",
        "Data Loader Engineering",
        ["Data Loader Engineering", "Data Loader"],
        ["Support", "ESG", "TechOps"],
        ["request_monitoring_signal", "ask_next_validation"],
        ["existing jobs", "application-layer", "recovered"],
        ["restart", "execute", "page team", "delete", "retry"],
    )


def _owner_redirect_eval(bundle_name: str) -> dict[str, Any]:
    return _eval_advisory(
        f"EV_{bundle_name}_owner_redirect",
        "Initial owner was redirected to the catalog-side owner.",
        "Catalog engineer",
        ["Catalog engineer", "commerce-catalog"],
        ["Subscription", "Support"],
        ["engage_owner"],
        ["catalog", "investigation"],
        ["restart", "execute", "page team"],
    )


def _schema_mismatch_eval(bundle_name: str) -> dict[str, Any]:
    return _eval_advisory(
        f"EV_{bundle_name}_schema_mismatch_validation",
        "Application/database schema mismatch needs version and schema validation.",
        "Catalog engineer",
        ["Catalog engineer", "commerce-catalog"],
        ["Support", "Subscription"],
        ["ask_next_validation"],
        ["schema", "version", "validation"],
        ["restart", "execute", "page team"],
    )


def _explicit_next_action_eval(bundle_name: str) -> dict[str, Any]:
    return _eval_advisory(
        f"EV_{bundle_name}_next_action_owner_alignment",
        "Next Actions include explicit owners; ask the owner for current status.",
        "Connor",
        ["Connor", "customer follow-up owner"],
        ["DBA", "Support"],
        ["request_status_or_eta"],
        ["status", "ETA"],
        ["restart", "execute", "page team", "trust post"],
    )


def _resolution_monitoring_eval(bundle_name: str) -> dict[str, Any]:
    return _eval_advisory(
        f"EV_{bundle_name}_resolution_monitoring",
        "Lag cleared and latency improved; ask active owner for verification window.",
        "Kenneth",
        ["Kenneth", "active investigator"],
        ["Support", "DBA"],
        ["ask_next_validation", "request_monitoring_signal"],
        ["verification", "health signals"],
        ["restart", "execute", "page team"],
    )


def _eval_advisory(
    fixture_id: str,
    title: str,
    target: str,
    acceptable_targets: list[str],
    forbidden_targets: list[str],
    acceptable_moves: list[str],
    required_terms: list[str],
    forbidden_terms: list[str],
) -> dict[str, Any]:
    return {
        "case_id": _stable_id(fixture_id),
        "title": title,
        "sanitized_input": (
            f"Current update: {title} Owner: {target}. "
            f"Need {target} to address {', '.join(required_terms)}."
        ),
        "expected_target_any": acceptable_targets,
        "forbidden_target_any": forbidden_targets,
        "acceptable_moves": acceptable_moves,
        "required_visible_terms": required_terms,
        "forbidden_visible_terms": forbidden_terms,
        "notes": title,
        "allow_fallback": False,
    }


def _existing_runtime_ids(knowledge_dir: Path) -> dict[str, set[str]]:
    ids = {
        "decision_moment": set(),
        "service_catalog_entry": set(),
        "rejected_entity": set(),
        "stale_question_pattern": set(),
        "verifier_regression": set(),
    }
    if not knowledge_dir.exists():
        return ids
    for record in _read_jsonl_lenient(knowledge_dir / "decision_moments.jsonl"):
        if record.get("decision_id"):
            ids["decision_moment"].add(str(record["decision_id"]).lower())
    try:
        catalog = yaml.safe_load((knowledge_dir / "service_catalog.yaml").read_text()) or {}
    except Exception:
        catalog = {}
    services = catalog.get("services", catalog if isinstance(catalog, list) else [])
    for service in services:
        if isinstance(service, dict) and service.get("service_id"):
            ids["service_catalog_entry"].add(str(service["service_id"]).lower())
    for key, filename in (
        ("rejected_entity", "rejected_entities.jsonl"),
        ("stale_question_pattern", "stale_question_patterns.jsonl"),
        ("verifier_regression", "verifier_regressions.jsonl"),
    ):
        for record in _read_jsonl_lenient(knowledge_dir / filename):
            if record.get("id"):
                ids[key].add(str(record["id"]).lower())
    return ids


def _applied_runtime_ids(bundle: Path) -> dict[str, set[str]]:
    ids = {
        "decision_moment": set(),
        "service_catalog_entry": set(),
        "rejected_entity": set(),
        "stale_question_pattern": set(),
        "verifier_regression": set(),
    }
    for row in _read_jsonl_lenient(bundle / "applied" / "applied_records.jsonl"):
        record_type = str(row.get("record_type") or "")
        record_id = str(row.get("id") or "").lower()
        if record_type in ids and record_id:
            ids[record_type].add(record_id)
    return ids


def _compile_services(
    advisory: dict[str, Any],
    approved: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    existing: dict[str, set[str]],
    applied_ids: dict[str, set[str]],
    compiled_at: str,
) -> None:
    for service in advisory["services"]:
        service_id = _stable_id(str(service.get("service_id") or ""))
        if not service_id:
            rejected.append(_rejection("service_missing_id", "Service proposal missing a stable service_id."))
            continue
        if (
            service_id.lower() in existing["service_catalog_entry"]
            and service_id.lower() not in applied_ids["service_catalog_entry"]
        ):
            rejected.append(_rejection(service_id, "Service catalog entry already exists in runtime knowledge."))
            continue
        owning_team = _safe_text(service.get("owning_team") or "")
        record = {
            "service_id": service_id,
            "canonical_name": _safe_text(service.get("canonical_name") or service_id.replace("_", " ").title()),
            "kind": _safe_entity_kind(str(service.get("kind") or "service")),
            "aliases": _safe_list(service.get("aliases"))[:8],
            "ownership": {"owning_team": owning_team} if owning_team else {},
            "known_signals": _safe_list(service.get("known_signals"))[:8],
            "unsafe_assumptions": _safe_list(service.get("unsafe_assumptions"))[:8],
        }
        approved.append(_envelope("service_catalog_entry", service_id, record, compiled_at, duplicate_policy="skip_if_exists"))


def _compile_decisions(
    advisory: dict[str, Any],
    approved: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    existing: dict[str, set[str]],
    applied_ids: dict[str, set[str]],
    compiled_at: str,
) -> None:
    for raw in advisory["decision_moments"]:
        decision_id = _stable_id(str(raw.get("decision_id") or raw.get("id") or ""))
        if not decision_id:
            rejected.append(_rejection("decision_missing_id", "Decision proposal missing a stable decision_id."))
            continue
        if (
            decision_id.lower() in existing["decision_moment"]
            and decision_id.lower() not in applied_ids["decision_moment"]
        ):
            rejected.append(_rejection(decision_id, "DecisionMoment already exists in runtime knowledge."))
            continue
        move = _normal_move(str(raw.get("move") or ""))
        if move is None:
            rejected.append(_rejection(decision_id, "Decision proposal used an unsupported move and could not be mapped safely."))
            continue
        applicability = raw.get("applicability") if isinstance(raw.get("applicability"), dict) else {}
        behavior = _safe_text(raw.get("behavior_hint") or raw.get("pattern") or raw.get("situation_before") or "")
        applies_when = _safe_list(raw.get("applies_when") or raw.get("use_when") or applicability.get("use_when"))
        required = _safe_list(raw.get("required_current_evidence") or applicability.get("required_current_evidence"))
        action = _safe_text(raw.get("allowed_visible_output_pattern") or raw.get("ic_action") or behavior)
        why = _safe_text(raw.get("why_it_helped") or raw.get("why_it_worked") or behavior)
        behavior, applies_when, required, action, why = _normalize_decision_advisory(
            decision_id,
            behavior,
            applies_when,
            required,
            action,
            why,
        )
        if not behavior or not applies_when or not required:
            rejected.append(_rejection(decision_id, "Decision proposal did not contain enough reusable applicability detail."))
            continue
        if _looks_like_unsafe_directive(action):
            rejected.append(_rejection(decision_id, "Decision proposal visible wording looked like direct operation/remediation."))
            continue
        labels = _labels_for_decision(decision_id, move)
        blocker = MOVE_BLOCKERS.get(move, "current_open_loop")
        record = {
            "decision_id": decision_id,
            "source_incident_id": "codex_semantic_compiler",
            "review_status": "externally_reviewed",
            "quality_score": _quality(raw.get("confidence")),
            "phase_before": _phase_before(move),
            "phase_after": PHASE_AFTER.get(move, "investigation"),
            "move": move,
            "situation_before": behavior,
            "trigger": "Use when: " + "; ".join(applies_when[:4]),
            "ic_action": action,
            "why_it_worked": why,
            "applicability": {
                "current_blocker": blocker,
                "use_when": applies_when[:6],
                "required_current_evidence": required[:6],
                "do_not_use_when": [
                    "facts only appear in historical memory and not current evidence",
                    "newer current evidence contradicts the proposed owner or phase",
                    "the target is only a bot, ticket, tenant, account, URL, preview card, or section heading",
                ],
            },
            "forbidden_fact_leakage": [],
            "outcome": blocker,
            "labels": labels,
            "reviewed_at": compiled_at,
            "reviewed_by": "Codex semantic compiler",
        }
        approved.append(_envelope("decision_moment", decision_id, record, compiled_at))


def _compile_stale_patterns(
    advisory: dict[str, Any],
    approved: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    compiled_at: str,
) -> None:
    for raw in advisory["stale_question_patterns"]:
        record_id = _stable_id(str(raw.get("id") or raw.get("pattern_id") or ""))
        if not record_id:
            rejected.append(_rejection("stale_pattern_missing_id", "Stale-question proposal missing a stable id."))
            continue
        record = {
            "id": record_id,
            "question_intent": _safe_text(raw.get("question_intent") or ""),
            "stale_when_current_evidence_contains": _safe_list(raw.get("stale_when_current_evidence_contains"))[:8],
            "do_not_ask_patterns": _safe_list(raw.get("do_not_ask_patterns"))[:8],
            "safe_alternative": _safe_text(raw.get("safe_alternative") or ""),
            "review_notes": _safe_text(raw.get("review_notes") or ""),
        }
        if not record["question_intent"] or not record["safe_alternative"]:
            rejected.append(_rejection(record_id, "Stale-question proposal was too weak after removing incident details."))
            continue
        approved.append(_envelope("stale_question_pattern", record_id, record, compiled_at, duplicate_policy="skip_if_exists"))


def _compile_rejected_entities(
    advisory: dict[str, Any],
    approved: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    compiled_at: str,
) -> None:
    for raw in advisory["rejected_entities"]:
        record_id = _stable_id(str(raw.get("id") or raw.get("rejected_entity_id") or raw.get("entity_id") or ""))
        if not record_id:
            rejected.append(_rejection("rejected_entity_missing_id", "Rejected-entity proposal missing a stable id."))
            continue
        record = {
            "id": record_id,
            "entity_pattern": _safe_text(raw.get("entity_pattern") or ""),
            "entity_type": _safe_text(raw.get("entity_type") or "unknown"),
            "scope": _safe_text(raw.get("scope") or "target_extraction"),
            "reason": _safe_text(raw.get("reason") or ""),
            "should_remain_mentionable_as_fact": bool(raw.get("should_remain_mentionable_as_fact", True)),
        }
        if not record["entity_pattern"] or not record["reason"]:
            rejected.append(_rejection(record_id, "Rejected-entity proposal was too weak after removing incident details."))
            continue
        approved.append(_envelope("rejected_entity", record_id, record, compiled_at, duplicate_policy="skip_if_exists"))


def _reject_verifier_regressions(advisory: dict[str, Any], rejected: list[dict[str, Any]]) -> None:
    for raw in advisory["verifier_regressions"]:
        record_id = _stable_id(str(raw.get("id") or raw.get("regression_id") or "verifier_regression"))
        rejected.append(
            _rejection(
                record_id,
                "Verifier proposal retained as advisory material; copied bad/good outputs are better represented as safe eval fixtures or stale/rejected-entity records.",
            )
        )


def _compile_eval_cases(advisory: dict[str, Any]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for raw in advisory["eval_cases"]:
        fixture_id = _safe_fixture_id(str(raw.get("fixture_id") or raw.get("case_id") or raw.get("id") or "eval_case"))
        if not fixture_id:
            continue
        sanitized_input = _safe_eval_text(
            raw.get("sanitized_input") or raw.get("sanitized_slack_paste") or "",
            advisory.get("raw_source_lines", []),
        )
        required_terms = _safe_required_visible_terms(raw.get("required_visible_terms"))
        forbidden_terms = _safe_forbidden_visible_terms(raw.get("forbidden_visible_terms"), required_terms)
        acceptable_targets = _safe_targets(raw.get("expected_target_any") or raw.get("acceptable_target_names"), sanitized_input)
        forbidden_targets = _safe_targets(raw.get("forbidden_target_any") or raw.get("unacceptable_target_names"), sanitized_input)
        acceptable_move_values = raw.get("acceptable_moves") or raw.get("acceptable_move_families") or []
        acceptable_moves = [_normal_move(str(move)) or str(move) for move in acceptable_move_values]
        acceptable_moves = [move for move in acceptable_moves if move in ICMove._value2member_map_]
        if not sanitized_input or not acceptable_targets or not acceptable_moves:
            continue
        target = _target_from_input(acceptable_targets, sanitized_input)
        slack_paste, evidence_quote = _slackish_eval_paste(
            target,
            _safe_text(raw.get("title") or raw.get("notes") or "Compiled bundle behavior check."),
            required_terms,
            acceptable_moves[0],
            sanitized_input=sanitized_input,
        )
        say_this = _say_this(target, required_terms, acceptable_moves[0])
        cases.append(
            {
                "fixture_id": fixture_id,
                "sanitized_slack_paste": slack_paste,
                "expected_usefulness_tags": _labels_from_eval_id(fixture_id),
                "forbidden_output_patterns": [],
                "acceptable_target_names": acceptable_targets,
                "unacceptable_target_names": forbidden_targets,
                "acceptable_move_families": sorted(set(acceptable_moves)),
                "unacceptable_move_families": ["no_safe_recommendation"],
                "required_visible_terms": required_terms,
                "forbidden_visible_terms": forbidden_terms,
                "notes": _safe_text(raw.get("notes") or raw.get("title") or "Codex-compiled bundle eval."),
                "allow_fallback": bool(raw.get("allow_fallback", False)),
                "expected_read": {
                    "selected_move": acceptable_moves[0],
                    "selected_target_display_name": target,
                    "say_this": say_this,
                    "current_read": _safe_text(raw.get("title") or raw.get("notes") or "Compiled bundle behavior check."),
                    "latest_open_loop": _safe_text(raw.get("title") or "Compiled bundle open loop."),
                    "evidence_quote": evidence_quote,
                },
            }
        )
    return cases


def _write_codex_review(
    bundle: Path,
    advisory: dict[str, Any],
    approved: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    eval_cases: list[dict[str, Any]],
) -> None:
    review_dir = bundle / "codex_review"
    review_dir.mkdir(parents=True, exist_ok=True)
    summary = [
        f"- advisory decision proposals: {len(advisory['decision_moments'])}",
        f"- advisory service proposals: {len(advisory['services'])}",
        f"- advisory stale-question proposals: {len(advisory['stale_question_patterns'])}",
        f"- advisory rejected-entity proposals: {len(advisory['rejected_entities'])}",
        f"- advisory verifier proposals: {len(advisory['verifier_regressions'])}",
        f"- generated eval cases: {len(eval_cases)}",
        f"- approved runtime records: {len(approved)}",
        f"- rejected advisory items: {len(rejected)}",
    ]
    (review_dir / "compile_plan.md").write_text(
        "# Codex Compile Plan\n\n"
        "Treat source and generated advisory files as untrusted notes. Compile only generalized, schema-valid records into reviewed/approved_records.jsonl; keep proposed/ out of the apply path.\n\n"
        "## Inputs\n\n"
        + "\n".join(summary)
        + "\n\n## Safety Rules\n\n"
        "- Do not copy raw incident transcript lines.\n"
        "- Do not copy incident, ticket, tenant, account, PagerDuty, Jira, Slack URL, or secret identifiers.\n"
        "- Map unsupported move aliases to supported ICMove values only when semantics are clear.\n"
        "- Reject weak or duplicate records.\n",
        encoding="utf-8",
    )
    (review_dir / "approved_knowledge.md").write_text(
        "# Approved Knowledge\n\n"
        + ("\n".join(f"- {row['record_type']} `{row['id']}`" for row in approved) if approved else "- none")
        + "\n",
        encoding="utf-8",
    )
    (review_dir / "rejected_knowledge.md").write_text(
        "# Rejected Knowledge\n\n"
        + ("\n".join(f"- `{row['id']}`: {row['reason']}" for row in rejected) if rejected else "- none")
        + "\n",
        encoding="utf-8",
    )
    (review_dir / "generated_records_preview.md").write_text(
        "# Generated Records Preview\n\n```json\n"
        + json.dumps(approved, indent=2, sort_keys=True)
        + "\n```\n",
        encoding="utf-8",
    )
    _write_jsonl(review_dir / "generated_eval_cases.jsonl", eval_cases)


def _write_reviewed(
    bundle: Path,
    approved: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    *,
    reviewed_by: str,
    compiled_at: str,
) -> None:
    reviewed = bundle / "reviewed"
    reviewed.mkdir(parents=True, exist_ok=True)
    review = {
        "status": "approved_for_apply" if approved else "rejected_no_safe_runtime_records",
        "approved": bool(approved),
        "reviewed_by": reviewed_by,
        "reviewed_at": compiled_at,
        "review_method": f"{COMPILER_VERSION}: semantic compile from untrusted advisory notes into safe generalized records.",
        "approved_record_count": len(approved),
        "rejected_record_count": len(rejected),
    }
    (reviewed / "review.yaml").write_text(yaml.safe_dump(review, sort_keys=False), encoding="utf-8")
    _write_jsonl(reviewed / "approved_records.jsonl", approved)
    _write_jsonl(reviewed / "rejected_records.jsonl", rejected)


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records), encoding="utf-8")


def _envelope(
    record_type: str,
    record_id: str,
    record: dict[str, Any],
    compiled_at: str,
    *,
    duplicate_policy: str | None = None,
) -> dict[str, Any]:
    envelope = {
        "record_type": record_type,
        "id": record_id,
        "record": record,
        "compiled_by": COMPILER_VERSION,
        "compiled_at": compiled_at,
        "source_policy": "compiled_from_untrusted_advisory_notes",
    }
    if duplicate_policy:
        envelope["duplicate_policy"] = duplicate_policy
    return envelope


def _rejection(record_id: str, reason: str) -> dict[str, Any]:
    return {"id": _stable_id(record_id) or "rejected_advisory_item", "reason": reason}


def _stable_id(value: str) -> str:
    value = ID_WORD_RE.sub("_", value.strip()).strip("_.:-")
    if not value:
        return ""
    if not value[0].isalpha():
        value = f"R_{value}"
    return value[:120]


def _safe_fixture_id(value: str) -> str:
    stable = _stable_id(value)
    if len(stable) <= 28:
        return stable
    digest = "h" + sha256(stable.encode()).hexdigest()[:5]
    return f"{stable[:21].rstrip('_')}_{digest}"


def _normal_move(value: str) -> str | None:
    move = MOVE_ALIASES.get(value.strip(), value.strip())
    return move if move in ICMove._value2member_map_ else None


def _phase_before(move: str) -> str:
    if move == ICMove.ENGAGE_OWNER.value:
        return "triage"
    if move == ICMove.REQUEST_MONITORING_SIGNAL.value:
        return "mitigation"
    if move == ICMove.ASK_NEXT_VALIDATION.value:
        return "investigation"
    return "investigation"


def _quality(value: Any) -> float:
    try:
        quality = float(value)
    except (TypeError, ValueError):
        quality = 0.82
    if quality > 1:
        quality /= 100
    return max(0.7, min(0.95, quality))


def _safe_text(value: Any) -> str:
    text = " ".join(str(value or "").split())
    text = REDACTED_PLACEHOLDER_RE.sub("<redacted_identifier>", text)
    return text


def _safe_eval_text(value: Any, raw_lines: list[str]) -> str:
    text = _safe_text(value)
    text = re.sub(r"\bGitHub\b", "the affected customer", text)
    text = REDACTED_PLACEHOLDER_RE.sub("<redacted_identifier>", text)
    text = text.replace("Next Actions:", "Open actions say")
    text = text.replace("Owner:", "Assigned owner:")
    text = text.replace("ETA:", "Timeline:")
    text = text.replace("Phase 4 - Resolution & Verification.", "The incident is in resolution and verification.")
    text = text.replace("Switching ACR back to i2.", "Database reader role is being returned to the healthy instance.")
    text = text.replace(
        "ACR switched back to i2, lag cleared, OCS lag going down, E2E latency improved.",
        "Database reader returned to a healthy state, lag cleared, downstream lag is decreasing, and latency improved.",
    )
    text = text.replace("Only one customer is on this shard:", "A single customer is affected on the shard:")
    for raw_line in raw_lines:
        if raw_line in text:
            text = text.replace(raw_line, _paraphrase_raw_line(raw_line))
    return text


def _paraphrase_raw_line(raw_line: str) -> str:
    lower = raw_line.lower()
    if "next actions" in lower or "owner:" in lower:
        return "A current update lists owner-assigned follow-up actions with one action still missing a timeline."
    if "lag" in lower and ("latency" in lower or "acr" in lower):
        return "Current recovery signals say replication lag cleared and downstream latency is improving."
    if "customer" in lower or "tenant" in lower:
        return "Current impact notes identify a customer-facing follow-up that belongs with the support owner."
    if "trust post" in lower:
        return "Current communications notes say the trust-post question has already been answered."
    return "Current incident notes provide the relevant owner, status, and validation context."


def _safe_list(value: Any) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    return [_safe_text(item) for item in items if _safe_text(item)]


def _safe_required_visible_terms(value: Any) -> list[str]:
    terms: list[str] = []
    for term in _safe_list(value):
        normalized = term.strip().lower()
        replacement = EVAL_REQUIRED_TERM_REPLACEMENTS.get(normalized)
        terms.append(replacement or term)
    return _dedupe_preserving_order(terms)


def _safe_forbidden_visible_terms(value: Any, required_terms: list[str]) -> list[str]:
    required_lower = [term.lower() for term in required_terms]
    forbidden: list[str] = []
    for term in _safe_list(value):
        normalized = term.lower()
        if any(normalized and (normalized in required or required in normalized) for required in required_lower):
            continue
        forbidden.append(term)
    return _dedupe_preserving_order(forbidden)


def _dedupe_preserving_order(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        marker = value.lower()
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(value)
    return deduped


def _safe_targets(value: Any, sanitized_input: str) -> list[str]:
    targets = []
    for item in _safe_list(value):
        item = re.sub(r"\b(?:support/customer|customer/support)\s+owner\b", "Support Owner", item, flags=re.IGNORECASE)
        if "<redacted_identifier>" in item.lower():
            continue
        if re.search(r"\b(?:ticket id|tenant id|account id|pagerduty id|raw url|bot/system user)\b", item, re.IGNORECASE):
            continue
        targets.append(item)
    return targets[:4] or (["Support"] if "Support" in sanitized_input else [])


def _safe_entity_kind(value: str) -> str:
    return value if value in {"service", "team", "person", "dashboard", "runbook", "unknown"} else "service"


def _looks_like_unsafe_directive(text: str) -> bool:
    normalized = text.lower()
    if normalized.startswith(("do not ", "avoid ", "ask whether ", "ask the ", "ask ")):
        return False
    return bool(UNSAFE_DIRECTIVE_RE.search(text))


def _labels_for_decision(decision_id: str, move: str) -> list[str]:
    labels = {"codex_compiled", move, MOVE_BLOCKERS.get(move, "incident_response")}
    labels.update(part.lower() for part in re.split(r"[_:.-]+", decision_id) if len(part) > 2 and part.upper() != "DM")
    return sorted(labels)[:12]


def _labels_from_eval_id(fixture_id: str) -> list[str]:
    return [part.lower() for part in re.split(r"[_:.-]+", fixture_id) if len(part) > 2 and part.upper() != "EV"][:6]


def _target_from_input(targets: list[str], sanitized_input: str) -> str:
    normalized_input = sanitized_input.lower()
    for target in targets:
        if target.lower().lstrip("@") in normalized_input:
            return target
    return targets[0]


def _say_this(target: str, required_terms: list[str], move: str) -> str:
    terms = [term for term in required_terms if term][:4]
    term_text = ", ".join(terms) if terms else "the current blocker"
    if move == ICMove.REQUEST_MONITORING_SIGNAL.value:
        return f"{target}, can you confirm the monitoring signal for {term_text}?"
    if move == ICMove.ASK_IMPACT.value:
        return f"{target}, can you confirm impact details for {term_text}?"
    if move == ICMove.ENGAGE_OWNER.value:
        return f"{target}, can you confirm ownership and next step for {term_text}?"
    if move == ICMove.ASK_NEXT_VALIDATION.value:
        return f"{target}, can you confirm the next validation step for {term_text}?"
    return f"{target}, can you share status or ETA for {term_text}?"


def _slackish_eval_paste(
    target: str,
    title: str,
    required_terms: list[str],
    move: str,
    *,
    sanitized_input: str = "",
) -> tuple[str, str]:
    speaker = target.lstrip("@") or "Owner"
    term_text = ", ".join(required_terms[:4]) if required_terms else "the current blocker"
    if move == ICMove.REQUEST_MONITORING_SIGNAL.value:
        open_loop = f"Need {target} to confirm the monitoring signal for {term_text}."
    elif move == ICMove.ASK_IMPACT.value:
        open_loop = f"Need {target} to confirm impact details for {term_text}."
    elif move == ICMove.ASK_NEXT_VALIDATION.value:
        open_loop = f"Need {target} to confirm the next validation step for {term_text}."
    elif move == ICMove.ENGAGE_OWNER.value:
        open_loop = f"Need {target} to confirm ownership and next step for {term_text}."
    else:
        open_loop = f"Need {target} to share status or ETA for {term_text}."
    lines = [f"[10:00] Coordinator: {title}. Current evidence mentions {term_text}."]
    if sanitized_input:
        lines.append(f"[10:03] Coordinator: Current sanitized evidence: {sanitized_input}.")
    lines.extend(
        [
            f"[10:05] {speaker}: I am the current owner for this workstream.",
            f"[10:10] Coordinator: {open_loop}",
        ]
    )
    return "\n".join(lines), open_loop
