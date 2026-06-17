from __future__ import annotations

from collections import Counter
from typing import Any


ROOT_CAUSES = {
    "normalizer_error",
    "latest_window_missing_evidence",
    "context_pack_omitted_evidence",
    "target_extraction_error",
    "memory_not_retrieved",
    "memory_not_applicable",
    "model_selected_wrong_move",
    "model_selected_wrong_target",
    "model_output_safe_but_weak",
    "actionability_block",
    "verifier_block",
    "eval_expectation_too_strict",
    "provider_network_or_timeout",
    "no_safe_recommendation_expected",
    "unknown",
}


def _reasons(case: dict[str, Any]) -> list[str]:
    return [str(item) for item in case.get("reasons", [])]


def _quality(case: dict[str, Any]) -> dict[str, Any]:
    quality = case.get("final_output_quality")
    return quality if isinstance(quality, dict) else {}


def _diagnosis(case: dict[str, Any]) -> dict[str, Any]:
    diagnosis = case.get("run_diagnosis_summary")
    return diagnosis if isinstance(diagnosis, dict) else {}


def classify_holdout_case(case: dict[str, Any]) -> dict[str, Any]:
    reasons = _reasons(case)
    quality = _quality(case)
    diagnosis = _diagnosis(case)
    verifier_status = str(case.get("verifier_status") or "")
    actionability_category = str(
        quality.get("actionability_failure_category")
        or diagnosis.get("actionability_failure_category")
        or "none"
    )
    safe_but_weak = bool(quality.get("safe_but_weak") or diagnosis.get("safe_but_weak"))
    fallback_used = bool(case.get("fallback_used"))
    passed = bool(case.get("passed"))
    move = str(case.get("move") or "")
    expected_no_safe = any("no_safe" in str(item).lower() for item in case.get("expected_usefulness_tags", []))
    direct_ask = bool(quality.get("direct_ask") or diagnosis.get("direct_ask"))
    root_cause = "unknown"
    should_become = "no action"

    if passed:
        if fallback_used and expected_no_safe:
            root_cause = "no_safe_recommendation_expected"
        should_become = "no action"
    elif any("timeout" in reason.lower() or "network" in reason.lower() for reason in reasons):
        root_cause = "provider_network_or_timeout"
        should_become = "no action"
    elif actionability_category not in {"", "none"}:
        root_cause = "actionability_block" if verifier_status != "pass" else "model_output_safe_but_weak"
        should_become = "prompt/actionability change"
    elif expected_no_safe and direct_ask and move == "no_safe_recommendation":
        root_cause = "model_output_safe_but_weak"
        should_become = "verifier change"
    elif "verifier_not_passed" in reasons or verifier_status in {"blocked", "fallback_required", "rewrite_required"}:
        root_cause = "verifier_block"
        should_become = "verifier change" if safe_but_weak else "no action"
    elif fallback_used and not expected_no_safe:
        root_cause = "verifier_block"
        should_become = "prompt/actionability change" if safe_but_weak else "verifier change"
    elif any(reason.startswith("wrong_owner") for reason in reasons):
        root_cause = "model_selected_wrong_target"
        should_become = "knowledge-bundle learning"
    elif "selected_target_not_acceptable" in reasons:
        root_cause = "target_extraction_error"
        should_become = "normalizer/context-pack change"
    elif any(reason.startswith("move_not_acceptable") or reason.startswith("move_forbidden") for reason in reasons):
        root_cause = "model_selected_wrong_move"
        should_become = "prompt/actionability change"
    elif safe_but_weak:
        root_cause = "model_output_safe_but_weak"
        should_become = "prompt/actionability change"
    elif any(reason.startswith("missing_visible_terms") for reason in reasons):
        root_cause = "eval_expectation_too_strict" if diagnosis.get("direct_ask") else "model_output_safe_but_weak"
        should_become = "eval expectation adjustment" if root_cause == "eval_expectation_too_strict" else "prompt/actionability change"
    elif not case.get("accepted_memory_ids") and case.get("rejected_memory_ids"):
        root_cause = "memory_not_applicable"
        should_become = "memory applicability change"
    elif not case.get("accepted_memory_ids") and case.get("expected_usefulness_tags"):
        root_cause = "memory_not_retrieved"
        should_become = "knowledge-bundle learning"

    if root_cause not in ROOT_CAUSES:
        root_cause = "unknown"
    return {
        "fixture_id": case.get("fixture_id"),
        "passed": passed,
        "root_cause": root_cause,
        "should_become": should_become,
        "safe_but_weak": safe_but_weak,
        "actionability_failure_category": actionability_category,
        "live_failed_reason": ",".join(reasons),
        "fallback_trigger_check": case.get("fallback_trigger_check", ""),
        "eval_alias_match_summary": case.get("eval_alias_match_summary", []),
        "target_dedup_applied": bool(case.get("target_dedup_applied")),
        "no_safe_wording_quality": quality.get("no_safe_wording_quality")
        or diagnosis.get("no_safe_wording_quality")
        or case.get("no_safe_wording_quality")
        or "not_applicable",
        "move_normalized_from": case.get("move_normalized_from") or diagnosis.get("move_normalized_from"),
        "move_normalized_to": case.get("move_normalized_to") or diagnosis.get("move_normalized_to"),
        "reasons": reasons,
        "diagnosis_summary": diagnosis,
    }


def aggregate_holdout_taxonomy(report: dict[str, Any]) -> dict[str, Any]:
    rows = [classify_holdout_case(case) for case in report.get("cases", [])]
    counts = Counter(row["root_cause"] for row in rows)
    return {
        "total_cases": len(rows),
        "passed_count": sum(1 for row in rows if row["passed"]),
        "failed_count": sum(1 for row in rows if not row["passed"]),
        "root_cause_counts": dict(sorted(counts.items())),
        "rows": rows,
    }


def format_holdout_taxonomy_markdown(
    *,
    scripted_report: dict[str, Any],
    scripted_taxonomy: dict[str, Any],
    live_report: dict[str, Any] | None = None,
    live_taxonomy: dict[str, Any] | None = None,
    title: str = "IC Copilot Holdout Eval Report",
) -> str:
    lines = [
        f"# {title}",
        "",
        "## Summary",
        "",
        f"- holdout_cases: {scripted_report.get('total_cases', 0)}",
        f"- scripted_useful: {scripted_report.get('useful_pass_count', 0)}/{scripted_report.get('total_cases', 0)}",
        f"- scripted_fallbacks: {scripted_report.get('fallback_count', 0)}",
        f"- scripted_wrong_owner: {scripted_report.get('wrong_owner_count', 0)}",
    ]
    if live_report is not None:
        lines.extend(
            [
                f"- live_useful: {live_report.get('useful_pass_count', 0)}/{live_report.get('total_cases', 0)}",
                f"- live_fallbacks: {live_report.get('fallback_count', 0)}",
                f"- live_wrong_owner: {live_report.get('wrong_owner_count', 0)}",
            ]
        )
    lines.extend(["", "## Scripted Cases", "", _case_table(scripted_report, scripted_taxonomy)])
    lines.extend(["", "## Scripted Failure Taxonomy", "", _taxonomy_counts(scripted_taxonomy)])
    if live_report is not None and live_taxonomy is not None:
        lines.extend(["", "## Live Cases", "", _case_table(live_report, live_taxonomy)])
        lines.extend(["", "## Live Failure Taxonomy", "", _taxonomy_counts(live_taxonomy)])
    lines.extend(
        [
            "",
            "## Candidate Learnings",
            "",
            "- Holdout failures are evaluation input only. No local_knowledge mutation was performed.",
            "- Any reusable learning should enter the existing Codex semantic compiler flow before application.",
            "",
            "## Architecture",
            "",
            "The simplified IncidentReadAndWhisper runtime spine remained unchanged. No Slack posting, paging, command execution, remediation, target scoring, blocker reselection, broad repair, fixture fallback, shadow path, or incident-specific branching was added.",
            "",
            "## Recommendation",
            "",
            "Runtime is safe to keep if deterministic validation passes. Investigate any live-only failures through prompt/actionability, verifier, context-pack, or knowledge-intake review as classified above.",
        ]
    )
    return "\n".join(lines) + "\n"


def _case_table(report: dict[str, Any], taxonomy: dict[str, Any]) -> str:
    tax_by_id = {row["fixture_id"]: row for row in taxonomy.get("rows", [])}
    lines = [
        "| Fixture | Status | Root cause | Should become | Move | Target | Diagnostics | SAY THIS | Reasons |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for case in report.get("cases", []):
        tax = tax_by_id.get(case.get("fixture_id"), {})
        diagnosis = case.get("run_diagnosis_summary") if isinstance(case.get("run_diagnosis_summary"), dict) else {}
        diagnosis_bits = [
            f"safe_but_weak={bool(diagnosis.get('safe_but_weak'))}",
            f"direct_ask={bool(diagnosis.get('direct_ask'))}",
            f"actionability={diagnosis.get('actionability_failure_category', 'none')}",
            f"no_safe={case.get('no_safe_wording_quality', diagnosis.get('no_safe_wording_quality', 'not_applicable'))}",
            f"dedup={bool(case.get('target_dedup_applied') or diagnosis.get('target_dedup_applied'))}",
            "move_norm={}->{}".format(
                case.get("move_normalized_from") or diagnosis.get("move_normalized_from") or "none",
                case.get("move_normalized_to") or diagnosis.get("move_normalized_to") or "none",
            ),
            f"answered={diagnosis.get('answered_open_loop_count', 0)}",
            f"unresolved={diagnosis.get('unresolved_open_loop_count', 0)}",
        ]
        lines.append(
            "| {fixture} | {status} | {root} | {should} | {move} | {target} | {diagnosis} | {say} | {reasons} |".format(
                fixture=_md(case.get("fixture_id")),
                status="PASS" if case.get("passed") else "FAIL",
                root=_md(tax.get("root_cause", "unknown")),
                should=_md(tax.get("should_become", "no action")),
                move=_md(case.get("move")),
                target=_md(", ".join(case.get("selected_target_names") or []) or "none"),
                diagnosis=_md("; ".join(diagnosis_bits)),
                say=_md(case.get("say_this")),
                reasons=_md(", ".join(case.get("reasons") or []) or "ok"),
            )
        )
    return "\n".join(lines)


def _taxonomy_counts(taxonomy: dict[str, Any]) -> str:
    rows = ["| Root cause | Count |", "|---|---:|"]
    for root_cause, count in taxonomy.get("root_cause_counts", {}).items():
        rows.append(f"| {_md(root_cause)} | {count} |")
    return "\n".join(rows)


def _md(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", "<br>")
