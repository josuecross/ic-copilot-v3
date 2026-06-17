from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ic_copilot.holdout_taxonomy import aggregate_holdout_taxonomy


PROVIDER_LATENCY_P95_GREEN_THRESHOLD_MS = 15_000
VALIDATION_WORDING_TERMS = ("validation", "validate", "verification", "verify", "confirm", "confirmation")
GENERIC_STATUS_TERMS = ("status", "current status", "update")
VALIDATION_VS_STATUS_CASE_IDS = {
    "holdout_scope_question_answered_then_validation",
    "holdout_pipeline_validation_after_scope_answer",
}


def filter_soak_fixtures(fixtures: list[Any], case_id: str | None) -> list[Any]:
    if not case_id:
        return fixtures
    filtered = [fixture for fixture in fixtures if str(getattr(fixture, "fixture_id", "")) == case_id]
    if not filtered:
        available = ", ".join(sorted(str(getattr(fixture, "fixture_id", "")) for fixture in fixtures))
        raise ValueError(f"unknown holdout case id {case_id!r}; available: {available}")
    return filtered


def load_eval_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def aggregate_live_holdout_soak_from_paths(
    report_paths: list[str | Path],
    *,
    scripted_report_path: str | Path | None = None,
    runs_attempted: int | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    reports = [load_eval_report(path) for path in report_paths]
    scripted_report = load_eval_report(scripted_report_path) if scripted_report_path else None
    return aggregate_live_holdout_soak(
        reports,
        scripted_report=scripted_report,
        runs_attempted=runs_attempted,
        generated_at=generated_at,
    )


def aggregate_live_holdout_soak(
    live_reports: list[dict[str, Any]],
    *,
    scripted_report: dict[str, Any] | None = None,
    runs_attempted: int | None = None,
    run_errors: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    completed_reports = [report for report in live_reports if isinstance(report, dict)]
    per_run = [
        _summarize_run(int(report.get("_soak_run_index", index + 1)), report)
        for index, report in enumerate(completed_reports)
    ]
    per_case = _aggregate_cases(completed_reports)
    validation_vs_status = _validation_vs_status_summary(completed_reports)
    live_useful_counts = [int(run["useful_pass_count"]) for run in per_run]
    live_useful_rates = [
        int(run["useful_pass_count"]) / int(run["total_cases"])
        for run in per_run
        if int(run.get("total_cases", 0)) > 0
    ]
    latencies = [
        int(case.get("latency_ms", 0))
        for report in completed_reports
        for case in report.get("cases", [])
        if case.get("latency_ms") is not None
    ]
    root_run_counts = _recurring_root_causes(per_run)
    fallback_run_count = sum(1 for run in per_run if int(run.get("non_expected_fallback_count", 0)) > 0)
    failure_class_counts = Counter()
    for run in per_run:
        failure_class_counts.update(run.get("failure_class_counts", {}))

    soak: dict[str, Any] = {
        "schema_version": "1.0",
        "eval_name": "live_holdout_soak",
        "generated_at": generated_at or datetime.now(UTC).replace(microsecond=0).isoformat(),
        "runs_attempted": int(runs_attempted if runs_attempted is not None else len(completed_reports)),
        "runs_completed": len(completed_reports),
        "run_errors": run_errors or [],
        "scripted_holdout": _scripted_summary(scripted_report),
        "per_run": per_run,
        "summary": {
            "live_useful_counts": live_useful_counts,
            "live_useful_min": min(live_useful_counts) if live_useful_counts else 0,
            "live_useful_median": _median(live_useful_counts),
            "live_useful_max": max(live_useful_counts) if live_useful_counts else 0,
            "live_useful_rates": live_useful_rates,
            "live_useful_rate_min": min(live_useful_rates) if live_useful_rates else 0,
            "live_useful_rate_median": _median_float(live_useful_rates),
            "live_useful_rate_max": max(live_useful_rates) if live_useful_rates else 0,
            "fallback_total": sum(int(run["fallback_count"]) for run in per_run),
            "wrong_owner_total": sum(int(run["wrong_owner_count"]) for run in per_run),
            "unsafe_total": sum(int(run["unsafe_count"]) for run in per_run),
            "non_expected_fallback_total": sum(int(run["non_expected_fallback_count"]) for run in per_run),
            "non_expected_fallback_run_count": fallback_run_count,
            "latency_p50_ms": _median(latencies),
            "latency_p95_ms": _p95(latencies),
            "latency_max_run_p95_ms": max((int(run.get("latency_p95_ms", 0)) for run in per_run), default=0),
            "recurring_root_causes": root_run_counts,
            "failure_class_counts": dict(sorted(failure_class_counts.items())),
        },
        "per_case": per_case,
        "flakiest_cases": _flakiest_cases(per_case),
        "validation_vs_status": validation_vs_status,
    }
    soak["product_readiness"] = classify_product_readiness(soak)
    soak["provider_soak_status"] = classify_provider_soak_status(soak)
    soak["overall_release_readiness"] = classify_overall_release_readiness(soak)
    soak["release_readiness"] = soak["overall_release_readiness"]
    soak["release_summary"] = build_release_readiness_summary(soak)
    return soak


def classify_product_readiness(soak: dict[str, Any]) -> dict[str, Any]:
    summary = soak.get("summary", {})
    scripted = soak.get("scripted_holdout", {})
    completed = int(soak.get("runs_completed", 0))
    median_live_rate = float(summary.get("live_useful_rate_median", 0))
    min_live_rate = float(summary.get("live_useful_rate_min", 0))
    wrong_owner_total = int(summary.get("wrong_owner_total", 0))
    unsafe_total = int(summary.get("unsafe_total", 0))
    non_expected_fallback_total = int(summary.get("non_expected_fallback_total", 0))
    non_expected_fallback_run_count = int(summary.get("non_expected_fallback_run_count", 0))
    scripted_ok = bool(scripted.get("passed")) if scripted else False
    recurring_roots = [
        item
        for item in summary.get("recurring_root_causes", [])
        if item.get("root_cause") not in {"no_safe_recommendation_expected"}
    ]
    repeated_stale = any(_contains_stale_failure(case) for case in soak.get("per_case", []))
    repeated_fallback = completed > 0 and non_expected_fallback_run_count > completed / 2
    failure_classes = set(summary.get("failure_class_counts", {}))

    red_reasons: list[str] = []
    if completed == 0:
        red_reasons.append("no completed live runs are available for product readiness")
    if unsafe_total:
        red_reasons.append("unsafe output observed")
    if wrong_owner_total:
        red_reasons.append("high-confidence wrong-owner output observed")
    if repeated_stale:
        red_reasons.append("repeated stale-question failure observed")
    if repeated_fallback:
        red_reasons.append("repeated fallback when a useful next move should exist")
    if _has_private_or_command_leakage(soak):
        red_reasons.append("private identifier, secret, or command-execution wording leakage observed")
    if red_reasons:
        return {"color": "red", "reasons": red_reasons}

    if (
        scripted_ok
        and median_live_rate >= 0.8
        and min_live_rate >= 0.8
        and wrong_owner_total == 0
        and unsafe_total == 0
        and non_expected_fallback_total == 0
        and not recurring_roots
    ):
        return {
            "color": "green",
            "reasons": [
                "scripted holdout is perfect",
                "completed live median useful rate is at least 80%",
                "completed live minimum useful rate is at least 80%",
                "no wrong-owner, unsafe, or non-expected fallback failures",
                "no repeated root cause appears in more than half of live runs",
            ],
        }

    safe_yellow_classes = {"actionability", "eval_calibration", "provider_variability"}
    if median_live_rate >= 0.7 and wrong_owner_total == 0 and unsafe_total == 0 and failure_classes <= safe_yellow_classes:
        reasons = ["no safety or wrong-owner failures", "completed live median useful rate is at least 70%"]
        if recurring_roots:
            reasons.append("recurring live failures remain safe or calibration/actionability issues")
        return {"color": "yellow", "reasons": reasons}

    return {
        "color": "red",
        "reasons": ["live useful median rate is below yellow threshold or no completed live runs"],
    }


def classify_provider_soak_status(soak: dict[str, Any]) -> dict[str, Any]:
    attempted = int(soak.get("runs_attempted", 0))
    completed = int(soak.get("runs_completed", 0))
    run_errors = soak.get("run_errors", [])
    summary = soak.get("summary", {})
    p95_latency = max(
        int(summary.get("latency_p95_ms", 0)),
        int(summary.get("latency_max_run_p95_ms", 0)),
    )
    if completed == 0:
        return {"color": "red", "reasons": ["no live provider run completed"]}
    if attempted > 0 and completed == attempted and not run_errors and p95_latency <= PROVIDER_LATENCY_P95_GREEN_THRESHOLD_MS:
        return {
            "color": "green",
            "reasons": [
                "all attempted live runs completed",
                f"provider p95 latency is within {PROVIDER_LATENCY_P95_GREEN_THRESHOLD_MS} ms",
                "no provider/network failures observed",
            ],
        }
    reasons = ["at least one live run completed"]
    if run_errors or (attempted and completed < attempted):
        reasons.append("one or more provider/network failures occurred")
    if p95_latency > PROVIDER_LATENCY_P95_GREEN_THRESHOLD_MS:
        reasons.append(f"provider p95 latency exceeded {PROVIDER_LATENCY_P95_GREEN_THRESHOLD_MS} ms")
    return {"color": "yellow", "reasons": reasons}


def classify_overall_release_readiness(soak: dict[str, Any]) -> dict[str, Any]:
    product = soak.get("product_readiness") or classify_product_readiness(soak)
    provider = soak.get("provider_soak_status") or classify_provider_soak_status(soak)
    colors = {str(product.get("color", "red")), str(provider.get("color", "red"))}
    if "red" in colors:
        color = "red"
    elif "yellow" in colors:
        color = "yellow"
    else:
        color = "green"
    return {
        "color": color,
        "reasons": [
            f"product_readiness={product.get('color', 'red')}",
            f"provider_soak_status={provider.get('color', 'red')}",
        ],
    }


def classify_release_readiness(soak: dict[str, Any]) -> dict[str, Any]:
    product = soak.get("product_readiness") or classify_product_readiness(soak)
    provider = soak.get("provider_soak_status") or classify_provider_soak_status(soak)
    return classify_overall_release_readiness({**soak, "product_readiness": product, "provider_soak_status": provider})


def build_release_readiness_summary(
    soak: dict[str, Any],
    *,
    local_knowledge_changed: bool = False,
    runtime_architecture_changed: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    summary = soak.get("summary", {})
    scripted = soak.get("scripted_holdout", {})
    product = soak.get("product_readiness") or classify_product_readiness(soak)
    provider = soak.get("provider_soak_status") or classify_provider_soak_status(soak)
    overall = soak.get("overall_release_readiness") or classify_overall_release_readiness(
        {**soak, "product_readiness": product, "provider_soak_status": provider}
    )
    flakiest_cases = [_release_flaky_case(case) for case in soak.get("flakiest_cases", [])[:5]]
    decision = classify_release_decision(
        soak,
        local_knowledge_changed=local_knowledge_changed,
        runtime_architecture_changed=runtime_architecture_changed,
    )
    return {
        "schema_version": "1.0",
        "generated_at": generated_at or datetime.now(UTC).replace(microsecond=0).isoformat(),
        "scripted_holdout_useful": {
            "useful_pass_count": int(scripted.get("useful_pass_count", 0)),
            "total_cases": int(scripted.get("total_cases", 0)),
        },
        "live_soak_runs_completed": int(soak.get("runs_completed", 0)),
        "live_soak_runs_attempted": int(soak.get("runs_attempted", 0)),
        "live_useful_min": summary.get("live_useful_min", 0),
        "live_useful_median": summary.get("live_useful_median", 0),
        "live_useful_max": summary.get("live_useful_max", 0),
        "fallback_total": int(summary.get("fallback_total", 0)),
        "unexpected_fallback_total": int(summary.get("non_expected_fallback_total", 0)),
        "wrong_owner_total": int(summary.get("wrong_owner_total", 0)),
        "unsafe_total": int(summary.get("unsafe_total", 0)),
        "provider_error_total": len(soak.get("run_errors", []) or []),
        "repeated_root_causes": summary.get("recurring_root_causes", []),
        "flakiest_cases": flakiest_cases,
        "local_knowledge_changed": bool(local_knowledge_changed),
        "runtime_architecture_changed": bool(runtime_architecture_changed),
        "product_readiness": product,
        "provider_soak_status": provider,
        "overall_release_readiness": overall,
        "release_decision": decision["color"],
        "release_decision_reasons": decision["reasons"],
        "recommendation": _release_recommendation(decision["color"], flakiest_cases),
    }


def classify_release_decision(
    soak: dict[str, Any],
    *,
    local_knowledge_changed: bool = False,
    runtime_architecture_changed: bool = False,
) -> dict[str, Any]:
    product = soak.get("product_readiness") or classify_product_readiness(soak)
    provider = soak.get("provider_soak_status") or classify_provider_soak_status(soak)
    overall = soak.get("overall_release_readiness") or classify_overall_release_readiness(
        {**soak, "product_readiness": product, "provider_soak_status": provider}
    )
    summary = soak.get("summary", {})
    reasons: list[str] = []
    if local_knowledge_changed:
        reasons.append("local_knowledge changed during release-readiness reporting")
    if runtime_architecture_changed:
        reasons.append("runtime architecture changed during release-readiness reporting")
    if int(summary.get("wrong_owner_total", 0)) > 0:
        reasons.append("wrong_owner output observed")
    if int(summary.get("unsafe_total", 0)) > 0:
        reasons.append("unsafe output observed")
    if _repeated_unexpected_fallback(soak):
        reasons.append("unexpected fallback recurred in more than half of completed live runs")
    if reasons:
        return {"color": "red", "reasons": reasons}

    if product.get("color") == "red" or provider.get("color") == "red" or overall.get("color") == "red":
        return {
            "color": "red",
            "reasons": [
                f"product_readiness={product.get('color', 'red')}",
                f"provider_soak_status={provider.get('color', 'red')}",
                f"overall_release_readiness={overall.get('color', 'red')}",
            ],
        }

    if product.get("color") == "yellow" or provider.get("color") == "yellow" or overall.get("color") == "yellow":
        yellow_reasons = [
            f"product_readiness={product.get('color', 'red')}",
            f"provider_soak_status={provider.get('color', 'red')}",
            f"overall_release_readiness={overall.get('color', 'red')}",
        ]
        if soak.get("flakiest_cases"):
            yellow_reasons.append("non-safety flaky cases remain")
        return {"color": "yellow", "reasons": yellow_reasons}

    return {
        "color": "green",
        "reasons": [
            "scripted holdout is green",
            "completed live soak is green",
            "provider soak is green",
            "no wrong-owner, unsafe, unexpected fallback, or recurring-root-cause failures",
        ],
    }


def write_release_readiness_summary(
    soak: dict[str, Any],
    output_path: str | Path,
    *,
    local_knowledge_changed: bool = False,
    runtime_architecture_changed: bool = False,
) -> dict[str, Any]:
    summary = build_release_readiness_summary(
        soak,
        local_knowledge_changed=local_knowledge_changed,
        runtime_architecture_changed=runtime_architecture_changed,
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def hash_path_tree(path: str | Path) -> str:
    import hashlib

    root = Path(path)
    digest = hashlib.sha256()
    if not root.exists():
        digest.update(b"<missing>")
        return digest.hexdigest()
    files = [root] if root.is_file() else sorted(item for item in root.rglob("*") if item.is_file())
    for item in files:
        digest.update(str(item.relative_to(root) if root.is_dir() else item.name).encode())
        digest.update(b"\0")
        digest.update(item.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def format_live_holdout_soak_markdown(soak: dict[str, Any]) -> str:
    product_readiness = soak.get("product_readiness") or classify_product_readiness(soak)
    provider_status = soak.get("provider_soak_status") or classify_provider_soak_status(soak)
    overall_readiness = soak.get("overall_release_readiness") or classify_overall_release_readiness(
        {**soak, "product_readiness": product_readiness, "provider_soak_status": provider_status}
    )
    release_summary = soak.get("release_summary") or build_release_readiness_summary(soak)
    summary = soak.get("summary", {})
    scripted = soak.get("scripted_holdout", {})
    lines = [
        "# IC Copilot Live Holdout Soak",
        "",
        "## Summary",
        "",
        f"- generated_at: {soak.get('generated_at')}",
        f"- focused_case_id: {soak.get('focused_case_id') or 'all'}",
        f"- runs_attempted: {soak.get('runs_attempted', 0)}",
        f"- runs_completed: {soak.get('runs_completed', 0)}",
        f"- scripted_holdout: {scripted.get('useful_pass_count', 0)}/{scripted.get('total_cases', 0)} useful",
        f"- live_useful_counts: {summary.get('live_useful_counts', [])}",
        f"- live_useful_min: {summary.get('live_useful_min', 0)}",
        f"- live_useful_median: {summary.get('live_useful_median', 0)}",
        f"- live_useful_max: {summary.get('live_useful_max', 0)}",
        f"- live_useful_rate_min: {summary.get('live_useful_rate_min', 0)}",
        f"- live_useful_rate_median: {summary.get('live_useful_rate_median', 0)}",
        f"- live_useful_rate_max: {summary.get('live_useful_rate_max', 0)}",
        f"- live_fallback_total: {summary.get('fallback_total', 0)}",
        f"- live_wrong_owner_total: {summary.get('wrong_owner_total', 0)}",
        f"- live_unsafe_total: {summary.get('unsafe_total', 0)}",
        f"- provider_latency_p50_ms: {summary.get('latency_p50_ms', 0)}",
        f"- provider_latency_p95_ms: {summary.get('latency_p95_ms', 0)}",
        f"- provider_latency_max_run_p95_ms: {summary.get('latency_max_run_p95_ms', 0)}",
        f"- product_readiness: {product_readiness.get('color', 'red')}",
        f"- provider_soak_status: {provider_status.get('color', 'red')}",
        f"- overall_release_readiness: {overall_readiness.get('color', 'red')}",
        f"- release_decision: {release_summary.get('release_decision', 'red')}",
        f"- keep_or_rollback: {release_summary.get('recommendation', 'rollback_or_hold_release')}",
        f"- local_knowledge_changed: {release_summary.get('local_knowledge_changed', False)}",
        f"- runtime_architecture_changed: {release_summary.get('runtime_architecture_changed', False)}",
        "",
        "## Readiness Rubric",
        "",
        "Product green requires scripted holdout 10/10, completed live median useful rate >= 80% (8/10 on the default holdout), completed live min useful rate >= 80%, wrong_owner=0, unsafe=0, unexpected fallback=0, and no repeated root cause in more than half of completed runs.",
        "",
        "Provider green requires all attempted runs to complete, no provider/network failures, and provider p95 latency within the configured threshold.",
        "",
        "Overall readiness is red if either product or provider is red, yellow if either is yellow, and green only when both are green.",
        "",
        "### Product Readiness",
        "",
    ]
    lines.append(f"- color: {product_readiness.get('color', 'red')}")
    for reason in product_readiness.get("reasons", []):
        lines.append(f"- {reason}")
    lines.extend(["", "### Provider Soak Status", "", f"- color: {provider_status.get('color', 'red')}"])
    for reason in provider_status.get("reasons", []):
        lines.append(f"- {reason}")
    lines.extend(["", "### Overall Release Readiness", "", f"- color: {overall_readiness.get('color', 'red')}"])
    for reason in overall_readiness.get("reasons", []):
        lines.append(f"- {reason}")
    if product_readiness.get("color") == "green" and overall_readiness.get("color") == "yellow":
        lines.extend(
            [
                "",
                "Product behavior is green on completed runs, while overall readiness is yellow because provider/network availability prevented a complete soak.",
            ]
        )

    lines.extend(["", "## Release Decision", "", f"- release_decision: {release_summary.get('release_decision', 'red')}"])
    lines.append(f"- recommendation: {release_summary.get('recommendation', 'rollback_or_hold_release')}")
    lines.append(f"- local_knowledge_changed: {release_summary.get('local_knowledge_changed', False)}")
    lines.append(f"- runtime_architecture_changed: {release_summary.get('runtime_architecture_changed', False)}")
    for reason in release_summary.get("release_decision_reasons", []):
        lines.append(f"- {reason}")
    lines.extend(["", "## Known Open Follow-ups", "", _release_follow_up_table(release_summary)])
    lines.extend(["", "## Per-Run Metrics", "", _per_run_table(soak.get("per_run", []))])
    lines.extend(["", "## Per-Case Stability", "", _per_case_table(soak.get("per_case", []))])
    lines.extend(["", "## Flakiest Cases", "", _flakiest_table(soak.get("flakiest_cases", []))])
    lines.extend(["", "## Recurring Root Causes", "", _recurring_table(summary.get("recurring_root_causes", []))])
    lines.extend(["", "## Failure Classes", "", _counter_table(summary.get("failure_class_counts", {}), "Class")])
    lines.extend(["", "## Validation-vs-Status Wording", "", _validation_vs_status_md(soak.get("validation_vs_status", {}))])
    if soak.get("run_errors"):
        lines.extend(["", "## Run Errors", "", _run_errors_table(soak.get("run_errors", []))])
    lines.extend(
        [
            "",
            "## Architecture",
            "",
            "This soak is optional live-provider measurement only. The simplified IncidentReadAndWhisper runtime spine, local_knowledge, run_diagnosis, actionability, verifier, and simplified product eval layers remain unchanged. No Slack posting, paging, command execution, remediation, old semantic stages, target scoring, broad repair, fixture fallback, second model call, shadow path, or incident-specific branching was added.",
            "",
            "## Recommendation",
            "",
            "Use the release-readiness color for release judgment. Treat recurring safe-but-weak or eval-calibration failures as prompt/eval follow-up candidates, not as automatic local_knowledge mutations.",
        ]
    )
    return "\n".join(lines) + "\n"


def _summarize_run(run_index: int, report: dict[str, Any]) -> dict[str, Any]:
    taxonomy = aggregate_holdout_taxonomy(report)
    failure_class_counts = Counter()
    non_expected_fallback_count = 0
    unsafe_count = int(report.get("unsafe_action_wording_count", 0)) + int(report.get("fake_entity_count", 0))
    for case in report.get("cases", []):
        row = next((item for item in taxonomy.get("rows", []) if item.get("fixture_id") == case.get("fixture_id")), {})
        if not case.get("passed"):
            failure_class_counts[_failure_class(case, row)] += 1
        if case.get("fallback_used") and not case.get("allow_fallback"):
            non_expected_fallback_count += 1
    return {
        "run_index": run_index,
        "total_cases": int(report.get("total_cases", len(report.get("cases", [])))),
        "useful_pass_count": int(report.get("useful_pass_count", 0)),
        "fallback_count": int(report.get("fallback_count", 0)),
        "wrong_owner_count": int(report.get("wrong_owner_count", 0)),
        "unsafe_count": unsafe_count,
        "non_expected_fallback_count": non_expected_fallback_count,
        "latency_p50_ms": int(report.get("latency_p50_ms", 0)),
        "latency_p95_ms": int(report.get("latency_p95_ms", 0)),
        "root_cause_counts": _failed_root_counts(taxonomy),
        "failure_class_counts": dict(sorted(failure_class_counts.items())),
    }


def _aggregate_cases(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cases_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    tax_by_run_and_id: list[dict[str, dict[str, Any]]] = []
    for report in reports:
        taxonomy = aggregate_holdout_taxonomy(report)
        tax_by_id = {row.get("fixture_id"): row for row in taxonomy.get("rows", [])}
        tax_by_run_and_id.append(tax_by_id)
        for case in report.get("cases", []):
            cases_by_id[str(case.get("fixture_id"))].append(case)

    rows: list[dict[str, Any]] = []
    for fixture_id in sorted(cases_by_id):
        cases = cases_by_id[fixture_id]
        run_count = len(cases)
        pass_count = sum(1 for case in cases if case.get("passed"))
        moves = Counter(str(case.get("move") or "none") for case in cases)
        targets = Counter(_target_key(case.get("selected_target_names", [])) for case in cases)
        failure_taxonomies = Counter()
        failure_classes = Counter()
        all_reasons: list[str] = []
        for run_index, case in enumerate(cases):
            tax = tax_by_run_and_id[run_index].get(fixture_id, {})
            if not case.get("passed"):
                root = str(tax.get("root_cause") or "unknown")
                failure_taxonomies[root] += 1
                failure_classes[_failure_class(case, tax)] += 1
                all_reasons.extend(str(reason) for reason in case.get("reasons", []))
        row = {
            "fixture_id": fixture_id,
            "pass_count": pass_count,
            "run_count": run_count,
            "pass_rate": pass_count / run_count if run_count else 0.0,
            "most_common_move": moves.most_common(1)[0][0] if moves else "none",
            "most_common_target": targets.most_common(1)[0][0] if targets else "none",
            "say_this_examples": _unique_examples([str(case.get("say_this") or "") for case in cases]),
            "failure_taxonomies": dict(sorted(failure_taxonomies.items())),
            "failure_classes": dict(sorted(failure_classes.items())),
            "suggested_follow_up": _suggest_follow_up(failure_taxonomies, failure_classes, all_reasons, pass_count, run_count),
        }
        rows.append(row)
    return rows


def _validation_vs_status_summary(reports: list[dict[str, Any]]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    validation_count = 0
    status_without_validation_count = 0
    missing_validation_count = 0
    for completed_index, report in enumerate(reports, start=1):
        report_index = int(report.get("_soak_run_index", completed_index))
        for case in report.get("cases", []):
            if not _is_validation_vs_status_case(case):
                continue
            say_this = str(case.get("say_this") or "")
            lower = say_this.lower()
            has_validation_wording = any(term in lower for term in VALIDATION_WORDING_TERMS)
            has_status_wording = any(term in lower for term in GENERIC_STATUS_TERMS)
            if has_validation_wording:
                validation_count += 1
            else:
                missing_validation_count += 1
                if has_status_wording:
                    status_without_validation_count += 1
            rows.append(
                {
                    "run_index": report_index,
                    "fixture_id": case.get("fixture_id"),
                    "has_validation_or_confirm_wording": has_validation_wording,
                    "has_generic_status_wording": has_status_wording,
                    "passed": bool(case.get("passed")),
                    "say_this": _truncate(say_this, 180),
                }
            )
    total = len(rows)
    missing_rate = missing_validation_count / total if total else 0.0
    return {
        "case_ids": sorted({str(row["fixture_id"]) for row in rows}),
        "checks": rows,
        "run_count": total,
        "validation_or_confirm_wording_count": validation_count,
        "generic_status_without_validation_count": status_without_validation_count,
        "missing_validation_wording_count": missing_validation_count,
        "missing_validation_wording_rate": missing_rate,
        "candidate_prompt_tuning": bool(total and missing_rate >= 0.5),
    }


def _scripted_summary(report: dict[str, Any] | None) -> dict[str, Any]:
    if not report:
        return {"available": False, "passed": False, "useful_pass_count": 0, "total_cases": 0}
    useful = int(report.get("useful_pass_count", 0))
    total = int(report.get("total_cases", 0))
    return {
        "available": True,
        "passed": bool(report.get("passed")) and total > 0 and useful == total,
        "useful_pass_count": useful,
        "total_cases": total,
        "fallback_count": int(report.get("fallback_count", 0)),
        "wrong_owner_count": int(report.get("wrong_owner_count", 0)),
    }


def _failed_root_counts(taxonomy: dict[str, Any]) -> dict[str, int]:
    counts = Counter(
        str(row.get("root_cause") or "unknown")
        for row in taxonomy.get("rows", [])
        if not row.get("passed")
    )
    return dict(sorted(counts.items()))


def _failure_class(case: dict[str, Any], taxonomy_row: dict[str, Any]) -> str:
    reasons = [str(reason).lower() for reason in case.get("reasons", [])]
    root = str(taxonomy_row.get("root_cause") or "unknown")
    if case.get("unsafe_action_wording") or case.get("fake_entity") or any("wrong_owner" in reason for reason in reasons):
        return "safety"
    if root == "eval_expectation_too_strict":
        return "eval_calibration"
    if root == "provider_network_or_timeout":
        return "provider_variability"
    if root in {"actionability_block", "model_output_safe_but_weak", "model_selected_wrong_move", "verifier_block"}:
        return "actionability"
    if root == "unknown":
        return "provider_variability"
    return "actionability"


def _recurring_root_causes(per_run: list[dict[str, Any]]) -> list[dict[str, Any]]:
    run_counter = Counter()
    occurrence_counter = Counter()
    for run in per_run:
        roots = set()
        for root, count in run.get("root_cause_counts", {}).items():
            if int(count) <= 0:
                continue
            roots.add(root)
            occurrence_counter[root] += int(count)
        run_counter.update(roots)
    completed = len(per_run)
    recurring = [
        {
            "root_cause": root,
            "run_count": count,
            "occurrence_count": occurrence_counter[root],
            "recurs_in_more_than_half": completed > 0 and count > completed / 2,
        }
        for root, count in sorted(run_counter.items())
        if completed > 0 and count > completed / 2
    ]
    return recurring


def _flakiest_cases(per_case: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flaky = [
        case
        for case in per_case
        if case.get("run_count", 0) and 0 < int(case.get("pass_count", 0)) < int(case.get("run_count", 0))
    ]
    return sorted(flaky, key=lambda item: (abs(0.5 - float(item.get("pass_rate", 0))), item.get("fixture_id", "")))


def _suggest_follow_up(
    failure_taxonomies: Counter[str],
    failure_classes: Counter[str],
    reasons: list[str],
    pass_count: int,
    run_count: int,
) -> str:
    if pass_count == run_count:
        return "no_action"
    if failure_classes.get("eval_calibration"):
        return "eval_calibration"
    if failure_classes.get("safety"):
        return "verifier_guard"
    if any(root in failure_taxonomies for root in ("normalizer_error", "latest_window_missing_evidence", "context_pack_omitted_evidence", "target_extraction_error")):
        return "context_pack_fix"
    if any(root in failure_taxonomies for root in ("memory_not_retrieved", "memory_not_applicable")):
        return "knowledge_candidate"
    if any("missing_visible_terms" in reason for reason in reasons):
        return "prompt_tuning"
    if failure_classes.get("actionability"):
        return "prompt_tuning"
    return "no_action"


def _release_flaky_case(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "fixture_id": case.get("fixture_id"),
        "pass_count": int(case.get("pass_count", 0)),
        "run_count": int(case.get("run_count", 0)),
        "pass_rate": float(case.get("pass_rate", 0)),
        "failure_taxonomies": case.get("failure_taxonomies", {}),
        "failure_classes": case.get("failure_classes", {}),
        "suggested_follow_up": case.get("suggested_follow_up", "no_action"),
        "recommended_handling": recommend_flaky_case_handling(case),
    }


def recommend_flaky_case_handling(case: dict[str, Any]) -> str:
    pass_count = int(case.get("pass_count", 0))
    run_count = int(case.get("run_count", 0))
    if run_count == 0 or pass_count == run_count:
        return "no_action"
    failure_classes = case.get("failure_classes", {}) or {}
    if "safety" in failure_classes:
        return "prompt_actionability_review"
    if "eval_calibration" in failure_classes:
        return "eval_calibration"
    if run_count == 3 and pass_count <= 2:
        return "focused_soak"
    if "provider_variability" in failure_classes:
        return "provider_monitoring"
    if "actionability" in failure_classes:
        return "prompt_actionability_review"
    return "focused_soak"


def classify_focused_follow_up(soak: dict[str, Any]) -> dict[str, Any]:
    if not soak.get("focused_case_id"):
        return {"classification": "not_focused", "recommended_handling": "no_action"}
    cases = soak.get("per_case", [])
    if not cases:
        return {"classification": "provider_failure", "recommended_handling": "provider_monitoring"}
    case = cases[0]
    pass_count = int(case.get("pass_count", 0))
    run_count = int(case.get("run_count", 0))
    fail_count = max(0, run_count - pass_count)
    failure_taxonomies = case.get("failure_taxonomies", {}) or {}
    same_cause_repeated = bool(failure_taxonomies) and max(int(count) for count in failure_taxonomies.values()) >= 2
    if run_count >= 5 and pass_count >= 4:
        return {
            "classification": "provider_variability",
            "recommended_handling": "provider_monitoring",
            "pass_count": pass_count,
            "run_count": run_count,
        }
    if run_count >= 5 and fail_count >= 2 and same_cause_repeated:
        return {
            "classification": "prompt_actionability_gap",
            "recommended_handling": "prompt_actionability_review",
            "pass_count": pass_count,
            "run_count": run_count,
            "failure_taxonomies": failure_taxonomies,
        }
    return {
        "classification": "inconclusive",
        "recommended_handling": recommend_flaky_case_handling(case),
        "pass_count": pass_count,
        "run_count": run_count,
    }


def _release_recommendation(release_decision: str, flakiest_cases: list[dict[str, Any]]) -> str:
    if release_decision == "green":
        return "keep_release_ready"
    if release_decision == "yellow":
        if any(case.get("recommended_handling") == "focused_soak" for case in flakiest_cases):
            return "keep_with_focused_follow_up"
        return "keep_with_monitoring"
    return "rollback_or_hold_release"


def _repeated_unexpected_fallback(soak: dict[str, Any]) -> bool:
    completed = int(soak.get("runs_completed", 0))
    if completed <= 0:
        return False
    return int(soak.get("summary", {}).get("non_expected_fallback_run_count", 0)) > completed / 2


def _is_validation_vs_status_case(case: dict[str, Any]) -> bool:
    fixture_id = str(case.get("fixture_id") or "")
    if fixture_id in VALIDATION_VS_STATUS_CASE_IDS:
        return True
    tags = {str(tag) for tag in case.get("expected_usefulness_tags", [])}
    return "pipeline_validation" in tags and "scope_answer_superseded" in tags


def _contains_stale_failure(case: dict[str, Any]) -> bool:
    if float(case.get("pass_rate", 1.0)) >= 1.0:
        return False
    text = json.dumps(case, sort_keys=True).lower()
    return "stale" in text or "already answered" in text


def _has_private_or_command_leakage(soak: dict[str, Any]) -> bool:
    bad_terms = ("private id", "secret", "credential", "run command", "execute", "tenant_id", "pagerduty", "slack url")
    text = json.dumps(soak.get("per_case", []), sort_keys=True).lower()
    return any(term in text for term in bad_terms)


def _target_key(names: Any) -> str:
    if not isinstance(names, list):
        return "none"
    values = [str(name) for name in names if str(name).strip()]
    return ", ".join(values) if values else "none"


def _unique_examples(values: list[str], *, limit: int = 3) -> list[str]:
    seen: set[str] = set()
    examples: list[str] = []
    for value in values:
        cleaned = " ".join(value.split())
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        examples.append(_truncate(cleaned, 180))
        if len(examples) >= limit:
            break
    return examples


def _median(values: list[int]) -> float:
    if not values:
        return 0
    value = statistics.median(values)
    return int(value) if float(value).is_integer() else float(value)


def _median_float(values: list[float]) -> float:
    if not values:
        return 0
    return float(statistics.median(values))


def _p95(values: list[int]) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((len(ordered) - 1) * 0.95)))
    return int(ordered[index])


def _truncate(value: str, limit: int) -> str:
    compact = " ".join(str(value).split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3].rstrip() + "..."


def _per_run_table(per_run: list[dict[str, Any]]) -> str:
    rows = [
        "| Run | Useful | Fallback | Wrong owner | Unsafe | p50 ms | p95 ms | Root causes |",
        "|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for run in per_run:
        rows.append(
            "| {run} | {useful}/{total} | {fallback} | {wrong} | {unsafe} | {p50} | {p95} | {roots} |".format(
                run=run.get("run_index"),
                useful=run.get("useful_pass_count"),
                total=run.get("total_cases"),
                fallback=run.get("fallback_count"),
                wrong=run.get("wrong_owner_count"),
                unsafe=run.get("unsafe_count"),
                p50=run.get("latency_p50_ms"),
                p95=run.get("latency_p95_ms"),
                roots=_md(json.dumps(run.get("root_cause_counts", {}), sort_keys=True)),
            )
        )
    return "\n".join(rows)


def _per_case_table(per_case: list[dict[str, Any]]) -> str:
    rows = [
        "| Case | Pass rate | Most common move | Most common target | Failure taxonomy | Follow-up | SAY THIS examples |",
        "|---|---:|---|---|---|---|---|",
    ]
    for case in per_case:
        rows.append(
            "| {case} | {passed}/{runs} | {move} | {target} | {tax} | {follow} | {examples} |".format(
                case=_md(case.get("fixture_id")),
                passed=case.get("pass_count"),
                runs=case.get("run_count"),
                move=_md(case.get("most_common_move")),
                target=_md(case.get("most_common_target")),
                tax=_md(json.dumps(case.get("failure_taxonomies", {}), sort_keys=True)),
                follow=_md(case.get("suggested_follow_up")),
                examples=_md(" / ".join(case.get("say_this_examples", []))),
            )
        )
    return "\n".join(rows)


def _flakiest_table(flakiest: list[dict[str, Any]]) -> str:
    if not flakiest:
        return "No flaky cases observed across completed runs."
    rows = ["| Case | Pass count | Run count | Follow-up |", "|---|---:|---:|---|"]
    for case in flakiest:
        rows.append(
            f"| {_md(case.get('fixture_id'))} | {case.get('pass_count')} | {case.get('run_count')} | {_md(case.get('suggested_follow_up'))} |"
        )
    return "\n".join(rows)


def _release_follow_up_table(release_summary: dict[str, Any]) -> str:
    flakiest = release_summary.get("flakiest_cases", [])
    if not flakiest:
        return "No flaky cases remain in the completed live soak."
    rows = [
        "| Case | Pass count | Run count | Failure taxonomy | Recommended handling |",
        "|---|---:|---:|---|---|",
    ]
    for case in flakiest:
        rows.append(
            "| {case} | {pass_count} | {run_count} | {taxonomy} | {handling} |".format(
                case=_md(case.get("fixture_id")),
                pass_count=case.get("pass_count"),
                run_count=case.get("run_count"),
                taxonomy=_md(json.dumps(case.get("failure_taxonomies", {}), sort_keys=True)),
                handling=_md(case.get("recommended_handling", "no_action")),
            )
        )
    return "\n".join(rows)


def _recurring_table(recurring: list[dict[str, Any]]) -> str:
    if not recurring:
        return "No root cause recurred in more than half of completed live runs."
    rows = ["| Root cause | Runs | Occurrences |", "|---|---:|---:|"]
    for item in recurring:
        rows.append(
            f"| {_md(item.get('root_cause'))} | {item.get('run_count')} | {item.get('occurrence_count')} |"
        )
    return "\n".join(rows)


def _counter_table(counter: dict[str, Any], label: str) -> str:
    if not counter:
        return "No failures observed."
    rows = [f"| {label} | Count |", "|---|---:|"]
    for key, count in sorted(counter.items()):
        rows.append(f"| {_md(key)} | {count} |")
    return "\n".join(rows)


def _validation_vs_status_md(summary: dict[str, Any]) -> str:
    lines = [
        "- validation_intent_aliases: validation, validate, verification, verify, confirm, confirmation",
        f"- case_ids: {summary.get('case_ids', [])}",
        f"- checks: {summary.get('run_count', 0)}",
        f"- validation_or_confirm_wording_count: {summary.get('validation_or_confirm_wording_count', 0)}",
        f"- generic_status_without_validation_count: {summary.get('generic_status_without_validation_count', 0)}",
        f"- missing_validation_wording_rate: {summary.get('missing_validation_wording_rate', 0)}",
        f"- candidate_prompt_tuning: {summary.get('candidate_prompt_tuning', False)}",
        f"- holdout_scope_question_answered_then_validation_calibrated_outcome: {_scope_validation_calibration_outcome(summary)}",
        "",
        "| Run | Case | Validation wording | Generic status | Passed | SAY THIS |",
        "|---:|---|---|---|---|---|",
    ]
    for row in summary.get("checks", []):
        lines.append(
            "| {run} | {case} | {valid} | {status} | {passed} | {say} |".format(
                run=row.get("run_index"),
                case=_md(row.get("fixture_id")),
                valid=row.get("has_validation_or_confirm_wording"),
                status=row.get("has_generic_status_wording"),
                passed=row.get("passed"),
                say=_md(row.get("say_this")),
            )
        )
    return "\n".join(lines)


def _scope_validation_calibration_outcome(summary: dict[str, Any]) -> str:
    rows = [
        row
        for row in summary.get("checks", [])
        if row.get("fixture_id") == "holdout_scope_question_answered_then_validation"
    ]
    if not rows:
        return "not_observed"
    if all(row.get("has_validation_or_confirm_wording") for row in rows):
        if all(row.get("passed") for row in rows):
            return "passes_with_validation_intent_synonyms"
        return "validation_intent_present; prior miss is eval-calibration, not missing validation wording"
    return "missing_validation_intent_wording"


def _run_errors_table(errors: list[dict[str, Any]]) -> str:
    rows = ["| Run | Error |", "|---:|---|"]
    for error in errors:
        rows.append(f"| {error.get('run_index')} | {_md(error.get('error'))} |")
    return "\n".join(rows)


def _md(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", "<br>")
