from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from statistics import mean
from typing import Literal

from pydantic import BaseModel, Field

from ic_copilot.runtime_config import load_product_runtime_config


Recommendation = Literal[
    "NOT_ENOUGH_SNIPPETS",
    "KEEP_TRIALING",
    "READY_FOR_PERSONAL_USE",
    "NEEDS_KNOWLEDGE_FIX",
    "NEEDS_PLANNER_FIX",
    "NEEDS_VERIFIER_FIX",
]
SAFETY_FAILURE_TAGS = {"unsafe", "stale_question", "fake_entity", "invalid_command", "historical_leakage"}
KNOWLEDGE_GAP_TAGS = {"wrong_owner", "unsupported_monitoring"}
PLANNER_GAP_TAGS = {"too_generic", "missed_blocker", "wrong_phase", "no_useful_output"}


class ProductTrialReport(BaseModel):
    total_runs: int = 0
    labeled_snippets: int = 0
    provider: str = "openai"
    model: str = "gpt-4.1-mini"
    usefulness_counts: dict[str, int] = Field(default_factory=dict)
    failure_tag_counts: dict[str, int] = Field(default_factory=dict)
    no_safe_recommendation: int = 0
    average_latency_ms: float | None = None
    p95_latency_ms: int | None = None
    top_recurring_blocker_categories: dict[str, int] = Field(default_factory=dict)
    top_local_knowledge_gaps: dict[str, int] = Field(default_factory=dict)
    recommendation: Recommendation
    reasons: list[str] = Field(default_factory=list)


def _connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _percentile(values: list[int], percentile: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((len(ordered) - 1) * percentile)))
    return ordered[index]


def build_product_trial_report(db_path: str | Path = ".ic_copilot/web.sqlite3") -> ProductTrialReport:
    config = load_product_runtime_config()
    path = Path(db_path)
    if not path.exists():
        return ProductTrialReport(
            provider=config.llm.provider,
            model=config.llm.model,
            recommendation="NOT_ENOUGH_SNIPPETS",
            reasons=["web run database not found"],
        )
    with _connect(path) as conn:
        runs = [dict(row) for row in conn.execute("SELECT * FROM runs").fetchall()]
        feedback = [dict(row) for row in conn.execute("SELECT * FROM feedback").fetchall()]
    usefulness_counts: dict[str, int] = {}
    failure_tag_counts: dict[str, int] = {}
    blocker_counts: dict[str, int] = {}
    knowledge_gap_counts: dict[str, int] = {}
    for row in feedback:
        usefulness_counts[row["usefulness"]] = usefulness_counts.get(row["usefulness"], 0) + 1
        for tag in json.loads(row.get("failure_tags_json") or "[]"):
            failure_tag_counts[tag] = failure_tag_counts.get(tag, 0) + 1
            if tag in KNOWLEDGE_GAP_TAGS:
                knowledge_gap_counts[tag] = knowledge_gap_counts.get(tag, 0) + 1
            if tag in PLANNER_GAP_TAGS or tag in SAFETY_FAILURE_TAGS:
                blocker_counts[tag] = blocker_counts.get(tag, 0) + 1
    latencies = [int(row["total_elapsed_ms"]) for row in runs if row.get("total_elapsed_ms") is not None]
    no_safe = sum(1 for row in runs if "no_safe_recommendation" in (row.get("final_output") or "").lower())
    recommendation, reasons = _recommendation(
        labeled_snippets=len({row["run_id"] for row in feedback}),
        usefulness_counts=usefulness_counts,
        failure_tag_counts=failure_tag_counts,
    )
    return ProductTrialReport(
        total_runs=len(runs),
        labeled_snippets=len({row["run_id"] for row in feedback}),
        provider=config.llm.provider,
        model=config.llm.model,
        usefulness_counts=usefulness_counts,
        failure_tag_counts=failure_tag_counts,
        no_safe_recommendation=no_safe,
        average_latency_ms=round(mean(latencies), 1) if latencies else None,
        p95_latency_ms=_percentile(latencies, 0.95),
        top_recurring_blocker_categories=dict(sorted(blocker_counts.items(), key=lambda item: item[1], reverse=True)[:5]),
        top_local_knowledge_gaps=dict(sorted(knowledge_gap_counts.items(), key=lambda item: item[1], reverse=True)[:5]),
        recommendation=recommendation,
        reasons=reasons,
    )


def _recommendation(
    labeled_snippets: int,
    usefulness_counts: dict[str, int],
    failure_tag_counts: dict[str, int],
) -> tuple[Recommendation, list[str]]:
    reasons: list[str] = []
    if labeled_snippets < 20:
        reasons.append("fewer than 20 labeled real/personal snippets")
        return "NOT_ENOUGH_SNIPPETS", reasons
    if any(failure_tag_counts.get(tag, 0) > 0 for tag in SAFETY_FAILURE_TAGS):
        reasons.append("one or more safety failure tags are present")
        return "NEEDS_VERIFIER_FIX", reasons
    if any(failure_tag_counts.get(tag, 0) > 0 for tag in KNOWLEDGE_GAP_TAGS):
        reasons.append("one or more local_knowledge gap tags are present")
        return "NEEDS_KNOWLEDGE_FIX", reasons
    useful = usefulness_counts.get("useful_as_is", 0) + usefulness_counts.get("useful_with_edit", 0)
    generic = usefulness_counts.get("safe_but_generic", 0)
    useful_rate = useful / labeled_snippets if labeled_snippets else 0.0
    generic_rate = generic / labeled_snippets if labeled_snippets else 0.0
    if useful_rate >= 0.6 and generic_rate <= 0.2:
        reasons.append("usefulness threshold met with no safety labels")
        return "READY_FOR_PERSONAL_USE", reasons
    if useful_rate < 0.6:
        reasons.append("useful_as_is + useful_with_edit is below 60%")
    if generic_rate > 0.2:
        reasons.append("safe_but_generic is above 20%")
    if useful_rate < 0.4 or failure_tag_counts.get("missed_blocker", 0) or failure_tag_counts.get("too_generic", 0):
        return "NEEDS_PLANNER_FIX", reasons
    return "KEEP_TRIALING", reasons


def format_product_trial_report_md(report: ProductTrialReport) -> str:
    lines = [
        "# Personal Product Trial Report",
        "",
        f"- provider: {report.provider}",
        f"- model: {report.model}",
        f"- total_runs: {report.total_runs}",
        f"- labeled_snippets: {report.labeled_snippets}",
        f"- recommendation: {report.recommendation}",
        f"- average_latency_ms: {report.average_latency_ms}",
        f"- p95_latency_ms: {report.p95_latency_ms}",
        f"- no_safe_recommendation: {report.no_safe_recommendation}",
        "",
        "## Usefulness",
        "",
    ]
    for key, value in sorted(report.usefulness_counts.items()):
        lines.append(f"- {key}: {value}")
    if not report.usefulness_counts:
        lines.append("- none")
    lines.extend(["", "## Failure Tags", ""])
    for key, value in sorted(report.failure_tag_counts.items()):
        lines.append(f"- {key}: {value}")
    if not report.failure_tag_counts:
        lines.append("- none")
    lines.extend(["", "## Top Recurring Blockers", ""])
    for key, value in sorted(report.top_recurring_blocker_categories.items()):
        lines.append(f"- {key}: {value}")
    if not report.top_recurring_blocker_categories:
        lines.append("- none")
    lines.extend(["", "## Top local_knowledge Gaps", ""])
    for key, value in sorted(report.top_local_knowledge_gaps.items()):
        lines.append(f"- {key}: {value}")
    if not report.top_local_knowledge_gaps:
        lines.append("- none")
    lines.extend(["", "## Reasons", ""])
    lines.extend(f"- {reason}" for reason in report.reasons)
    return "\n".join(lines) + "\n"


def write_product_trial_report(
    db_path: str | Path,
    output_md: str | Path,
    output_json: str | Path,
) -> ProductTrialReport:
    report = build_product_trial_report(db_path)
    json_path = Path(output_json)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(report.model_dump_json(indent=2))
    md_path = Path(output_md)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(format_product_trial_report_md(report))
    return report
