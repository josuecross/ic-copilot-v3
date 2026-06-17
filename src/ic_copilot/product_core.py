from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable, Literal


ProductCoreClass = Literal["product", "offline_curation", "dev_eval", "test", "docs", "unknown"]


PRODUCT_MODULES = {
    "src/ic_copilot/pipeline.py",
    "src/ic_copilot/runtime_config.py",
    "src/ic_copilot/runtime_resources.py",
    "src/ic_copilot/product_knowledge.py",
    "src/ic_copilot/llm/product_client.py",
    "src/ic_copilot/provider_health.py",
    "src/ic_copilot/runtime_diagnostics.py",
    "src/ic_copilot/error_sanitizer.py",
    "src/ic_copilot/env.py",
    "src/ic_copilot/incident_loader.py",
    "src/ic_copilot/input_processing.py",
    "src/ic_copilot/incident_brief.py",
    "src/ic_copilot/slack_turns.py",
    "src/ic_copilot/clean_context.py",
    "src/ic_copilot/extractor.py",
    "src/ic_copilot/schema_repair.py",
    "src/ic_copilot/state_merge.py",
    "src/ic_copilot/trigger.py",
    "src/ic_copilot/planner.py",
    "src/ic_copilot/semantic_intent.py",
    "src/ic_copilot/sharp_blocker.py",
    "src/ic_copilot/decision_repair.py",
    "src/ic_copilot/verifier.py",
    "src/ic_copilot/render.py",
    "src/ic_copilot/catalog.py",
    "src/ic_copilot/memory.py",
    "src/ic_copilot/storage.py",
    "src/ic_copilot/cli.py",
    "src/ic_copilot/web/app.py",
    "src/ic_copilot/web/pipeline_events.py",
    "src/ic_copilot/web/run_store.py",
    "src/ic_copilot/web/models.py",
    "src/ic_copilot/web/safety.py",
}

OFFLINE_CURATION_MARKERS = (
    "src/ic_copilot/artifacts/",
    "src/ic_copilot/previous_incident",
    "src/ic_copilot/calibration",
    "src/ic_copilot/remediation_plan.py",
    "src/ic_copilot/fixture_quality.py",
    "src/ic_copilot/private_corpus.py",
    "src/ic_copilot/personal_corpus/",
    "src/ic_copilot/corpus",
    "src/ic_copilot/review_queue",
    "src/ic_copilot/review_analysis.py",
    "src/ic_copilot/review_schema.py",
    "src/ic_copilot/reviewed_artifact_calibration.py",
)

DEV_EVAL_MARKERS = (
    "src/ic_copilot/shadow",
    "src/ic_copilot/prompt_variant",
    "src/ic_copilot/prompt_versions.py",
    "src/ic_copilot/reviewer_agreement.py",
    "src/ic_copilot/promotion_report.py",
    "src/ic_copilot/llm/fixture_client.py",
    "src/ic_copilot/llm/stub_client.py",
    "src/ic_copilot/llm/factory.py",
    "src/ic_copilot/llm/config.py",
    "scripts/dev/",
)

OFFLINE_SCRIPT_MARKERS = (
    "scripts/import_",
    "scripts/build_previous_incident",
    "scripts/run_previous_incident",
    "scripts/compare_previous_incident",
    "scripts/build_calibration",
    "scripts/check_calibration",
    "scripts/promote_artifact",
    "scripts/validate_artifact",
    "scripts/build_artifact",
    "scripts/run_reviewed_artifact",
    "scripts/build_product_memory_candidate_report.py",
    "scripts/build_personal_corpus.py",
    "scripts/export_personal_corpus_views.py",
)

DEV_SCRIPT_MARKERS = (
    "scripts/run_openai_shadow",
    "scripts/run_prompt_variant",
    "scripts/compare_prompt_variants.py",
    "scripts/run_openai_review_workflow.py",
    "scripts/run_openai_live_gate.py",
    "scripts/run_personal_shadow_calibration.py",
    "scripts/run_phase19_smoke.py",
)

PRODUCT_SCRIPT_NAMES = {
    "scripts/run_local_web.py",
    "scripts/check_product_provider.py",
    "scripts/run_product_smoke.py",
    "scripts/run_product_latency_smoke.py",
    "scripts/run_personal_product_trial_report.py",
    "scripts/run_personal_regression_eval.py",
    "scripts/run_acceptance_gate.py",
    "scripts/validate_fixture_shapes.py",
    "scripts/run_replay_eval.py",
    "scripts/audit_repo_conflicts.py",
    "scripts/audit_web_console.py",
    "scripts/bootstrap_product_knowledge.py",
}


def _normalize(path: Path) -> str:
    text = path.as_posix()
    if text.startswith("./"):
        text = text[2:]
    return text


def classify_module_path(path: Path) -> ProductCoreClass:
    rel = _normalize(path)
    parts = Path(rel).parts
    if parts and parts[0] == "tests":
        return "test"
    if parts and parts[0] == "docs":
        return "docs"
    if rel in PRODUCT_MODULES or rel in PRODUCT_SCRIPT_NAMES:
        return "product"
    if rel.startswith("scripts/dev/") or any(
        rel.startswith(marker) for marker in DEV_SCRIPT_MARKERS
    ):
        return "dev_eval"
    if any(rel.startswith(marker) for marker in OFFLINE_SCRIPT_MARKERS):
        return "offline_curation"
    if any(rel.startswith(marker) for marker in OFFLINE_CURATION_MARKERS):
        return "offline_curation"
    if any(rel.startswith(marker) for marker in DEV_EVAL_MARKERS):
        return "dev_eval"
    if parts and parts[0] == "scripts":
        return "offline_curation"
    if parts and parts[0] in {"README.md", "AGENTS.md"}:
        return "docs"
    if rel in {"README.md", "AGENTS.md"}:
        return "docs"
    return "unknown"


def product_core_report(paths: Iterable[Path]) -> dict:
    rows = [{"path": _normalize(path), "classification": classify_module_path(path)} for path in paths]
    counts = Counter(row["classification"] for row in rows)
    return {"counts": dict(sorted(counts.items())), "files": rows}
