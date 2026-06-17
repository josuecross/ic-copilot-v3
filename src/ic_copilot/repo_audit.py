from __future__ import annotations

import json
import re
import shutil
import ast
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ic_copilot.product_core import classify_module_path


class RepoAuditFinding(BaseModel):
    finding_id: str
    severity: Literal["info", "warning", "error"]
    category: str
    path: str
    line: int | None = None
    message: str
    recommended_action: str


class RepoAuditResult(BaseModel):
    passed: bool
    findings: list[RepoAuditFinding] = Field(default_factory=list)
    scanned_files: int = 0
    ignored_files: list[str] = Field(default_factory=list)


IGNORED_DIRS = {
    ".git",
    ".venv",
    ".ic_copilot",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "dev_archive",
    "ic_copilot_previous_incidents__try_20260523_193347__fixture_package",
}
ALLOWED_NORMALIZER_PATH_PARTS = {
    "src/ic_copilot/incident_loader.py",
    "src/ic_copilot/normalizers",
}
FORBIDDEN_DEPENDENCIES = (
    "neo4j",
    "chromadb",
    "qdrant_client",
    "dspy",
    "langgraph",
)
AUTO_ACTION_NAMES = (
    "auto_page",
    "execute_command",
    "remediate",
    "post_to_slack",
    "write_pagerduty",
    "write_incident_io",
)
DEV_DOC_PREFIXES = ("docs/dev_archive/",)


def _iter_files(root: Path, include_tests: bool = False):
    ignored: list[str] = []
    files: list[Path] = []
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        rel_text = rel.as_posix()
        if any(part in IGNORED_DIRS for part in rel.parts):
            if path.is_file():
                ignored.append(rel_text)
            continue
        if not include_tests and (rel.parts and rel.parts[0] == "tests"):
            continue
        if path.is_file() and path.suffix in {".py", ".md", ".yaml", ".yml", ".json", ".toml", ".txt"}:
            files.append(path)
    return files, ignored


def _line_number(text: str, pattern: str) -> int | None:
    for index, line in enumerate(text.splitlines(), start=1):
        if pattern in line:
            return index
    return None


def _add(
    findings: list[RepoAuditFinding],
    severity: str,
    category: str,
    path: Path,
    root: Path,
    message: str,
    action: str,
    line: int | None = None,
) -> None:
    findings.append(
        RepoAuditFinding(
            finding_id=f"{category}:{len(findings) + 1}",
            severity=severity,  # type: ignore[arg-type]
            category=category,
            path=path.relative_to(root).as_posix() if path.is_absolute() else path.as_posix(),
            line=line,
            message=message,
            recommended_action=action,
        )
    )


def _is_allowed_normalizer_path(rel: str) -> bool:
    return any(rel == allowed or rel.startswith(f"{allowed}/") for allowed in ALLOWED_NORMALIZER_PATH_PARTS)


def _is_dev_archive_doc(rel: str) -> bool:
    return rel.startswith(DEV_DOC_PREFIXES)


def _has_product_shadow_import(text: str) -> bool:
    return bool(
        re.search(
            r"^\s*(?:from\s+ic_copilot\.(?:shadow|shadow_evals|shadow_artifacts|prompt_variant|prompt_versions)"
            r"|import\s+ic_copilot\.(?:shadow|shadow_evals|shadow_artifacts|prompt_variant|prompt_versions))\b",
            text,
            re.M,
        )
    )


def _allowed_explicit_fixture_reference(rel: str) -> bool:
    return rel in {"scripts/run_acceptance_gate.py"}


PRODUCT_IMPORT_ENTRYPOINTS = (
    "ic_copilot.pipeline",
    "ic_copilot.cli",
    "ic_copilot.web.app",
    "ic_copilot.web.pipeline_events",
)
FORBIDDEN_PRODUCT_IMPORT_PREFIXES = (
    "ic_copilot.artifacts",
    "ic_copilot.personal_corpus",
    "ic_copilot.previous_incident",
    "ic_copilot.calibration",
    "ic_copilot.overlay",
    "ic_copilot.review_queue",
    "ic_copilot.review_analysis",
    "ic_copilot.reviewer_agreement",
    "ic_copilot.promotion_report",
    "ic_copilot.prompt_variant",
    "ic_copilot.prompt_versions",
    "ic_copilot.shadow",
    "ic_copilot.remediation_plan",
    "ic_copilot.fixture_quality",
    "ic_copilot.private_corpus",
    "ic_copilot.corpus",
    "ic_copilot.llm.fixture_client",
    "ic_copilot.llm.stub_client",
    "ic_copilot.llm.factory",
)


def _module_name_for_path(root: Path, path: Path) -> str | None:
    try:
        rel = path.relative_to(root / "src")
    except ValueError:
        return None
    if rel.suffix != ".py":
        return None
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _local_imports(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except SyntaxError:
        return set()
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("ic_copilot."):
                    imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.startswith("ic_copilot."):
                imports.add(module)
    return imports


def _module_to_path(root: Path, module: str) -> Path | None:
    if not module.startswith("ic_copilot"):
        return None
    rel = Path("src").joinpath(*module.split("."))
    candidates = (root / rel.with_suffix(".py"), root / rel / "__init__.py")
    for candidate in candidates:
        if candidate.exists():
            return candidate
    # `from ic_copilot.catalog import load_service_catalog` resolves to the parent module.
    while "." in module:
        module = module.rsplit(".", 1)[0]
        rel = Path("src").joinpath(*module.split("."))
        candidate = root / rel.with_suffix(".py")
        if candidate.exists():
            return candidate
    return None


def _reachable_product_modules(root: Path) -> tuple[set[str], dict[str, set[str]]]:
    module_paths = {
        module: path
        for path in (root / "src/ic_copilot").rglob("*.py")
        if (module := _module_name_for_path(root, path))
    }
    edges: dict[str, set[str]] = {}
    seen: set[str] = set()
    stack = list(PRODUCT_IMPORT_ENTRYPOINTS)
    while stack:
        module = stack.pop()
        if module in seen:
            continue
        seen.add(module)
        path = module_paths.get(module) or _module_to_path(root, module)
        if path is None:
            continue
        edges[module] = set()
        for imported in _local_imports(path):
            imported_path = _module_to_path(root, imported)
            if imported_path is None:
                edges[module].add(imported)
                continue
            imported_module = _module_name_for_path(root, imported_path)
            if imported_module:
                edges[module].add(imported_module)
                stack.append(imported_module)
    return seen, edges


def run_repo_audit(root: str | Path = ".", include_tests: bool = False) -> RepoAuditResult:
    source = Path(root).resolve()
    files, ignored = _iter_files(source, include_tests=include_tests)
    findings: list[RepoAuditFinding] = []
    for path in files:
        rel = path.relative_to(source).as_posix()
        text = path.read_text(errors="replace")
        classification = classify_module_path(Path(rel))
        if path.suffix == ".py":
            audit_self = rel == "src/ic_copilot/repo_audit.py"
            if "normalize_slack_paste_file(" in text and not _is_allowed_normalizer_path(rel):
                if not audit_self:
                    _add(
                        findings,
                        "error",
                        "direct_slack_paste_runtime_path",
                        path,
                        source,
                        "Runtime incident input bypasses load_incident_events.",
                        "Route incident file loading through ic_copilot.incident_loader.load_incident_events.",
                        _line_number(text, "normalize_slack_paste_file("),
                    )
            if "def _incident_id_from_path" in text and not audit_self:
                _add(
                    findings,
                    "warning",
                    "direct_incident_id_from_path_duplicate",
                    path,
                    source,
                    "Private incident-id helper duplicates the shared loader helper.",
                    "Prefer ic_copilot.incident_loader.incident_id_from_path.",
                    _line_number(text, "def _incident_id_from_path"),
                )
            if ("input=str(request)" in text or "input = str(request)" in text) and not audit_self:
                _add(
                    findings,
                    "error",
                    "legacy_openai_stringified_request",
                    path,
                    source,
                    "OpenAI request appears to stringify the provider payload.",
                    "Use structured messages plus Pydantic/JSON-schema validation.",
                    _line_number(text, "input=str(request)") or _line_number(text, "input = str(request)"),
                )
            if "glob(\"*.yaml\")" in text and "jsonl" not in text.lower():
                category = "yaml_only_memory_loader" if "DecisionMoment" in text else "yaml_only_eval_loader"
                _add(
                    findings,
                    "error",
                    category,
                    path,
                    source,
                    "Loader appears to support YAML files only.",
                    "Support YAML, JSON, and JSONL in runtime loaders.",
                    _line_number(text, 'glob("*.yaml")'),
                )
            for dependency in FORBIDDEN_DEPENDENCIES:
                if re.search(rf"^\s*(?:import|from)\s+{re.escape(dependency)}\b", text, re.M):
                    _add(
                        findings,
                        "error",
                        "forbidden_runtime_dependencies",
                        path,
                        source,
                        f"Forbidden runtime dependency imported: {dependency}.",
                        "Remove forbidden dependency from runtime code.",
                    )
            if re.search(r"^\s*(?:import|from)\s+(?:openai|anthropic|google\.generativeai)\b", text, re.M):
                _add(
                    findings,
                    "error",
                    "direct_provider_import",
                    path,
                    source,
                    "Provider SDK imported at module import time.",
                    "Use lazy import inside explicit provider adapter call.",
                )
            for name in AUTO_ACTION_NAMES:
                if re.search(rf"def\s+{name}\s*\(", text):
                    _add(
                        findings,
                        "error",
                        "auto_action_functions",
                        path,
                        source,
                        f"Forbidden auto-action function exists: {name}.",
                        "Remove auto-action path or keep as explicit NotImplemented placeholder outside pipeline.",
                    )
            fixture_runtime_usage = re.search(
                r"^\s*(?:from\s+\S+\s+import\s+.*(?:FixtureLLMClient|ConfigurableStubLLMClient)"
                r"|import\s+.*(?:FixtureLLMClient|ConfigurableStubLLMClient))\b"
                r"|(?:FixtureLLMClient|ConfigurableStubLLMClient)\s*\(",
                text,
                re.M,
            )
            if classification == "product" and fixture_runtime_usage and not _allowed_explicit_fixture_reference(rel):
                _add(
                    findings,
                    "error",
                    "fixture_client_in_product_runtime",
                    path,
                    source,
                    "Product runtime module instantiates a fixture/stub LLM client.",
                    "Product paths must resolve a configured real provider or fail closed; fixtures are test/eval/dev only.",
                    _line_number(text, "FixtureLLMClient") or _line_number(text, "ConfigurableStubLLMClient"),
                )
            if classification == "product" and _has_product_shadow_import(text):
                _add(
                    findings,
                    "error",
                    "shadow_import_in_product_runtime",
                    path,
                    source,
                    "Product runtime imports shadow/prompt-variant developer tooling.",
                    "Move shadow/prompt-variant code to dev/eval tooling and keep normal product paths single-runtime.",
                )
            if classification == "product" and rel != "src/ic_copilot/pipeline.py" and "def run_pipeline(" in text:
                if "_shared_run_pipeline" not in text:
                    _add(
                        findings,
                        "error",
                        "duplicate_product_pipeline_orchestration",
                        path,
                        source,
                        "Product module defines a local run_pipeline instead of delegating to ic_copilot.pipeline.",
                        "Use the shared pipeline as the only normal product orchestration path.",
                        _line_number(text, "def run_pipeline("),
                    )
            if classification == "product":
                runtime_draft_reads = (
                    '".ic_copilot/artifact_staging"',
                    "'.ic_copilot/artifact_staging'",
                    '".ic_copilot/corrections/drafts"',
                    "'.ic_copilot/corrections/drafts'",
                    '".ic_copilot/personal_corpus"',
                    "'.ic_copilot/personal_corpus'",
                    '"data/generated"',
                    "'data/generated'",
                )
                if any(marker in text for marker in runtime_draft_reads) and rel in {
                    "src/ic_copilot/pipeline.py",
                }:
                    _add(
                        findings,
                        "error",
                        "draft_artifact_path_in_runtime_resources",
                        path,
                        source,
                        "Product runtime resources mention corpus, artifact staging, generated data, or correction draft paths.",
                        "Only base product data and reviewed overlay/memory paths may be runtime-loaded.",
                    )
            if classification == "product" and re.search(r"provider\s*:\s*(fixture|stub)", text, re.I):
                _add(
                    findings,
                    "error",
                    "fixture_provider_in_product_config",
                    path,
                    source,
                    "Product config path contains a fixture/stub provider mode.",
                    "Product runtime must use a configured real provider or fail closed.",
                )
            if (
                classification == "product"
                and any(token in text for token in ("primary_disabled", "shadow_enabled", "openai_shadow_enabled"))
            ):
                _add(
                    findings,
                    "error",
                    "product_runtime_mode_flag",
                    path,
                    source,
                    "Product runtime exposes shadow/disabled mode flags.",
                    "Keep shadow/dev flags out of the normal product path.",
                )
            if rel == "src/ic_copilot/web/models.py":
                forbidden_run_fields = (
                    "catalog_path",
                    "memory_path",
                    "command_registry_path",
                    "openai_shadow_enabled",
                    "openai_model",
                )
                if "class RunRequest" in text:
                    for field in forbidden_run_fields:
                        if re.search(rf"^\s+{field}\s*:", text, re.M):
                            _add(
                                findings,
                                "error",
                                "web_run_request_dev_field",
                                path,
                                source,
                                f"Default web RunRequest exposes non-product field: {field}.",
                                "Keep path/shadow overrides out of the normal product request model.",
                                _line_number(text, field),
                            )
        if rel in {"README.md", "AGENTS.md"} and "Phase 1.36C" not in text:
            _add(
                findings,
                "warning",
                "stale_docs_phase_label",
                path,
                source,
                "Current docs do not mention Phase 1.36C.",
                "Update docs with current phase status.",
            )
        if path.suffix in {".md", ".html", ".js"}:
            lowered = text.lower()
            if not _is_dev_archive_doc(rel):
                stale_phrases = (
                    "fixture remains authoritative",
                    "fixtures remain authoritative",
                    "current mvp uses deterministic fixtures",
                    "openai remains shadow-only for normal product",
                    "openai remains shadow-only",
                    "fixture mode remains authoritative",
                    "trusted fixture baseline",
                    "live providers disabled by default",
                    "make openai primary",
                    "enable ai",
                    "enable openai shadow",
                    "fixture baseline",
                    "product gui artifact curation",
                    "artifact curation is product gui behavior",
                    "promote reviewed artifacts from product gui",
                    "console stages artifact packages",
                    "console promotes reviewed artifacts",
                    "console lets you create correction drafts",
                    "calibration mode in product gui",
                    "mark reviewed as product action",
                    "developer path overrides",
                )
                for phrase in stale_phrases:
                    if phrase in lowered:
                        _add(
                            findings,
                            "error",
                            "stale_product_runtime_wording",
                            path,
                            source,
                            f"User-facing text contains stale product runtime wording: {phrase!r}.",
                            "Update product-facing docs/UI to describe the default verified real-LLM runtime.",
                            _line_number(lowered, phrase),
                        )

    reachable_modules, import_edges = _reachable_product_modules(source)
    for module in sorted(reachable_modules):
        for forbidden in FORBIDDEN_PRODUCT_IMPORT_PREFIXES:
            if module == forbidden or module.startswith(f"{forbidden}."):
                _add(
                    findings,
                    "error",
                    "forbidden_product_import_graph",
                    source / "src/ic_copilot",
                    source,
                    f"Product import graph reaches forbidden module {module}.",
                    "Remove legacy/dev/curation/shadow imports from the product spine.",
                )
    for importer, imports in sorted(import_edges.items()):
        for imported in sorted(imports):
            for forbidden in FORBIDDEN_PRODUCT_IMPORT_PREFIXES:
                if imported == forbidden or imported.startswith(f"{forbidden}."):
                    _add(
                        findings,
                        "error",
                        "forbidden_product_import_edge",
                        source / "src/ic_copilot",
                        source,
                        f"{importer} imports forbidden module {imported}.",
                    "Keep the product import graph limited to the Phase 1.36C product whitelist.",
                    )

    schema = source / "src/ic_copilot/schemas.py"
    if schema.exists():
        schema_text = schema.read_text()
        required_terms = (
            "ENGAGEMENT",
            "VERIFICATION",
            "CUSTOMER_COMMS",
            "REQUEST_MONITORING_SIGNAL",
            "WAIT_FOR_ACTIVE_WORK",
            "NO_SAFE_RECOMMENDATION",
        )
        missing = [term for term in required_terms if term not in schema_text]
        if missing:
            _add(
                findings,
                "error",
                "old_compact_schema_snapshot",
                schema,
                source,
                f"Schema is missing modern terms: {', '.join(missing)}.",
                "Use the current Phase 1.14 schema surface.",
            )

    prompts = source / "src/ic_copilot/llm/prompts.py"
    if prompts.exists():
        prompt_text = prompts.read_text()
        if "Allowed move values" not in prompt_text or "Do not invent a new move value" not in prompt_text:
            _add(
                findings,
                "error",
                "planner_prompt_missing_allowed_moves",
                prompts,
                source,
                "IC_PLANNER_PROMPT does not clearly list allowed canonical move values.",
                "List canonical ICMove values and instruct the model to put domain-specific labels in domain_intent.",
            )
        if "INCIDENT_BRIEF_PROMPT" not in prompt_text or "IncidentBrief" not in prompt_text:
            _add(
                findings,
                "error",
                "missing_incident_brief_prompt",
                prompts,
                source,
                "Prompts do not define the AI IncidentBrief extraction contract.",
                "Keep IncidentBrief as the central semantic product object.",
            )
        if "allowed_targets" not in prompt_text or "target_id" not in prompt_text:
            _add(
                findings,
                "error",
                "incident_brief_prompt_missing_allowed_targets",
                prompts,
                source,
                "Prompts do not require target IDs from the deterministic allowed target list.",
                "Tell IncidentBrief and planner prompts to choose targets only from allowed_targets.",
            )
        if "reporter/validator" not in prompt_text.lower() or "technical investigator" not in prompt_text.lower():
            _add(
                findings,
                "error",
                "planner_prompt_missing_role_targeting_rule",
                prompts,
                source,
                "IC_PLANNER_PROMPT does not clearly distinguish reporter/validator and technical investigator targeting.",
                "Tell the planner to ask technical investigators for status and reporters/validators for validation only.",
            )
        if "root cause analysis" not in prompt_text.lower() or "primary move" not in prompt_text.lower():
            _add(
                findings,
                "error",
                "planner_prompt_missing_premature_rca_rule",
                prompts,
                source,
                "IC_PLANNER_PROMPT does not block premature RCA asks while validation or mitigation is unresolved.",
                "Tell the planner to keep RCA as follow-up only after the main status/validation ask.",
            )
        if "do not ask for details again" not in prompt_text.lower():
            _add(
                findings,
                "error",
                "planner_prompt_missing_stale_details_rule",
                prompts,
                source,
                "IC_PLANNER_PROMPT does not clearly block stale researcher/details asks after a details link exists.",
                "Tell the planner to move to owner, exposure scope, containment, mitigation, or validation after details are provided.",
            )
        prompt_lower = prompt_text.lower()
        for prompt_name in (
            "CLEAN_TURN_LEDGER_PROMPT",
            "ACTOR_WORKSTREAM_LEDGER_PROMPT",
            "INCIDENT_FACT_LEDGER_PROMPT",
            "QUESTION_INTENT_LEDGER_PROMPT",
        ):
            if prompt_name not in prompt_text:
                _add(
                    findings,
                    "error",
                    "missing_parallel_semantic_read_prompt",
                    prompts,
                    source,
                    f"Prompts do not define {prompt_name}.",
                    "Keep Phase 1.36C typed semantic read prompts available for the product path.",
                )
        if "observations" not in prompt_lower or "proposed next actions" not in prompt_lower:
            _add(
                findings,
                "error",
                "planner_prompt_missing_observations_stale_rule",
                prompts,
                source,
                "IC_PLANNER_PROMPT does not block stale observations/proposed-actions asks after details are provided.",
                "Tell the planner not to ask for observations, context, or proposed next actions after a details link exists.",
            )

    pipeline = source / "src/ic_copilot/pipeline.py"
    if pipeline.exists():
        pipeline_text = pipeline.read_text()
        if (
            "parallel_semantic_read_incident_brief" not in pipeline_text
            and "latest_window_incident_brief_first" not in pipeline_text
        ) or "state_delta_status" not in pipeline_text:
            _add(
                findings,
                "error",
                "pipeline_missing_latest_window_first_mode",
                pipeline,
                source,
                "Product pipeline does not clearly use latest-window IncidentBrief before non-blocking StateDelta.",
                "Keep IncidentBrief latest-window mode as the operator-facing product path.",
            )
        if "run_parallel_semantic_read" not in pipeline_text or "reduce_ledgers_to_incident_brief" not in pipeline_text:
            _add(
                findings,
                "error",
                "pipeline_missing_parallel_semantic_read",
                pipeline,
                source,
                "Pipeline does not clearly run typed parallel semantic readers before IncidentBrief.",
                "Run clean-turn, actor/workstream, fact, and question ledgers before reducing to IncidentBrief.",
            )
        if "_emit_artifact" not in pipeline_text or "PipelineStepArtifact" not in pipeline_text:
            _add(
                findings,
                "error",
                "pipeline_missing_step_artifacts",
                pipeline,
                source,
                "Pipeline does not emit product-safe generated step artifacts.",
                "Record compact artifacts for normalization, semantic read, IncidentBrief, planner, verifier, repair, and rendering.",
            )
        if "full_context_enrichment_status" not in pipeline_text:
            _add(
                findings,
                "error",
                "pipeline_missing_non_blocking_full_context_enrichment",
                pipeline,
                source,
                "Pipeline does not record non-blocking full-context enrichment status.",
                "Full-context/StateDelta compatibility must not block product output.",
            )

    latency_script = source / "scripts/run_product_latency_smoke.py"
    if not latency_script.exists():
            _add(
                findings,
                "error",
                "missing_latency_smoke_script",
                latency_script,
                source,
                "Phase 1.36C latency smoke script is missing.",
                "Add scripts/run_product_latency_smoke.py for live bounded-runtime smoke reporting.",
            )

    verifier = source / "src/ic_copilot/verifier.py"
    if verifier.exists():
        verifier_text = verifier.read_text()
        if "DETAILS_REQUEST_INTENTS" not in verifier_text or "request_details_from_researcher" not in verifier_text:
            _add(
                findings,
                "error",
                "verifier_missing_details_request_family",
                verifier,
                source,
                "Verifier helper does not define the request_details_from_researcher details-request family.",
                "Keep stale details/request-observations matching centralized in verifier.py.",
            )

    pipeline = source / "src/ic_copilot/pipeline.py"
    if pipeline.exists():
        pipeline_text = pipeline.read_text()
        if "extract_incident_brief" not in pipeline_text or "build_allowed_targets" not in pipeline_text:
            _add(
                findings,
                "error",
                "pipeline_missing_incident_brief_spine",
                pipeline,
                source,
                "Product pipeline is not IncidentBrief-first.",
                "Build allowed targets, extract IncidentBrief, then plan and verify the ICDecision.",
            )
        if "incident_brief=incident_brief" not in pipeline_text or "allowed_targets=allowed_targets" not in pipeline_text:
            _add(
                findings,
                "error",
                "pipeline_does_not_pass_incident_brief_to_planner_verifier",
                pipeline,
                source,
                "Product pipeline does not pass IncidentBrief and allowed targets through planning/verifier/repair.",
                "Thread IncidentBrief and allowed_targets through planner, verifier, and repair.",
            )

    semantic_intent = source / "src/ic_copilot/semantic_intent.py"
    if not semantic_intent.exists():
        _add(
            findings,
            "error",
            "missing_semantic_intent_module",
            semantic_intent,
            source,
            "Semantic intent module is missing.",
            "Create semantic_intent.py so stale paraphrase detection is AI-assessed rather than regex-only.",
        )

    semantic_read = source / "src/ic_copilot/semantic_read.py"
    if not semantic_read.exists():
        _add(
            findings,
            "error",
            "missing_parallel_semantic_read_module",
            semantic_read,
            source,
            "Parallel semantic read module is missing.",
            "Create semantic_read.py for typed clean-turn, actor/workstream, fact, and question ledgers.",
        )

    slack_turns = source / "src/ic_copilot/slack_turns.py"
    if not slack_turns.exists():
        _add(
            findings,
            "error",
            "missing_slack_turn_reconstruction_module",
            slack_turns,
            source,
            "Slack turn reconstruction module is missing.",
            "Create slack_turns.py so collapsed Slack paste speaker turns can be reconstructed before clean context.",
        )

    sharp_blocker = source / "src/ic_copilot/sharp_blocker.py"
    if not sharp_blocker.exists():
        _add(
            findings,
            "error",
            "missing_sharp_blocker_module",
            sharp_blocker,
            source,
            "Sharp blocker module is missing.",
            "Create sharp_blocker.py so blocker selection is general and AI-assessed.",
        )

    rpcapd_fixture = source / "data/personal_regression/incidents/p3_rpcapd_billing_disk_full_static.txt"
    if not rpcapd_fixture.exists():
        _add(
            findings,
            "error",
            "missing_rpcapd_sharp_blocker_regression",
            rpcapd_fixture,
            source,
            "rpcapd-style sharp-blocker regression fixture is missing.",
            "Keep a sanitized fixture for rollback/disable/status-vs-customer-comms regression.",
        )

    anti_hardcode_paths = [
        source / "src/ic_copilot/incident_brief.py",
        source / "src/ic_copilot/clean_context.py",
        source / "src/ic_copilot/extractor.py",
        source / "src/ic_copilot/planner.py",
        source / "src/ic_copilot/verifier.py",
        source / "src/ic_copilot/semantic_intent.py",
        source / "src/ic_copilot/sharp_blocker.py",
        source / "src/ic_copilot/pipeline.py",
        source / "src/ic_copilot/llm/prompts.py",
    ]
    regression_terms = (
        "rpcapd",
        "extrahop",
        "billing tomcat",
        "balaji",
        "vinod",
        "csbx0001",
        "cm-31348",
        "sriram",
        "aditya",
        "trimble",
        "semrush",
        "srerev-1864",
        "ria-sandbox-rest",
        "elb health",
        "504 gateway",
        "revenue engineering",
        "revpro support",
        "dentsply",
        "srerev-1864",
        "q3xzuz7cgv3ew2",
        "p3_in-11009",
        "connection limit",
        "okta",
        "udemy",
        "nova",
        "apfl",
        "ora-00001",
        "in-11058",
        "in-10997",
        "subscriptionorderprocessed",
        "tenant 17474",
        "ecra-4509",
        "p3_in-11085",
    )
    for product_path in anti_hardcode_paths:
        if not product_path.exists():
            continue
        lowered = product_path.read_text(errors="replace").lower()
        for term in regression_terms:
            if term in lowered:
                _add(
                    findings,
                    "error",
                    "regression_specific_keyword_in_product_logic",
                    product_path,
                    source,
                    f"Product runtime contains regression-specific keyword: {term}.",
                    "Keep rpcapd/Extrahop/Billing-specific terms in fixtures/tests only; product logic must stay general.",
                )

    if verifier.exists():
        verifier_text = verifier.read_text()
        if "no_premature_rca" not in verifier_text or "role_target_aligned" not in verifier_text:
            _add(
                findings,
                "error",
                "verifier_missing_role_targeting_checks",
                verifier,
                source,
                "Verifier is missing no_premature_rca or role_target_aligned checks.",
                "Block premature RCA and wrong-role fix-status asks before rendering.",
            )

    repair = source / "src/ic_copilot/schema_repair.py"
    if repair.exists() and "request_details_from_researcher" not in repair.read_text():
        _add(
            findings,
            "error",
            "schema_repair_missing_security_move_alias",
            repair,
            source,
            "Schema repair does not normalize request_details_from_researcher.",
            "Map domain-specific security planner labels to canonical ICMove values.",
        )

    security_fixture = source / "data/personal_regression/incidents/p3_security_workflow_vulnerability_static.txt"
    if not security_fixture.exists():
        _add(
            findings,
            "error",
            "missing_security_workflow_regression",
            security_fixture,
            source,
            "Security workflow static regression fixture is missing.",
            "Keep a sanitized static regression for the security/workflow details-stale scenario.",
        )
    else:
        fixture_text = security_fixture.read_text().lower()
        if "observations" not in fixture_text or "proposed next actions" not in fixture_text:
            _add(
                findings,
                "error",
                "security_workflow_regression_missing_stale_paraphrase",
                security_fixture,
                source,
                "Security workflow regression fixture does not include stale observations/proposed-actions wording.",
                "Keep the exact Bimodh-style stale paraphrase in the sanitized static regression.",
            )

    security_tests = source / "tests/test_phase1261_security_move_robustness.py"
    if security_tests.exists():
        tests_text = security_tests.read_text().lower()
        if "provide your observations" not in tests_text or "say_this" not in tests_text:
            _add(
                findings,
                "error",
                "missing_say_this_stale_paraphrase_test",
                security_tests,
                source,
                "Product output tests do not cover stale observations/proposed-actions text in SAY THIS.",
                "Keep a regression for the exact stale Bimodh output in SAY THIS.",
            )

    gitignore = source / ".gitignore"
    required_ignores = (
        ".env",
        ".ic_copilot/",
        "data/private/",
        "local_corpus/",
        "local_knowledge/",
        "ic_copilot_previous_incidents__*/",
    )
    if gitignore.exists():
        ignore_text = gitignore.read_text()
        for item in required_ignores:
            if item not in ignore_text:
                _add(
                    findings,
                    "error",
                    "unignored_private_artifacts",
                    gitignore,
                    source,
                    f"Missing private/artifact ignore pattern: {item}.",
                    "Add ignore pattern before creating local/private artifacts.",
                )

    for name in ("cli.py", "schemas.py", "verifier.py", "planner.py", "memory.py", "shadow.py", "evals.py"):
        root_module = source / name
        if root_module.exists():
            _add(
                findings,
                "error",
                "duplicate_runtime_module",
                root_module,
                source,
                f"Root-level module shadows src/ic_copilot/{name}.",
                "Remove or rename stale root-level module.",
            )

    passed = not any(finding.severity == "error" for finding in findings)
    return RepoAuditResult(passed=passed, findings=findings, scanned_files=len(files), ignored_files=ignored)


def format_repo_audit_markdown(result: RepoAuditResult) -> str:
    lines = [
        "# IC Copilot Repo Audit",
        "",
        f"- passed: {result.passed}",
        f"- scanned_files: {result.scanned_files}",
        f"- findings: {len(result.findings)}",
        "",
    ]
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines)
    for finding in result.findings:
        loc = f"{finding.path}:{finding.line}" if finding.line else finding.path
        lines.extend(
            [
                f"## {finding.finding_id}",
                "",
                f"- severity: {finding.severity}",
                f"- category: {finding.category}",
                f"- location: {loc}",
                f"- message: {finding.message}",
                f"- recommended_action: {finding.recommended_action}",
                "",
            ]
        )
    return "\n".join(lines)


def save_repo_audit(result: RepoAuditResult, output_json: str | Path, output_md: str | Path) -> None:
    json_path = Path(output_json)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
    md_path = Path(output_md)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(format_repo_audit_markdown(result))


def apply_safe_cleanup(root: str | Path = ".") -> list[str]:
    source = Path(root)
    removed: list[str] = []
    for name in ("__pycache__", ".pytest_cache", ".ruff_cache"):
        for path in source.rglob(name):
            if path.is_dir():
                shutil.rmtree(path)
                removed.append(path.as_posix())
    return removed
