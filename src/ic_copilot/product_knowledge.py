from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, ValidationError

from ic_copilot.catalog import load_command_registry, load_service_catalog
from ic_copilot.error_sanitizer import sanitize_provider_error
from ic_copilot.memory import load_decision_moments
from ic_copilot.runtime_config import load_product_runtime_config
from ic_copilot.schemas import (
    CommandRegistryEntry,
    DecisionMoment,
    ServiceCatalogEntry,
    StrictBaseModel,
)


PRODUCT_KNOWLEDGE_SETUP_MESSAGE = (
    "Product knowledge folder is missing or invalid. Run "
    "`python -m ic_copilot.cli validate-knowledge local_knowledge` or bootstrap it with "
    "`python scripts/bootstrap_product_knowledge.py --apply`."
)

SUPPORTED_KNOWLEDGE_STATUSES = {"externally_reviewed", "approved_for_product"}
SUPPORTED_MEMORY_STATUSES = {"approved", "human_reviewed", "externally_reviewed", "approved_for_product"}
REJECTED_MEMORY_STATUSES = {"draft", "raw_ai_extracted", "candidate_human_review_required", "rejected"}

SUPPORT_FILE_NAMES = (
    "verifier_regressions",
    "rejected_entities",
    "stale_question_patterns",
)

DANGEROUS_COMMAND_PATTERNS = (
    r"\brollback\b",
    r"\brestart\b",
    r"\bdeploy\b",
    r"\bdelete\b",
    r"\bscale\b",
    r"\bdisable\b",
    r"\btruncate\b",
    r"\bdrop\b",
    r"\bupdate\b",
    r"\binsert\b",
    r"\bcurl\s+-x\s+post\b",
    r"\bcurl\s+--data\b",
    r"\bkubectl\b",
    r"\baws\b",
    r"\bgcloud\b",
    r"\baz\b",
    r"\s&&\s",
    r"\s\|\|\s",
    r";\s*\S",
    r"`[^`]+`",
    r"\$\(",
)

UNSAFE_COMMAND_TYPE_TERMS = ("remediation", "write", "mutation", "execute", "deploy", "rollback")
SAFE_COMMAND_DANGER_LEVELS = {"read_only", "read_only_lookup", "manual_copy_read_only"}

SECRET_PATTERNS = (
    ("openai_key", re.compile(r"sk-[A-Za-z0-9_-]{10,}")),
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE)),
    ("authorization_header", re.compile(r"Authorization\s*[:=]\s*[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE)),
    ("cookie", re.compile(r"Cookie\s*[:=]\s*[^;\n]{24,}", re.IGNORECASE)),
    (
        "api_key_assignment",
        re.compile(
            r"\b(?:api[_-]?key|access_token|refresh_token|secret)\s*[:=]\s*[\"']?[A-Za-z0-9._~+/=-]{24,}",
            re.IGNORECASE,
        ),
    ),
)


class ProductKnowledgeError(RuntimeError):
    pass


class ProductKnowledgeManifestFiles(StrictBaseModel):
    service_catalog: str = "service_catalog.yaml"
    command_registry: str = "command_registry.yaml"
    decision_moments: str = "decision_moments.jsonl"
    verifier_regressions: str = "verifier_regressions.jsonl"
    rejected_entities: str = "rejected_entities.jsonl"
    stale_question_patterns: str = "stale_question_patterns.jsonl"


class ProductKnowledgeSafetyRules(StrictBaseModel):
    commands_manual_copy_only: bool = True
    no_command_execution: bool = True
    no_slack_posting: bool = True
    no_paging: bool = True
    no_remediation: bool = True
    historical_facts_require_current_evidence: bool = True


class ProductKnowledgeManifest(StrictBaseModel):
    schema_version: str = "1.0"
    knowledge_status: Literal["externally_reviewed", "approved_for_product"]
    runtime_usable: bool
    reviewed_by: str
    reviewed_at: str
    review_method: str
    files: ProductKnowledgeManifestFiles = Field(default_factory=ProductKnowledgeManifestFiles)
    safety_rules: ProductKnowledgeSafetyRules = Field(default_factory=ProductKnowledgeSafetyRules)


class ProductKnowledgeCounts(StrictBaseModel):
    services: int = 0
    commands: int = 0
    decision_moments: int = 0
    verifier_regressions: int = 0
    rejected_entities: int = 0
    stale_question_patterns: int = 0


class ProductKnowledgeFinding(StrictBaseModel):
    severity: Literal["info", "warning", "error"]
    category: str
    path: str | None = None
    message: str


class ProductKnowledgeValidationResult(StrictBaseModel):
    path: str
    passed: bool
    manifest_valid: bool = False
    runtime_usable: bool = False
    counts: ProductKnowledgeCounts = Field(default_factory=ProductKnowledgeCounts)
    findings: list[ProductKnowledgeFinding] = Field(default_factory=list)

    @property
    def errors(self) -> list[ProductKnowledgeFinding]:
        return [finding for finding in self.findings if finding.severity == "error"]

    @property
    def warnings(self) -> list[ProductKnowledgeFinding]:
        return [finding for finding in self.findings if finding.severity == "warning"]


class ProductKnowledgeStatus(StrictBaseModel):
    path: str
    exists: bool
    manifest_valid: bool
    runtime_usable: bool
    passed: bool
    counts: ProductKnowledgeCounts = Field(default_factory=ProductKnowledgeCounts)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ProductKnowledge(StrictBaseModel):
    path: str
    manifest: ProductKnowledgeManifest
    catalog: list[ServiceCatalogEntry]
    command_registry: list[CommandRegistryEntry]
    decision_moments: list[DecisionMoment]
    verifier_regressions: list[dict[str, Any]] = Field(default_factory=list)
    rejected_entities: list[dict[str, Any]] = Field(default_factory=list)
    stale_question_patterns: list[dict[str, Any]] = Field(default_factory=list)
    counts: ProductKnowledgeCounts = Field(default_factory=ProductKnowledgeCounts)


def _add(
    findings: list[ProductKnowledgeFinding],
    severity: Literal["info", "warning", "error"],
    category: str,
    path: Path | str | None,
    message: str,
) -> None:
    findings.append(
        ProductKnowledgeFinding(
            severity=severity,
            category=category,
            path=str(path) if path is not None else None,
            message=sanitize_provider_error(message),
        )
    )


def _is_forbidden_runtime_source(path: Path) -> bool:
    parts = set(path.parts)
    text = path.as_posix()
    return (
        "artifact_staging" in parts
        or ("corrections" in parts and "drafts" in parts)
        or "personal_corpus" in parts
        or ("data" in parts and "generated" in parts)
        or ("data" in parts and "dev_eval" in parts)
        or ("data" in parts and "corpus" in parts)
        or ("data" in parts and "prompt_variants" in parts)
        or any(part.startswith("ic_copilot_previous_incidents__") for part in parts)
        or ".ic_copilot/artifact_staging" in text
        or ".ic_copilot/personal_corpus" in text
    )


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: invalid JSONL: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: JSONL record must be an object")
        records.append(value)
    return records


def _scan_secrets(path: Path, findings: list[ProductKnowledgeFinding]) -> None:
    for file_path in sorted(item for item in path.rglob("*") if item.is_file()):
        if file_path.suffix in {".sqlite3", ".db", ".pyc"}:
            continue
        try:
            text = file_path.read_text(errors="ignore")
        except Exception:
            continue
        for category, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                _add(
                    findings,
                    "error",
                    "secret_detected",
                    file_path,
                    f"Secret-like value detected in product knowledge file ({category}); value redacted.",
                )


def _command_is_dangerous(command: CommandRegistryEntry) -> str | None:
    text = f"{command.command} {command.pattern or ''}".lower()
    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return pattern
    command_type = (command.command_type or "").lower()
    if any(term in command_type for term in UNSAFE_COMMAND_TYPE_TERMS):
        return f"unsafe command_type={command.command_type}"
    danger = (command.danger_level or "").lower()
    if danger and danger not in SAFE_COMMAND_DANGER_LEVELS:
        return f"unsafe danger_level={command.danger_level}"
    return None


def _validate_commands(
    commands: list[CommandRegistryEntry],
    findings: list[ProductKnowledgeFinding],
    path: Path,
) -> None:
    for command in commands:
        if not command.requires_human_approval:
            _add(
                findings,
                "error",
                "command_requires_human_approval",
                path,
                f"Command must require human approval/manual copy only: {command.command}",
            )
        dangerous = _command_is_dangerous(command)
        if dangerous:
            _add(
                findings,
                "error",
                "dangerous_command",
                path,
                f"Command is not allowed in product knowledge ({dangerous}): {command.command}",
            )


def _validate_decision_moments(
    moments: list[DecisionMoment],
    findings: list[ProductKnowledgeFinding],
    path: Path,
) -> None:
    for moment in moments:
        if moment.review_status in REJECTED_MEMORY_STATUSES or moment.review_status not in SUPPORTED_MEMORY_STATUSES:
            _add(
                findings,
                "error",
                "decision_moment_review_status",
                path,
                f"DecisionMoment {moment.decision_id} is not approved for product runtime.",
            )
        if not moment.applicability:
            _add(
                findings,
                "error",
                "decision_moment_applicability",
                path,
                f"DecisionMoment {moment.decision_id} must include applicability/use_when/do_not_use_when.",
            )
        if moment.forbidden_fact_leakage is None:
            _add(
                findings,
                "error",
                "decision_moment_forbidden_fact_leakage",
                path,
                f"DecisionMoment {moment.decision_id} must include forbidden_fact_leakage.",
            )


def validate_product_knowledge(path: str | Path = "local_knowledge") -> ProductKnowledgeValidationResult:
    root = Path(path)
    findings: list[ProductKnowledgeFinding] = []
    counts = ProductKnowledgeCounts()

    if _is_forbidden_runtime_source(root):
        _add(
            findings,
            "error",
            "forbidden_runtime_source",
            root,
            "Product runtime may not load knowledge from curation, draft, generated, or previous-package sources.",
        )

    if not root.exists():
        _add(findings, "error", "missing_knowledge_folder", root, PRODUCT_KNOWLEDGE_SETUP_MESSAGE)
        return ProductKnowledgeValidationResult(path=str(root), passed=False, counts=counts, findings=findings)
    if not root.is_dir():
        _add(findings, "error", "knowledge_path_not_directory", root, "Product knowledge path must be a directory.")
        return ProductKnowledgeValidationResult(path=str(root), passed=False, counts=counts, findings=findings)

    _scan_secrets(root, findings)

    manifest_path = root / "manifest.yaml"
    manifest: ProductKnowledgeManifest | None = None
    manifest_valid = False
    runtime_usable = False
    if not manifest_path.exists():
        _add(findings, "error", "missing_manifest", manifest_path, "Product knowledge manifest.yaml is required.")
    else:
        try:
            manifest = ProductKnowledgeManifest.model_validate(yaml.safe_load(manifest_path.read_text()) or {})
            manifest_valid = True
            runtime_usable = manifest.runtime_usable
        except (ValidationError, ValueError, yaml.YAMLError) as exc:
            _add(findings, "error", "invalid_manifest", manifest_path, f"Invalid manifest: {exc}")

    if manifest is not None:
        if manifest.schema_version != "1.0":
            _add(findings, "error", "unsupported_schema_version", manifest_path, "Only schema_version 1.0 is supported.")
        if not manifest.runtime_usable:
            _add(findings, "error", "runtime_usable_false", manifest_path, "runtime_usable must be true.")
        if manifest.knowledge_status not in SUPPORTED_KNOWLEDGE_STATUSES:
            _add(
                findings,
                "error",
                "knowledge_status_not_reviewed",
                manifest_path,
                "knowledge_status must be externally_reviewed or approved_for_product.",
            )
        if not manifest.reviewed_by.strip() or not manifest.reviewed_at.strip() or not manifest.review_method.strip():
            _add(
                findings,
                "error",
                "missing_review_metadata",
                manifest_path,
                "reviewed_by, reviewed_at, and review_method are required.",
            )
        for key, value in manifest.safety_rules.model_dump().items():
            if value is not True:
                _add(findings, "error", "unsafe_manifest_safety_rule", manifest_path, f"safety_rules.{key} must be true.")

        files = manifest.files.model_dump()
        for logical_name, rel_path in files.items():
            file_path = root / rel_path
            if not file_path.exists():
                _add(findings, "error", "missing_required_file", file_path, f"Required file missing: {logical_name}.")

        catalog_path = root / manifest.files.service_catalog
        command_path = root / manifest.files.command_registry
        memory_path = root / manifest.files.decision_moments

        catalog: list[ServiceCatalogEntry] = []
        if catalog_path.exists():
            try:
                catalog = load_service_catalog(catalog_path)
                counts.services = len(catalog)
            except Exception as exc:
                _add(findings, "error", "invalid_service_catalog", catalog_path, f"Service catalog failed to load: {exc}")

        if command_path.exists():
            try:
                commands = load_command_registry(command_path, catalog)
                counts.commands = len(commands)
                _validate_commands(commands, findings, command_path)
            except Exception as exc:
                _add(
                    findings,
                    "error",
                    "invalid_command_registry",
                    command_path,
                    f"Command registry failed to load: {exc}",
                )

        if memory_path.exists():
            try:
                moments = load_decision_moments(memory_path)
                counts.decision_moments = len(moments)
                _validate_decision_moments(moments, findings, memory_path)
            except Exception as exc:
                _add(findings, "error", "invalid_decision_moments", memory_path, f"DecisionMoment memory failed: {exc}")

        for logical_name in SUPPORT_FILE_NAMES:
            support_path = root / getattr(manifest.files, logical_name)
            if not support_path.exists():
                continue
            try:
                records = _read_jsonl(support_path)
                setattr(counts, logical_name, len(records))
            except Exception as exc:
                _add(findings, "error", f"invalid_{logical_name}", support_path, f"{logical_name} failed to load: {exc}")

    passed = not any(finding.severity == "error" for finding in findings)
    return ProductKnowledgeValidationResult(
        path=str(root),
        passed=passed,
        manifest_valid=manifest_valid,
        runtime_usable=runtime_usable,
        counts=counts,
        findings=findings,
    )


def load_product_knowledge(path: str | Path = "local_knowledge") -> ProductKnowledge:
    validation = validate_product_knowledge(path)
    if not validation.passed:
        errors = "; ".join(finding.message for finding in validation.errors[:5]) or PRODUCT_KNOWLEDGE_SETUP_MESSAGE
        raise ProductKnowledgeError(f"{PRODUCT_KNOWLEDGE_SETUP_MESSAGE} {errors}")

    root = Path(path)
    manifest = ProductKnowledgeManifest.model_validate(yaml.safe_load((root / "manifest.yaml").read_text()) or {})
    catalog = load_service_catalog(root / manifest.files.service_catalog)
    command_registry = load_command_registry(root / manifest.files.command_registry, catalog)
    decision_moments = load_decision_moments(root / manifest.files.decision_moments)
    verifier_regressions = _read_jsonl(root / manifest.files.verifier_regressions)
    rejected_entities = _read_jsonl(root / manifest.files.rejected_entities)
    stale_question_patterns = _read_jsonl(root / manifest.files.stale_question_patterns)
    return ProductKnowledge(
        path=str(root),
        manifest=manifest,
        catalog=catalog,
        command_registry=command_registry,
        decision_moments=decision_moments,
        verifier_regressions=verifier_regressions,
        rejected_entities=rejected_entities,
        stale_question_patterns=stale_question_patterns,
        counts=validation.counts,
    )


def product_knowledge_status(path: str | Path = "local_knowledge") -> dict[str, Any]:
    root = Path(path)
    validation = validate_product_knowledge(root)
    status = ProductKnowledgeStatus(
        path=str(root),
        exists=root.exists(),
        manifest_valid=validation.manifest_valid,
        runtime_usable=validation.runtime_usable,
        passed=validation.passed,
        counts=validation.counts,
        errors=[finding.message for finding in validation.errors],
        warnings=[finding.message for finding in validation.warnings],
    )
    return status.model_dump(mode="json")


def find_product_knowledge_path(config_path: str | Path | None = None) -> Path:
    config = load_product_runtime_config(config_path)
    return Path(config.product_knowledge_path)
