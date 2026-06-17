from __future__ import annotations

import json
import re
import shutil
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field

from ic_copilot.catalog import load_service_catalog
from ic_copilot.error_sanitizer import sanitize_provider_error
from ic_copilot.memory import _adapt_decision_moment
from ic_copilot.product_knowledge import SECRET_PATTERNS, validate_product_knowledge
from ic_copilot.schemas import DecisionMoment, ServiceCatalogEntry, StrictBaseModel
from ic_copilot.simplified_product_eval import SimplifiedProductEvalFixture


APPLY_RECORD_TYPES = {
    "decision_moment",
    "service_catalog_entry",
    "rejected_entity",
    "stale_question_pattern",
    "verifier_regression",
}

PROPOSED_JSONL_FILES = {
    "decision_moment": "decision_moments.proposed.jsonl",
    "rejected_entity": "rejected_entities.proposed.jsonl",
    "stale_question_pattern": "stale_question_patterns.proposed.jsonl",
    "verifier_regression": "verifier_regressions.proposed.jsonl",
    "eval_case": "eval_cases.proposed.jsonl",
}

REQUIRED_SOURCE_FILES = ("raw.sanitized.txt", "redaction_report.json", "source_hash.txt")
REQUIRED_PROPOSED_FILES = (
    "decision_moments.proposed.jsonl",
    "service_catalog.proposed.yaml",
    "rejected_entities.proposed.jsonl",
    "stale_question_patterns.proposed.jsonl",
    "verifier_regressions.proposed.jsonl",
    "eval_cases.proposed.jsonl",
)
REQUIRED_REVIEWED_FILES = ("review.yaml", "approved_records.jsonl", "rejected_records.jsonl")
REQUIRED_EXTRACTED_FILES = (
    "incident_learning.md",
    "candidate_patterns.md",
    "candidate_eval_scenarios.md",
    "reviewer_notes.md",
)
REQUIRED_CODEX_REVIEW_FILES = (
    "compile_plan.md",
    "approved_knowledge.md",
    "rejected_knowledge.md",
    "generated_records_preview.md",
)
IGNORED_BUNDLE_FILE_NAMES = {".DS_Store"}
ADVISORY_RELATIVE_DIRS = {"proposed", "extracted"}
ALLOWED_TOP_LEVEL = {"manifest.yaml", "source", "extracted", "proposed", "codex_review", "reviewed", "applied", "eval"}
ALLOWED_RELATIVE_DIRS = {"source", "extracted", "proposed", "codex_review", "reviewed", "applied", "eval"}
ALLOWED_RELATIVE_FILES = {
    "manifest.yaml",
    "source/raw.sanitized.txt",
    "source/redaction_report.json",
    "source/source_hash.txt",
    "extracted/incident_learning.md",
    "extracted/candidate_patterns.md",
    "extracted/candidate_eval_scenarios.md",
    "extracted/reviewer_notes.md",
    "proposed/decision_moments.proposed.jsonl",
    "proposed/service_catalog.proposed.yaml",
    "proposed/rejected_entities.proposed.jsonl",
    "proposed/stale_question_patterns.proposed.jsonl",
    "proposed/verifier_regressions.proposed.jsonl",
    "proposed/eval_cases.proposed.jsonl",
    "codex_review/compile_plan.md",
    "codex_review/approved_knowledge.md",
    "codex_review/rejected_knowledge.md",
    "codex_review/generated_records_preview.md",
    "codex_review/generated_eval_cases.jsonl",
    "reviewed/review.yaml",
    "reviewed/approved_records.jsonl",
    "reviewed/rejected_records.jsonl",
    "applied/apply_report.md",
    "applied/applied_records.jsonl",
    "eval/simplified_product_eval.json",
    "eval/simplified_product_eval.md",
}

STABLE_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{2,}$")
SAFE_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SLACK_URL_RE = re.compile(r"https?://[^\s\"']*slack\.com/[^\s\"']*", re.IGNORECASE)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
JIRA_TICKET_RE = re.compile(r"\b[A-Z][A-Z0-9]{1,10}-\d{2,}\b")
INCIDENT_ID_RE = re.compile(r"\b(?:INC|IN|PD|PAGERDUTY)[-_]?\d{3,}\b", re.IGNORECASE)
PAGERDUTY_ID_RE = re.compile(r"\bP[A-Z0-9]{6,}\b")
TENANT_ACCOUNT_RE = re.compile(
    r"\b(?:tenant|account|customer|org|organization|subscription)[ _-]?(?:id|number|num|#)?\s*[:=#-]?\s*\d{4,}\b",
    re.IGNORECASE,
)
LONG_NUMERIC_ID_RE = re.compile(r"(?<![A-Za-z0-9])\d{5,}(?![A-Za-z0-9])")
SOURCE_HASH_RE = re.compile(r"^(?:sha256:)?[a-fA-F0-9]{64}$")
UNIX_ABSOLUTE_PATH_RE = re.compile(r"(^|\s)/(?!/)[A-Za-z0-9._~/-]+")
WINDOWS_ABSOLUTE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
RAW_SOURCE_LINE_MIN_LENGTH = 40
CUSTOMER_IDENTIFIER_KEYS = {
    "account",
    "account_id",
    "account_name",
    "affected_account",
    "affected_accounts",
    "affected_customer",
    "affected_customers",
    "affected_tenant",
    "affected_tenants",
    "customer",
    "customer_id",
    "customer_name",
    "tenant",
    "tenant_id",
    "tenant_name",
}
GENERIC_CUSTOMER_VALUES = {
    "account",
    "account id",
    "account name",
    "affected account",
    "affected customer",
    "affected tenant",
    "customer",
    "customer communications",
    "customer impact",
    "customer support",
    "customers",
    "example account",
    "example customer",
    "example tenant",
    "redacted",
    "redacted_account",
    "redacted_customer",
    "redacted_tenant",
    "tenant",
    "tenant id",
    "tenant name",
    "tenants",
    "<account>",
    "<customer>",
    "<tenant>",
}
DESTINATION_FILES = {
    "decision_moment": "decision_moments.jsonl",
    "service_catalog_entry": "service_catalog.yaml",
    "rejected_entity": "rejected_entities.jsonl",
    "stale_question_pattern": "stale_question_patterns.jsonl",
    "verifier_regression": "verifier_regressions.jsonl",
}


class KnowledgeBundleFinding(StrictBaseModel):
    severity: Literal["info", "warning", "error"]
    category: str
    path: str | None = None
    message: str


class KnowledgeBundleCounts(StrictBaseModel):
    proposed_records: int = 0
    approved_records: int = 0
    rejected_records: int = 0
    eval_cases: int = 0
    apply_ready_records: int = 0


class KnowledgeBundleValidationResult(StrictBaseModel):
    path: str
    knowledge_dir: str
    passed: bool
    review_approved: bool = False
    counts: KnowledgeBundleCounts = Field(default_factory=KnowledgeBundleCounts)
    findings: list[KnowledgeBundleFinding] = Field(default_factory=list)

    @property
    def errors(self) -> list[KnowledgeBundleFinding]:
        return [finding for finding in self.findings if finding.severity == "error"]

    @property
    def warnings(self) -> list[KnowledgeBundleFinding]:
        return [finding for finding in self.findings if finding.severity == "warning"]


class KnowledgeBundleApplyResult(StrictBaseModel):
    path: str
    knowledge_dir: str
    passed: bool
    applied: bool
    dry_run: bool = False
    validation_passed: bool = False
    product_validation_passed: bool = False
    applied_count: int = 0
    skipped_count: int = 0
    applied_records_path: str | None = None
    apply_report_path: str | None = None
    record_results: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[KnowledgeBundleFinding] = Field(default_factory=list)


def validate_knowledge_bundle(
    bundle_path: str | Path,
    *,
    knowledge_dir: str | Path = "local_knowledge",
    require_review_approved: bool = False,
) -> KnowledgeBundleValidationResult:
    bundle = Path(bundle_path)
    target = Path(knowledge_dir)
    findings: list[KnowledgeBundleFinding] = []
    counts = KnowledgeBundleCounts()

    if not bundle.exists():
        _add(findings, "error", "missing_bundle", bundle, "Knowledge bundle folder is missing.")
        return _validation_result(bundle, target, findings, counts, review_approved=False)
    if bundle.is_symlink():
        _add(findings, "error", "symlink_bundle", bundle, "Knowledge bundle root must not be a symlink.")
        return _validation_result(bundle, target, findings, counts, review_approved=False)
    if not bundle.is_dir():
        _add(findings, "error", "bundle_not_directory", bundle, "Knowledge bundle path must be a directory.")
        return _validation_result(bundle, target, findings, counts, review_approved=False)

    _validate_path_safety(bundle, findings, label="bundle")
    _validate_directory_shape(bundle, findings)
    _scan_credential_patterns(bundle, findings)
    _validate_raw_source_isolated(bundle, findings)

    manifest = _read_yaml_checked(bundle / "manifest.yaml", findings)
    if manifest is not None and not isinstance(manifest, dict):
        _add(findings, "error", "invalid_manifest", bundle / "manifest.yaml", "Bundle manifest must be a YAML object.")
    elif isinstance(manifest, dict):
        _validate_manifest_metadata(bundle, manifest, findings)

    _validate_source_files(bundle, findings)
    _validate_eval_outputs(bundle, findings)
    proposed_records = _validate_proposed(bundle, findings, counts)
    review_approved = _validate_review(bundle, findings, require_review_approved=require_review_approved)
    approved_records = _validate_approved_records(bundle, target, findings, counts)
    _validate_rejected_records(bundle, findings, counts)

    _validate_unique_ids("proposed", proposed_records, findings)
    _validate_unique_ids("approved", approved_records, findings)

    return _validation_result(bundle, target, findings, counts, review_approved=review_approved)


def apply_approved_knowledge_bundle(
    bundle_path: str | Path,
    *,
    knowledge_dir: str | Path = "local_knowledge",
    dry_run: bool = False,
) -> KnowledgeBundleApplyResult:
    bundle = Path(bundle_path)
    target = Path(knowledge_dir)
    validation = validate_knowledge_bundle(bundle, knowledge_dir=target, require_review_approved=True)
    findings = list(validation.findings)
    if not validation.passed:
        return KnowledgeBundleApplyResult(
            path=str(bundle),
            knowledge_dir=str(target),
            passed=False,
            applied=False,
            dry_run=dry_run,
            validation_passed=False,
            findings=findings,
        )
    if validation.counts.approved_records == 0:
        _add(
            findings,
            "error",
            "no_approved_records",
            bundle / "reviewed" / "approved_records.jsonl",
            "Apply requires at least one reviewed approved record.",
        )
        return KnowledgeBundleApplyResult(
            path=str(bundle),
            knowledge_dir=str(target),
            passed=False,
            applied=False,
            dry_run=dry_run,
            validation_passed=True,
            findings=findings,
        )

    _validate_path_safety(target, findings, label="runtime_knowledge")
    if any(finding.severity == "error" and finding.category.startswith("runtime_knowledge_") for finding in findings):
        return KnowledgeBundleApplyResult(
            path=str(bundle),
            knowledge_dir=str(target),
            passed=False,
            applied=False,
            dry_run=dry_run,
            validation_passed=True,
            findings=findings,
        )

    current_validation = validate_product_knowledge(target)
    if not current_validation.passed:
        for finding in current_validation.errors:
            _add(findings, "error", "target_knowledge_invalid", finding.path, finding.message)
        return KnowledgeBundleApplyResult(
            path=str(bundle),
            knowledge_dir=str(target),
            passed=False,
            applied=False,
            dry_run=dry_run,
            validation_passed=True,
            findings=findings,
        )

    approved = _read_approved_envelopes(bundle / "reviewed" / "approved_records.jsonl")
    applied_rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="knowledge-bundle-apply-") as tmp:
        staged = Path(tmp) / "local_knowledge"
        shutil.copytree(target, staged)
        applied_count, skipped_count = _apply_records_to_knowledge(staged, approved, applied_rows)
        staged_validation = validate_product_knowledge(staged)
        if not staged_validation.passed:
            for finding in staged_validation.errors:
                _add(findings, "error", "post_apply_knowledge_invalid", finding.path, finding.message)
            if not dry_run:
                _write_apply_outputs(bundle, applied_rows, findings, applied=False, dry_run=False)
            return KnowledgeBundleApplyResult(
                path=str(bundle),
                knowledge_dir=str(target),
                passed=False,
                applied=False,
                dry_run=dry_run,
                validation_passed=True,
                product_validation_passed=False,
                applied_count=0,
                skipped_count=skipped_count,
                applied_records_path=None if dry_run else str(bundle / "applied" / "applied_records.jsonl"),
                apply_report_path=None if dry_run else str(bundle / "applied" / "apply_report.md"),
                record_results=applied_rows,
                findings=findings,
            )

        if not dry_run and applied_count > 0:
            _copy_applied_product_files(staged, target)
        if not dry_run:
            _write_apply_outputs(bundle, applied_rows, findings, applied=applied_count > 0, dry_run=False)

    if dry_run:
        _add(
            findings,
            "info",
            "dry_run",
            bundle,
            "Bundle validated and staged successfully; no local_knowledge files were changed.",
        )

    return KnowledgeBundleApplyResult(
        path=str(bundle),
        knowledge_dir=str(target),
        passed=True,
        applied=not dry_run and applied_count > 0,
        dry_run=dry_run,
        validation_passed=True,
        product_validation_passed=True,
        applied_count=applied_count,
        skipped_count=skipped_count,
        applied_records_path=None if dry_run else str(bundle / "applied" / "applied_records.jsonl"),
        apply_report_path=None if dry_run else str(bundle / "applied" / "apply_report.md"),
        record_results=applied_rows,
        findings=findings,
    )


def format_bundle_validation(result: KnowledgeBundleValidationResult) -> str:
    status = "passed" if result.passed else "failed"
    manual_status = "approved for apply" if result.review_approved else "manual review required before apply"
    lines = [
        f"Knowledge bundle validation {status}: {result.path}",
        f"review: {manual_status}",
        (
            "counts: "
            f"proposed={result.counts.proposed_records} "
            f"approved={result.counts.approved_records} "
            f"rejected={result.counts.rejected_records} "
            f"eval_cases={result.counts.eval_cases} "
            f"apply_ready={result.counts.apply_ready_records}"
        ),
    ]
    if result.passed and not result.review_approved:
        lines.append("next: complete reviewed/review.yaml approval and reviewed/approved_records.jsonl before applying.")
    elif result.passed:
        lines.append("next: run apply_approved_knowledge_bundle.py --dry-run to preview the merge.")
    else:
        lines.append("next: fix the errors below; no records are safe to apply until validation passes.")
    for finding in result.findings:
        lines.append(f"[{finding.severity}] {finding.category}: {finding.message}")
    return "\n".join(lines)


def format_apply_result(result: KnowledgeBundleApplyResult) -> str:
    status = "passed" if result.passed else "failed"
    applied = "dry-run" if result.dry_run else ("applied" if result.applied else "not applied")
    record_summary = (
        f"records: would_apply={result.applied_count} would_skip={result.skipped_count}"
        if result.dry_run
        else f"records: applied={result.applied_count} skipped={result.skipped_count}"
    )
    lines = [
        f"Knowledge bundle apply {status}: {result.path}",
        f"status: {applied}",
        record_summary,
    ]
    for row in result.record_results:
        verb = "would apply" if result.dry_run and row["status"] == "applied" else row["status"]
        if result.dry_run and row["status"].startswith("skipped"):
            verb = "would skip"
        lines.append(
            f"- {verb}: {row['record_type']} {row['id']} -> local_knowledge/{row.get('destination_file', 'unknown')}"
        )
    for finding in result.findings:
        lines.append(f"[{finding.severity}] {finding.category}: {finding.message}")
    return "\n".join(lines)


def _validation_result(
    bundle: Path,
    target: Path,
    findings: list[KnowledgeBundleFinding],
    counts: KnowledgeBundleCounts,
    *,
    review_approved: bool,
) -> KnowledgeBundleValidationResult:
    return KnowledgeBundleValidationResult(
        path=str(bundle),
        knowledge_dir=str(target),
        passed=not any(finding.severity == "error" for finding in findings),
        review_approved=review_approved,
        counts=counts,
        findings=findings,
    )


def _add(
    findings: list[KnowledgeBundleFinding],
    severity: Literal["info", "warning", "error"],
    category: str,
    path: Path | str | None,
    message: str,
) -> None:
    findings.append(
        KnowledgeBundleFinding(
            severity=severity,
            category=category,
            path=str(path) if path is not None else None,
            message=sanitize_provider_error(message),
        )
    )


def _validate_path_safety(root: Path, findings: list[KnowledgeBundleFinding], *, label: str) -> None:
    if root.is_symlink():
        _add(findings, "error", f"{label}_symlink_path", root, "Path must not be a symlink.")
        return
    if not root.exists():
        return
    root_resolved = root.resolve()
    for item in sorted(root.rglob("*")):
        if item.is_symlink():
            _add(findings, "error", f"{label}_symlink_path", item, "Symlinks are not allowed in knowledge paths.")
            continue
        try:
            item.resolve().relative_to(root_resolved)
        except ValueError:
            _add(findings, "error", f"{label}_path_escape", item, "Path resolves outside its knowledge root.")


def _unsafe_path_for_read(path: Path, findings: list[KnowledgeBundleFinding]) -> bool:
    if path.is_symlink():
        _add(findings, "error", "symlink_path", path, "Refusing to read symlinked bundle file.")
        return True
    if path.exists() and not path.is_file():
        _add(findings, "error", "path_not_file", path, "Expected a regular file.")
        return True
    return False


def _read_yaml_checked(path: Path, findings: list[KnowledgeBundleFinding]) -> Any:
    if not path.exists():
        _add(findings, "error", "missing_file", path, f"Required file missing: {path.name}.")
        return None
    if _unsafe_path_for_read(path, findings):
        return None
    try:
        return yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        _add(findings, "error", "invalid_yaml", path, f"YAML failed to parse: {exc}")
        return None


def _read_json_checked(path: Path, findings: list[KnowledgeBundleFinding]) -> Any:
    if not path.exists():
        _add(findings, "error", "missing_file", path, f"Required file missing: {path.name}.")
        return None
    if _unsafe_path_for_read(path, findings):
        return None
    try:
        return json.loads(path.read_text() or "{}")
    except json.JSONDecodeError as exc:
        _add(findings, "error", "invalid_json", path, f"JSON failed to parse: {exc}")
        return None


def _read_jsonl_checked(path: Path, findings: list[KnowledgeBundleFinding]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        _add(findings, "error", "missing_file", path, f"Required file missing: {path.name}.")
        return records
    if _unsafe_path_for_read(path, findings):
        return records
    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            _add(findings, "error", "invalid_jsonl", path, f"{path}:{line_number}: invalid JSONL: {exc}")
            continue
        if not isinstance(value, dict):
            _add(findings, "error", "invalid_jsonl_record", path, f"{path}:{line_number}: record must be an object.")
            continue
        records.append(value)
    return records


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    for line in path.read_text().splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records))


def _write_yaml(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False))


def _validate_directory_shape(bundle: Path, findings: list[KnowledgeBundleFinding]) -> None:
    for item in sorted(bundle.iterdir()):
        if item.name in IGNORED_BUNDLE_FILE_NAMES:
            continue
        if item.name not in ALLOWED_TOP_LEVEL:
            _add(findings, "error", "unexpected_bundle_path", item, "Unexpected top-level bundle path.")
    for item in sorted(bundle.rglob("*")):
        if item.name in IGNORED_BUNDLE_FILE_NAMES:
            continue
        rel = item.relative_to(bundle).as_posix()
        if item.is_symlink():
            continue
        if item.is_dir():
            if rel not in ALLOWED_RELATIVE_DIRS:
                _add(findings, "error", "unexpected_bundle_path", item, "Unexpected bundle directory.")
        elif item.is_file() and rel not in ALLOWED_RELATIVE_FILES:
            _add(findings, "error", "unexpected_bundle_path", item, "Unexpected bundle file.")
    for dirname in ("source", "reviewed"):
        path = bundle / dirname
        if not path.exists():
            _add(findings, "error", "missing_directory", path, f"Required directory missing: {dirname}/.")
        elif not path.is_dir():
            _add(findings, "error", "path_not_directory", path, f"Expected directory: {dirname}/.")
    for dirname in ("extracted", "proposed", "codex_review", "applied", "eval"):
        path = bundle / dirname
        if path.exists() and not path.is_dir():
            _add(findings, "error", "path_not_directory", path, f"Expected directory: {dirname}/.")

    source = bundle / "source"
    if source.exists() and source.is_dir():
        for filename in REQUIRED_SOURCE_FILES:
            if not (source / filename).exists():
                _add(findings, "error", "missing_source_file", source / filename, f"Missing source/{filename}.")
    proposed = bundle / "proposed"
    if proposed.exists() and proposed.is_dir():
        for filename in REQUIRED_PROPOSED_FILES:
            if not (proposed / filename).exists():
                _add(findings, "warning", "missing_advisory_proposed_file", proposed / filename, f"Missing proposed/{filename}.")
    extracted = bundle / "extracted"
    if extracted.exists() and extracted.is_dir():
        for filename in REQUIRED_EXTRACTED_FILES:
            if not (extracted / filename).exists():
                _add(findings, "warning", "missing_extracted_note_file", extracted / filename, f"Missing extracted/{filename}.")
    codex_review = bundle / "codex_review"
    if codex_review.exists() and codex_review.is_dir():
        for filename in REQUIRED_CODEX_REVIEW_FILES:
            if not (codex_review / filename).exists():
                _add(findings, "error", "missing_codex_review_file", codex_review / filename, f"Missing codex_review/{filename}.")
    reviewed = bundle / "reviewed"
    if reviewed.exists() and reviewed.is_dir():
        for filename in REQUIRED_REVIEWED_FILES:
            if not (reviewed / filename).exists():
                _add(findings, "error", "missing_reviewed_file", reviewed / filename, f"Missing reviewed/{filename}.")


def _validate_source_files(bundle: Path, findings: list[KnowledgeBundleFinding]) -> None:
    redaction_report = _read_json_checked(bundle / "source" / "redaction_report.json", findings)
    if redaction_report is not None and not isinstance(redaction_report, dict):
        _add(findings, "error", "invalid_redaction_report", bundle / "source" / "redaction_report.json", "redaction_report.json must be an object.")
    raw_path = bundle / "source" / "raw.sanitized.txt"
    source_hash = bundle / "source" / "source_hash.txt"
    if source_hash.exists() and _unsafe_path_for_read(source_hash, findings):
        return
    if raw_path.exists() and _unsafe_path_for_read(raw_path, findings):
        return
    if source_hash.exists() and not source_hash.read_text().strip():
        _add(findings, "error", "empty_source_hash", source_hash, "source_hash.txt must not be empty.")
    if source_hash.exists() and raw_path.exists():
        declared = source_hash.read_text().strip()
        normalized = declared.removeprefix("sha256:").lower()
        actual = sha256(raw_path.read_bytes()).hexdigest()
        if not SOURCE_HASH_RE.match(declared):
            _add(findings, "error", "invalid_source_hash", source_hash, "source_hash.txt must contain a SHA-256 hash.")
        elif normalized != actual:
            _add(findings, "error", "source_hash_mismatch", source_hash, "source_hash.txt must match source/raw.sanitized.txt.")


def _validate_manifest_metadata(bundle: Path, manifest: dict[str, Any], findings: list[KnowledgeBundleFinding]) -> None:
    slug = str(manifest.get("incident_slug") or bundle.name)
    if not SAFE_SLUG_RE.match(slug):
        _add(findings, "error", "unsafe_incident_slug", bundle / "manifest.yaml", "incident_slug must be a safe relative slug.")
    _validate_no_path_references(manifest, bundle / "manifest.yaml", findings)


def _validate_eval_outputs(bundle: Path, findings: list[KnowledgeBundleFinding]) -> None:
    eval_dir = bundle / "eval"
    if not eval_dir.exists():
        return
    output_json = eval_dir / "simplified_product_eval.json"
    output_md = eval_dir / "simplified_product_eval.md"
    if output_json.exists():
        data = _read_json_checked(output_json, findings)
        if data is not None and not isinstance(data, dict):
            _add(findings, "error", "invalid_eval_report", output_json, "simplified_product_eval.json must be an object.")
    if output_md.exists():
        if _unsafe_path_for_read(output_md, findings):
            return
        if not output_md.read_text().strip():
            _add(findings, "error", "empty_eval_report", output_md, "simplified_product_eval.md must not be empty.")


def _scan_credential_patterns(bundle: Path, findings: list[KnowledgeBundleFinding]) -> None:
    credential_patterns = [
        *SECRET_PATTERNS,
        ("private_key", PRIVATE_KEY_RE),
        ("aws_access_key", AWS_KEY_RE),
    ]
    for path in _text_files(bundle):
        text = path.read_text(errors="ignore")
        for category, pattern in credential_patterns:
            if pattern.search(text):
                _add(findings, "error", "secret_detected", path, f"Secret-like value detected ({category}); value redacted.")


def _validate_raw_source_isolated(bundle: Path, findings: list[KnowledgeBundleFinding]) -> None:
    raw_path = bundle / "source" / "raw.sanitized.txt"
    if not raw_path.exists():
        return
    if _unsafe_path_for_read(raw_path, findings):
        return
    raw_lines = [
        " ".join(line.split())
        for line in raw_path.read_text(errors="ignore").splitlines()
        if len(" ".join(line.split())) >= RAW_SOURCE_LINE_MIN_LENGTH
    ]
    if not raw_lines:
        return
    for path in _text_files(bundle):
        if _under(path, bundle / "source"):
            continue
        if path == bundle / "manifest.yaml":
            continue
        if any(_under(path, bundle / dirname) for dirname in ADVISORY_RELATIVE_DIRS):
            continue
        text = " ".join(path.read_text(errors="ignore").split())
        for line in raw_lines:
            if line and line in text:
                _add(
                    findings,
                    "error",
                    "raw_source_leaked_outside_source",
                    path,
                    "A long raw source line appears outside source/; raw incident text must remain audit-only.",
                )
                break


def _validate_proposed(
    bundle: Path,
    findings: list[KnowledgeBundleFinding],
    counts: KnowledgeBundleCounts,
) -> list[tuple[str, str, Path]]:
    proposed = bundle / "proposed"
    records_seen: list[tuple[str, str, Path]] = []
    if not proposed.exists():
        _validate_codex_review_eval_cases(bundle, findings, counts)
        return records_seen
    for record_type, filename in PROPOSED_JSONL_FILES.items():
        path = proposed / filename
        if not path.exists():
            continue
        records = _read_jsonl_checked(path, findings)
        counts.proposed_records += len(records)
        if record_type == "eval_case":
            counts.eval_cases += len(records)
        for record in records:
            record_id = _id_for_record(record_type, record)
            _validate_advisory_record_id(record_id, record_type, path, findings)
            if record_id:
                records_seen.append((record_type, record_id, path))

    catalog_path = proposed / "service_catalog.proposed.yaml"
    if not catalog_path.exists():
        _validate_codex_review_eval_cases(bundle, findings, counts)
        return records_seen
    data = _read_yaml_checked(catalog_path, findings)
    if isinstance(data, dict):
        services = data.get("services", [])
    elif isinstance(data, list):
        services = data
    else:
        services = []
        if data is not None:
            _add(findings, "error", "invalid_service_catalog_proposed", catalog_path, "service_catalog.proposed.yaml must contain a services list.")
    if not isinstance(services, list):
        _add(findings, "error", "invalid_service_catalog_proposed", catalog_path, "services must be a list.")
        services = []
    counts.proposed_records += len([item for item in services if isinstance(item, dict)])
    for service in services:
        if not isinstance(service, dict):
            _add(findings, "error", "invalid_service_catalog_record", catalog_path, "Service catalog proposed record must be an object.")
            continue
        service_id = _id_for_record("service_catalog_entry", service)
        _validate_advisory_record_id(service_id, "service_catalog_entry", catalog_path, findings)
        if service_id:
            records_seen.append(("service_catalog_entry", service_id, catalog_path))
    _validate_codex_review_eval_cases(bundle, findings, counts)
    return records_seen


def _validate_advisory_record_id(
    record_id: str | None,
    record_type: str,
    path: Path,
    findings: list[KnowledgeBundleFinding],
) -> None:
    before = len(findings)
    _validate_record_id(record_id, record_type, path, findings)
    for index in range(before, len(findings)):
        finding = findings[index]
        if finding.severity == "error":
            findings[index] = finding.model_copy(update={"severity": "warning", "category": f"advisory_{finding.category}"})


def _validate_codex_review_eval_cases(
    bundle: Path,
    findings: list[KnowledgeBundleFinding],
    counts: KnowledgeBundleCounts,
) -> None:
    path = bundle / "codex_review" / "generated_eval_cases.jsonl"
    if not path.exists():
        return
    records = _read_jsonl_checked(path, findings)
    counts.eval_cases += len(records)
    for record in records:
        record_id = _id_for_record("eval_case", record)
        _validate_record_id(record_id, "eval_case", path, findings)
        _validate_generalized_record(record, path, findings, allow_eval_case=True)
        _validate_eval_case(record, path, findings)


def _validate_review(
    bundle: Path,
    findings: list[KnowledgeBundleFinding],
    *,
    require_review_approved: bool,
) -> bool:
    review_path = bundle / "reviewed" / "review.yaml"
    review = _read_yaml_checked(review_path, findings)
    if review is None or not isinstance(review, dict):
        return False
    status = str(review.get("status") or review.get("review_status") or "").strip().lower()
    approved = bool(review.get("approved")) or status in {"approved", "approved_for_apply", "approved_for_product"}
    if require_review_approved and not approved:
        _add(findings, "error", "review_not_approved", review_path, "review.yaml must be approved before applying.")
    for key in ("reviewed_by", "reviewed_at", "review_method"):
        if not str(review.get(key) or "").strip():
            _add(findings, "error", "missing_review_metadata", review_path, f"review.yaml missing {key}.")
    _validate_generalized_record(review, review_path, findings)
    return approved


def _validate_approved_records(
    bundle: Path,
    knowledge_dir: Path,
    findings: list[KnowledgeBundleFinding],
    counts: KnowledgeBundleCounts,
) -> list[tuple[str, str, Path]]:
    path = bundle / "reviewed" / "approved_records.jsonl"
    records = _read_jsonl_checked(path, findings)
    counts.approved_records = len(records)
    existing = _existing_records_by_type(knowledge_dir)
    seen: list[tuple[str, str, Path]] = []
    for envelope in records:
        record_type = str(envelope.get("record_type") or envelope.get("type") or "").strip()
        record_id = str(envelope.get("id") or "").strip()
        record = envelope.get("record")
        if record_type not in APPLY_RECORD_TYPES:
            _add(findings, "error", "unsupported_approved_record_type", path, f"Approved record type is not mergeable: {record_type or '<missing>'}.")
            continue
        if not isinstance(record, dict):
            _add(findings, "error", "invalid_approved_record", path, f"Approved record {record_id or '<missing>'} must contain a record object.")
            continue
        inferred_id = _id_for_record(record_type, record)
        if inferred_id and record_id and inferred_id != record_id:
            _add(findings, "error", "approved_id_mismatch", path, f"Approved id {record_id} does not match record id {inferred_id}.")
        record_id = record_id or inferred_id
        _validate_record_id(record_id, record_type, path, findings)
        _validate_generalized_record(envelope, path, findings)
        if record_id:
            seen.append((record_type, record_id, path))
        _validate_approved_record_body(record_type, record, path, findings)
        _validate_duplicate(record_type, record_id, record, envelope, existing, path, findings)
        if record_type in APPLY_RECORD_TYPES:
            counts.apply_ready_records += 1
    return seen


def _validate_rejected_records(
    bundle: Path,
    findings: list[KnowledgeBundleFinding],
    counts: KnowledgeBundleCounts,
) -> None:
    path = bundle / "reviewed" / "rejected_records.jsonl"
    records = _read_jsonl_checked(path, findings)
    counts.rejected_records = len(records)
    for record in records:
        rejected_id = str(record.get("id") or record.get("proposed_id") or "").strip()
        _validate_record_id(rejected_id, "rejected_review_record", path, findings)
        reason = str(record.get("reason") or record.get("rejection_reason") or "").strip()
        if not reason:
            _add(findings, "error", "missing_rejection_reason", path, f"Rejected record {rejected_id or '<missing>'} must include a reason.")
        _validate_generalized_record(record, path, findings)


def _validate_unique_ids(
    label: str,
    records: list[tuple[str, str, Path]],
    findings: list[KnowledgeBundleFinding],
) -> None:
    seen: dict[tuple[str, str], Path] = {}
    for record_type, record_id, path in records:
        key = (record_type, record_id.lower())
        if key in seen:
            _add(findings, "error", f"duplicate_{label}_id", path, f"Duplicate {label} id for {record_type}: {record_id}.")
        else:
            seen[key] = path


def _validate_record_id(
    record_id: str | None,
    record_type: str,
    path: Path,
    findings: list[KnowledgeBundleFinding],
) -> None:
    if not record_id:
        _add(findings, "error", "missing_stable_id", path, f"{record_type} record is missing a stable id.")
        return
    if not STABLE_ID_RE.match(record_id):
        _add(findings, "error", "unstable_id", path, f"{record_type} id is not stable/generalized: {record_id}.")
    if _private_identifier_hits(record_id):
        _add(findings, "error", "incident_specific_id", path, f"{record_type} id contains an incident-specific identifier.")


def _validate_generalized_record(
    record: dict[str, Any],
    path: Path,
    findings: list[KnowledgeBundleFinding],
    *,
    allow_eval_case: bool = False,
) -> None:
    text = json.dumps(record, sort_keys=True, default=str)
    for category, pattern in _private_identifier_patterns(allow_eval_case=allow_eval_case):
        if pattern.search(text):
            _add(
                findings,
                "error",
                "private_identifier_detected",
                path,
                f"Reusable record contains a private or incident-specific identifier ({category}); value redacted.",
            )
    if _contains_runtime_raw_source_fields(record):
        _add(
            findings,
            "error",
            "raw_source_field_in_reusable_record",
            path,
            "Reusable records must not carry raw source text or source audit payloads.",
        )
    if _contains_customer_specific_field(record):
        _add(
            findings,
            "error",
            "customer_specific_identifier",
            path,
            "Reusable records must use placeholders instead of customer, tenant, or account identifiers.",
        )
    _validate_no_path_references(record, path, findings)


def _validate_decision_record(record: dict[str, Any], path: Path, findings: list[KnowledgeBundleFinding]) -> None:
    try:
        DecisionMoment.model_validate(_adapt_decision_moment(record))
    except Exception as exc:
        _add(findings, "error", "invalid_decision_moment", path, f"DecisionMoment proposed record failed schema validation: {exc}")


def _validate_eval_case(record: dict[str, Any], path: Path, findings: list[KnowledgeBundleFinding]) -> None:
    try:
        fixture = SimplifiedProductEvalFixture.from_dict(record)
    except Exception as exc:
        _add(findings, "error", "invalid_simplified_eval_case", path, f"Simplified product eval case failed validation: {exc}")
        return
    read = fixture.expected_read
    selected_target = str(read.get("selected_target_display_name") or "")
    say_this = str(read.get("say_this") or "")
    selected_text = f"{selected_target}\n{say_this}"
    if fixture.acceptable_target_names and not any(
        _contains_name(selected_text, target) for target in fixture.acceptable_target_names
    ):
        _add(
            findings,
            "error",
            "eval_case_owner_alignment",
            path,
            f"Eval case {fixture.fixture_id} expected_read does not target an acceptable owner.",
        )
    bad_targets = [target for target in fixture.unacceptable_target_names if _contains_name(selected_text, target)]
    if bad_targets:
        _add(
            findings,
            "error",
            "eval_case_bad_owner_ask",
            path,
            f"Eval case {fixture.fixture_id} targets an unacceptable owner.",
        )
    for pattern in fixture.forbidden_output_patterns:
        if re.search(pattern, say_this, flags=re.IGNORECASE):
            _add(
                findings,
                "error",
                "eval_case_forbidden_output",
                path,
                f"Eval case {fixture.fixture_id} expected output matches a forbidden pattern.",
            )


def _contains_name(text: str, name: str) -> bool:
    text_key = _norm_name(text)
    name_key = _norm_name(name)
    if not text_key or not name_key:
        return False
    return bool(re.search(rf"(?<![a-z0-9])@?{re.escape(name_key)}(?![a-z0-9])", text_key))


def _norm_name(value: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9@_./-]+", " ", str(value).lower()).split()).lstrip("@")


def _validate_approved_record_body(
    record_type: str,
    record: dict[str, Any],
    path: Path,
    findings: list[KnowledgeBundleFinding],
) -> None:
    if record_type == "decision_moment":
        _validate_decision_record(record, path, findings)
        try:
            moment = DecisionMoment.model_validate(_adapt_decision_moment(record))
        except Exception:
            return
        if moment.review_status not in {"approved", "human_reviewed", "externally_reviewed", "approved_for_product"}:
            _add(findings, "error", "approved_decision_not_reviewed", path, f"DecisionMoment {moment.decision_id} is not approved.")
        if not moment.applicability or moment.forbidden_fact_leakage is None:
            _add(findings, "error", "approved_decision_missing_safety_fields", path, f"DecisionMoment {moment.decision_id} is missing safety fields.")
    elif record_type == "service_catalog_entry":
        _validate_service_record(record, path, findings)
    else:
        if not isinstance(record.get("id"), str) or not record["id"].strip():
            _add(findings, "error", "support_record_missing_id", path, f"{record_type} support record must include id.")


def _validate_service_record(record: dict[str, Any], path: Path, findings: list[KnowledgeBundleFinding]) -> None:
    with tempfile.TemporaryDirectory(prefix="knowledge-bundle-service-") as tmp:
        candidate = Path(tmp) / "service_catalog.yaml"
        _write_yaml(candidate, {"services": [record]})
        try:
            entries = load_service_catalog(candidate)
        except Exception as exc:
            _add(findings, "error", "invalid_service_catalog_entry", path, f"Service catalog entry failed validation: {exc}")
            return
    entry = ServiceCatalogEntry.model_validate(entries[0].model_dump(mode="json"))
    for command in entry.known_commands:
        command_text = str(command.get("command") or "")
        if command_text and not command.get("requires_human_approval", True):
            _add(findings, "error", "service_command_not_manual_copy", path, f"Known command for {entry.service_id} must require human approval.")


def _validate_duplicate(
    record_type: str,
    record_id: str,
    record: dict[str, Any],
    envelope: dict[str, Any],
    existing: dict[str, dict[str, dict[str, Any]]],
    path: Path,
    findings: list[KnowledgeBundleFinding],
) -> None:
    if not record_id:
        return
    existing_record = existing.get(record_type, {}).get(record_id.lower())
    if existing_record is None:
        return
    if _canonical_json(existing_record) == _canonical_json(record):
        return
    duplicate_policy = str(envelope.get("duplicate_policy") or "").strip()
    if duplicate_policy == "skip_if_exists":
        return
    _add(
        findings,
        "error",
        "duplicate_existing_id",
        path,
        f"Approved {record_type} id already exists in local_knowledge and is not explicitly handled: {record_id}.",
    )


def _existing_records_by_type(knowledge_dir: Path) -> dict[str, dict[str, dict[str, Any]]]:
    existing: dict[str, dict[str, dict[str, Any]]] = {record_type: {} for record_type in APPLY_RECORD_TYPES}
    if not knowledge_dir.exists():
        return existing

    decision_path = knowledge_dir / "decision_moments.jsonl"
    try:
        decision_records = _read_jsonl(decision_path)
    except Exception:
        decision_records = []
    for record in decision_records:
        record_id = str(record.get("decision_id") or "").strip()
        if record_id:
            existing["decision_moment"][record_id.lower()] = record

    catalog_path = knowledge_dir / "service_catalog.yaml"
    if catalog_path.exists():
        try:
            data = yaml.safe_load(catalog_path.read_text()) or {}
            services = data.get("services", data if isinstance(data, list) else [])
            for service in services:
                if isinstance(service, dict) and service.get("service_id"):
                    existing["service_catalog_entry"][str(service["service_id"]).lower()] = service
        except yaml.YAMLError:
            pass

    for record_type, filename in {
        "rejected_entity": "rejected_entities.jsonl",
        "stale_question_pattern": "stale_question_patterns.jsonl",
        "verifier_regression": "verifier_regressions.jsonl",
    }.items():
        try:
            records = _read_jsonl(knowledge_dir / filename)
        except Exception:
            records = []
        for record in records:
            record_id = str(record.get("id") or "").strip()
            if record_id:
                existing[record_type][record_id.lower()] = record
    return existing


def _read_approved_envelopes(path: Path) -> list[dict[str, Any]]:
    return _read_jsonl(path)


def _apply_records_to_knowledge(
    knowledge_dir: Path,
    approved: list[dict[str, Any]],
    applied_rows: list[dict[str, Any]],
) -> tuple[int, int]:
    existing = _existing_records_by_type(knowledge_dir)
    catalog_changed = False
    support_records: dict[str, list[dict[str, Any]]] = {
        "decision_moment": _read_jsonl(knowledge_dir / "decision_moments.jsonl"),
        "rejected_entity": _read_jsonl(knowledge_dir / "rejected_entities.jsonl"),
        "stale_question_pattern": _read_jsonl(knowledge_dir / "stale_question_patterns.jsonl"),
        "verifier_regression": _read_jsonl(knowledge_dir / "verifier_regressions.jsonl"),
    }
    catalog_data = yaml.safe_load((knowledge_dir / "service_catalog.yaml").read_text()) or {}
    services = catalog_data.get("services", catalog_data if isinstance(catalog_data, list) else [])

    applied_count = 0
    skipped_count = 0
    for envelope in approved:
        record_type = str(envelope["record_type"])
        record = dict(envelope["record"])
        record_id = str(envelope["id"])
        existing_record = existing.get(record_type, {}).get(record_id.lower())
        if existing_record is not None:
            skipped_count += 1
            applied_rows.append(_applied_row(envelope, status="skipped_existing"))
            continue
        if record_type == "service_catalog_entry":
            services.append(record)
            catalog_changed = True
        elif record_type in support_records:
            support_records[record_type].append(record)
        existing[record_type][record_id.lower()] = record
        applied_count += 1
        applied_rows.append(_applied_row(envelope, status="applied"))

    if catalog_changed:
        _write_yaml(knowledge_dir / "service_catalog.yaml", {"services": services})
    _write_jsonl(knowledge_dir / "decision_moments.jsonl", support_records["decision_moment"])
    _write_jsonl(knowledge_dir / "rejected_entities.jsonl", support_records["rejected_entity"])
    _write_jsonl(knowledge_dir / "stale_question_patterns.jsonl", support_records["stale_question_pattern"])
    _write_jsonl(knowledge_dir / "verifier_regressions.jsonl", support_records["verifier_regression"])
    return applied_count, skipped_count


def _applied_row(envelope: dict[str, Any], *, status: str) -> dict[str, Any]:
    return {
        "id": envelope["id"],
        "record_type": envelope["record_type"],
        "status": status,
        "destination_file": DESTINATION_FILES.get(str(envelope["record_type"]), "unknown"),
    }


def _copy_applied_product_files(staged: Path, target: Path) -> None:
    for filename in (
        "service_catalog.yaml",
        "decision_moments.jsonl",
        "rejected_entities.jsonl",
        "stale_question_patterns.jsonl",
        "verifier_regressions.jsonl",
    ):
        shutil.copy2(staged / filename, target / filename)


def _write_apply_outputs(
    bundle: Path,
    applied_rows: list[dict[str, Any]],
    findings: list[KnowledgeBundleFinding],
    *,
    applied: bool,
    dry_run: bool,
) -> None:
    applied_dir = bundle / "applied"
    applied_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(applied_dir / "applied_records.jsonl", applied_rows)
    lines = [
        "# Knowledge Bundle Apply Report",
        "",
        f"- applied: {applied}",
        f"- dry_run: {dry_run}",
        f"- records_applied: {sum(1 for row in applied_rows if row['status'] == 'applied')}",
        f"- records_skipped: {sum(1 for row in applied_rows if row['status'].startswith('skipped'))}",
        f"- source_hash: {_source_hash_for_report(bundle)}",
        "",
        "## Counts By Record Type",
        "",
    ]
    counts_by_type = _counts_by_type(applied_rows)
    if counts_by_type:
        for record_type, count in sorted(counts_by_type.items()):
            lines.append(f"- {record_type}: {count}")
    else:
        lines.append("- none")

    lines.extend(["", "## Destination Files", ""])
    destination_files = sorted({row["destination_file"] for row in applied_rows if row["status"] == "applied"})
    if destination_files:
        for destination in destination_files:
            lines.append(f"- local_knowledge/{destination}")
    else:
        lines.append("- none")

    lines.extend(["", "## Applied Records", ""])
    applied_only = [row for row in applied_rows if row["status"] == "applied"]
    if applied_only:
        for row in applied_only:
            lines.append(f"- {row['record_type']} {row['id']} -> local_knowledge/{row['destination_file']}")
    else:
        lines.append("- none")

    lines.extend(["", "## Skipped Records", ""])
    skipped = [row for row in applied_rows if row["status"].startswith("skipped")]
    if skipped:
        for row in skipped:
            lines.append(f"- {row['record_type']} {row['id']}: {row['status']}")
    else:
        lines.append("- none")

    lines.extend(["", "## Rejected During Review", ""])
    rejected = _read_rejected_for_report(bundle / "reviewed" / "rejected_records.jsonl")
    if rejected:
        for row in rejected:
            lines.append(f"- {row['id']}: {row['reason']}")
    else:
        lines.append("- none")

    lines.extend([
        "",
        "## Findings",
        "",
    ])
    if findings:
        for finding in findings:
            lines.append(f"- [{finding.severity}] {finding.category}: {finding.message}")
    else:
        lines.append("- none")
    (applied_dir / "apply_report.md").write_text("\n".join(lines) + "\n")


def _id_for_record(record_type: str, record: dict[str, Any]) -> str:
    if record_type == "decision_moment":
        return str(record.get("decision_id") or record.get("id") or "").strip()
    if record_type == "service_catalog_entry":
        return str(record.get("service_id") or record.get("id") or "").strip()
    if record_type == "eval_case":
        return str(record.get("fixture_id") or record.get("case_id") or record.get("id") or "").strip()
    return str(
        record.get("id")
        or record.get("pattern_id")
        or record.get("entity_id")
        or record.get("regression_id")
        or ""
    ).strip()


def _private_identifier_patterns(*, allow_eval_case: bool) -> list[tuple[str, re.Pattern[str]]]:
    patterns = [
        ("slack_url", SLACK_URL_RE),
        ("jira_ticket_id", JIRA_TICKET_RE),
        ("incident_id", INCIDENT_ID_RE),
        ("pagerduty_id", PAGERDUTY_ID_RE),
        ("tenant_or_account_id", TENANT_ACCOUNT_RE),
    ]
    if not allow_eval_case:
        patterns.append(("long_numeric_id", LONG_NUMERIC_ID_RE))
    return patterns


def _private_identifier_hits(text: str) -> bool:
    return any(pattern.search(text) for _, pattern in _private_identifier_patterns(allow_eval_case=False))


def _contains_runtime_raw_source_fields(record: dict[str, Any]) -> bool:
    forbidden_keys = {
        "raw",
        "raw_text",
        "raw_slack",
        "raw_incident_text",
        "source_text",
        "source_payload",
        "redaction_report",
    }
    stack: list[Any] = [record]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                if str(key) in forbidden_keys:
                    return True
                stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)
    return False


def _contains_customer_specific_field(record: dict[str, Any]) -> bool:
    stack: list[Any] = [record]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                key_text = str(key).strip().lower()
                if key_text in CUSTOMER_IDENTIFIER_KEYS and _value_has_specific_customer_identifier(value):
                    return True
                stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)
    return False


def _value_has_specific_customer_identifier(value: Any) -> bool:
    if value in (None, "", []):
        return False
    if isinstance(value, list):
        return any(_value_has_specific_customer_identifier(item) for item in value)
    if isinstance(value, dict):
        return any(_value_has_specific_customer_identifier(item) for item in value.values())
    text = " ".join(str(value).strip().split())
    if not text:
        return False
    normalized = text.lower()
    if normalized in GENERIC_CUSTOMER_VALUES:
        return False
    if normalized.startswith(("redacted_", "<")) or "placeholder" in normalized:
        return False
    return True


def _validate_no_path_references(
    value: Any,
    path: Path,
    findings: list[KnowledgeBundleFinding],
) -> None:
    for text in _string_values(value):
        if _looks_like_forbidden_path_reference(text):
            _add(
                findings,
                "error",
                "forbidden_path_reference",
                path,
                "Reusable bundle content must not contain absolute paths or path traversal references.",
            )
            return


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        values: list[str] = []
        for item in value.values():
            values.extend(_string_values(item))
        return values
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(_string_values(item))
        return values
    return []


def _looks_like_forbidden_path_reference(text: str) -> bool:
    compact = URL_RE.sub("", text).strip()
    if not compact:
        return False
    if compact.startswith(("/", "~/", "../", "..\\")):
        return True
    if UNIX_ABSOLUTE_PATH_RE.search(compact):
        return True
    if WINDOWS_ABSOLUTE_PATH_RE.match(compact):
        return True
    return "/../" in compact or "\\..\\" in compact


def _source_hash_for_report(bundle: Path) -> str:
    path = bundle / "source" / "source_hash.txt"
    if not path.exists() or path.is_symlink():
        return "missing"
    return path.read_text().strip()


def _counts_by_type(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        if row["status"] != "applied":
            continue
        record_type = str(row["record_type"])
        counts[record_type] = counts.get(record_type, 0) + 1
    return counts


def _read_rejected_for_report(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    try:
        records = _read_jsonl(path)
    except Exception:
        return rows
    for record in records:
        rows.append(
            {
                "id": str(record.get("id") or record.get("proposed_id") or "<missing>"),
                "reason": str(record.get("reason") or record.get("rejection_reason") or "<missing reason>"),
            }
        )
    return rows


def _text_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if path.name in IGNORED_BUNDLE_FILE_NAMES:
            continue
        if path.is_symlink():
            continue
        if path.suffix.lower() in {".sqlite3", ".db", ".pyc", ".png", ".jpg", ".jpeg", ".gif", ".zip"}:
            continue
        files.append(path)
    return files


def _under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _canonical_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
