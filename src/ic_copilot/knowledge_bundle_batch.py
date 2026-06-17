from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml

from ic_copilot.error_sanitizer import sanitize_provider_error
from ic_copilot.knowledge_bundle import (
    KnowledgeBundleApplyResult,
    KnowledgeBundleValidationResult,
    apply_approved_knowledge_bundle,
    validate_knowledge_bundle,
)
from ic_copilot.knowledge_bundle_compiler import compile_knowledge_bundle


DEFAULT_EXTRACTED_ROOT = Path(".ic_copilot/knowledge_intake/extracted")
DEFAULT_REGISTRY_PATH = Path(".ic_copilot/knowledge_intake/registry/applied_bundles.jsonl")
DEFAULT_REPORT_DIR = Path(".ic_copilot/knowledge_intake/reports")


@dataclass(frozen=True)
class BundleIdentity:
    bundle_dir_name: str
    manifest_incident_slug: str
    schema_version: str
    source_hash: str
    approved_records_hash: str

    @property
    def bundle_key(self) -> str:
        return f"{self.bundle_dir_name}|{self.manifest_incident_slug}|{self.schema_version}"

    @property
    def identity_hash(self) -> str:
        payload = {
            "approved_records_hash": self.approved_records_hash,
            "bundle_dir_name": self.bundle_dir_name,
            "manifest_incident_slug": self.manifest_incident_slug,
            "schema_version": self.schema_version,
            "source_hash": self.source_hash,
        }
        return sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def model_dump(self) -> dict[str, Any]:
        return {
            "bundle_dir_name": self.bundle_dir_name,
            "manifest_incident_slug": self.manifest_incident_slug,
            "schema_version": self.schema_version,
            "source_hash": self.source_hash,
            "approved_records_hash": self.approved_records_hash,
            "bundle_key": self.bundle_key,
            "identity_hash": self.identity_hash,
        }


def review_extracted_knowledge_bundles(
    extracted_root: str | Path = DEFAULT_EXTRACTED_ROOT,
    *,
    knowledge_dir: str | Path = "local_knowledge",
    require_review_approved: bool = False,
    compile_before_review: bool = False,
    report_dir: str | Path | None = DEFAULT_REPORT_DIR,
    write_report: bool = True,
) -> dict[str, Any]:
    root = Path(extracted_root)
    target = Path(knowledge_dir)
    rows: list[dict[str, Any]] = []
    for bundle in _bundle_dirs(root):
        compile_result = None
        if compile_before_review:
            compile_result = compile_knowledge_bundle(bundle, knowledge_dir=target)
        validation = validate_knowledge_bundle(
            bundle,
            knowledge_dir=target,
            require_review_approved=require_review_approved,
        )
        identity = compute_bundle_identity(bundle)
        row = _review_row(bundle, validation, identity)
        if compile_result is not None:
            row["compile_result"] = compile_result.__dict__
        rows.append(row)

    report = _review_report(root, target, rows)
    if write_report and report_dir is not None:
        _write_batch_report(Path(report_dir), "knowledge_bundle_review", report)
    return report


def apply_extracted_knowledge_delta(
    extracted_root: str | Path = DEFAULT_EXTRACTED_ROOT,
    *,
    knowledge_dir: str | Path = "local_knowledge",
    registry_path: str | Path = DEFAULT_REGISTRY_PATH,
    report_dir: str | Path | None = DEFAULT_REPORT_DIR,
    dry_run: bool = False,
    write_report: bool = True,
) -> dict[str, Any]:
    root = Path(extracted_root)
    target = Path(knowledge_dir)
    registry = _load_registry(Path(registry_path))
    registry_by_key = {str(row.get("bundle_key") or ""): row for row in registry if row.get("bundle_key")}
    rows: list[dict[str, Any]] = []

    bundle_dirs = _bundle_dirs(root)
    changed_rows = [
        _changed_registry_row_if_needed(bundle, target, registry_by_key)
        for bundle in bundle_dirs
    ]
    changed_rows = [row for row in changed_rows if row is not None]
    if changed_rows:
        rows = [
            _plan_delta_bundle(bundle, target, registry_by_key, dry_run=True)
            for bundle in bundle_dirs
        ]
        report = _delta_report(root, target, rows, dry_run=dry_run)
        if write_report and report_dir is not None:
            _write_batch_report(Path(report_dir), "knowledge_bundle_delta_blocked", report)
        return report

    if dry_run:
        for bundle in bundle_dirs:
            rows.append(_plan_delta_bundle(bundle, target, registry_by_key, dry_run=True))
        report = _delta_report(root, target, rows, dry_run=True)
        if write_report and report_dir is not None:
            _write_batch_report(Path(report_dir), "knowledge_bundle_delta_dry_run", report)
        return report

    for bundle in bundle_dirs:
        row = _plan_delta_bundle(bundle, target, registry_by_key, dry_run=False)
        if row["status"] != "new_approved":
            rows.append(row)
            continue

        result = apply_approved_knowledge_bundle(bundle, knowledge_dir=target, dry_run=False)
        applied_row = _apply_row(bundle, row["identity"], result)
        rows.append(applied_row)
        if result.passed:
            registry_row = _registry_row(bundle, row["identity"], result)
            _append_registry_rows(Path(registry_path), [registry_row])
            registry_by_key[row["identity"]["bundle_key"]] = registry_row

    report = _delta_report(root, target, rows, dry_run=False)
    if write_report and report_dir is not None:
        _write_batch_report(Path(report_dir), "knowledge_bundle_delta_apply", report)
    return report


def compute_bundle_identity(bundle: str | Path) -> dict[str, Any]:
    path = Path(bundle)
    manifest = _read_yaml_lenient(path / "manifest.yaml")
    manifest_slug = str(
        manifest.get("incident_slug")
        or manifest.get("incident_id")
        or manifest.get("source_incident_id")
        or path.name
    )
    schema_version = str(manifest.get("schema_version") or "unknown")
    source_hash = _read_text_hash_value(path / "source" / "source_hash.txt")
    approved_records_hash = _hash_file(path / "reviewed" / "approved_records.jsonl")
    identity = BundleIdentity(
        bundle_dir_name=path.name,
        manifest_incident_slug=manifest_slug,
        schema_version=schema_version,
        source_hash=source_hash,
        approved_records_hash=approved_records_hash,
    )
    return identity.model_dump()


def format_batch_review(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        f"Knowledge bundle batch review: {report['extracted_root']}",
        (
            "counts: "
            f"scanned={counts['scanned_bundles']} "
            f"valid={counts['valid_bundles']} "
            f"invalid={counts['invalid_bundles']} "
            f"approved={counts['approved_bundles']} "
            f"manual_review={counts['manual_review_bundles']}"
        ),
    ]
    for row in report["bundles"]:
        lines.append(f"- {row['bundle']}: {row['status']} approved_records={row['approved_records']}")
        for finding in row["findings"][:5]:
            lines.append(f"  [{finding['severity']}] {finding['category']}: {finding['message']}")
    return "\n".join(lines)


def format_delta_apply(report: dict[str, Any]) -> str:
    counts = report["counts"]
    label = "dry-run" if report["dry_run"] else "apply"
    lines = [
        f"Knowledge bundle delta {label}: {report['extracted_root']}",
        (
            "counts: "
            f"scanned={counts['scanned_bundles']} "
            f"new={counts['new_bundles']} "
            f"applied={counts['newly_applied_bundles']} "
            f"skipped_unchanged={counts['skipped_unchanged_bundles']} "
            f"blocked_changed={counts['blocked_changed_bundles']} "
            f"invalid={counts['invalid_bundles']} "
            f"unapproved={counts['unapproved_bundles']}"
        ),
    ]
    for row in report["bundles"]:
        action = row.get("action") or row["status"]
        lines.append(f"- {row['bundle']}: {action}")
        for record in row.get("record_results", []):
            verb = "would apply" if report["dry_run"] and record["status"] == "applied" else record["status"]
            lines.append(
                f"  {verb}: {record['record_type']} {record['id']} -> local_knowledge/{record['destination_file']}"
            )
        for reason in row.get("reasons", [])[:5]:
            lines.append(f"  reason: {reason}")
    return "\n".join(lines)


def _bundle_dirs(root: Path) -> list[Path]:
    if not root.exists() or not root.is_dir() or root.is_symlink():
        return []
    return sorted(path for path in root.iterdir() if path.is_dir() and not path.is_symlink())


def _plan_delta_bundle(
    bundle: Path,
    knowledge_dir: Path,
    registry_by_key: dict[str, dict[str, Any]],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    identity = compute_bundle_identity(bundle)
    validation = validate_knowledge_bundle(bundle, knowledge_dir=knowledge_dir, require_review_approved=True)
    existing = registry_by_key.get(identity["bundle_key"])
    if existing is not None:
        changed = _registry_entry_changed(existing, identity)
        if changed:
            return _blocked_changed_row(bundle, identity, existing, validation)
        return _unchanged_row(bundle, identity, validation)
    if not validation.passed:
        return _invalid_or_unapproved_row(bundle, identity, validation)
    result = apply_approved_knowledge_bundle(bundle, knowledge_dir=knowledge_dir, dry_run=True)
    row = _apply_row(bundle, identity, result)
    row["status"] = "new_approved" if result.passed else "invalid"
    row["action"] = "would_apply" if dry_run and result.passed else row["status"]
    return row


def _changed_registry_row_if_needed(
    bundle: Path,
    knowledge_dir: Path,
    registry_by_key: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    identity = compute_bundle_identity(bundle)
    existing = registry_by_key.get(identity["bundle_key"])
    if existing is None or not _registry_entry_changed(existing, identity):
        return None
    validation = validate_knowledge_bundle(bundle, knowledge_dir=knowledge_dir, require_review_approved=True)
    return _blocked_changed_row(bundle, identity, existing, validation)


def _registry_entry_changed(existing: dict[str, Any], identity: dict[str, Any]) -> bool:
    return (
        str(existing.get("source_hash") or "") != identity["source_hash"]
        or str(existing.get("approved_records_hash") or "") != identity["approved_records_hash"]
        or str(existing.get("identity_hash") or "") != identity["identity_hash"]
    )


def _review_row(
    bundle: Path,
    validation: KnowledgeBundleValidationResult,
    identity: dict[str, Any],
) -> dict[str, Any]:
    status = "valid" if validation.passed else "invalid"
    if validation.passed and not validation.review_approved:
        status = "manual_review"
    return {
        "bundle": bundle.name,
        "bundle_path": str(bundle),
        "identity": identity,
        "status": status,
        "approved": validation.review_approved,
        "approved_records": validation.counts.approved_records,
        "rejected_records": validation.counts.rejected_records,
        "eval_cases": validation.counts.eval_cases,
        "findings": [finding.model_dump(mode="json") for finding in validation.findings],
    }


def _unchanged_row(
    bundle: Path,
    identity: dict[str, Any],
    validation: KnowledgeBundleValidationResult,
) -> dict[str, Any]:
    row = _review_row(bundle, validation, identity)
    row.update(
        {
            "status": "skipped_unchanged",
            "action": "skip_unchanged",
            "reasons": ["bundle already applied and source/approved hashes are unchanged"],
            "record_results": [],
            "applied_count": 0,
            "skipped_count": validation.counts.approved_records,
        }
    )
    return row


def _blocked_changed_row(
    bundle: Path,
    identity: dict[str, Any],
    existing: dict[str, Any],
    validation: KnowledgeBundleValidationResult,
) -> dict[str, Any]:
    row = _review_row(bundle, validation, identity)
    reasons = ["bundle was already applied but source_hash or approved_records_hash changed"]
    if existing.get("source_hash") != identity["source_hash"]:
        reasons.append("source_hash changed")
    if existing.get("approved_records_hash") != identity["approved_records_hash"]:
        reasons.append("approved_records_hash changed")
    row.update(
        {
            "status": "changed_blocked",
            "action": "block_changed",
            "reasons": reasons,
            "previous_identity": existing,
            "record_results": [],
            "applied_count": 0,
            "skipped_count": 0,
        }
    )
    return row


def _invalid_or_unapproved_row(
    bundle: Path,
    identity: dict[str, Any],
    validation: KnowledgeBundleValidationResult,
) -> dict[str, Any]:
    row = _review_row(bundle, validation, identity)
    status = "unapproved" if validation.passed and not validation.review_approved else "invalid"
    row.update(
        {
            "status": status,
            "action": "manual_review_required" if status == "unapproved" else "blocked_invalid",
            "reasons": [finding.message for finding in validation.errors] or ["review.yaml is not approved"],
            "record_results": [],
            "applied_count": 0,
            "skipped_count": 0,
        }
    )
    return row


def _apply_row(
    bundle: Path,
    identity: dict[str, Any],
    result: KnowledgeBundleApplyResult,
) -> dict[str, Any]:
    status = "applied" if result.passed else "apply_failed"
    return {
        "bundle": bundle.name,
        "bundle_path": str(bundle),
        "identity": identity,
        "status": status,
        "action": status,
        "approved": result.validation_passed,
        "approved_records": result.applied_count + result.skipped_count,
        "applied_count": result.applied_count,
        "skipped_count": result.skipped_count,
        "record_results": result.record_results,
        "findings": [finding.model_dump(mode="json") for finding in result.findings],
        "reasons": [finding.message for finding in result.findings if finding.severity == "error"],
        "applied_records_path": result.applied_records_path,
        "apply_report_path": result.apply_report_path,
    }


def _registry_row(
    bundle: Path,
    identity: dict[str, Any],
    result: KnowledgeBundleApplyResult,
) -> dict[str, Any]:
    row = dict(identity)
    row.update(
        {
            "bundle_path": str(bundle),
            "applied_at": datetime.now(UTC).isoformat(),
            "applied_count": result.applied_count,
            "skipped_count": result.skipped_count,
            "destination_files": sorted(
                {
                    record["destination_file"]
                    for record in result.record_results
                    if record.get("status") == "applied"
                }
            ),
        }
    )
    return row


def _review_report(root: Path, target: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "report_type": "knowledge_bundle_review",
        "generated_at": datetime.now(UTC).isoformat(),
        "extracted_root": str(root),
        "knowledge_dir": str(target),
        "counts": {
            "scanned_bundles": len(rows),
            "valid_bundles": sum(1 for row in rows if row["status"] == "valid"),
            "invalid_bundles": sum(1 for row in rows if row["status"] == "invalid"),
            "approved_bundles": sum(1 for row in rows if row["approved"]),
            "manual_review_bundles": sum(1 for row in rows if row["status"] == "manual_review"),
            "approved_record_count": sum(int(row["approved_records"]) for row in rows),
        },
        "bundles": rows,
    }


def _delta_report(root: Path, target: Path, rows: list[dict[str, Any]], *, dry_run: bool) -> dict[str, Any]:
    return {
        "report_type": "knowledge_bundle_delta",
        "generated_at": datetime.now(UTC).isoformat(),
        "dry_run": dry_run,
        "extracted_root": str(root),
        "knowledge_dir": str(target),
        "counts": {
            "scanned_bundles": len(rows),
            "new_bundles": sum(1 for row in rows if row["status"] in {"new_approved", "applied"}),
            "newly_applied_bundles": sum(1 for row in rows if row["status"] == "applied"),
            "skipped_unchanged_bundles": sum(1 for row in rows if row["status"] == "skipped_unchanged"),
            "blocked_changed_bundles": sum(1 for row in rows if row["status"] == "changed_blocked"),
            "invalid_bundles": sum(1 for row in rows if row["status"] in {"invalid", "apply_failed"}),
            "unapproved_bundles": sum(1 for row in rows if row["status"] == "unapproved"),
            "approved_record_count": sum(int(row.get("approved_records", 0)) for row in rows),
            "skipped_duplicate_records": sum(int(row.get("skipped_count", 0)) for row in rows),
            "applied_record_count": sum(int(row.get("applied_count", 0)) for row in rows),
        },
        "destination_files_changed": sorted(
            {
                record["destination_file"]
                for row in rows
                for record in row.get("record_results", [])
                if record.get("status") == "applied"
            }
        ),
        "bundles": rows,
    }


def _write_batch_report(report_dir: Path, stem: str, report: dict[str, Any]) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / f"{stem}.json").write_text(json.dumps(report, indent=2, sort_keys=True))
    if report["report_type"] == "knowledge_bundle_review":
        md = format_batch_review(report)
    else:
        md = format_delta_apply(report)
    (report_dir / f"{stem}.md").write_text(md + "\n")


def _load_registry(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: invalid registry JSONL: {exc}") from exc
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _append_registry_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _read_yaml_lenient(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text()) or {}
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _read_text_hash_value(path: Path) -> str:
    if not path.exists() or path.is_symlink():
        return ""
    return path.read_text(errors="ignore").strip()


def _hash_file(path: Path) -> str:
    if not path.exists() or path.is_symlink():
        return ""
    return sha256(path.read_bytes()).hexdigest()


def safe_batch_error(exc: Exception) -> str:
    return sanitize_provider_error(str(exc))
