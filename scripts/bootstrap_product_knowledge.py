#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from ic_copilot.product_knowledge import (
    _command_is_dangerous,
    validate_product_knowledge,
)
from ic_copilot.memory import _adapt_decision_moment
from ic_copilot.schemas import CommandRegistryEntry, DecisionMoment


def _read_yaml(path: Path) -> Any:
    if not path.exists():
        return None
    return yaml.safe_load(path.read_text()) or {}


def _write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records))


def _manifest(reviewed_by: str, reviewed_at: str, review_method: str, runtime_usable: bool = True) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "knowledge_status": "externally_reviewed",
        "runtime_usable": runtime_usable,
        "reviewed_by": reviewed_by,
        "reviewed_at": reviewed_at,
        "review_method": review_method,
        "files": {
            "service_catalog": "service_catalog.yaml",
            "command_registry": "command_registry.yaml",
            "decision_moments": "decision_moments.jsonl",
            "verifier_regressions": "verifier_regressions.jsonl",
            "rejected_entities": "rejected_entities.jsonl",
            "stale_question_patterns": "stale_question_patterns.jsonl",
        },
        "safety_rules": {
            "commands_manual_copy_only": True,
            "no_command_execution": True,
            "no_slack_posting": True,
            "no_paging": True,
            "no_remediation": True,
            "historical_facts_require_current_evidence": True,
        },
    }


def _load_candidate_yaml(paths: list[Path], key: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        data = _read_yaml(path)
        if isinstance(data, dict):
            values = data.get(key, [])
        elif isinstance(data, list):
            values = data
        else:
            values = []
        for value in values or []:
            if isinstance(value, dict):
                row = dict(value)
                row["_source_path"] = str(path)
                rows.append(row)
    return rows


def _safe_service_candidate(raw: dict[str, Any]) -> dict[str, Any]:
    entry = dict(raw)
    entry.pop("_source_path", None)
    entry.pop("review_status", None)
    entry.pop("source_case_ids", None)
    if entry.get("kind") not in {None, "service", "team", "unknown"}:
        entry["kind"] = "service"
    entry.setdefault("aliases", [])
    entry.setdefault("status", "active")
    entry.setdefault("ownership", {})
    entry.setdefault("slack", {})
    entry.setdefault("oncall", {})
    entry.setdefault("runbooks", [])
    entry.setdefault("dashboards", [])
    entry.setdefault("known_commands", [])
    entry.setdefault("dependencies", [])
    entry.setdefault("environments", [])
    entry.setdefault("known_signals", [])
    entry.setdefault("unsafe_assumptions", [])
    return entry


def _safe_command_candidate(raw: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    command_text = raw.get("command") or raw.get("command_text") or raw.get("command_text_template") or raw.get("pattern")
    if not command_text:
        return None, "missing command text"
    safe_for_suggestion = raw.get("safe_for_suggestion", True)
    read_only = raw.get("read_only", True)
    if safe_for_suggestion is False or read_only is False:
        return None, "candidate is not read-only/safe_for_suggestion"
    entry = CommandRegistryEntry(
        command=str(command_text),
        target=str(raw.get("target") or raw.get("target_type") or "*"),
        source_service_id=str(raw.get("source_service_id") or raw.get("command_id") or "external_review"),
        requires_human_approval=True,
        allowed_prefixes=raw.get("allowed_prefixes", []),
        command_id=raw.get("command_id"),
        command_type=str(raw.get("command_type") or "exact"),
        pattern=raw.get("pattern"),
        requires_catalog_target=bool(raw.get("requires_catalog_target", False)),
        danger_level="read_only_lookup" if "oncall" in str(raw.get("command_type", "")) else "read_only",
        exact=raw.get("pattern") is None,
    )
    dangerous = _command_is_dangerous(entry)
    if dangerous:
        return None, f"dangerous command: {dangerous}"
    return entry.model_dump(mode="json"), None


def _normalize_memory_candidate(raw: dict[str, Any]) -> dict[str, Any]:
    row = dict(raw)
    row.pop("_source_path", None)
    row.pop("source_case_ids", None)
    row["review_status"] = "externally_reviewed"
    if row.get("quality_score", 0) > 1:
        row["quality_score"] = row["quality_score"] / 10 if row["quality_score"] <= 10 else row["quality_score"] / 100
    row.setdefault("quality_score", 0.8)
    row.setdefault("forbidden_fact_leakage", [])
    row.setdefault("applicability", {})
    return row


def build_bootstrap_plan(args: argparse.Namespace) -> dict[str, Any]:
    source_contract = Path(args.source_contract)
    candidate_catalog_paths = [
        Path(args.source_personal_regression) / "catalog_candidates.review_required.yaml",
        Path(args.source_corpus) / "generated_views/catalog_candidates.review_required.yaml",
    ]
    candidate_command_paths = [
        Path(args.source_personal_regression) / "command_candidates.review_required.yaml",
        Path(args.source_corpus) / "generated_views/command_candidates.review_required.yaml",
    ]
    candidate_memory_paths = [
        Path(args.source_corpus) / "generated_views/personal_decision_moments.review_required.jsonl",
    ]

    catalog_candidates = _load_candidate_yaml(candidate_catalog_paths, "services")
    command_candidates = _load_candidate_yaml(candidate_command_paths, "commands")
    memory_candidates: list[dict[str, Any]] = []
    for path in candidate_memory_paths:
        for row in _read_jsonl(path):
            row["_source_path"] = str(path)
            memory_candidates.append(row)

    plan: dict[str, Any] = {
        "source_contract": str(source_contract),
        "catalog_candidates_seen": len(catalog_candidates),
        "command_candidates_seen": len(command_candidates),
        "decision_moment_candidates_seen": len(memory_candidates),
        "imported_catalog_candidates": [],
        "imported_command_candidates": [],
        "imported_decision_moments": [],
        "rejected_catalog_candidates": [],
        "rejected_command_candidates": [],
        "rejected_decision_moments": [],
    }
    if not args.assume_externally_reviewed:
        plan["rejected_catalog_candidates"] = [
            {"reason": "external review metadata not asserted", "candidate": item} for item in catalog_candidates
        ]
        plan["rejected_command_candidates"] = [
            {"reason": "external review metadata not asserted", "candidate": item} for item in command_candidates
        ]
        plan["rejected_decision_moments"] = [
            {"reason": "external review metadata not asserted", "candidate": item} for item in memory_candidates
        ]
        return plan

    for raw in catalog_candidates:
        if not raw.get("service_id") or not raw.get("canonical_name"):
            plan["rejected_catalog_candidates"].append({"reason": "missing service_id/canonical_name", "candidate": raw})
            continue
        plan["imported_catalog_candidates"].append(_safe_service_candidate(raw))

    for raw in command_candidates:
        entry, reason = _safe_command_candidate(raw)
        if entry is None:
            plan["rejected_command_candidates"].append({"reason": reason or "unsafe command", "candidate": raw})
        else:
            plan["imported_command_candidates"].append(entry)

    for raw in memory_candidates:
        if raw.get("review_status") not in {"review_required", "candidate_human_review_required", "draft"}:
            plan["rejected_decision_moments"].append({"reason": "unexpected candidate status", "candidate": raw})
            continue
        normalized = _normalize_memory_candidate(raw)
        try:
            DecisionMoment.model_validate(_adapt_decision_moment(normalized))
        except Exception as exc:
            plan["rejected_decision_moments"].append(
                {"reason": f"candidate does not validate as product DecisionMoment: {exc}", "candidate": raw}
            )
            continue
        plan["imported_decision_moments"].append(normalized)

    return plan


def _dedupe_services(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for entry in entries:
        key = str(entry.get("service_id") or entry.get("canonical_name", "")).lower()
        if key:
            by_id[key] = entry
    return list(by_id.values())


def _dedupe_commands(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_command: dict[str, dict[str, Any]] = {}
    for entry in entries:
        key = " ".join(str(entry.get("command", "")).lower().split())
        if key:
            by_command[key] = entry
    return list(by_command.values())


def _write_report(output: Path, plan: dict[str, Any], validation: dict[str, Any] | None) -> None:
    report_dir = output / "import_report"
    report_dir.mkdir(parents=True, exist_ok=True)
    payload = {"plan": plan, "validation": validation or {}}
    (report_dir / "migration_report.json").write_text(json.dumps(payload, indent=2, sort_keys=True))
    lines = [
        "# Product Knowledge Migration Report",
        "",
        f"- catalog candidates seen: {plan['catalog_candidates_seen']}",
        f"- command candidates seen: {plan['command_candidates_seen']}",
        f"- DecisionMoment candidates seen: {plan['decision_moment_candidates_seen']}",
        f"- catalog candidates imported: {len(plan['imported_catalog_candidates'])}",
        f"- command candidates imported: {len(plan['imported_command_candidates'])}",
        f"- DecisionMoments imported: {len(plan['imported_decision_moments'])}",
        f"- validation passed: {bool(validation and validation.get('passed'))}",
        "",
    ]
    if validation and validation.get("errors"):
        lines.append("## Validation Errors")
        for error in validation["errors"]:
            lines.append(f"- {error}")
    (report_dir / "migration_report.md").write_text("\n".join(lines))
    _write_yaml(report_dir / "rejected_catalog_candidates.yaml", {"services": plan["rejected_catalog_candidates"]})
    _write_yaml(report_dir / "rejected_command_candidates.yaml", {"commands": plan["rejected_command_candidates"]})
    _write_jsonl(report_dir / "rejected_decision_moments.jsonl", plan["rejected_decision_moments"])


def apply_bootstrap(args: argparse.Namespace, plan: dict[str, Any]) -> dict[str, Any]:
    output = Path(args.output)
    if output.exists() and any(output.iterdir()) and not args.force:
        raise SystemExit(f"{output} already exists. Use --force to overwrite.")
    source_contract = Path(args.source_contract)
    if not (source_contract / "service_catalog.yaml").exists():
        raise SystemExit(f"source contract missing service_catalog.yaml: {source_contract}")

    if output.exists() and args.force:
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    base_catalog_data = _read_yaml(source_contract / "service_catalog.yaml")
    base_catalog_entries = base_catalog_data.get("services", base_catalog_data if isinstance(base_catalog_data, list) else [])
    catalog_entries = _dedupe_services([*base_catalog_entries, *plan["imported_catalog_candidates"]])
    _write_yaml(output / "service_catalog.yaml", {"services": catalog_entries})

    base_command_data = _read_yaml(source_contract / "command_registry.yaml")
    base_commands = base_command_data.get("commands", base_command_data if isinstance(base_command_data, list) else [])
    safe_base_commands = []
    for raw in base_commands:
        item = dict(raw)
        item["requires_human_approval"] = True
        safe_base_commands.append(item)
    commands = _dedupe_commands([*safe_base_commands, *plan["imported_command_candidates"]])
    _write_yaml(output / "command_registry.yaml", {"commands": commands})

    base_moments = _read_jsonl(source_contract / "decision_moments.jsonl")
    all_moments = [*base_moments, *plan["imported_decision_moments"]]
    _write_jsonl(output / "decision_moments.jsonl", all_moments)

    _write_jsonl(output / "verifier_regressions.jsonl", [])
    _write_jsonl(output / "rejected_entities.jsonl", [])
    _write_jsonl(output / "stale_question_patterns.jsonl", [])
    (output / "README.md").write_text(
        "# Local Product Knowledge\n\n"
        "This folder is the private runtime knowledge source for the personal IC Copilot. "
        "Review changes outside the app, validate this folder, then run the local console.\n"
    )
    (output / "incidents").mkdir(exist_ok=True)
    (output / "schemas").mkdir(exist_ok=True)
    _write_yaml(output / "manifest.yaml", _manifest(args.reviewed_by, args.reviewed_at, args.review_method, True))

    validation = validate_product_knowledge(output)
    if not validation.passed:
        _write_yaml(output / "manifest.yaml", _manifest(args.reviewed_by, args.reviewed_at, args.review_method, False))
    validation_payload = {
        "passed": validation.passed,
        "errors": [finding.message for finding in validation.errors],
        "warnings": [finding.message for finding in validation.warnings],
        "counts": validation.counts.model_dump(mode="json"),
    }
    _write_report(output, plan, validation_payload)
    return validation_payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap local_knowledge from reviewed local sources.")
    parser.add_argument("--output", default="local_knowledge")
    parser.add_argument("--source-contract", default="data/contract")
    parser.add_argument("--source-personal-regression", default="data/personal_regression")
    parser.add_argument("--source-corpus", default=".ic_copilot/personal_corpus")
    parser.add_argument("--source-product-readiness", default=".ic_copilot/product_readiness")
    parser.add_argument("--reviewed-by", default="")
    parser.add_argument("--review-method", default="")
    parser.add_argument("--reviewed-at", default="")
    parser.add_argument("--assume-externally-reviewed", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    args.reviewed_at = args.reviewed_at or datetime.now(UTC).date().isoformat()
    if args.apply and (not args.reviewed_by or not args.review_method):
        raise SystemExit("--apply requires --reviewed-by and --review-method")

    plan = build_bootstrap_plan(args)
    if args.apply:
        validation = apply_bootstrap(args, plan)
        print(json.dumps({"applied": True, "output": args.output, "validation": validation}, indent=2))
        return 0 if validation["passed"] else 1
    print(json.dumps({"applied": False, "output": args.output, "plan": plan}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
