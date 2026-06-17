from __future__ import annotations

import json
import shutil
from hashlib import sha256
from pathlib import Path

import yaml

from ic_copilot.knowledge_bundle_batch import (
    apply_extracted_knowledge_delta,
    compute_bundle_identity,
    review_extracted_knowledge_bundles,
)


SAMPLE_BUNDLE = Path("data/sample/knowledge_bundle_intake/owner_aligned_bundle")


def _copy_knowledge(tmp_path: Path) -> Path:
    knowledge = tmp_path / "local_knowledge"
    shutil.copytree("data/product_knowledge_example", knowledge)
    return knowledge


def _copy_bundle(root: Path, name: str, decision_id: str) -> Path:
    bundle = root / name
    shutil.copytree(SAMPLE_BUNDLE, bundle)
    manifest_path = bundle / "manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text())
    manifest["incident_slug"] = name
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))

    proposed_path = bundle / "proposed" / "decision_moments.proposed.jsonl"
    proposed = json.loads(proposed_path.read_text().splitlines()[0])
    proposed["decision_id"] = decision_id
    proposed["source_incident_id"] = f"generalized_{name}"
    proposed_path.write_text(json.dumps(proposed, sort_keys=True) + "\n")

    approved_path = bundle / "reviewed" / "approved_records.jsonl"
    envelope = json.loads(approved_path.read_text().splitlines()[0])
    envelope["id"] = decision_id
    envelope["record"]["decision_id"] = decision_id
    envelope["record"]["source_incident_id"] = f"generalized_{name}"
    approved_path.write_text(json.dumps(envelope, sort_keys=True) + "\n")
    return bundle


def _snapshot_tree(root: Path) -> dict[str, bytes]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _rewrite_source_hash(bundle: Path) -> None:
    raw_path = bundle / "source" / "raw.sanitized.txt"
    digest = sha256(raw_path.read_bytes()).hexdigest()
    (bundle / "source" / "source_hash.txt").write_text(digest + "\n")


def test_batch_review_scans_multiple_bundles(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    _copy_bundle(extracted, "incident_one", "DM_batch_incident_one")
    _copy_bundle(extracted, "incident_two", "DM_batch_incident_two")

    report = review_extracted_knowledge_bundles(
        extracted,
        knowledge_dir="data/product_knowledge_example",
        require_review_approved=True,
        write_report=False,
    )

    assert report["counts"]["scanned_bundles"] == 2
    assert report["counts"]["valid_bundles"] == 2
    assert report["counts"]["approved_bundles"] == 2


def test_batch_review_can_compile_before_validation(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    bundle = _copy_bundle(extracted, "incident_one", "DM_batch_compile_incident_one")
    (bundle / "reviewed" / "approved_records.jsonl").write_text("")

    report = review_extracted_knowledge_bundles(
        extracted,
        knowledge_dir="data/product_knowledge_example",
        require_review_approved=True,
        compile_before_review=True,
        write_report=False,
    )

    assert report["counts"]["scanned_bundles"] == 1
    assert report["counts"]["valid_bundles"] == 1
    assert report["counts"]["approved_bundles"] == 1
    assert report["bundles"][0]["compile_result"]["approved_count"] >= 1
    assert (bundle / "codex_review" / "compile_plan.md").exists()


def test_delta_skips_already_applied_and_applies_new_bundle(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    knowledge = _copy_knowledge(tmp_path)
    registry = tmp_path / "registry" / "applied_bundles.jsonl"
    reports = tmp_path / "reports"
    first = _copy_bundle(extracted, "incident_one", "DM_batch_incident_one")

    first_report = apply_extracted_knowledge_delta(
        extracted,
        knowledge_dir=knowledge,
        registry_path=registry,
        report_dir=reports,
        dry_run=False,
    )
    assert first_report["counts"]["newly_applied_bundles"] == 1
    assert registry.exists()

    _copy_bundle(extracted, "incident_two", "DM_batch_incident_two")
    second_report = apply_extracted_knowledge_delta(
        extracted,
        knowledge_dir=knowledge,
        registry_path=registry,
        report_dir=reports,
        dry_run=True,
        write_report=False,
    )

    assert second_report["counts"]["skipped_unchanged_bundles"] == 1
    assert second_report["counts"]["new_bundles"] == 1
    rows = {row["bundle"]: row for row in second_report["bundles"]}
    assert rows[first.name]["status"] == "skipped_unchanged"
    assert rows["incident_two"]["action"] == "would_apply"


def test_delta_blocks_changed_already_applied_bundle_without_mutating_new_bundle(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    knowledge = _copy_knowledge(tmp_path)
    registry = tmp_path / "registry" / "applied_bundles.jsonl"
    first = _copy_bundle(extracted, "incident_one", "DM_batch_incident_one")

    apply_extracted_knowledge_delta(
        extracted,
        knowledge_dir=knowledge,
        registry_path=registry,
        report_dir=tmp_path / "reports",
    )
    _copy_bundle(extracted, "incident_two", "DM_batch_incident_two")
    (first / "source" / "raw.sanitized.txt").write_text("[10:00] Coordinator: changed sanitized audit text.\n")
    _rewrite_source_hash(first)
    before_knowledge = _snapshot_tree(knowledge)
    before_registry = registry.read_bytes()

    report = apply_extracted_knowledge_delta(
        extracted,
        knowledge_dir=knowledge,
        registry_path=registry,
        report_dir=tmp_path / "reports",
    )

    assert report["counts"]["blocked_changed_bundles"] == 1
    assert report["counts"]["newly_applied_bundles"] == 0
    assert _snapshot_tree(knowledge) == before_knowledge
    assert registry.read_bytes() == before_registry
    assert "DM_batch_incident_two" not in (knowledge / "decision_moments.jsonl").read_text()


def test_delta_dry_run_does_not_mutate_knowledge_registry_or_applied_dirs(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    bundle = _copy_bundle(extracted, "incident_one", "DM_batch_incident_one")
    knowledge = _copy_knowledge(tmp_path)
    registry = tmp_path / "registry" / "applied_bundles.jsonl"
    before_knowledge = _snapshot_tree(knowledge)

    report = apply_extracted_knowledge_delta(
        extracted,
        knowledge_dir=knowledge,
        registry_path=registry,
        report_dir=tmp_path / "reports",
        dry_run=True,
        write_report=False,
    )

    assert report["counts"]["new_bundles"] == 1
    assert _snapshot_tree(knowledge) == before_knowledge
    assert not registry.exists()
    assert not (bundle / "applied").exists()


def test_delta_real_apply_updates_registry_after_success(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    bundle = _copy_bundle(extracted, "incident_one", "DM_batch_incident_one")
    knowledge = _copy_knowledge(tmp_path)
    registry = tmp_path / "registry" / "applied_bundles.jsonl"

    report = apply_extracted_knowledge_delta(
        extracted,
        knowledge_dir=knowledge,
        registry_path=registry,
        report_dir=tmp_path / "reports",
    )

    registry_rows = [json.loads(line) for line in registry.read_text().splitlines() if line.strip()]
    assert report["counts"]["newly_applied_bundles"] == 1
    assert len(registry_rows) == 1
    assert registry_rows[0]["identity_hash"] == compute_bundle_identity(bundle)["identity_hash"]
    assert "DM_batch_incident_one" in (knowledge / "decision_moments.jsonl").read_text()


def test_batch_never_merges_source_proposed_or_eval_files(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    bundle = _copy_bundle(extracted, "incident_one", "DM_batch_incident_one")
    knowledge = _copy_knowledge(tmp_path)
    raw_text = (bundle / "source" / "raw.sanitized.txt").read_text().strip()
    proposed_eval_id = "security_workflow_owner_aligned_eta"

    report = apply_extracted_knowledge_delta(
        extracted,
        knowledge_dir=knowledge,
        registry_path=tmp_path / "registry" / "applied_bundles.jsonl",
        report_dir=tmp_path / "reports",
    )

    runtime_text = "\n".join(path.read_text(errors="ignore") for path in knowledge.rglob("*") if path.is_file())
    assert report["counts"]["newly_applied_bundles"] == 1
    assert raw_text not in runtime_text
    assert proposed_eval_id not in runtime_text


def test_proposed_only_bundle_is_not_applied(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    _copy_bundle(extracted, "incident_one", "DM_batch_incident_one")
    (extracted / "incident_one" / "reviewed" / "approved_records.jsonl").write_text("")
    knowledge = _copy_knowledge(tmp_path)

    report = apply_extracted_knowledge_delta(
        extracted,
        knowledge_dir=knowledge,
        registry_path=tmp_path / "registry" / "applied_bundles.jsonl",
        report_dir=tmp_path / "reports",
    )

    assert report["counts"]["invalid_bundles"] == 1
    assert report["counts"]["newly_applied_bundles"] == 0
    assert "DM_batch_incident_one" not in (knowledge / "decision_moments.jsonl").read_text()


def test_missing_review_approval_fails_closed_in_batch(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    bundle = _copy_bundle(extracted, "incident_one", "DM_batch_incident_one")
    review_path = bundle / "reviewed" / "review.yaml"
    review = yaml.safe_load(review_path.read_text())
    review["status"] = "needs_review"
    review["approved"] = False
    review_path.write_text(yaml.safe_dump(review, sort_keys=False))

    report = apply_extracted_knowledge_delta(
        extracted,
        knowledge_dir=_copy_knowledge(tmp_path),
        registry_path=tmp_path / "registry" / "applied_bundles.jsonl",
        report_dir=tmp_path / "reports",
    )

    assert report["counts"]["invalid_bundles"] == 1
    assert report["bundles"][0]["action"] == "blocked_invalid"


def test_duplicate_approved_records_fail_closed_in_batch(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    bundle = _copy_bundle(extracted, "incident_one", "DM_batch_incident_one")
    approved_path = bundle / "reviewed" / "approved_records.jsonl"
    line = approved_path.read_text().strip()
    approved_path.write_text(line + "\n" + line + "\n")

    report = apply_extracted_knowledge_delta(
        extracted,
        knowledge_dir=_copy_knowledge(tmp_path),
        registry_path=tmp_path / "registry" / "applied_bundles.jsonl",
        report_dir=tmp_path / "reports",
    )

    assert report["counts"]["invalid_bundles"] == 1
    assert any("Duplicate approved id" in reason for reason in report["bundles"][0]["reasons"])


def test_malformed_or_unsafe_bundle_fails_closed_in_batch(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    bundle = _copy_bundle(extracted, "incident_one", "DM_batch_incident_one")
    (bundle / "reviewed" / "approved_records.jsonl").write_text("{bad json\n")

    report = apply_extracted_knowledge_delta(
        extracted,
        knowledge_dir=_copy_knowledge(tmp_path),
        registry_path=tmp_path / "registry" / "applied_bundles.jsonl",
        report_dir=tmp_path / "reports",
    )

    assert report["counts"]["invalid_bundles"] == 1
    assert any("invalid JSONL" in reason for reason in report["bundles"][0]["reasons"])


def test_batch_report_includes_counts_and_reasons(tmp_path: Path) -> None:
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    _copy_bundle(extracted, "incident_one", "DM_batch_incident_one")
    knowledge = _copy_knowledge(tmp_path)
    reports = tmp_path / "reports"

    report = apply_extracted_knowledge_delta(
        extracted,
        knowledge_dir=knowledge,
        registry_path=tmp_path / "registry" / "applied_bundles.jsonl",
        report_dir=reports,
    )

    report_json = json.loads((reports / "knowledge_bundle_delta_apply.json").read_text())
    report_md = (reports / "knowledge_bundle_delta_apply.md").read_text()
    assert report["counts"]["scanned_bundles"] == 1
    assert report_json["counts"]["newly_applied_bundles"] == 1
    assert "skipped_unchanged=0" in report_md
    assert "decision_moments.jsonl" in report_md
