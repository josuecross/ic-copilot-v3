from __future__ import annotations

import json
import shutil
from pathlib import Path

import yaml

from ic_copilot.knowledge_bundle import (
    apply_approved_knowledge_bundle,
    format_apply_result,
    validate_knowledge_bundle,
)
from ic_copilot.knowledge_bundle_compiler import compile_knowledge_bundle


SAMPLE_BUNDLE = Path("data/sample/knowledge_bundle_intake/owner_aligned_bundle")


def _copy_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    shutil.copytree(SAMPLE_BUNDLE, bundle)
    return bundle


def _copy_knowledge(tmp_path: Path) -> Path:
    knowledge = tmp_path / "local_knowledge"
    shutil.copytree("data/product_knowledge_example", knowledge)
    return knowledge


def _read_single_jsonl(path: Path) -> dict:
    return json.loads(path.read_text().splitlines()[0])


def _write_single_jsonl(path: Path, record: dict) -> None:
    path.write_text(json.dumps(record, sort_keys=True) + "\n")


def _blank_legacy_proposed(bundle: Path) -> None:
    proposed = bundle / "proposed"
    for filename in (
        "decision_moments.proposed.jsonl",
        "rejected_entities.proposed.jsonl",
        "stale_question_patterns.proposed.jsonl",
        "verifier_regressions.proposed.jsonl",
        "eval_cases.proposed.jsonl",
    ):
        (proposed / filename).write_text("")
    (proposed / "service_catalog.proposed.yaml").write_text("services: []\n")


def _add_extracted_notes(bundle: Path, *, candidate_patterns: str) -> Path:
    extracted = bundle / "extracted"
    extracted.mkdir(exist_ok=True)
    (extracted / "incident_learning.md").write_text(
        "# Incident Learning\n\n"
        "ChatGPT notes are advisory only. Codex must generalize any reusable pattern before runtime apply.\n"
    )
    (extracted / "candidate_patterns.md").write_text(candidate_patterns)
    (extracted / "candidate_eval_scenarios.md").write_text(
        "# Candidate Eval Scenarios\n\n"
        "- Check that visible guidance targets the owner and preserves the unresolved object.\n"
    )
    (extracted / "reviewer_notes.md").write_text(
        "# Reviewer Notes\n\n- Reject raw transcript lines and incident-specific identifiers.\n"
    )
    return extracted


def _add_codex_review_shell(bundle: Path) -> Path:
    codex_review = bundle / "codex_review"
    codex_review.mkdir()
    for filename in (
        "compile_plan.md",
        "approved_knowledge.md",
        "rejected_knowledge.md",
        "generated_records_preview.md",
    ):
        (codex_review / filename).write_text(f"# {filename}\n")
    return codex_review


def _snapshot_tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_review_bundle_accepts_owner_aligned_sample() -> None:
    result = validate_knowledge_bundle(SAMPLE_BUNDLE, knowledge_dir="data/product_knowledge_example")
    assert result.passed
    assert result.counts.approved_records == 1
    assert result.counts.eval_cases == 1


def test_review_bundle_blocks_unexpected_files_and_symlink_escape(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    (bundle / "proposed" / "unexpected.txt").write_text("not part of the bundle contract")
    (bundle / "source" / "raw.sanitized.txt").unlink()
    (tmp_path / "outside.txt").write_text("outside")
    (bundle / "source" / "raw.sanitized.txt").symlink_to(tmp_path / "outside.txt")

    result = validate_knowledge_bundle(bundle, knowledge_dir="data/product_knowledge_example")

    categories = {finding.category for finding in result.findings}
    assert not result.passed
    assert "unexpected_bundle_path" in categories
    assert "bundle_symlink_path" in categories


def test_review_bundle_blocks_source_hash_mismatch(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    (bundle / "source" / "source_hash.txt").write_text("0" * 64)

    result = validate_knowledge_bundle(bundle, knowledge_dir="data/product_knowledge_example")

    assert not result.passed
    assert any(finding.category == "source_hash_mismatch" for finding in result.findings)


def test_review_bundle_blocks_bad_owner_eval_case(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    codex_review = _add_codex_review_shell(bundle)
    path = codex_review / "generated_eval_cases.jsonl"
    record = _read_single_jsonl(bundle / "proposed" / "eval_cases.proposed.jsonl")
    record["expected_read"]["selected_target_display_name"] = "Security Lead"
    record["expected_read"]["say_this"] = "Security Lead, can you give ETA for the input validation fix?"
    _write_single_jsonl(path, record)

    result = validate_knowledge_bundle(bundle, knowledge_dir="data/product_knowledge_example")

    categories = {finding.category for finding in result.findings}
    assert not result.passed
    assert "eval_case_bad_owner_ask" in categories


def test_review_bundle_blocks_raw_source_leak_outside_source(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    codex_review = _add_codex_review_shell(bundle)
    raw_text = (bundle / "source" / "raw.sanitized.txt").read_text().strip()
    (codex_review / "approved_knowledge.md").write_text(raw_text)

    result = validate_knowledge_bundle(bundle, knowledge_dir="data/product_knowledge_example")

    assert not result.passed
    assert any(finding.category == "raw_source_leaked_outside_source" for finding in result.findings)


def test_review_bundle_treats_old_proposed_as_advisory_notes(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    raw_text = (bundle / "source" / "raw.sanitized.txt").read_text().strip()
    (bundle / "proposed" / "stale_question_patterns.proposed.jsonl").write_text(
        json.dumps({"id": "stale_raw_leak", "pattern": raw_text}) + "\n"
    )

    result = validate_knowledge_bundle(bundle, knowledge_dir="data/product_knowledge_example")

    assert result.passed


def test_review_bundle_blocks_private_identifiers_in_reusable_records(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    path = bundle / "reviewed" / "approved_records.jsonl"
    envelope = _read_single_jsonl(path)
    envelope["record"]["ic_action"] = "Ask the owner for status without referencing PSG-1843."
    _write_single_jsonl(path, envelope)

    result = validate_knowledge_bundle(bundle, knowledge_dir="data/product_knowledge_example")

    assert not result.passed
    assert any(finding.category == "private_identifier_detected" for finding in result.findings)


def test_review_bundle_blocks_structured_customer_identifier(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    path = bundle / "reviewed" / "approved_records.jsonl"
    envelope = _read_single_jsonl(path)
    envelope["record"]["applicability"]["affected_customer"] = "Acme Corp"
    _write_single_jsonl(path, envelope)

    result = validate_knowledge_bundle(bundle, knowledge_dir="data/product_knowledge_example")

    assert not result.passed
    assert any(finding.category == "customer_specific_identifier" for finding in result.findings)


def test_review_bundle_blocks_absolute_or_traversal_paths_in_records(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    path = bundle / "reviewed" / "approved_records.jsonl"
    envelope = _read_single_jsonl(path)
    envelope["record"]["ic_action"] = "See https://runbooks.example.local/path and write this to /tmp/unsafe-output.json"
    _write_single_jsonl(path, envelope)

    result = validate_knowledge_bundle(bundle, knowledge_dir="data/product_knowledge_example")

    assert not result.passed
    assert any(finding.category == "forbidden_path_reference" for finding in result.findings)


def test_review_bundle_allows_regular_urls_in_reusable_records(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    path = bundle / "reviewed" / "approved_records.jsonl"
    envelope = _read_single_jsonl(path)
    envelope["record"]["ic_action"] = "Ask the owner to confirm the dashboard signal at https://telemetry.example.local/d/general-health."
    _write_single_jsonl(path, envelope)

    result = validate_knowledge_bundle(bundle, knowledge_dir="data/product_knowledge_example")

    assert result.passed


def test_review_bundle_blocks_unhandled_duplicate_existing_id(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    path = bundle / "reviewed" / "approved_records.jsonl"
    envelope = _read_single_jsonl(path)
    envelope["id"] = "DM_codefix_eta_blocker"
    envelope["record"]["decision_id"] = "DM_codefix_eta_blocker"
    envelope["record"]["ic_action"] = "Ask the implementation owner for generalized code-fix status and ETA."
    _write_single_jsonl(path, envelope)

    result = validate_knowledge_bundle(bundle, knowledge_dir="data/product_knowledge_example")

    assert not result.passed
    assert any(finding.category == "duplicate_existing_id" for finding in result.findings)


def test_review_bundle_blocks_duplicate_approved_records(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    path = bundle / "reviewed" / "approved_records.jsonl"
    record = _read_single_jsonl(path)
    path.write_text(json.dumps(record, sort_keys=True) + "\n" + json.dumps(record, sort_keys=True) + "\n")

    result = validate_knowledge_bundle(bundle, knowledge_dir="data/product_knowledge_example")

    assert not result.passed
    assert any(finding.category == "duplicate_approved_id" for finding in result.findings)


def test_apply_refuses_proposed_records_without_approval(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    knowledge = _copy_knowledge(tmp_path)
    (bundle / "reviewed" / "approved_records.jsonl").write_text("")

    result = apply_approved_knowledge_bundle(bundle, knowledge_dir=knowledge)

    assert not result.passed
    assert not result.applied
    assert any(finding.category == "no_approved_records" for finding in result.findings)
    assert "DM_security_workflow_owner_eta" not in (knowledge / "decision_moments.jsonl").read_text()


def test_apply_merges_only_reviewed_records_and_is_idempotent(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    knowledge = _copy_knowledge(tmp_path)
    proposed_catalog = bundle / "proposed" / "service_catalog.proposed.yaml"
    proposed_catalog.write_text(
        yaml.safe_dump(
            {"services": [{"service_id": "proposed_only_service", "canonical_name": "Proposed Only"}]},
            sort_keys=False,
        )
    )

    result = apply_approved_knowledge_bundle(bundle, knowledge_dir=knowledge)

    assert result.passed
    assert result.applied
    assert result.applied_count == 1
    assert (bundle / "applied" / "apply_report.md").exists()
    assert (bundle / "applied" / "applied_records.jsonl").exists()
    report = (bundle / "applied" / "apply_report.md").read_text()
    assert "## Counts By Record Type" in report
    assert "local_knowledge/decision_moments.jsonl" in report
    assert "bad_owner_ask_security_input_validation" in report
    assert "DM_security_workflow_owner_eta" in (knowledge / "decision_moments.jsonl").read_text()
    assert "proposed_only_service" not in (knowledge / "service_catalog.yaml").read_text()

    second = apply_approved_knowledge_bundle(bundle, knowledge_dir=knowledge)

    assert second.passed
    assert not second.applied
    assert second.applied_count == 0
    assert second.skipped_count == 1


def test_apply_dry_run_prints_plan_without_mutating_local_knowledge_or_bundle(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    knowledge = _copy_knowledge(tmp_path)
    before_knowledge = _snapshot_tree(knowledge)
    assert not (bundle / "applied").exists()

    result = apply_approved_knowledge_bundle(bundle, knowledge_dir=knowledge, dry_run=True)

    assert result.passed
    assert result.dry_run
    assert result.applied_count == 1
    assert result.record_results == [
        {
            "id": "DM_security_workflow_owner_eta",
            "record_type": "decision_moment",
            "status": "applied",
            "destination_file": "decision_moments.jsonl",
        }
    ]
    output = format_apply_result(result)
    assert "records: would_apply=1 would_skip=0" in output
    assert "would apply: decision_moment DM_security_workflow_owner_eta" in output
    assert _snapshot_tree(knowledge) == before_knowledge
    assert not (bundle / "applied").exists()


def test_apply_refuses_malformed_approved_records_jsonl(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    knowledge = _copy_knowledge(tmp_path)
    before_knowledge = _snapshot_tree(knowledge)
    (bundle / "reviewed" / "approved_records.jsonl").write_text("{bad json\n")

    result = apply_approved_knowledge_bundle(bundle, knowledge_dir=knowledge)

    assert not result.passed
    assert not result.applied
    assert any(finding.category == "invalid_jsonl" for finding in result.findings)
    assert _snapshot_tree(knowledge) == before_knowledge


def test_apply_never_merges_raw_text_or_eval_cases(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    knowledge = _copy_knowledge(tmp_path)
    raw_text = (bundle / "source" / "raw.sanitized.txt").read_text().strip()
    eval_id = "security_workflow_owner_aligned_eta"

    result = apply_approved_knowledge_bundle(bundle, knowledge_dir=knowledge)

    assert result.passed
    runtime_text = "\n".join(path.read_text(errors="ignore") for path in knowledge.rglob("*") if path.is_file())
    assert raw_text not in runtime_text
    assert eval_id not in runtime_text


def test_apply_refuses_unapproved_review(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    knowledge = _copy_knowledge(tmp_path)
    review_path = bundle / "reviewed" / "review.yaml"
    review = yaml.safe_load(review_path.read_text())
    review["status"] = "needs_review"
    review["approved"] = False
    review_path.write_text(yaml.safe_dump(review, sort_keys=False))

    result = apply_approved_knowledge_bundle(bundle, knowledge_dir=knowledge)

    assert not result.passed
    assert not result.applied
    assert "DM_security_workflow_owner_eta" not in (knowledge / "decision_moments.jsonl").read_text()


def test_codex_semantic_compiler_writes_final_reviewed_records_from_advisory_proposed(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    knowledge = _copy_knowledge(tmp_path)
    approved_path = bundle / "reviewed" / "approved_records.jsonl"
    approved_path.write_text("")
    proposed_path = bundle / "proposed" / "decision_moments.proposed.jsonl"
    record = _read_single_jsonl(proposed_path)
    record["decision_id"] = "DM_compile_owner_aligned_eta"
    _write_single_jsonl(proposed_path, record)

    result = compile_knowledge_bundle(bundle, knowledge_dir=knowledge)

    assert result.validation_passed
    assert result.review_approved
    assert result.approved_count >= 1
    assert (bundle / "codex_review" / "compile_plan.md").exists()
    assert (bundle / "codex_review" / "generated_records_preview.md").exists()
    approved = [
        json.loads(line)
        for line in approved_path.read_text().splitlines()
        if line.strip()
    ]
    assert all(row["record_type"] != "eval_case" for row in approved)
    assert all(row["source_policy"] == "compiled_from_untrusted_advisory_notes" for row in approved)


def test_codex_semantic_compiler_maps_unsupported_customer_impact_move(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    proposed_path = bundle / "proposed" / "decision_moments.proposed.jsonl"
    record = _read_single_jsonl(proposed_path)
    record["decision_id"] = "DM_compile_customer_impact_alias"
    record["move"] = "request_customer_impact"
    record["behavior_hint"] = "When customer impact is missing, ask the customer-facing owner to confirm current impact scope."
    record["applies_when"] = ["current incident has unresolved customer impact"]
    record["required_current_evidence"] = ["customer impact question is open", "customer-facing owner is present"]
    record["allowed_visible_output_pattern"] = "@{support_owner}, can you confirm current customer impact scope?"
    _write_single_jsonl(proposed_path, record)

    result = compile_knowledge_bundle(bundle, knowledge_dir=_copy_knowledge(tmp_path))

    assert result.validation_passed
    approved = [
        json.loads(line)
        for line in (bundle / "reviewed" / "approved_records.jsonl").read_text().splitlines()
        if line.strip()
    ]
    compiled = [row for row in approved if row["id"] == "DM_compile_customer_impact_alias"]
    assert compiled
    assert compiled[0]["record"]["move"] == "ask_impact"


def test_codex_semantic_compiler_compiles_extracted_markdown_notes(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    _blank_legacy_proposed(bundle)
    (bundle / "reviewed" / "approved_records.jsonl").write_text("")
    extracted = _add_extracted_notes(
        bundle,
        candidate_patterns=(
            "# Candidate Patterns\n\n"
            "- Data Loader partial mitigation: scale-up improves capacity for new work, but existing jobs, "
            "stuck jobs, backlog, or in-flight jobs may still be waiting.\n"
            "- Ask Data Loader Engineering for the application-layer signal proving existing jobs are "
            "decreasing or recovered.\n"
            "- Do not suggest restarting, deleting, retrying, draining, or executing remediation.\n"
        ),
    )
    (extracted / ".DS_Store").write_text("DM_noise_should_not_be_seen")

    result = compile_knowledge_bundle(bundle, knowledge_dir=_copy_knowledge(tmp_path))

    assert result.validation_passed
    assert result.review_approved
    assert "DM_partial_mitigation_remaining_impact" in result.approved_ids
    assert "DM_noise_should_not_be_seen" not in result.approved_ids
    approved_text = (bundle / "reviewed" / "approved_records.jsonl").read_text()
    assert "existing jobs/backlog/in-flight work" in approved_text
    eval_text = (bundle / "codex_review" / "generated_eval_cases.jsonl").read_text()
    assert "existing jobs" in eval_text


def test_codex_semantic_compiler_normalizes_legacy_partial_mitigation_proposal(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    proposed_path = bundle / "proposed" / "decision_moments.proposed.jsonl"
    record = _read_single_jsonl(proposed_path)
    record["decision_id"] = "DM_partial_mitigation_remaining_impact"
    record["move"] = "request_monitoring_signal"
    record["behavior_hint"] = (
        "When a partial mitigation is complete but current evidence says existing work remains stalled, "
        "ask for the remaining impact signal and app-layer recovery indicator."
    )
    record["applies_when"] = ["Current evidence says a mitigation or capacity change completed."]
    record["required_current_evidence"] = ["completed partial mitigation"]
    record["allowed_visible_output_pattern"] = (
        "@{service_owner}, now that {partial_mitigation} is complete, can you confirm what app-side signal "
        "we should monitor for recovery?"
    )
    _write_single_jsonl(proposed_path, record)

    result = compile_knowledge_bundle(bundle, knowledge_dir=_copy_knowledge(tmp_path))

    assert result.validation_passed
    approved = [
        json.loads(line)
        for line in (bundle / "reviewed" / "approved_records.jsonl").read_text().splitlines()
        if line.strip()
    ]
    compiled = [row for row in approved if row["id"] == "DM_partial_mitigation_remaining_impact"]
    assert compiled
    decision = compiled[0]["record"]
    assert "existing jobs/backlog/in-flight work" in decision["ic_action"]
    assert "Do not suggest restarting" in decision["situation_before"]


def test_codex_semantic_compiler_sanitizes_temporary_traffic_control_guidance(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    proposed_path = bundle / "proposed" / "decision_moments.proposed.jsonl"
    record = _read_single_jsonl(proposed_path)
    record["decision_id"] = "DM_temporary_traffic_controls_need_owner_status_and_reversibility"
    record["move"] = "request_status_or_eta"
    record["behavior_hint"] = (
        "When WAF blocking or temporary traffic controls are used, ask for status and rollback/unblock plan."
    )
    record["applies_when"] = ["Current incident mentions WAF blocking or temporary traffic controls."]
    record["required_current_evidence"] = ["temporary traffic control", "named owner"]
    record["allowed_visible_output_pattern"] = (
        "@{owner}, can you share status, monitoring, and rollback/unblock path?"
    )
    _write_single_jsonl(proposed_path, record)

    result = compile_knowledge_bundle(bundle, knowledge_dir=_copy_knowledge(tmp_path))

    assert result.validation_passed
    approved = [
        json.loads(line)
        for line in (bundle / "reviewed" / "approved_records.jsonl").read_text().splitlines()
        if line.strip()
    ]
    compiled = [
        row
        for row in approved
        if row["id"] == "DM_temporary_traffic_controls_need_owner_status_and_reversibility"
    ]
    assert compiled
    record_text = json.dumps(compiled[0]["record"], sort_keys=True)
    assert "rollback/unblock" not in record_text
    assert "what criteria show the temporary control is no longer needed" in record_text
    assert "Do not tell the team to block, unblock, scale, execute, disable" in record_text


def test_codex_semantic_compiler_removes_eval_required_forbidden_contradictions(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    eval_path = bundle / "proposed" / "eval_cases.proposed.jsonl"
    record = _read_single_jsonl(eval_path)
    record["fixture_id"] = "EV_compiler_conflicting_terms"
    record["case_id"] = "EV_compiler_conflicting_terms"
    record["required_visible_terms"] = ["after the restart", "status", "rollback"]
    record["forbidden_visible_terms"] = ["restart", "execute", "rollback"]
    _write_single_jsonl(eval_path, record)

    result = compile_knowledge_bundle(bundle, knowledge_dir=_copy_knowledge(tmp_path))

    assert result.validation_passed
    cases = [
        json.loads(line)
        for line in (bundle / "codex_review" / "generated_eval_cases.jsonl").read_text().splitlines()
        if line.strip()
    ]
    compiled = [case for case in cases if case["fixture_id"] == "EV_compiler_conflicti_h17d2e"]
    assert compiled
    case = compiled[0]
    assert "post-action validation" in case["required_visible_terms"]
    assert "reversibility criteria" in case["required_visible_terms"]
    assert "restart" in case["forbidden_visible_terms"]
    assert "rollback" in case["forbidden_visible_terms"]
    assert all(
        forbidden.lower() not in required.lower()
        for forbidden in case["forbidden_visible_terms"]
        for required in case["required_visible_terms"]
    )


def test_codex_semantic_compiler_is_idempotent_for_approved_records(tmp_path: Path) -> None:
    bundle = _copy_bundle(tmp_path)
    knowledge = _copy_knowledge(tmp_path)
    proposed_path = bundle / "proposed" / "decision_moments.proposed.jsonl"
    record = _read_single_jsonl(proposed_path)
    record["decision_id"] = "DM_compile_idempotent_owner_eta"
    _write_single_jsonl(proposed_path, record)

    first = compile_knowledge_bundle(bundle, knowledge_dir=knowledge)
    approved_once = (bundle / "reviewed" / "approved_records.jsonl").read_text()
    second = compile_knowledge_bundle(bundle, knowledge_dir=knowledge)
    approved_twice = (bundle / "reviewed" / "approved_records.jsonl").read_text()

    assert first.validation_passed
    assert second.validation_passed
    assert approved_once == approved_twice
