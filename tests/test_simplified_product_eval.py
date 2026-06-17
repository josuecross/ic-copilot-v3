from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from ic_copilot.schemas import EntityRef, EntityType, ICDecision, ICMove, IncidentPhase, VerifierResult
from ic_copilot.simplified_product_eval import (
    DEFAULT_FIXTURE_PATH,
    SimplifiedProductEvalFixture,
    load_simplified_product_eval_fixtures,
    run_simplified_product_eval,
    score_simplified_product_result,
)


def test_simplified_product_eval_fixtures_have_required_shape() -> None:
    fixtures = load_simplified_product_eval_fixtures(DEFAULT_FIXTURE_PATH)
    assert len(fixtures) >= 10
    required_ids = {
        "security_workflow_input_validation_owner",
        "security_workflow_credential_rotation_owner",
        "security_workflow_audit_logs_owner",
        "ocs_lag_biglobe_sandbox_activity",
        "ocs_lag_kafka_stale_summary_avoidance",
        "revpro_owner_engagement",
        "api_504_revenue_status",
        "db_high_cpu_subscription_order_processed",
        "l3_duplicate_line_status",
        "rpcapd_billing_disk_full",
    }
    assert required_ids.issubset({fixture.fixture_id for fixture in fixtures})
    for fixture in fixtures:
        assert fixture.sanitized_slack_paste.strip()
        assert fixture.expected_read.get("say_this")
        assert fixture.acceptable_move_families
        assert fixture.unacceptable_move_families


def test_simplified_product_eval_catches_old_bimodh_for_workflow_fix_failure() -> None:
    fixture = next(
        item
        for item in load_simplified_product_eval_fixtures(DEFAULT_FIXTURE_PATH)
        if item.fixture_id == "security_workflow_input_validation_owner"
    )
    decision = ICDecision(
        decision_id="bad-owner",
        incident_id=fixture.fixture_id,
        move=ICMove.REQUEST_STATUS_OR_ETA,
        phase=IncidentPhase.UNKNOWN,
        output={
            "say_this": "@Bimodh, when do we need the input validation fix completed, and can it be done within the next 24 hours?"
        },
        target_ids=["t-bimodh"],
        targets=[EntityRef(entity_type=EntityType.PERSON, display_name="Bimodh", status="targeted")],
        confidence=0.7,
    )
    result = {
        "decision": decision,
        "final_output": (
            "SAY THIS:\n"
            "@Bimodh, when do we need the input validation fix completed, and can it be done within the next 24 hours?"
        ),
        "verifier_result": VerifierResult(passed=True, final_status="pass", checks={}, blocked_claims=[]),
    }

    scored = score_simplified_product_result(fixture, result, latency_ms=50)

    assert not scored["passed"]
    assert scored["wrong_owner"]
    assert any(reason.startswith("wrong_owner") for reason in scored["reasons"])


def test_simplified_product_eval_required_term_groups_accept_semantic_aliases() -> None:
    fixture = SimplifiedProductEvalFixture.from_dict(
        {
            "fixture_id": "alias-groups",
            "sanitized_slack_paste": "CacheOps needs recovery signal.",
            "expected_usefulness_tags": ["monitoring_signal"],
            "forbidden_output_patterns": [],
            "acceptable_target_names": ["CacheOps"],
            "unacceptable_target_names": [],
            "acceptable_move_families": ["request_monitoring_signal"],
            "unacceptable_move_families": ["no_safe_recommendation"],
            "required_visible_terms": ["validation", "backlog"],
            "required_visible_term_groups": [
                ["validation", "validate", "confirm", "verification"],
                ["backlog", "queue", "queue depth", "oldest job age", "existing jobs"],
            ],
            "forbidden_visible_terms": [],
            "notes": "Alias groups should allow genuinely equivalent visible wording.",
            "expected_read": {"say_this": "unused"},
        }
    )
    decision = ICDecision(
        decision_id="alias-pass",
        incident_id=fixture.fixture_id,
        move=ICMove.REQUEST_MONITORING_SIGNAL,
        phase=IncidentPhase.UNKNOWN,
        output={"say_this": "CacheOps, can you confirm queue depth and oldest job age?"},
        target_ids=["t-cacheops"],
        targets=[EntityRef(entity_type=EntityType.TEAM, display_name="CacheOps", status="targeted")],
    )
    result = {
        "decision": decision,
        "final_output": "SAY THIS:\nCacheOps, can you confirm queue depth and oldest job age?",
        "verifier_result": VerifierResult(passed=True, final_status="pass", checks={}, blocked_claims=[]),
    }

    scored = score_simplified_product_result(fixture, result, latency_ms=50)

    assert scored["passed"]
    assert any(item["match_type"] == "alias_group" for item in scored["eval_alias_match_summary"])


def test_simplified_product_eval_validation_intent_accepts_verify_confirmation_synonyms() -> None:
    scored = _score_validation_intent_output(
        "Analytics Export Pipeline, can you verify the row-count mismatch and share confirmation before update?"
    )

    assert scored["passed"]
    assert any(
        item["required"] == "validation" and item["matched"] in {"verify", "confirmation"}
        for item in scored["eval_alias_match_summary"]
    )


def test_simplified_product_eval_validation_intent_rejects_generic_status_only() -> None:
    scored = _score_validation_intent_output(
        "Analytics Export Pipeline, can you share the current status of the row-count mismatch before update?"
    )

    assert not scored["passed"]
    assert "missing_visible_terms:validation" in scored["reasons"]


def test_simplified_product_eval_pipeline_validation_direct_ask_passes() -> None:
    scored = _score_validation_intent_output(
        "Pipeline owner, can you validate the billing pipeline row-count mismatch and share the next monitoring signal?",
        fixture_id="holdout_pipeline_validation_after_scope_answer",
        target_name="Pipeline owner",
    )

    assert scored["passed"]


def test_simplified_product_eval_dedupes_duplicate_selected_target_names() -> None:
    fixture = SimplifiedProductEvalFixture.from_dict(
        {
            "fixture_id": "target-dedupe",
            "sanitized_slack_paste": "DACO is validating topic ownership.",
            "expected_usefulness_tags": ["target_dedupe"],
            "forbidden_output_patterns": [],
            "acceptable_target_names": ["DACO"],
            "unacceptable_target_names": [],
            "acceptable_move_families": ["ask_next_validation"],
            "unacceptable_move_families": ["no_safe_recommendation"],
            "required_visible_terms": ["DACO"],
            "forbidden_visible_terms": [],
            "notes": "Duplicate aliases should not render duplicate selected target summaries.",
            "expected_read": {"say_this": "unused"},
        }
    )
    decision = ICDecision(
        decision_id="dedupe",
        incident_id=fixture.fixture_id,
        move=ICMove.ASK_NEXT_VALIDATION,
        phase=IncidentPhase.UNKNOWN,
        output={"say_this": "DACO, can you confirm topic ownership?"},
        target_ids=["t-daco-1", "t-daco-2"],
        targets=[
            EntityRef(entity_type=EntityType.TEAM, display_name="DACO", status="targeted"),
            EntityRef(entity_type=EntityType.TEAM, display_name="DACO", status="targeted"),
        ],
    )
    result = {
        "decision": decision,
        "final_output": "SAY THIS:\nDACO, can you confirm topic ownership?",
        "verifier_result": VerifierResult(passed=True, final_status="pass", checks={}, blocked_claims=[]),
    }

    scored = score_simplified_product_result(fixture, result, latency_ms=50)

    assert scored["selected_target_names"] == ["DACO"]
    assert scored["target_dedup_applied"] is True


def test_simplified_product_eval_passes_current_wenxuan_fixture() -> None:
    fixture = next(
        item
        for item in load_simplified_product_eval_fixtures(DEFAULT_FIXTURE_PATH)
        if item.fixture_id == "security_workflow_input_validation_owner"
    )
    report = run_simplified_product_eval([fixture])

    assert report["passed"]
    assert report["useful_pass_count"] == 1
    case = report["cases"][0]
    assert case["selected_target_names"]
    assert any(name.lower() == "wenxuan" for name in case["selected_target_names"])
    assert "input validation" in case["say_this"].lower()
    assert "action_type" in case["say_this"]


def test_simplified_product_eval_cli_writes_json_and_markdown(tmp_path: Path) -> None:
    output_json = tmp_path / "simplified_product_eval.json"
    output_md = tmp_path / "simplified_product_eval.md"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_simplified_product_eval.py",
            "--output-json",
            str(output_json),
            "--output-md",
            str(output_md),
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(output_json.read_text())
    assert report["passed"]
    assert report["useful_pass_count"] == report["total_cases"]
    assert "security_workflow_input_validation_owner" in output_md.read_text()


def test_simplified_product_eval_normal_run_does_not_call_legacy_semantic_stages(monkeypatch) -> None:
    import ic_copilot.pipeline as pipeline

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("legacy semantic stage should not run in simplified product eval")

    for name in (
        "run_parallel_semantic_read",
        "reduce_ledgers_to_incident_brief",
        "extract_incident_brief",
        "select_authoritative_blocker",
        "build_target_shortlist",
        "assess_output_intent",
        "repair_blocked_decision",
        "build_fallback_workstream_ledger",
    ):
        monkeypatch.setattr(pipeline, name, fail_if_called)

    fixture = next(
        item
        for item in load_simplified_product_eval_fixtures(DEFAULT_FIXTURE_PATH)
        if item.fixture_id == "security_workflow_input_validation_owner"
    )

    report = run_simplified_product_eval([fixture])

    assert report["passed"]
    assert report["cases"][0]["fallback_used"] is False


def _score_validation_intent_output(
    say_this: str,
    *,
    fixture_id: str = "holdout_scope_question_answered_then_validation",
    target_name: str = "Analytics Export Pipeline",
) -> dict:
    fixture = SimplifiedProductEvalFixture.from_dict(
        {
            "fixture_id": fixture_id,
            "sanitized_slack_paste": "Scope is answered; pipeline validation remains.",
            "expected_usefulness_tags": ["scope_answer_superseded", "pipeline_validation"],
            "forbidden_output_patterns": [],
            "acceptable_target_names": [target_name],
            "unacceptable_target_names": [],
            "acceptable_move_families": ["ask_next_validation"],
            "unacceptable_move_families": ["no_safe_recommendation"],
            "required_visible_terms": ["row-count", "validation"],
            "forbidden_visible_terms": [],
            "notes": "Validation-intent fixture should accept narrow validation synonyms.",
            "expected_read": {"say_this": "unused"},
        }
    )
    decision = ICDecision(
        decision_id="validation-intent",
        incident_id=fixture.fixture_id,
        move=ICMove.ASK_NEXT_VALIDATION,
        phase=IncidentPhase.UNKNOWN,
        output={"say_this": say_this},
        target_ids=["t-pipeline"],
        targets=[EntityRef(entity_type=EntityType.SERVICE, display_name=target_name, status="targeted")],
    )
    result = {
        "decision": decision,
        "final_output": f"SAY THIS:\n{say_this}",
        "verifier_result": VerifierResult(passed=True, final_status="pass", checks={}, blocked_claims=[]),
    }
    return score_simplified_product_result(fixture, result, latency_ms=50)
