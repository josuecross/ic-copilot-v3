from __future__ import annotations

from pathlib import Path

from ic_copilot.holdout_taxonomy import aggregate_holdout_taxonomy, classify_holdout_case
from ic_copilot.simplified_product_eval import load_simplified_product_eval_fixtures


HOLDOUT_CASES = Path("data/holdout/incident_read_holdout_cases.jsonl")


def test_holdout_cases_load_with_expected_coverage() -> None:
    fixtures = load_simplified_product_eval_fixtures(HOLDOUT_CASES)
    tags = {tag for fixture in fixtures for tag in fixture.expected_usefulness_tags}

    assert len(fixtures) == 10
    assert {
        "explicit_work_item_owner",
        "stale_status_avoided",
        "scope_answer_superseded",
        "permission_loop_safe",
        "pipeline_validation",
        "monitoring_signal",
        "customer_validation",
        "low_quality_helper_rejected",
        "noise_target_rejected",
        "no_safe_expected",
    }.issubset(tags)
    assert all(fixture.expected_read.get("say_this") for fixture in fixtures)


def test_holdout_taxonomy_handles_passing_case() -> None:
    row = classify_holdout_case(
        {
            "fixture_id": "pass_case",
            "passed": True,
            "reasons": [],
            "verifier_status": "pass",
            "fallback_used": False,
            "run_diagnosis_summary": {"safe_but_weak": False},
        }
    )

    assert row["root_cause"] == "unknown"
    assert row["should_become"] == "no action"


def test_holdout_taxonomy_classifies_safe_but_weak_case() -> None:
    row = classify_holdout_case(
        {
            "fixture_id": "weak_case",
            "passed": False,
            "reasons": ["missing_visible_terms:validation"],
            "verifier_status": "pass",
            "fallback_used": False,
            "run_diagnosis_summary": {
                "safe_but_weak": True,
                "direct_ask": False,
                "actionability_failure_category": "none",
            },
            "final_output_quality": {
                "safe_but_weak": True,
                "direct_ask": False,
                "actionability_failure_category": "none",
                "no_safe_wording_quality": "not_applicable",
            },
            "target_dedup_applied": True,
            "move_normalized_from": "request_monitoring_signal",
            "move_normalized_to": "ask_next_validation",
        }
    )

    assert row["root_cause"] == "model_output_safe_but_weak"
    assert row["should_become"] == "prompt/actionability change"
    assert row["target_dedup_applied"] is True
    assert row["move_normalized_to"] == "ask_next_validation"


def test_holdout_taxonomy_classifies_verifier_blocked_case() -> None:
    row = classify_holdout_case(
        {
            "fixture_id": "blocked_case",
            "passed": False,
            "reasons": ["verifier_not_passed"],
            "verifier_status": "fallback_required",
            "fallback_used": True,
            "run_diagnosis_summary": {
                "safe_but_weak": False,
                "actionability_failure_category": "none",
            },
        }
    )

    assert row["root_cause"] == "verifier_block"
    assert row["should_become"] == "no action"


def test_holdout_taxonomy_aggregates_counts() -> None:
    report = {
        "cases": [
            {"fixture_id": "pass", "passed": True, "reasons": [], "verifier_status": "pass"},
            {"fixture_id": "wrong", "passed": False, "reasons": ["wrong_owner:APP"], "verifier_status": "pass"},
        ]
    }

    taxonomy = aggregate_holdout_taxonomy(report)

    assert taxonomy["total_cases"] == 2
    assert taxonomy["passed_count"] == 1
    assert taxonomy["failed_count"] == 1
    assert taxonomy["root_cause_counts"]["model_selected_wrong_target"] == 1
