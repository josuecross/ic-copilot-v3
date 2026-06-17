from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ic_copilot.holdout_soak import (
    aggregate_live_holdout_soak,
    aggregate_live_holdout_soak_from_paths,
    build_release_readiness_summary,
    classify_focused_follow_up,
    classify_overall_release_readiness,
    classify_product_readiness,
    classify_provider_soak_status,
    classify_release_readiness,
    filter_soak_fixtures,
    format_live_holdout_soak_markdown,
    hash_path_tree,
    write_release_readiness_summary,
)


def test_soak_aggregation_from_synthetic_eval_result_files(tmp_path) -> None:
    run_one = _report(
        [
            _case("holdout_scope_question_answered_then_validation", passed=True),
            _case("holdout_no_actionable_current_ask", passed=True, allow_fallback=True),
        ]
    )
    run_two = _report(
        [
            _case(
                "holdout_scope_question_answered_then_validation",
                passed=False,
                say_this="@Lina, what is the current status of the row-count mismatch?",
                reasons=["missing_visible_terms:validation"],
            ),
            _case("holdout_no_actionable_current_ask", passed=True, allow_fallback=True),
        ]
    )
    scripted = _report([_case("scripted", passed=True)])
    path_one = tmp_path / "run_one.json"
    path_two = tmp_path / "run_two.json"
    scripted_path = tmp_path / "scripted.json"
    path_one.write_text(json.dumps(run_one))
    path_two.write_text(json.dumps(run_two))
    scripted_path.write_text(json.dumps(scripted | {"total_cases": 1, "useful_pass_count": 1, "passed": True}))

    soak = aggregate_live_holdout_soak_from_paths(
        [path_one, path_two],
        scripted_report_path=scripted_path,
        runs_attempted=2,
        generated_at="2026-06-05T00:00:00+00:00",
    )

    assert soak["runs_completed"] == 2
    assert soak["summary"]["live_useful_counts"] == [2, 1]
    assert soak["summary"]["live_useful_median"] == 1.5
    case = _case_summary(soak, "holdout_scope_question_answered_then_validation")
    assert case["pass_count"] == 1
    assert case["run_count"] == 2
    assert case["failure_taxonomies"] == {"eval_expectation_too_strict": 1}
    assert soak["validation_vs_status"]["missing_validation_wording_count"] == 1
    assert soak["validation_vs_status"]["candidate_prompt_tuning"] is True


def test_release_rubric_green() -> None:
    reports = [_report([_case(f"case_{index}", passed=True) for index in range(10)]) for _ in range(3)]
    scripted = _report([_case(f"case_{index}", passed=True) for index in range(10)])

    soak = aggregate_live_holdout_soak(reports, scripted_report=scripted, runs_attempted=3)

    assert soak["product_readiness"]["color"] == "green"
    assert soak["provider_soak_status"]["color"] == "green"
    assert soak["overall_release_readiness"]["color"] == "green"
    assert soak["release_readiness"]["color"] == "green"
    assert build_release_readiness_summary(soak)["release_decision"] == "green"


def test_release_rubric_yellow_for_safe_live_variability() -> None:
    reports = [
        _report(_mixed_cases(8, 2, "eval_expectation")),
        _report(_mixed_cases(7, 3, "eval_expectation")),
        _report(_mixed_cases(7, 3, "eval_expectation")),
    ]
    scripted = _report([_case(f"case_{index}", passed=True) for index in range(10)])

    soak = aggregate_live_holdout_soak(reports, scripted_report=scripted, runs_attempted=3)

    assert soak["summary"]["live_useful_median"] == 7
    assert soak["release_readiness"]["color"] == "yellow"
    assert soak["summary"]["recurring_root_causes"]


def test_release_rubric_yellow_when_provider_run_errors() -> None:
    reports = [_report([_case(f"case_{index}", passed=True) for index in range(10)]) for _ in range(2)]
    reports[0]["_soak_run_index"] = 1
    reports[1]["_soak_run_index"] = 3
    scripted = _report([_case(f"case_{index}", passed=True) for index in range(10)])

    soak = aggregate_live_holdout_soak(
        reports,
        scripted_report=scripted,
        runs_attempted=3,
        run_errors=[{"run_index": 2, "error": "ProviderJSONError: network"}],
    )

    assert soak["summary"]["live_useful_median"] == 10
    assert [run["run_index"] for run in soak["per_run"]] == [1, 3]
    assert soak["product_readiness"]["color"] == "green"
    assert soak["provider_soak_status"]["color"] == "yellow"
    assert soak["overall_release_readiness"]["color"] == "yellow"


def test_provider_red_when_no_live_runs_complete() -> None:
    soak = aggregate_live_holdout_soak(
        [],
        scripted_report=_report([_case(f"case_{index}", passed=True) for index in range(10)]),
        runs_attempted=3,
        run_errors=[{"run_index": 1, "error": "network"}, {"run_index": 2, "error": "network"}],
    )

    assert soak["provider_soak_status"]["color"] == "red"
    assert soak["overall_release_readiness"]["color"] == "red"


def test_product_readiness_not_downgraded_by_provider_only_errors() -> None:
    reports = [_report([_case(f"case_{index}", passed=True) for index in range(10)])]

    soak = aggregate_live_holdout_soak(
        reports,
        scripted_report=_report([_case(f"case_{index}", passed=True) for index in range(10)]),
        runs_attempted=3,
        run_errors=[{"run_index": 2, "error": "network"}, {"run_index": 3, "error": "network"}],
    )

    assert soak["product_readiness"]["color"] == "green"
    assert soak["provider_soak_status"]["color"] == "yellow"
    assert soak["overall_release_readiness"]["color"] == "yellow"


def test_release_rubric_red_for_safety_or_wrong_owner() -> None:
    soak = {
        "runs_completed": 1,
        "summary": {
            "live_useful_median": 9,
            "wrong_owner_total": 1,
            "unsafe_total": 0,
            "non_expected_fallback_total": 0,
            "non_expected_fallback_run_count": 0,
            "recurring_root_causes": [],
        },
        "scripted_holdout": {"passed": True},
        "per_case": [],
    }

    readiness = classify_release_readiness(soak)

    assert readiness["color"] == "red"
    assert "product_readiness=red" in readiness["reasons"]


def test_product_red_always_makes_overall_red() -> None:
    soak = {
        "runs_attempted": 3,
        "runs_completed": 3,
        "summary": {
            "live_useful_median": 10,
            "live_useful_min": 10,
            "wrong_owner_total": 0,
            "unsafe_total": 1,
            "non_expected_fallback_total": 0,
            "non_expected_fallback_run_count": 0,
            "latency_p95_ms": 1000,
            "recurring_root_causes": [],
            "failure_class_counts": {},
        },
        "scripted_holdout": {"passed": True},
        "per_case": [],
    }

    product = classify_product_readiness(soak)
    provider = classify_provider_soak_status(soak)
    overall = classify_overall_release_readiness(
        {**soak, "product_readiness": product, "provider_soak_status": provider}
    )

    assert product["color"] == "red"
    assert provider["color"] == "green"
    assert overall["color"] == "red"


def test_release_decision_red_for_wrong_owner_or_unsafe() -> None:
    wrong_owner_soak = aggregate_live_holdout_soak(
        [_report([_case("bad_owner", passed=False, reasons=["wrong_owner:APP"], target=["APP"])])],
        scripted_report=_report([_case("scripted", passed=True)]),
    )
    unsafe_soak = aggregate_live_holdout_soak(
        [_report([_case("unsafe", passed=False, unsafe=True, reasons=["forbidden_visible_terms:execute"])])],
        scripted_report=_report([_case("scripted", passed=True)]),
    )

    assert build_release_readiness_summary(wrong_owner_soak)["release_decision"] == "red"
    assert build_release_readiness_summary(unsafe_soak)["release_decision"] == "red"


def test_release_decision_red_for_repeated_unexpected_fallback() -> None:
    reports = [
        _report([_case("fallback_one", passed=False, fallback_used=True, reasons=["unexpected_fallback"])]),
        _report([_case("fallback_two", passed=False, fallback_used=True, reasons=["unexpected_fallback"])]),
        _report([_case("pass", passed=True)]),
    ]

    soak = aggregate_live_holdout_soak(reports, scripted_report=_report([_case("scripted", passed=True)]))
    summary = build_release_readiness_summary(soak)

    assert summary["release_decision"] == "red"
    assert "unexpected fallback recurred in more than half of completed live runs" in summary["release_decision_reasons"]


def test_release_decision_yellow_for_single_non_safety_flaky_case() -> None:
    stable_cases = [_case(f"stable_{index}", passed=True) for index in range(9)]
    reports = [
        _report(
            [
                _case(
                    "flaky",
                    passed=False,
                    fallback_used=True,
                    move="no_safe_recommendation",
                    target=[],
                    reasons=["verifier_not_passed", "unexpected_fallback"],
                ),
                *stable_cases,
            ]
        ),
        _report([_case("flaky", passed=True), *stable_cases]),
        _report([_case("flaky", passed=True), *stable_cases]),
    ]

    soak = aggregate_live_holdout_soak(
        reports,
        scripted_report=_report([_case(f"case_{index}", passed=True) for index in range(10)]),
        runs_attempted=3,
    )
    summary = build_release_readiness_summary(soak)

    assert summary["live_useful_median"] == 10
    assert summary["wrong_owner_total"] == 0
    assert summary["unsafe_total"] == 0
    assert summary["release_decision"] == "yellow"
    assert summary["flakiest_cases"][0]["recommended_handling"] == "focused_soak"


def test_release_summary_green_with_min_nine_and_no_recurring_root_cause() -> None:
    stable_cases = [_case(f"stable_{index}", passed=True) for index in range(9)]
    reports = [
        _report(
            [
                _case(
                    "one_off_eval",
                    passed=False,
                    reasons=["missing_visible_terms:validation"],
                    say_this="@Lina, what is the current status of the row-count mismatch?",
                ),
                *stable_cases,
            ]
        ),
        _report([_case("one_off_eval", passed=True), *stable_cases]),
        _report([_case("one_off_eval", passed=True), *stable_cases]),
    ]

    soak = aggregate_live_holdout_soak(
        reports,
        scripted_report=_report([_case(f"case_{index}", passed=True) for index in range(10)]),
        runs_attempted=3,
    )
    summary = build_release_readiness_summary(soak)

    assert summary["live_useful_min"] == 9
    assert summary["unexpected_fallback_total"] == 0
    assert summary["repeated_root_causes"] == []
    assert summary["release_decision"] == "green"


def test_report_generation_includes_stability_and_rubric() -> None:
    reports = [
        _report(
            [
                _case("holdout_scope_question_answered_then_validation", passed=True),
                _case("holdout_no_actionable_current_ask", passed=True, allow_fallback=True),
            ]
        )
    ]
    scripted = _report([_case("scripted", passed=True)])
    soak = aggregate_live_holdout_soak(reports, scripted_report=scripted, runs_attempted=1)

    markdown = format_live_holdout_soak_markdown(soak)

    assert "# IC Copilot Live Holdout Soak" in markdown
    assert "## Readiness Rubric" in markdown
    assert "- product_readiness:" in markdown
    assert "- provider_soak_status:" in markdown
    assert "- overall_release_readiness:" in markdown
    assert "- release_decision:" in markdown
    assert "## Release Decision" in markdown
    assert "## Known Open Follow-ups" in markdown
    assert "## Per-Case Stability" in markdown
    assert "## Validation-vs-Status Wording" in markdown


def test_report_markdown_matches_aggregate_json_values() -> None:
    reports = [
        _report(
            [
                _case("holdout_pipeline_validation_after_scope_answer", passed=True),
                _case(
                    "holdout_scope_question_answered_then_validation",
                    passed=False,
                    reasons=["missing_visible_terms:validation"],
                    say_this="@Lina, what is the current status of the row-count mismatch?",
                ),
            ]
        )
    ]
    soak = aggregate_live_holdout_soak(
        reports,
        scripted_report=_report([_case("scripted", passed=True)]),
        runs_attempted=1,
        generated_at="2026-06-05T00:00:00+00:00",
    )
    markdown = format_live_holdout_soak_markdown(soak)

    assert _md_value(markdown, "runs_attempted") == str(soak["runs_attempted"])
    assert _md_value(markdown, "runs_completed") == str(soak["runs_completed"])
    assert _md_value(markdown, "live_useful_counts") == str(soak["summary"]["live_useful_counts"])
    assert _md_value(markdown, "live_fallback_total") == str(soak["summary"]["fallback_total"])
    assert _md_value(markdown, "product_readiness") == soak["product_readiness"]["color"]
    assert _md_value(markdown, "provider_soak_status") == soak["provider_soak_status"]["color"]
    assert _md_value(markdown, "overall_release_readiness") == soak["overall_release_readiness"]["color"]
    assert "holdout_scope_question_answered_then_validation" in markdown


def test_filter_soak_fixtures_selects_single_case() -> None:
    fixtures = [_Fixture("one"), _Fixture("two")]

    assert filter_soak_fixtures(fixtures, "two") == [fixtures[1]]


def test_filter_soak_fixtures_rejects_unknown_case() -> None:
    fixtures = [_Fixture("one")]

    try:
        filter_soak_fixtures(fixtures, "missing")
    except ValueError as exc:
        assert "unknown holdout case id" in str(exc)
    else:  # pragma: no cover - defensive assertion path.
        raise AssertionError("expected unknown case id to fail")


def test_focused_soak_aggregation_tracks_pass_provider_error_and_fallback() -> None:
    pass_report = _report([_case("holdout_pipeline_validation_after_scope_answer", passed=True)])
    fallback_report = _report(
        [
            _case(
                "holdout_pipeline_validation_after_scope_answer",
                passed=False,
                reasons=["verifier_not_passed", "unexpected_fallback"],
                fallback_used=True,
                move="no_safe_recommendation",
                target=[],
                say_this="I do not have a safe, grounded next move yet.",
            )
        ]
    )
    pass_report["_soak_run_index"] = 1
    fallback_report["_soak_run_index"] = 3

    soak = aggregate_live_holdout_soak(
        [pass_report, fallback_report],
        scripted_report=_report([_case("scripted", passed=True)]),
        runs_attempted=3,
        run_errors=[{"run_index": 2, "error": "network"}],
    )
    soak["focused_case_id"] = "holdout_pipeline_validation_after_scope_answer"

    assert soak["runs_completed"] == 2
    assert soak["run_errors"][0]["run_index"] == 2
    case = _case_summary(soak, "holdout_pipeline_validation_after_scope_answer")
    assert case["pass_count"] == 1
    assert case["failure_taxonomies"] == {"verifier_block": 1}
    assert soak["summary"]["non_expected_fallback_total"] == 1


def test_focused_follow_up_classifies_provider_variability_after_four_of_five_pass() -> None:
    reports = [_report([_case("focused", passed=True)]) for _ in range(4)]
    reports.append(_report([_case("focused", passed=False, reasons=["verifier_not_passed"])]))
    soak = aggregate_live_holdout_soak(reports, scripted_report=_report([_case("scripted", passed=True)]), runs_attempted=5)
    soak["focused_case_id"] = "focused"

    assert classify_focused_follow_up(soak)["classification"] == "provider_variability"


def test_focused_follow_up_classifies_repeated_same_cause_failure_as_prompt_gap() -> None:
    reports = [_report([_case("focused", passed=True)]) for _ in range(3)]
    reports.extend(
        [
            _report([_case("focused", passed=False, reasons=["verifier_not_passed"])]),
            _report([_case("focused", passed=False, reasons=["verifier_not_passed"])]),
        ]
    )
    soak = aggregate_live_holdout_soak(reports, scripted_report=_report([_case("scripted", passed=True)]), runs_attempted=5)
    soak["focused_case_id"] = "focused"

    assert classify_focused_follow_up(soak)["classification"] == "prompt_actionability_gap"


def test_release_summary_write_does_not_change_local_knowledge_hash(tmp_path) -> None:
    knowledge = tmp_path / "local_knowledge"
    knowledge.mkdir()
    (knowledge / "decision_moments.jsonl").write_text('{"id":"DM_test"}\n')
    output = tmp_path / "reports" / "latest_release_readiness.json"
    soak = aggregate_live_holdout_soak(
        [_report([_case("case", passed=True)])],
        scripted_report=_report([_case("scripted", passed=True)]),
    )
    before = hash_path_tree(knowledge)

    summary = write_release_readiness_summary(soak, output)

    assert output.exists()
    assert summary["local_knowledge_changed"] is False
    assert hash_path_tree(knowledge) == before


def test_no_safe_fallback_expected_only_for_no_actionable_fixture() -> None:
    no_actionable = _case(
        "holdout_no_actionable_current_ask",
        passed=True,
        fallback_used=True,
        allow_fallback=True,
        move="no_safe_recommendation",
        target=[],
        say_this="I do not have a safe, grounded next move yet.",
    )
    pipeline = _case(
        "holdout_pipeline_validation_after_scope_answer",
        passed=False,
        reasons=["unexpected_fallback"],
        fallback_used=True,
        allow_fallback=False,
        move="no_safe_recommendation",
        target=[],
        say_this="I do not have a safe, grounded next move yet.",
    )
    soak = aggregate_live_holdout_soak([_report([no_actionable, pipeline])], scripted_report=_report([_case("scripted", passed=True)]))

    assert soak["summary"]["fallback_total"] == 2
    assert soak["summary"]["non_expected_fallback_total"] == 1


def _mixed_cases(pass_count: int, fail_count: int, failure_type: str) -> list[dict]:
    cases = [_case(f"pass_{index}", passed=True) for index in range(pass_count)]
    for index in range(fail_count):
        if failure_type == "eval_expectation":
            cases.append(
                _case(
                    f"fail_{index}",
                    passed=False,
                    reasons=["missing_visible_terms:validation"],
                    say_this="@Lina, can you confirm current status?",
                )
            )
        elif failure_type == "fallback":
            cases.append(
                _case(
                    f"fail_{index}",
                    passed=False,
                    fallback_used=True,
                    move="no_safe_recommendation",
                    target=[],
                    reasons=["verifier_not_passed", "unexpected_fallback"],
                    say_this="I do not have a safe, grounded next move yet.",
                )
            )
        else:
            cases.append(_case(f"fail_{index}", passed=False, reasons=["verifier_not_passed"]))
    return cases


def _case(
    fixture_id: str,
    *,
    passed: bool,
    reasons: list[str] | None = None,
    say_this: str = "@Lina, can you confirm validation for the row-count mismatch?",
    move: str = "ask_next_validation",
    target: list[str] | None = None,
    fallback_used: bool = False,
    allow_fallback: bool = False,
    unsafe: bool = False,
) -> dict:
    tags = ["no_safe_expected"] if "no_actionable" in fixture_id else ["scope_answer_superseded", "pipeline_validation"]
    return {
        "fixture_id": fixture_id,
        "passed": passed,
        "reasons": reasons or [],
        "say_this": say_this,
        "move": move,
        "selected_target_names": target or ["Lina"],
        "fallback_used": fallback_used,
        "allow_fallback": allow_fallback,
        "verifier_status": "pass" if not fallback_used else "fallback",
        "unsafe_action_wording": unsafe,
        "fake_entity": False,
        "wrong_owner": any(str(reason).startswith("wrong_owner") for reason in reasons or []),
        "latency_ms": 1000,
        "expected_usefulness_tags": tags,
        "run_diagnosis_summary": {"direct_ask": True, "safe_but_weak": False},
        "final_output_quality": {"direct_ask": True, "safe_but_weak": False},
    }


def _report(cases: list[dict]) -> dict:
    useful = sum(1 for case in cases if case["passed"])
    return {
        "eval_name": "simplified_product_eval",
        "mode": "live_product_provider",
        "total_cases": len(cases),
        "useful_pass_count": useful,
        "failed_count": len(cases) - useful,
        "fallback_count": sum(1 for case in cases if case.get("fallback_used")),
        "wrong_owner_count": sum(1 for case in cases if case.get("wrong_owner")),
        "unsafe_action_wording_count": sum(1 for case in cases if case.get("unsafe_action_wording")),
        "fake_entity_count": sum(1 for case in cases if case.get("fake_entity")),
        "latency_p50_ms": 1000,
        "latency_p95_ms": 1000,
        "passed": useful == len(cases),
        "cases": cases,
    }


def _case_summary(soak: dict, fixture_id: str) -> dict:
    return next(case for case in soak["per_case"] if case["fixture_id"] == fixture_id)


def _md_value(markdown: str, key: str) -> str:
    match = re.search(rf"^- {re.escape(key)}: (.+)$", markdown, flags=re.MULTILINE)
    assert match, f"missing markdown key {key}"
    return match.group(1)


@dataclass(frozen=True)
class _Fixture:
    fixture_id: str
