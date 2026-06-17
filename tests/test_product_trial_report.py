from __future__ import annotations

from ic_copilot.product_trial import _recommendation, write_product_trial_report
from ic_copilot.web.models import FeedbackRequest
from ic_copilot.web.run_store import create_run, init_web_db, save_feedback, update_run


def test_product_trial_empty_db_needs_more_snippets(tmp_path) -> None:
    report = write_product_trial_report(
        tmp_path / "missing.sqlite3",
        tmp_path / "report.md",
        tmp_path / "report.json",
    )
    assert report.recommendation == "NOT_ENOUGH_SNIPPETS"


def test_product_trial_recommendation_logic() -> None:
    assert _recommendation(19, {}, {})[0] == "NOT_ENOUGH_SNIPPETS"
    assert _recommendation(20, {"useful_as_is": 20}, {"unsafe": 1})[0] == "NEEDS_VERIFIER_FIX"
    assert _recommendation(20, {"safe_but_generic": 20}, {})[0] == "NEEDS_PLANNER_FIX"
    assert _recommendation(20, {"useful_as_is": 12, "safe_but_generic": 4}, {})[0] == "READY_FOR_PERSONAL_USE"


def test_product_trial_report_counts_labeled_feedback(tmp_path) -> None:
    db = tmp_path / "web.sqlite3"
    init_web_db(db)
    run_id = create_run("paste", "snippet", path=db)
    update_run(run_id, path=db, status="succeeded", total_elapsed_ms=100, final_output="SAY THIS:\nok")
    save_feedback(
        run_id,
        FeedbackRequest(usefulness="useful_as_is", failure_tags=["wrong_owner"], reviewer_notes=""),
        path=db,
    )
    report = write_product_trial_report(db, tmp_path / "report.md", tmp_path / "report.json")
    assert report.labeled_snippets == 1
    assert report.usefulness_counts["useful_as_is"] == 1
    assert report.failure_tag_counts["wrong_owner"] == 1
    assert report.top_local_knowledge_gaps["wrong_owner"] == 1
