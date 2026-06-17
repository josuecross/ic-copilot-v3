from __future__ import annotations

from ic_copilot.web.models import FeedbackRequest, PipelineStepEvent
from ic_copilot.web.run_store import (
    add_step_event,
    create_run,
    delete_run,
    get_run,
    init_web_db,
    list_step_events,
    save_feedback,
    update_run,
)


def test_web_run_store_create_update_get_delete(tmp_path):
    db_path = tmp_path / "web.sqlite3"
    init_web_db(db_path).close()
    run_id = create_run("paste", "test", "input.txt", db_path)
    update_run(run_id, path=db_path, status="succeeded", final_output="SAY THIS:\nok")

    run = get_run(run_id, db_path)
    assert run is not None
    assert run["status"] == "succeeded"
    assert run["final_output"] == "SAY THIS:\nok"

    deleted = delete_run(run_id, db_path)
    assert deleted is not None
    assert get_run(run_id, db_path) is None


def test_web_run_store_step_and_feedback(tmp_path):
    db_path = tmp_path / "web.sqlite3"
    run_id = create_run("paste", "test", "input.txt", db_path)
    add_step_event(
        PipelineStepEvent(run_id=run_id, step="normalize_input", status="succeeded", elapsed_ms=1),
        db_path,
    )
    label_id = save_feedback(
        run_id,
        FeedbackRequest(usefulness="useful_with_edit", failure_tags=["too_generic"]),
        "SAY THIS:\nok",
        db_path,
    )

    assert list_step_events(run_id, db_path)[0]["step"] == "normalize_input"
    assert label_id.startswith("label-")
