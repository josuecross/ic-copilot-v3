from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from ic_copilot.schemas import utc_now
from ic_copilot.llm.redaction import redact_for_llm
from ic_copilot.web.models import FeedbackRequest, PipelineStepEvent


DEFAULT_WEB_DB = Path(".ic_copilot/web.sqlite3")


def _now_iso() -> str:
    return utc_now().isoformat()


def _connect(path: str | Path = DEFAULT_WEB_DB) -> sqlite3.Connection:
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_web_db(path: str | Path = DEFAULT_WEB_DB) -> sqlite3.Connection:
    conn = _connect(path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            input_kind TEXT NOT NULL,
            input_name TEXT,
            input_path TEXT,
            total_elapsed_ms INTEGER,
            final_output TEXT,
            trace_id TEXT,
            error TEXT,
            result_json TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS step_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            step TEXT NOT NULL,
            status TEXT NOT NULL,
            message TEXT,
            started_at TEXT,
            finished_at TEXT,
            elapsed_ms INTEGER,
            error TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS feedback (
            label_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            usefulness TEXT NOT NULL,
            failure_tags_json TEXT NOT NULL,
            reviewer_notes TEXT NOT NULL,
            final_output_snapshot TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS step_artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            step TEXT NOT NULL,
            artifact_type TEXT NOT NULL,
            summary_json TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            redacted INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            warnings_json TEXT NOT NULL DEFAULT '[]',
            error TEXT
        )
        """
    )
    conn.commit()
    return conn


def mark_stale_running_runs(
    path: str | Path = DEFAULT_WEB_DB,
    *,
    older_than_seconds: int = 1800,
) -> int:
    cutoff = utc_now() - timedelta(seconds=older_than_seconds)
    marked = 0
    with init_web_db(path) as conn:
        rows = conn.execute("SELECT run_id, updated_at FROM runs WHERE status = 'running'").fetchall()
        for row in rows:
            try:
                updated_at = datetime.fromisoformat(row["updated_at"])
            except (TypeError, ValueError):
                updated_at = cutoff - timedelta(seconds=1)
            if updated_at <= cutoff:
                conn.execute(
                    """
                    UPDATE runs
                    SET status = 'failed', updated_at = ?, error = ?
                    WHERE run_id = ? AND status = 'running'
                    """,
                    (
                        _now_iso(),
                        "Run was marked failed because it was still running after server restart.",
                        row["run_id"],
                    ),
                )
                marked += 1
        conn.commit()
    return marked


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    for key in (
        "result_json",
        "failure_tags_json",
    ):
        if result.get(key):
            result[key] = json.loads(result[key])
    return result


def create_run(
    input_kind: str,
    input_name: str | None = None,
    input_path: str | None = None,
    path: str | Path = DEFAULT_WEB_DB,
) -> str:
    run_id = f"run-{uuid4().hex[:12]}"
    now = _now_iso()
    with init_web_db(path) as conn:
        conn.execute(
            """
            INSERT INTO runs(run_id, status, created_at, updated_at, input_kind, input_name, input_path)
            VALUES (?, 'queued', ?, ?, ?, ?, ?)
            """,
            (run_id, now, now, input_kind, input_name, input_path),
        )
        conn.commit()
    return run_id


def update_run(
    run_id: str,
    path: str | Path = DEFAULT_WEB_DB,
    **updates: Any,
) -> None:
    if not updates:
        return
    updates["updated_at"] = _now_iso()
    json_fields = {"result_json"}
    columns = []
    values: list[Any] = []
    for key, value in updates.items():
        if key in json_fields and value is not None:
            value = json.dumps(value, default=str)
        columns.append(f"{key} = ?")
        values.append(value)
    values.append(run_id)
    with init_web_db(path) as conn:
        conn.execute(f"UPDATE runs SET {', '.join(columns)} WHERE run_id = ?", values)
        conn.commit()


def add_step_event(
    event: PipelineStepEvent,
    path: str | Path = DEFAULT_WEB_DB,
) -> int:
    started_at = event.started_at.isoformat() if event.started_at else None
    finished_at = event.finished_at.isoformat() if event.finished_at else None
    with init_web_db(path) as conn:
        cur = conn.execute(
            """
            INSERT INTO step_events(
                run_id, step, status, message, started_at, finished_at, elapsed_ms, error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.run_id,
                event.step,
                event.status,
                event.message,
                started_at,
                finished_at,
                event.elapsed_ms,
                event.error,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def save_step_artifact(
    run_id: str,
    step: str,
    artifact_type: str,
    summary_json: dict[str, Any],
    payload_json: dict[str, Any],
    *,
    redacted: bool = True,
    warnings: list[str] | None = None,
    error: str | None = None,
    path: str | Path = DEFAULT_WEB_DB,
) -> int:
    summary = redact_for_llm(summary_json)
    payload = redact_for_llm(payload_json)
    safe_warnings = redact_for_llm(warnings or [])
    safe_error = redact_for_llm(error) if error else None
    with init_web_db(path) as conn:
        cur = conn.execute(
            """
            INSERT INTO step_artifacts(
                run_id, step, artifact_type, summary_json, payload_json,
                redacted, created_at, warnings_json, error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                step,
                artifact_type,
                json.dumps(summary, default=str),
                json.dumps(payload, default=str),
                1 if redacted else 0,
                _now_iso(),
                json.dumps(safe_warnings, default=str),
                safe_error,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_step_artifacts(
    run_id: str,
    path: str | Path = DEFAULT_WEB_DB,
    *,
    include_payload: bool = False,
) -> list[dict[str, Any]]:
    fields = (
        "id, run_id, step, artifact_type, summary_json, payload_json, redacted, created_at, warnings_json, error"
        if include_payload
        else "id, run_id, step, artifact_type, summary_json, redacted, created_at, warnings_json, error"
    )
    with init_web_db(path) as conn:
        rows = conn.execute(
            f"SELECT {fields} FROM step_artifacts WHERE run_id = ? ORDER BY id",
            (run_id,),
        ).fetchall()
    artifacts: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["summary_json"] = json.loads(item.get("summary_json") or "{}")
        if include_payload:
            item["payload_json"] = json.loads(item.get("payload_json") or "{}")
        item["warnings_json"] = json.loads(item.get("warnings_json") or "[]")
        item["redacted"] = bool(item.get("redacted"))
        artifacts.append(item)
    return artifacts


def get_step_artifact(
    artifact_id: int,
    path: str | Path = DEFAULT_WEB_DB,
) -> dict[str, Any] | None:
    with init_web_db(path) as conn:
        row = conn.execute("SELECT * FROM step_artifacts WHERE id = ?", (artifact_id,)).fetchone()
    if row is None:
        return None
    item = dict(row)
    item["summary_json"] = json.loads(item.get("summary_json") or "{}")
    item["payload_json"] = json.loads(item.get("payload_json") or "{}")
    item["warnings_json"] = json.loads(item.get("warnings_json") or "[]")
    item["redacted"] = bool(item.get("redacted"))
    return item


def list_step_events(run_id: str, path: str | Path = DEFAULT_WEB_DB) -> list[dict[str, Any]]:
    with init_web_db(path) as conn:
        rows = conn.execute(
            "SELECT * FROM step_events WHERE run_id = ? ORDER BY id",
            (run_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def save_feedback(
    run_id: str,
    feedback: FeedbackRequest,
    final_output_snapshot: str | None = None,
    path: str | Path = DEFAULT_WEB_DB,
) -> str:
    label_id = f"label-{uuid4().hex[:12]}"
    with init_web_db(path) as conn:
        conn.execute(
            """
            INSERT INTO feedback(
                label_id, run_id, created_at, usefulness, failure_tags_json,
                reviewer_notes, final_output_snapshot
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                label_id,
                run_id,
                _now_iso(),
                feedback.usefulness,
                json.dumps(feedback.failure_tags),
                feedback.reviewer_notes,
                final_output_snapshot,
            ),
        )
        conn.commit()
    return label_id


def list_feedback(
    run_id: str | None = None,
    path: str | Path = DEFAULT_WEB_DB,
) -> list[dict[str, Any]]:
    query = "SELECT feedback.* FROM feedback"
    clauses: list[str] = []
    values: list[Any] = []
    if run_id:
        clauses.append("run_id = ?")
        values.append(run_id)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY feedback.created_at"
    with init_web_db(path) as conn:
        rows = conn.execute(query, values).fetchall()
    return [_row_to_dict(row) or {} for row in rows]


def get_run(run_id: str, path: str | Path = DEFAULT_WEB_DB) -> dict[str, Any] | None:
    with init_web_db(path) as conn:
        row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    return _row_to_dict(row)


def delete_run(run_id: str, path: str | Path = DEFAULT_WEB_DB) -> dict[str, Any] | None:
    existing = get_run(run_id, path)
    if existing is None:
        return None
    with init_web_db(path) as conn:
        conn.execute("DELETE FROM step_events WHERE run_id = ?", (run_id,))
        conn.execute("DELETE FROM step_artifacts WHERE run_id = ?", (run_id,))
        conn.execute("DELETE FROM feedback WHERE run_id = ?", (run_id,))
        conn.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
        conn.commit()
    return existing


def delete_all_runs(path: str | Path = DEFAULT_WEB_DB) -> list[dict[str, Any]]:
    existing = list_runs(limit=10000, path=path)
    with init_web_db(path) as conn:
        conn.execute("DELETE FROM step_events")
        conn.execute("DELETE FROM step_artifacts")
        conn.execute("DELETE FROM feedback")
        conn.execute("DELETE FROM runs")
        conn.commit()
    return existing


def list_runs(limit: int = 50, path: str | Path = DEFAULT_WEB_DB) -> list[dict[str, Any]]:
    with init_web_db(path) as conn:
        rows = conn.execute(
            "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_row_to_dict(row) or {} for row in rows]


def parse_datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None
