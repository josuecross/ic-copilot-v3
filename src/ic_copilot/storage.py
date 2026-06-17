from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel


def init_db(path: str | Path) -> sqlite3.Connection:
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS traces (
            trace_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    return conn


def save_model(conn: sqlite3.Connection, trace_id: str, kind: str, model: BaseModel) -> None:
    payload = model.model_dump_json()
    conn.execute(
        """
        INSERT OR REPLACE INTO traces(trace_id, kind, payload)
        VALUES (?, ?, ?)
        """,
        (trace_id, kind, payload),
    )
    conn.commit()


def save_payload(conn: sqlite3.Connection, trace_id: str, kind: str, payload: dict) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO traces(trace_id, kind, payload)
        VALUES (?, ?, ?)
        """,
        (trace_id, kind, json.dumps(payload, default=str)),
    )
    conn.commit()


def iter_traces(conn: sqlite3.Connection, kind: str | None = None) -> Iterable[dict]:
    if kind:
        rows = conn.execute(
            "SELECT trace_id, kind, payload, created_at FROM traces WHERE kind = ? ORDER BY created_at",
            (kind,),
        )
    else:
        rows = conn.execute("SELECT trace_id, kind, payload, created_at FROM traces ORDER BY created_at")
    for trace_id, row_kind, payload, created_at in rows:
        yield {
            "trace_id": trace_id,
            "kind": row_kind,
            "payload": json.loads(payload),
            "created_at": created_at,
        }

