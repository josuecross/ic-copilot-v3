from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from ic_copilot.schemas import utc_now


RunLifecycleStatus = Literal["queued", "running", "succeeded", "failed"]
InputKind = Literal["paste", "upload", "sample", "jsonl"]
StepStatus = Literal["pending", "running", "succeeded", "failed", "skipped"]


class RunStatus(BaseModel):
    run_id: str
    status: RunLifecycleStatus
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    input_kind: InputKind
    input_name: str | None = None
    total_elapsed_ms: int | None = None
    final_output: str | None = None
    error: str | None = None
    trace_id: str | None = None


class PipelineStepEvent(BaseModel):
    run_id: str
    step: str
    status: StepStatus
    message: str = ""
    started_at: datetime | None = None
    finished_at: datetime | None = None
    elapsed_ms: int | None = None
    error: str | None = None


class RunRequest(BaseModel):
    pasted_text: str | None = None
    sample_path: str | None = None
    save_trace: bool = True


class RunResultView(BaseModel):
    run_id: str
    final_output: str
    say_this: str | None = None
    next_line: str | None = None
    command: str | None = None
    do_not_ask: list[str] = Field(default_factory=list)
    why: dict[str, Any] = Field(default_factory=dict)
    verifier_status: str | None = None
    verifier_passed: bool = False
    fallback_used: bool = False
    trace_id: str | None = None
    total_elapsed_ms: int | None = None


class FeedbackRequest(BaseModel):
    usefulness: Literal["useful_as_is", "useful_with_edit", "safe_but_generic", "wrong", "unsafe"]
    failure_tags: list[str] = Field(default_factory=list)
    reviewer_notes: str = ""
