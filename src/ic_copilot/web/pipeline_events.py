from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from ic_copilot.error_sanitizer import sanitize_user_facing_error
from ic_copilot.pipeline import run_pipeline
from ic_copilot.schemas import PipelineStepArtifact, utc_now
from ic_copilot.web.models import PipelineStepEvent


STEP_ORDER = [
    "input_saved",
    "normalize_input",
    "input_assessment",
    "trigger_decision",
    "product_runtime_config",
    "catalog_lookup",
    "command_registry_load",
    "allowed_targets",
    "latest_window_selection",
    "context_pack",
    "slack_turn_reconstruction",
    "semantic_read",
    "incident_brief",
    "clean_context",
    "state_extraction",
    "state_merge",
    "memory_load",
    "memory_retrieval",
    "applicability_gate",
    "sharp_blocker_assessment",
    "planning",
    "semantic_intent_check",
    "verification",
    "repair",
    "rendering",
    "run_diagnosis",
    "trace_saved",
    "complete",
]


def _event(
    run_id: str,
    step: str,
    status: str,
    message: str = "",
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    elapsed_ms: int | None = None,
    error: str | None = None,
) -> PipelineStepEvent:
    return PipelineStepEvent(
        run_id=run_id,
        step=step,
        status=status,
        message=message,
        started_at=started_at,
        finished_at=finished_at,
        elapsed_ms=elapsed_ms,
        error=error,
    )


def run_pipeline_with_progress(
    incident_file: Path,
    catalog_path: Path | None,
    memory_path: Path | None,
    command_registry_path: Path | None,
    save_trace: bool,
    on_event: Callable[[PipelineStepEvent], None],
    on_artifact: Callable[[PipelineStepArtifact], None] | None = None,
    run_id: str = "manual",
    llm_client=None,
    config_path: str | Path | None = None,
) -> dict[str, Any]:
    started = utc_now()
    on_event(
        _event(
            run_id,
            "input_saved",
            "succeeded",
            "Input is stored locally for this run",
            started_at=started,
            finished_at=started,
            elapsed_ms=0,
        )
    )
    step_starts: dict[str, datetime] = {}
    terminal_steps: set[str] = {"input_saved"}

    def on_step(step: str, status: str, message: str, elapsed_ms: int | None, error: str | None) -> None:
        now = utc_now()
        if status == "running":
            step_starts[step] = now
            on_event(_event(run_id, step, "running", message, started_at=now))
            return
        started_at = step_starts.get(step, now)
        finished_at = now
        normalized_status = status if status in {"succeeded", "failed", "skipped"} else "running"
        if normalized_status in {"succeeded", "failed", "skipped"}:
            terminal_steps.add(step)
        on_event(
            _event(
                run_id,
                step,
                normalized_status,
                message,
                started_at=started_at,
                finished_at=finished_at,
                elapsed_ms=elapsed_ms,
                error=error,
            )
        )

    try:
        return run_pipeline(
            incident_file=incident_file,
            catalog_path=catalog_path,
            memory_path=memory_path,
            command_registry_path=command_registry_path,
            save_trace=save_trace,
            on_step=on_step,
            on_artifact=on_artifact,
            run_id=run_id,
            llm_client=llm_client,
            config_path=config_path,
        )
    except Exception as exc:
        now = utc_now()
        error_text = sanitize_user_facing_error(exc)
        for step in STEP_ORDER:
            if step == "complete":
                continue
            if step not in terminal_steps:
                on_event(
                    _event(
                        run_id,
                        step,
                        "skipped",
                        "Skipped because the pipeline failed earlier",
                        started_at=now,
                        finished_at=now,
                        elapsed_ms=0,
                    )
                )
                terminal_steps.add(step)
        if "complete" not in terminal_steps:
            on_event(
                _event(
                    run_id,
                    "complete",
                    "failed",
                    "Pipeline failed",
                    started_at=now,
                    finished_at=now,
                    elapsed_ms=0,
                    error=error_text,
                )
            )
            terminal_steps.add("complete")
        raise
