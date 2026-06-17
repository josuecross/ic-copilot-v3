from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ic_copilot.error_sanitizer import sanitize_user_facing_error
from ic_copilot.llm.base import LLMClient
from ic_copilot.pipeline import run_pipeline
from ic_copilot.runtime_config import load_product_runtime_config


def run_product_smoke(
    incident: str | Path,
    *,
    output_json: str | Path | None = None,
    llm_client: LLMClient | None = None,
    knowledge_dir: str | Path | None = None,
) -> dict[str, Any]:
    config = load_product_runtime_config()
    if knowledge_dir is not None:
        config = config.model_copy(update={"product_knowledge_path": str(knowledge_dir)})
    try:
        result = run_pipeline(incident, save_trace=False, llm_client=llm_client, runtime_config=config)
    except Exception as exc:
        payload = {
            "ok": False,
            "provider": config.llm.provider,
            "model": config.llm.model,
            "error": sanitize_user_facing_error(exc),
        }
        if output_json is not None:
            path = Path(output_json)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2, default=str))
        raise
    command = (result["decision"].output or {}).get("command")
    verifier_passed = result["verifier_result"].passed
    semantic_quality = result.get("semantic_quality")
    original_incident_brief_quality = result.get("original_incident_brief_quality")
    incident_brief_quality = result.get("incident_brief_quality")
    blocker_reselection = result.get("blocker_reselection")
    decision = result.get("decision")
    incident_brief = result.get("incident_brief")
    payload = {
        "ok": verifier_passed,
        "provider": config.llm.provider,
        "model": config.llm.model,
        "state_delta_schema_valid": result.get("raw_delta") is not None or result.get("state") is not None,
        "decision_schema_valid": result.get("decision") is not None,
        "verifier_status": result["verifier_result"].final_status,
        "verifier_passed": verifier_passed,
        "semantic_quality_status": getattr(semantic_quality, "status", None),
        "original_brief_quality_status": getattr(original_incident_brief_quality, "status", None),
        "brief_quality_status": getattr(incident_brief_quality, "status", None),
        "brief_quality_passed": getattr(incident_brief_quality, "passed", None),
        "blocker_reselection_status": getattr(blocker_reselection, "status", None),
        "blocker_reselection_source": getattr(blocker_reselection, "source", None),
        "output_move": str(getattr(getattr(decision, "move", None), "value", getattr(decision, "move", None))),
        "selected_target_ids": list(getattr(decision, "target_ids", []) or []),
        "selected_target_names": list(getattr(blocker_reselection, "selected_target_names", []) or []),
        "latest_blocker_type": (
            getattr(getattr(getattr(incident_brief, "latest_blocker", None), "blocker_type", None), "value", None)
            or str(getattr(getattr(incident_brief, "latest_blocker", None), "blocker_type", "") or "")
        ),
        "final_output": result["final_output"],
        "latency_ms": result.get("latency_ms"),
        "timeout_stage": result["trace"].provider_timeout_stage,
        "processing_strategy": result["trace"].processing_strategy,
        "latest_window_event_ids": result["trace"].latest_window_event_ids,
        "safe_command": not command or isinstance(command, str),
        "command_execution": False,
        "slack_posting": False,
        "paging": False,
    }
    if output_json is not None:
        path = Path(output_json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, default=str))
    return payload
