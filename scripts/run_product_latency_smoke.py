#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import time
from pathlib import Path
from typing import Any

from ic_copilot.error_sanitizer import sanitize_user_facing_error
from ic_copilot.incident_loader import load_incident_events
from ic_copilot.input_processing import assess_input_size
from ic_copilot.product_smoke import run_product_smoke
from ic_copilot.runtime_config import load_product_runtime_config, product_provider_is_configured


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = [
    ("revpro", "data/sample/incidents/revpro_early_engage.txt", 45_000),
    ("security_workflow", "data/personal_regression/incidents/p3_security_workflow_vulnerability_static.txt", 45_000),
    ("api_504_revenue", "data/personal_regression/incidents/p3_api_504_revenue_timeout_static.txt", 60_000),
    ("ocs_lag", "data/personal_regression/incidents/p3_ocs_lag_trust_post_static.txt", 60_000),
]


def _run_smoke_worker(path: str, knowledge_dir: str, queue: mp.Queue) -> None:
    try:
        queue.put({"ok": True, "smoke": run_product_smoke(Path(path), knowledge_dir=knowledge_dir)})
    except Exception as exc:  # pragma: no cover - defensive child-process boundary
        queue.put({"ok": False, "error": sanitize_user_facing_error(exc)})


def _run_smoke_with_timeout(path: Path, knowledge_dir: str, timeout_seconds: float) -> dict[str, Any]:
    ctx = mp.get_context("spawn")
    queue: mp.Queue = ctx.Queue(maxsize=1)
    process = ctx.Process(target=_run_smoke_worker, args=(str(path), knowledge_dir, queue))
    process.start()
    process.join(timeout_seconds)
    if process.is_alive():
        process.terminate()
        process.join(2)
        if process.is_alive():
            process.kill()
            process.join(2)
        return {
            "ok": False,
            "timed_out": True,
            "error": "Product smoke exceeded the latency smoke case timeout.",
            "timeout_stage": "latency_smoke_case_timeout",
        }
    if not queue.empty():
        payload = queue.get()
        if payload.get("ok"):
            return payload["smoke"]
        return {
            "ok": False,
            "error": payload.get("error") or "Product smoke failed.",
            "timeout_stage": "unknown",
        }
    return {
        "ok": False,
        "error": f"Product smoke exited with code {process.exitcode}.",
        "timeout_stage": "unknown",
    }


def _case_input_metrics(path: Path) -> dict[str, Any]:
    events = load_incident_events(path, incident_id=path.stem)
    assessment = assess_input_size(path.read_text(errors="replace"), events)
    return {
        "event_count": len(events),
        "estimated_token_count": assessment.estimated_token_count,
        "input_size_assessment": assessment.model_dump(mode="json"),
    }


def _write_outputs(payload: dict[str, Any], output_json: Path, output_md: Path | None) -> None:
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(payload, indent=2, default=str))
    if output_md is None:
        return
    output_md.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Product Latency Smoke",
        "",
        f"- provider: {payload.get('provider')}",
        f"- model: {payload.get('model')}",
        f"- status: {'PASS' if payload.get('passed') else 'FAIL'}",
        "",
        "| case | status | events | est tokens | elapsed ms | verifier | timeout stage | error |",
        "| --- | --- | ---: | ---: | ---: | --- | --- | --- |",
    ]
    for row in payload.get("cases", []):
        lines.append(
            "| {case} | {status} | {event_count} | {estimated_token_count} | {elapsed_ms} | {verifier_status} | {timeout_stage} | {error} |".format(
                case=row.get("case"),
                status=row.get("status"),
                event_count=row.get("event_count", 0),
                estimated_token_count=row.get("estimated_token_count", 0),
                elapsed_ms=row.get("elapsed_ms", 0),
                verifier_status=row.get("verifier_status") or "",
                timeout_stage=row.get("timeout_stage") or "",
                error=(row.get("error") or "").replace("|", "/"),
            )
        )
    output_md.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run live product latency smokes for key personal IC fixtures.")
    parser.add_argument("--knowledge-dir", default="local_knowledge")
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-md", default=None)
    parser.add_argument("--case-timeout-seconds", type=float, default=75.0)
    args = parser.parse_args()

    config = load_product_runtime_config()
    payload: dict[str, Any] = {
        "provider": config.llm.provider,
        "model": config.llm.model,
        "knowledge_dir": args.knowledge_dir,
        "provider_configured": product_provider_is_configured(config),
        "passed": True,
        "cases": [],
    }
    output_json = Path(args.output_json)
    output_md = Path(args.output_md) if args.output_md else None

    if not payload["provider_configured"]:
        payload["passed"] = False
        payload["skipped_reason"] = "Provider is not configured; latency smoke is live-only."
        _write_outputs(payload, output_json, output_md)
        print(json.dumps({"passed": False, "skipped_reason": payload["skipped_reason"]}, indent=2))
        return 0

    for case, rel_path, threshold_ms in DEFAULT_CASES:
        path = ROOT / rel_path
        if not path.exists():
            payload["cases"].append({"case": case, "status": "skipped", "reason": "fixture missing"})
            continue
        row = {"case": case, "path": rel_path, "threshold_ms": threshold_ms, **_case_input_metrics(path)}
        started = time.perf_counter()
        try:
            smoke = _run_smoke_with_timeout(
                path,
                args.knowledge_dir,
                min(args.case_timeout_seconds, max(30.0, (threshold_ms / 1000) + 15.0)),
            )
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            row.update(
                {
                    "status": "passed" if smoke.get("ok") else "failed",
                    "elapsed_ms": smoke.get("latency_ms") or elapsed_ms,
                    "incident_brief_ms": None,
                    "planner_ms": None,
                    "verifier_ms": None,
                    "verifier_status": smoke.get("verifier_status"),
                    "timeout_stage": smoke.get("timeout_stage"),
                    "error": smoke.get("error"),
                    "final_output": smoke.get("final_output"),
                    "over_threshold": (smoke.get("latency_ms") or elapsed_ms) > threshold_ms,
                    "over_hard_limit": (smoke.get("latency_ms") or elapsed_ms) > 75_000,
                }
            )
            if not smoke.get("ok"):
                payload["passed"] = False
            if row["over_hard_limit"]:
                payload["passed"] = False
        except Exception as exc:
            payload["passed"] = False
            row.update(
                {
                    "status": "failed",
                    "elapsed_ms": int((time.perf_counter() - started) * 1000),
                    "error": sanitize_user_facing_error(exc),
                    "verifier_status": None,
                    "timeout_stage": "unknown",
                }
            )
        payload["cases"].append(row)

    _write_outputs(payload, output_json, output_md)
    print(json.dumps({"passed": payload["passed"], "cases": len(payload["cases"])}, indent=2))
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
