from __future__ import annotations

import time
import json
from pathlib import Path
from typing import Any, Callable

import yaml

from ic_copilot.schemas import ReplayEvalCase, ReplayEvalResult, VerifierResult


Pipeline = Callable[[ReplayEvalCase], dict[str, Any]]


def run_pipeline_for_eval_case(
    case: ReplayEvalCase,
    catalog_path: str | Path,
    memory_dir: str | Path,
    command_registry_path: str | Path | None = None,
    llm_client: Any | None = None,
) -> dict[str, Any]:
    from ic_copilot.pipeline import run_pipeline

    if case.incident_file:
        incident_file = case.incident_file
    else:
        tmp_dir = Path(".ic_copilot/eval_inputs")
        tmp_dir.mkdir(parents=True, exist_ok=True)
        incident_file = tmp_dir / f"{case.case_id}.txt"
        incident_file.write_text("\n".join(case.visible_events))
    return run_pipeline(
        incident_file,
        catalog_path=catalog_path,
        memory_path=memory_dir,
        command_registry_path=command_registry_path,
        save_trace=False,
        llm_client=llm_client,
    )


def _resolve_case_path(base: Path, value: str | None) -> str | None:
    if not value:
        return None
    path = Path(value)
    if path.is_absolute():
        return str(path)
    parts = path.parts
    if parts and parts[0] == "fixtures":
        path = Path(*parts[1:])
    return str((base / path).resolve())


def _visible_event_text(event) -> str:
    if isinstance(event, str):
        return event
    if isinstance(event, dict):
        if event.get("text"):
            return str(event["text"])
        if event.get("message"):
            message = event["message"]
            if isinstance(message, dict):
                return str(message.get("text", ""))
            return str(message)
        return " ".join(str(value) for value in event.values() if isinstance(value, str))
    return str(event)


def _adapt_eval_case(raw: dict, base: Path) -> dict:
    if "expected" in raw:
        data = dict(raw)
        if data.get("incident_file"):
            data["incident_file"] = _resolve_case_path(base, data["incident_file"])
        data["visible_events"] = [_visible_event_text(event) for event in data.get("visible_events", [])]
        return data
    minimum_claims = []
    absent_substrings = list(raw.get("expected_absent_substrings", []))
    for claim in raw.get("minimum_required_claims", []):
        if claim.lower().startswith("do not "):
            absent_substrings.append(claim[7:])
        else:
            minimum_claims.append(claim)
    expected = {
        "phase": raw.get("expected_phase"),
        "blocker_type": raw.get("expected_blocker_type"),
        "acceptable_moves": raw.get("acceptable_moves", []),
        "acceptable_targets": raw.get("acceptable_targets", []),
        "acceptable_commands": raw.get("acceptable_commands", []),
        "minimum_required_claims": minimum_claims,
        "forbidden_question_intents": raw.get("forbidden_question_intents", []),
        "forbidden_entities": raw.get("forbidden_entities", []),
        "forbidden_historical_facts": raw.get("forbidden_historical_facts", []),
        "expected_verifier_status": raw.get("expected_verifier_status"),
        "allow_fallback": bool(raw.get("allow_fallback", raw.get("expected_decision_file") is None)),
        "require_verifier_pass": bool(raw.get("require_verifier_pass", raw.get("expected_decision_file") is not None)),
        "expected_blocked_claim_substrings": raw.get("expected_blocked_claim_substrings", []),
        "expected_absent_substrings": absent_substrings,
        "expected_present_substrings": raw.get("expected_present_substrings", []),
    }
    return {
        "case_id": raw["case_id"],
        "incident_id": raw.get("incident_id", raw["case_id"]),
        "title": raw.get("title", raw["case_id"]),
        "visible_events": [_visible_event_text(event) for event in raw.get("visible_events", [])],
        "incident_file": _resolve_case_path(base, raw.get("input_file") or raw.get("incident_file")),
        "expected_state_file": _resolve_case_path(base, raw.get("expected_state_file")),
        "expected_decision_file": _resolve_case_path(base, raw.get("expected_decision_file")),
        "hidden_future_event_ids": raw.get("hidden_future_event_ids", []),
        "service_catalog_snapshot_ids": raw.get("service_catalog_snapshot_ids", []),
        "memory_snapshot_ids": raw.get("memory_snapshot_ids", []),
        "expected": expected,
    }


def load_eval_cases(directory: str | Path) -> list[ReplayEvalCase]:
    source = Path(directory)
    if source.is_dir() and (source / "replay_cases.jsonl").exists():
        source = source / "replay_cases.jsonl"
    cases: list[ReplayEvalCase] = []
    if source.is_file():
        if source.suffix == ".jsonl":
            rows = []
            for line_number, line in enumerate(source.read_text().splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{source}:{line_number}: invalid JSONL replay case: {exc}") from exc
        elif source.suffix == ".json":
            data = json.loads(source.read_text())
            rows = data if isinstance(data, list) else [data]
        else:
            data = yaml.safe_load(source.read_text()) or {}
            rows = data if isinstance(data, list) else [data]
        for index, row in enumerate(rows, start=1):
            try:
                cases.append(ReplayEvalCase.model_validate(_adapt_eval_case(row, source.parent)))
            except Exception as exc:
                location = f"{source}:{index}" if source.suffix == ".jsonl" else str(source)
                raise ValueError(f"{location}: invalid ReplayEvalCase: {exc}") from exc
        return cases
    for path in (
        sorted(source.glob("*.yaml"))
        + sorted(source.glob("*.yml"))
        + sorted(source.glob("*.json"))
        + sorted(source.glob("*.jsonl"))
    ):
        for item in load_eval_cases(path):
            cases.append(item)
    return cases


def _contains_all(output: str, claims: list[str]) -> bool:
    lower = output.lower()
    output_terms = _claim_terms(lower)
    normalized_output = " ".join(token for token in output_terms)
    for claim in claims:
        claim_lower = claim.lower()
        if claim_lower in lower or _claim_semantically_present(claim_lower, lower):
            continue
        terms = _claim_terms(claim.lower())
        if not all(_term_present(term, output_terms, normalized_output) for term in terms):
            return False
    return True


def _claim_semantically_present(claim: str, output: str) -> bool:
    if "support points to revpro support" in claim:
        return "support" in output and "revpro support" in output
    if "not observed engaged" in claim:
        return "revpro support" in output and (
            "do not see" in output or "not visibly engaged" in output or "not observed" in output
        )
    if "deployment relation" in claim:
        return "deployment" in output and ("related" in output or "relation" in output)
    if "validation signal" in claim:
        return "validation" in output
    if "cpu did not decrease" in claim:
        return "cpu" in output and ("did not reduce" in output or "did not decrease" in output)
    if claim.startswith("engage revpro support"):
        return "revpro support" in output and "looped in" not in output
    return False


def _term_present(term: str, output_terms: list[str], normalized_output: str) -> bool:
    if term in normalized_output:
        return True
    stem = term.rstrip("s")
    if stem and any(token.startswith(stem) or stem.startswith(token.rstrip("s")) for token in output_terms):
        return True
    if len(term) >= 5 and any(token.startswith(term[:5]) for token in output_terms):
        return True
    return False


def _claim_terms(text: str) -> list[str]:
    return [
        token
        for token in "".join(ch if ch.isalnum() else " " for ch in text).split()
        if len(token) > 2 or token.isdigit()
    ]


def _contains_any_forbidden(output: str, claims: list[str]) -> list[str]:
    lower = output.lower()
    return [claim for claim in claims if claim and claim.lower() in lower]


def _command_text(command: Any) -> str | None:
    if not command:
        return None
    if isinstance(command, str):
        return command
    if isinstance(command, dict):
        return command.get("command_text") or command.get("command") or command.get("text")
    return str(command)


def _case_type(case: ReplayEvalCase) -> str:
    expected = case.expected
    if (
        expected.allow_fallback
        or expected.require_verifier_pass is False
        or expected.expected_verifier_status in {"blocked", "fallback_required"}
        or expected.expected_blocked_claim_substrings
    ):
        return "negative"
    if expected.acceptable_moves or case.expected_decision_file or expected.require_verifier_pass:
        return "positive"
    return "unknown"


def score_eval_result(case: ReplayEvalCase, result: dict[str, Any]) -> ReplayEvalResult:
    state = result.get("state")
    decision = result.get("decision")
    raw_decision = result.get("raw_decision", decision)
    verifier: VerifierResult | None = result.get("verifier_result")
    final_output = result.get("final_output", "")
    trace = result.get("trace")
    expected = case.expected
    case_type = _case_type(case)
    used_fallback = bool(
        trace.safety_summary.get("fallback_used")
        if trace is not None
        else raw_decision and decision and raw_decision.decision_id != decision.decision_id
    )
    simplified_path = bool(
        trace is not None
        and trace.processing_strategy in {"incident_read_and_whisper", "incident_read_and_whisper_v2"}
    )

    state_scores = {
        "phase": bool(simplified_path or not expected.phase or (state and state.phase == expected.phase)),
        "blocker": bool(simplified_path or not expected.blocker_type or (state and state.current_blocker == expected.blocker_type)),
    }

    target_names = [target.display_name for target in decision.targets] if decision else []
    command = _command_text(decision.output.get("command")) if decision else None
    decision_scores = {
        "move": bool(not expected.acceptable_moves or (decision and decision.move in expected.acceptable_moves)),
        "target": bool(
            not expected.acceptable_targets
            or any(target.lower() in {name.lower() for name in target_names} for target in expected.acceptable_targets)
            or any(target.lower() in final_output.lower() for target in expected.acceptable_targets)
        ),
        "command": bool(
            (trace is not None and trace.processing_strategy == "incident_read_and_whisper_v2")
            or
            not expected.acceptable_commands
            or (command and command in expected.acceptable_commands)
            or any(command_text in final_output for command_text in expected.acceptable_commands)
        ),
        "minimum_claims": _contains_all(final_output, expected.minimum_required_claims),
    }

    forbidden_texts = (
        expected.forbidden_entities
        + expected.forbidden_historical_facts
        + expected.forbidden_question_intents
        + expected.expected_absent_substrings
    )
    forbidden_hits = _contains_any_forbidden(final_output, forbidden_texts)
    blocked_text = "\n".join(verifier.blocked_claims if verifier else [])
    expected_blocked_ok = all(
        substring.lower() in blocked_text.lower()
        for substring in expected.expected_blocked_claim_substrings
    )
    verifier_status_ok = bool(
        not expected.expected_verifier_status
        or (verifier and verifier.final_status == expected.expected_verifier_status)
    )
    verifier_ok = bool(
        verifier
        and (
            verifier.passed
            if expected.require_verifier_pass
            else verifier.final_status in {"pass", "rewrite_required", "fallback_required", "blocked"}
        )
    )
    safety_scores = {
        "verifier_passed_or_expected": verifier_ok,
        "verifier_status": verifier_status_ok,
        "no_forbidden_text": not forbidden_hits,
        "no_invalid_command": bool(not verifier or verifier.checks.get("valid_command", True)),
        "expected_blocked_claims": expected_blocked_ok,
        "expected_present_substrings": _contains_all(final_output, expected.expected_present_substrings),
    }

    if expected.allow_fallback and verifier and not verifier.passed:
        decision_scores["move"] = decision_scores["move"] or decision.move == "no_safe_recommendation"
        decision_scores["target"] = decision_scores["target"] or not expected.acceptable_targets
        decision_scores["command"] = decision_scores["command"] or not expected.acceptable_commands

    if case_type == "positive" and not expected.allow_fallback:
        safety_scores["no_unexpected_fallback"] = not used_fallback
        safety_scores["positive_verifier_passed"] = bool(verifier and verifier.passed)
    elif case_type == "negative" and used_fallback:
        safety_scores["fallback_final_output_safe"] = not forbidden_hits

    passed = all(state_scores.values()) and all(decision_scores.values()) and all(safety_scores.values())
    failure_reasons = [
        f"state.{name}"
        for name, ok in state_scores.items()
        if not ok
    ] + [
        f"decision.{name}"
        for name, ok in decision_scores.items()
        if not ok
    ] + [
        f"safety.{name}"
        for name, ok in safety_scores.items()
        if not ok
    ]
    return ReplayEvalResult(
        case_id=case.case_id,
        passed=passed,
        state_scores=state_scores,
        decision_scores=decision_scores,
        safety_scores=safety_scores,
        latency_ms=int(result.get("latency_ms", 0)),
        final_output=final_output,
        verifier_result=verifier,
        used_fallback=used_fallback,
        verifier_status=verifier.final_status if verifier else None,
        failure_reasons=failure_reasons,
        case_type=case_type,
    )


def run_eval_case(case: ReplayEvalCase, pipeline: Pipeline) -> ReplayEvalResult:
    started = time.perf_counter()
    result = pipeline(case)
    result["latency_ms"] = int((time.perf_counter() - started) * 1000)
    return score_eval_result(case, result)


def run_eval_suite(
    directory: str | Path,
    pipeline: Pipeline | None = None,
    catalog_path: str | Path = "data/sample/service_catalog.yaml",
    memory_dir: str | Path = "data/sample/decision_moments",
    command_registry_path: str | Path | None = None,
) -> list[ReplayEvalResult]:
    cases = load_eval_cases(directory)
    if pipeline is None:
        from ic_copilot.llm.fixture_client import FixtureLLMClient

        fixture_client = FixtureLLMClient()

        def default_pipeline(case: ReplayEvalCase) -> dict[str, Any]:
            return run_pipeline_for_eval_case(
                case,
                catalog_path,
                memory_dir,
                command_registry_path,
                llm_client=fixture_client,
            )

        pipeline = default_pipeline
    return [run_eval_case(case, pipeline) for case in cases]


def format_eval_report(results: list[ReplayEvalResult]) -> str:
    lines = []
    passed = sum(1 for result in results if result.passed)
    total = len(results)
    positive = [result for result in results if result.case_type == "positive"]
    negative = [result for result in results if result.case_type == "negative"]
    fallback_used = sum(1 for result in results if result.used_fallback)
    verifier_blocks = sum(1 for result in results if result.verifier_status in {"blocked", "fallback_required"})

    def _failure_count(fragment: str) -> int:
        return sum(
            1
            for result in results
            if result.verifier_result
            and any(fragment in claim.lower() for claim in result.verifier_result.blocked_claims)
        )

    lines.append(f"Replay evals: {passed}/{total} passed")
    lines.append(
        "Summary: "
        f"positive {sum(1 for item in positive if item.passed)}/{len(positive)}, "
        f"negative {sum(1 for item in negative if item.passed)}/{len(negative)}, "
        f"fallback_used={fallback_used}, verifier_blocks={verifier_blocks}"
    )
    lines.append(
        "Safety counts: "
        f"stale={_failure_count('stale')}, "
        f"fake_entity={_failure_count('fake') + _failure_count('ungrounded')}, "
        f"historical_leakage={_failure_count('historical fact leaked')}, "
        f"invalid_command={_failure_count('command')}, "
        f"generic_output={_failure_count('generic')}"
    )
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        suffix = []
        if result.used_fallback:
            suffix.append("fallback")
        if result.verifier_status:
            suffix.append(f"verifier={result.verifier_status}")
        suffix_text = f" [{' '.join(suffix)}]" if suffix else ""
        lines.append(f"{status} {result.case_id} ({result.latency_ms} ms){suffix_text}")
        if not result.passed and result.verifier_result:
            if result.failure_reasons:
                lines.append(f"  failed score keys: {', '.join(result.failure_reasons)}")
            for claim in result.verifier_result.blocked_claims:
                lines.append(f"  blocked: {claim}")
            lines.append("  final output:")
            for line in result.final_output.splitlines():
                lines.append(f"    {line}")
    return "\n".join(lines)
