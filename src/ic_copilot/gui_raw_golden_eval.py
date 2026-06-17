from __future__ import annotations

import json
import re
import statistics
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from ic_copilot.incident_read_v2 import incident_read_v2_from_v1_fixture, is_pseudo_target_name
from ic_copilot.raw_paste_product_eval import _evidence_for_quote, _move_value, _target_id_for_display
from ic_copilot.run_diagnosis import summarize_run_diagnosis
from ic_copilot.schemas import ICMove, IncidentReadAndWhisper, WhisperEvidenceRef
from ic_copilot.simplified_product_eval import MOVE_FAMILY_ALIASES


DEFAULT_GUI_RAW_GOLDEN_CASES = Path("data/sample/gui_raw_golden_cases.jsonl")
DEFAULT_GUI_RAW_GOLDEN_OUTPUT_JSON = Path(".ic_copilot/product_eval/gui_raw_golden_eval.json")
DEFAULT_GUI_RAW_GOLDEN_OUTPUT_MD = Path(".ic_copilot/product_eval/gui_raw_golden_eval.md")


@dataclass(frozen=True)
class GuiRawGoldenCase:
    case_id: str
    raw_paste: str
    expected_blocker_types: list[str]
    expected_target_classes: list[str]
    allowed_targets: list[str]
    forbidden_targets: list[str]
    expected_move_families: list[str]
    must_include_terms: list[str]
    must_include_any_terms: list[str]
    must_not_include_terms: list[str]
    expected_accepted_memory_ids: list[str]
    allow_no_safe: bool
    manual_acceptance_notes: str
    expected_read: dict[str, Any]
    latency_warning_ms: int = 15_000
    source_path: str | None = None
    forbidden_asker_targets: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, root: Path) -> "GuiRawGoldenCase":
        case_id = str(raw.get("id") or raw.get("case_id") or "")
        if not case_id:
            raise ValueError("GUI raw golden case missing id")
        raw_paste = str(raw.get("raw_paste") or "")
        source_path = raw.get("raw_paste_path")
        if source_path:
            path = (root / str(source_path)).resolve()
            if not path.is_file():
                raise ValueError(f"{case_id}: raw_paste_path does not exist: {source_path}")
            raw_paste = path.read_text()
        if not raw_paste.strip():
            raise ValueError(f"{case_id}: raw paste is empty")
        expected_read = dict(raw.get("expected_read") or {})
        if not expected_read:
            raise ValueError(f"{case_id}: expected_read is required")
        blocker = raw.get("expected_blocker_type")
        blockers = [str(item) for item in raw.get("expected_blocker_types", [])]
        if blocker and not blockers:
            blockers = [str(blocker)]
        return cls(
            case_id=case_id,
            raw_paste=raw_paste,
            expected_blocker_types=blockers,
            expected_target_classes=[str(item) for item in raw.get("expected_target_class", [])]
            if isinstance(raw.get("expected_target_class"), list)
            else ([str(raw["expected_target_class"])] if raw.get("expected_target_class") else []),
            allowed_targets=[str(item) for item in raw.get("allowed_targets", [])],
            forbidden_targets=[str(item) for item in raw.get("forbidden_targets", [])],
            expected_move_families=[str(item) for item in raw.get("expected_move_family", [])]
            if isinstance(raw.get("expected_move_family"), list)
            else ([str(raw["expected_move_family"])] if raw.get("expected_move_family") else []),
            must_include_terms=[str(item) for item in raw.get("must_include_terms", [])],
            must_include_any_terms=[str(item) for item in raw.get("must_include_any_terms", [])],
            must_not_include_terms=[str(item) for item in raw.get("must_not_include_terms", [])],
            expected_accepted_memory_ids=[str(item) for item in raw.get("expected_accepted_memory_ids", [])],
            allow_no_safe=bool(raw.get("allow_no_safe", False)),
            manual_acceptance_notes=str(raw.get("manual_acceptance_notes") or raw.get("notes") or ""),
            expected_read=expected_read,
            latency_warning_ms=int(raw.get("latency_warning_ms", 15_000)),
            source_path=str(source_path) if source_path else None,
            forbidden_asker_targets=[str(item) for item in raw.get("forbidden_asker_targets", [])],
        )


class GuiRawGoldenScriptedClient:
    def __init__(self, cases_by_id: dict[str, GuiRawGoldenCase]) -> None:
        self.cases_by_id = cases_by_id
        self.payloads: list[dict[str, Any]] = []

    def generate_json(self, prompt_name: str, input_payload: dict, response_model: type[BaseModel]):
        self.payloads.append(input_payload)
        case = self.cases_by_id[str(input_payload.get("incident_id") or "")]
        read = _incident_read_for_case(case, input_payload)
        if response_model.__name__ == "IncidentReadAndWhisper":
            return read
        if response_model.__name__ == "IncidentReadAndWhisperV2":
            read_v2 = incident_read_v2_from_v1_fixture(read=read, context_pack=input_payload)
            blocker_type = case.expected_blocker_types[0] if case.expected_blocker_types else read_v2.next_blocker.blocker_type
            return read_v2.model_copy(
                update={
                    "next_blocker": read_v2.next_blocker.model_copy(
                        update={
                            "blocker_type": blocker_type,
                            "best_target_reason": case.manual_acceptance_notes
                            or read_v2.next_blocker.best_target_reason,
                        }
                    )
                }
            )
        raise AssertionError(f"GUI raw golden eval should only call IncidentReadAndWhisper/V2: {prompt_name}")


def load_gui_raw_golden_cases(
    path: str | Path = DEFAULT_GUI_RAW_GOLDEN_CASES,
    *,
    root: str | Path | None = None,
) -> list[GuiRawGoldenCase]:
    source = Path(path)
    repo_root = Path(root) if root is not None else Path(__file__).resolve().parents[2]
    cases: list[GuiRawGoldenCase] = []
    for line_number, line in enumerate(source.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            cases.append(GuiRawGoldenCase.from_dict(json.loads(line), root=repo_root))
        except Exception as exc:
            raise ValueError(f"{source}:{line_number}: invalid GUI raw golden case: {exc}") from exc
    return cases


def _incident_read_for_case(case: GuiRawGoldenCase, payload: dict[str, Any]) -> IncidentReadAndWhisper:
    read = case.expected_read
    target_display = str(read.get("selected_target_display_name") or "")
    target_id = _target_id_for_display(payload.get("candidate_targets", []), target_display)
    evidence_quote = str(read.get("evidence_quote") or "")
    event_id, quote = _evidence_for_quote(payload.get("latest_window_events", []), evidence_quote)
    return IncidentReadAndWhisper(
        incident_id=str(payload.get("incident_id") or case.case_id),
        current_read=str(read.get("current_read") or case.manual_acceptance_notes),
        latest_open_loop=str(read.get("latest_open_loop") or read.get("say_this") or ""),
        already_answered=[str(item) for item in read.get("already_answered", [])],
        selected_move=ICMove(_move_value(str(read.get("selected_move") or "ask_next_validation"))),
        selected_target_id=target_id,
        selected_target_display_name=target_display or None,
        say_this=str(read.get("say_this") or ""),
        next_line=str(read["next_line"]) if read.get("next_line") else None,
        evidence=[WhisperEvidenceRef(event_id=event_id, quote=quote, confidence=0.86)] if event_id else [],
        uncertainty=str(read["uncertainty"]) if read.get("uncertainty") else None,
        confidence=float(read.get("confidence", 0.86)),
    )


def _key(value: str | None) -> str:
    return " ".join(re.sub(r"[^a-z0-9@_./-]+", " ", str(value or "").lower()).split()).lstrip("@")


def _contains(text: str, term: str) -> bool:
    if _key(term) in _key(text):
        return True
    return _key(term.replace("-", " ")) in _key(text.replace("-", " "))


def _directly_addresses(text: str, target_name: str) -> bool:
    target = target_name.strip()
    if not target:
        return False
    escaped = re.escape(target)
    if re.search(rf"(?i)(?:^|\n|\s)@?{escaped}\b\s*(?:,|:|\bcan\b|\bcould\b|\bplease\b)", text):
        return True
    return _key(text[: max(90, len(target) + 50)]).startswith(_key(target))


def _move_family_values(families: list[str]) -> set[str]:
    values: set[str] = set()
    for family in families:
        values.update(MOVE_FAMILY_ALIASES.get(family, {family}))
    return values


def _selected_target_names(result: dict[str, Any]) -> list[str]:
    decision = result.get("decision")
    if decision is None:
        return []
    names = [target.display_name for target in getattr(decision, "targets", [])]
    return list(dict.fromkeys(name for name in names if name))


def _visible_text(result: dict[str, Any]) -> str:
    decision = result.get("decision")
    if decision is None:
        return str(result.get("final_output") or "")
    output = getattr(decision, "output", {}) or {}
    return "\n".join(str(output.get(key) or "") for key in ("say_this", "next_line", "command"))


def _v2_payload(result: dict[str, Any]) -> dict[str, Any]:
    trace = result.get("trace")
    safety = getattr(trace, "safety_summary", {}) if trace is not None else {}
    return safety.get("incident_read_and_whisper_v2") or result.get("incident_read_and_whisper_v2") or {}


def score_gui_raw_golden_result(case: GuiRawGoldenCase, result: dict[str, Any], *, latency_ms: int) -> dict[str, Any]:
    trace = result.get("trace")
    safety = getattr(trace, "safety_summary", {}) if trace is not None else {}
    verifier = result.get("verifier_result")
    decision = result.get("decision")
    visible_text = _visible_text(result)
    selected_targets = _selected_target_names(result)
    selected_target_text = " ".join(selected_targets)
    move = getattr(decision, "move", "") if decision is not None else ""
    move_value = str(getattr(move, "value", move or ""))
    v2 = _v2_payload(result)
    v2_blocker = ((v2.get("next_blocker") or {}).get("blocker_type") or safety.get("v2_blocker_type") or "")
    diagnosis = summarize_run_diagnosis(getattr(trace, "run_diagnosis", {}) if trace is not None else {})
    likely_failure = str(diagnosis.get("likely_failure_category") or "none")
    usefulness = str(safety.get("usefulness_status") or "")
    fallback_used = bool(safety.get("fallback_used")) or move_value == ICMove.NO_SAFE_RECOMMENDATION.value
    accepted_memory_ids = set(getattr(trace, "accepted_memory_ids", []) if trace is not None else [])
    accepted_contracts = safety.get("accepted_memory_behavior_contracts") or []
    provider_output_was_invalid = bool(safety.get("provider_output_was_invalid"))
    model_payload_over_cap = bool(safety.get("model_payload_over_cap"))
    reasons: list[str] = []
    warnings: list[str] = []

    if not verifier or not verifier.passed:
        reasons.append("verifier_not_passed")
    if fallback_used and not case.allow_no_safe:
        reasons.append("unexpected_no_safe")
    if provider_output_was_invalid:
        reasons.append("provider_output_invalid")
    if model_payload_over_cap:
        reasons.append("model_payload_over_cap")
    if case.expected_blocker_types and v2_blocker not in case.expected_blocker_types:
        reasons.append(f"blocker_type_not_expected:{v2_blocker or 'missing'}")
    if case.expected_move_families and move_value not in _move_family_values(case.expected_move_families):
        reasons.append(f"move_not_expected:{move_value}")
    if case.allowed_targets and not any(_contains(selected_target_text, name) for name in case.allowed_targets):
        reasons.append("selected_target_not_allowed")
    bad_targets = [
        name for name in case.forbidden_targets if _contains(selected_target_text, name) or _directly_addresses(visible_text, name)
    ]
    if bad_targets:
        reasons.append(f"forbidden_target:{','.join(bad_targets)}")
    pseudo_targets = [name for name in selected_targets if is_pseudo_target_name(name)]
    if pseudo_targets:
        reasons.append(f"pseudo_author_target:{','.join(pseudo_targets)}")
    asker_repeats = [
        name for name in case.forbidden_asker_targets if _contains(selected_target_text, name) or _directly_addresses(visible_text, name)
    ]
    if asker_repeats:
        reasons.append(f"ask_the_asker:{','.join(asker_repeats)}")
    missing_terms = [term for term in case.must_include_terms if not _contains(visible_text, term)]
    if missing_terms:
        reasons.append(f"missing_terms:{','.join(missing_terms)}")
    if case.must_include_any_terms and not any(_contains(visible_text, term) for term in case.must_include_any_terms):
        reasons.append("missing_any_terms:" + ",".join(case.must_include_any_terms))
    forbidden_terms = [term for term in case.must_not_include_terms if _contains(visible_text, term)]
    if forbidden_terms:
        reasons.append(f"forbidden_terms:{','.join(forbidden_terms)}")
    missing_memories = [
        memory_id for memory_id in case.expected_accepted_memory_ids if memory_id not in accepted_memory_ids
    ]
    if missing_memories:
        reasons.append(f"missing_accepted_memory:{','.join(missing_memories)}")
    if case.expected_accepted_memory_ids and not accepted_contracts:
        reasons.append("missing_accepted_memory_behavior_contracts")
    if likely_failure != "none" and usefulness == "pass":
        reasons.append("likely_failure_but_usefulness_pass")
    if latency_ms > case.latency_warning_ms:
        warnings.append(f"latency_warning:{latency_ms}ms")

    return {
        "case_id": case.case_id,
        "passed": not reasons,
        "status": "pass" if not reasons else "fail",
        "reasons": reasons,
        "warnings": warnings,
        "source_path": case.source_path,
        "selected_target_names": selected_targets,
        "expected_blocker_types": case.expected_blocker_types,
        "blocker_type": v2_blocker,
        "move": move_value,
        "say_this": visible_text.splitlines()[0] if visible_text else "",
        "verifier_status": getattr(verifier, "final_status", None) if verifier is not None else None,
        "verifier_passed": bool(verifier and verifier.passed),
        "fallback_used": fallback_used,
        "provider_output_was_invalid": provider_output_was_invalid,
        "model_payload_over_cap": model_payload_over_cap,
        "answered_questions_from_actions": safety.get("answered_questions_from_actions", []),
        "do_not_ask_from_actions": safety.get("do_not_ask_from_actions", []),
        "action_state_transitions": safety.get("action_state_transitions", []),
        "accepted_memory_ids": sorted(accepted_memory_ids),
        "expected_accepted_memory_ids": case.expected_accepted_memory_ids,
        "accepted_memory_behavior_contract_count": len(accepted_contracts),
        "safety_status": safety.get("safety_status"),
        "usefulness_status": safety.get("usefulness_status"),
        "state_quality_status": safety.get("state_quality_status"),
        "parser_quality_status": safety.get("parser_quality_status"),
        "likely_failure_category": likely_failure,
        "latency_ms": latency_ms,
        "manual_acceptance_notes": case.manual_acceptance_notes,
    }


def run_gui_raw_golden_eval(
    cases: list[GuiRawGoldenCase],
    *,
    catalog_path: str | Path = "local_knowledge/service_catalog.yaml",
    command_registry_path: str | Path = "local_knowledge/command_registry.yaml",
    memory_path: str | Path = "local_knowledge/decision_moments.jsonl",
    repeat: int = 1,
) -> dict[str, Any]:
    from ic_copilot.pipeline import run_pipeline

    case_results: list[dict[str, Any]] = []
    cases_by_id = {case.case_id: case for case in cases}
    client = GuiRawGoldenScriptedClient(cases_by_id)
    with tempfile.TemporaryDirectory(prefix="gui-raw-golden-eval-") as tmp:
        tmp_dir = Path(tmp)
        for case in cases:
            for attempt in range(1, max(1, repeat) + 1):
                incident_path = tmp_dir / f"{case.case_id}.txt"
                incident_path.write_text(case.raw_paste)
                started = time.perf_counter()
                result = run_pipeline(
                    incident_path,
                    catalog_path=catalog_path,
                    command_registry_path=command_registry_path,
                    memory_path=memory_path,
                    save_trace=False,
                    llm_client=client,
                )
                latency_ms = int((time.perf_counter() - started) * 1000)
                scored = score_gui_raw_golden_result(case, result, latency_ms=latency_ms)
                scored["attempt"] = attempt
                case_results.append(scored)
    return _summary(case_results, repeat=repeat)


def _summary(case_results: list[dict[str, Any]], *, repeat: int) -> dict[str, Any]:
    latencies = [int(case["latency_ms"]) for case in case_results]
    p50 = int(statistics.median(latencies)) if latencies else 0
    p95 = int(statistics.quantiles(latencies, n=20)[18]) if len(latencies) >= 2 else (latencies[0] if latencies else 0)
    passed_count = sum(1 for case in case_results if case["passed"])
    return {
        "eval_name": "gui_raw_golden_eval",
        "mode": "scripted_incident_read_v2",
        "repeat": repeat,
        "total_cases": len(case_results),
        "passed": passed_count == len(case_results),
        "useful_pass_count": passed_count,
        "failed_count": len(case_results) - passed_count,
        "unsafe_output_count": sum(1 for case in case_results if "verifier_not_passed" in case["reasons"]),
        "pseudo_author_target_count": sum(
            1 for case in case_results if any(reason.startswith("pseudo_author_target") for reason in case["reasons"])
        ),
        "ask_the_asker_count": sum(
            1 for case in case_results if any(reason.startswith("ask_the_asker") for reason in case["reasons"])
        ),
        "likely_failure_health_mismatch_count": sum(
            1 for case in case_results if "likely_failure_but_usefulness_pass" in case["reasons"]
        ),
        "fallback_count": sum(1 for case in case_results if case["fallback_used"]),
        "latency_p50_ms": p50,
        "latency_p95_ms": p95,
        "cases": case_results,
    }


def format_gui_raw_golden_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# GUI Raw Golden Eval",
        "",
        f"- mode: {report['mode']}",
        f"- repeat: {report['repeat']}",
        f"- total_cases: {report['total_cases']}",
        f"- useful_pass_count: {report['useful_pass_count']}",
        f"- failed_count: {report['failed_count']}",
        f"- unsafe_output_count: {report['unsafe_output_count']}",
        f"- pseudo_author_target_count: {report['pseudo_author_target_count']}",
        f"- ask_the_asker_count: {report['ask_the_asker_count']}",
        f"- likely_failure_health_mismatch_count: {report['likely_failure_health_mismatch_count']}",
        f"- fallback_count: {report['fallback_count']}",
        f"- latency_p50_ms: {report['latency_p50_ms']}",
        f"- latency_p95_ms: {report['latency_p95_ms']}",
        "",
        "## Cases",
        "",
        "| Case | Status | Blocker | Target | Move | Memories | Payload cap | SAY THIS | Reasons | Latency |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |",
    ]
    for case in report["cases"]:
        reasons = ", ".join(case["reasons"]) if case["reasons"] else "ok"
        target = ", ".join(case["selected_target_names"]) or "none"
        memories = ", ".join(case.get("accepted_memory_ids", [])) or "none"
        say_this = str(case["say_this"]).replace("|", "\\|")
        lines.append(
            f"| {case['case_id']} | {case['status']} | {case['blocker_type']} | {target} | "
            f"{case['move']} | {memories} | "
            f"{'over' if case.get('model_payload_over_cap') else 'ok'} | "
            f"{say_this} | {reasons} | {case['latency_ms']} |"
        )
    return "\n".join(lines) + "\n"
