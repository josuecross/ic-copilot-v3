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

from ic_copilot.incident_read_v2 import incident_read_v2_from_v1_fixture
from ic_copilot.run_diagnosis import summarize_run_diagnosis
from ic_copilot.schemas import ICMove, IncidentReadAndWhisper, WhisperEvidenceRef
from ic_copilot.simplified_product_eval import MOVE_FAMILY_ALIASES


DEFAULT_RAW_PASTE_FIXTURE_PATH = Path("data/sample/raw_paste_product_eval_cases.jsonl")
DEFAULT_RAW_PASTE_OUTPUT_JSON = Path(".ic_copilot/product_eval/raw_paste_product_eval.json")
DEFAULT_RAW_PASTE_OUTPUT_MD = Path(".ic_copilot/product_eval/raw_paste_product_eval.md")
RAW_TERM_ALIASES: dict[str, tuple[str, ...]] = {
    "required permission": ("required permission", "permission denied", "permission-blocked", "permission"),
    "different shards": ("different shards", "different shard", "scope", "same issue"),
    "Kafka Investigation": ("Kafka Investigation", "Kafka cluster", "Kafka team", "performance check"),
    "Temporal workflow execution history": (
        "Temporal workflow execution history",
        "Temporal workflow status",
        "execution history",
        "Temporal workflow",
    ),
    "Temporal workflow": ("Temporal workflow", "Temporal Transfer Accounting workflow", "temporal"),
    "activity error": ("activity error", "activity error scope", "activity"),
    "Only Toast has reported impact": (
        "Only Toast has reported impact",
        "scope is currently limited to Toast",
        "limited to Toast",
    ),
    "row-count mismatch": ("row-count mismatch", "row-count", "row count"),
}
DEFAULT_FULL_AUDIT_JSON = Path(".ic_copilot/knowledge_intake/reports/latest_full_product_audit.json")
DEFAULT_FULL_AUDIT_MD = Path(".ic_copilot/knowledge_intake/reports/latest_full_product_audit.md")


@dataclass(frozen=True)
class RawPasteProductEvalFixture:
    fixture_id: str
    raw_paste_input: str
    expected_normalized_evidence_anchors: list[str]
    expected_retained_diagnostic_terms: list[str]
    expected_retained_diagnostic_fact_ids: list[str]
    expected_accepted_memory_ids: list[str]
    expected_target_classes: list[str]
    acceptable_target_names: list[str]
    unacceptable_target_names: list[str]
    expected_move_families: list[str]
    required_visible_ask_terms: list[str]
    forbidden_visible_ask_terms: list[str]
    allow_no_safe: bool
    notes: str
    expected_read: dict[str, Any]
    forbidden_retained_diagnostic_fact_ids: list[str] = field(default_factory=list)
    latency_warning_ms: int = 15_000

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RawPasteProductEvalFixture":
        required = {
            "fixture_id",
            "raw_paste_input",
            "expected_normalized_evidence_anchors",
            "expected_retained_diagnostic_terms",
            "expected_retained_diagnostic_fact_ids",
            "expected_accepted_memory_ids",
            "expected_target_classes",
            "acceptable_target_names",
            "unacceptable_target_names",
            "expected_move_families",
            "required_visible_ask_terms",
            "forbidden_visible_ask_terms",
            "allow_no_safe",
            "notes",
            "expected_read",
        }
        missing = sorted(required.difference(raw))
        if missing:
            raise ValueError(f"raw-paste product eval fixture missing fields: {', '.join(missing)}")
        return cls(
            fixture_id=str(raw["fixture_id"]),
            raw_paste_input=str(raw["raw_paste_input"]),
            expected_normalized_evidence_anchors=[str(item) for item in raw.get("expected_normalized_evidence_anchors", [])],
            expected_retained_diagnostic_terms=[str(item) for item in raw.get("expected_retained_diagnostic_terms", [])],
            expected_retained_diagnostic_fact_ids=[str(item) for item in raw.get("expected_retained_diagnostic_fact_ids", [])],
            forbidden_retained_diagnostic_fact_ids=[
                str(item) for item in raw.get("forbidden_retained_diagnostic_fact_ids", [])
            ],
            expected_accepted_memory_ids=[str(item) for item in raw.get("expected_accepted_memory_ids", [])],
            expected_target_classes=[str(item) for item in raw.get("expected_target_classes", [])],
            acceptable_target_names=[str(item) for item in raw.get("acceptable_target_names", [])],
            unacceptable_target_names=[str(item) for item in raw.get("unacceptable_target_names", [])],
            expected_move_families=[str(item) for item in raw.get("expected_move_families", [])],
            required_visible_ask_terms=[str(item) for item in raw.get("required_visible_ask_terms", [])],
            forbidden_visible_ask_terms=[str(item) for item in raw.get("forbidden_visible_ask_terms", [])],
            allow_no_safe=bool(raw.get("allow_no_safe", False)),
            notes=str(raw.get("notes", "")),
            expected_read=dict(raw.get("expected_read") or {}),
            latency_warning_ms=int(raw.get("latency_warning_ms", 15_000)),
        )


class RawPasteScriptedReadClient:
    def __init__(self, fixtures_by_id: dict[str, RawPasteProductEvalFixture]) -> None:
        self.fixtures_by_id = fixtures_by_id
        self.payloads: list[dict[str, Any]] = []

    def generate_json(self, prompt_name: str, input_payload: dict, response_model: type[BaseModel]):
        self.payloads.append(input_payload)
        fixture = self.fixtures_by_id[str(input_payload.get("incident_id") or "")]
        read = _incident_read_for_fixture(fixture, input_payload)
        if response_model is IncidentReadAndWhisper or response_model.__name__ == "IncidentReadAndWhisper":
            return read
        if response_model.__name__ == "IncidentReadAndWhisperV2":
            return incident_read_v2_from_v1_fixture(read=read, context_pack=input_payload)
        raise AssertionError(f"raw-paste eval should only call IncidentReadAndWhisper/V2: {prompt_name}")


def load_raw_paste_product_eval_fixtures(
    path: str | Path = DEFAULT_RAW_PASTE_FIXTURE_PATH,
) -> list[RawPasteProductEvalFixture]:
    source = Path(path)
    fixtures: list[RawPasteProductEvalFixture] = []
    for line_number, line in enumerate(source.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
            fixtures.append(RawPasteProductEvalFixture.from_dict(raw))
        except Exception as exc:
            raise ValueError(f"{source}:{line_number}: invalid raw-paste eval fixture: {exc}") from exc
    return fixtures


def _incident_read_for_fixture(fixture: RawPasteProductEvalFixture, payload: dict[str, Any]) -> IncidentReadAndWhisper:
    read = fixture.expected_read
    target_display = str(read.get("selected_target_display_name") or "")
    target_id = _target_id_for_display(payload.get("candidate_targets", []), target_display)
    evidence_quote = str(read.get("evidence_quote") or "")
    event_id, quote = _evidence_for_quote(payload.get("latest_window_events", []), evidence_quote)
    move_value = _move_value(str(read.get("selected_move") or "ask_next_validation"))
    return IncidentReadAndWhisper(
        incident_id=str(payload.get("incident_id") or fixture.fixture_id),
        current_read=str(read.get("current_read") or fixture.notes),
        latest_open_loop=str(read.get("latest_open_loop") or read.get("say_this") or ""),
        already_answered=[str(item) for item in read.get("already_answered", [])],
        selected_move=ICMove(move_value),
        selected_target_id=target_id,
        selected_target_display_name=target_display or None,
        say_this=str(read.get("say_this") or ""),
        next_line=str(read["next_line"]) if read.get("next_line") else None,
        evidence=[WhisperEvidenceRef(event_id=event_id, quote=quote, confidence=0.86)] if event_id else [],
        uncertainty=str(read["uncertainty"]) if read.get("uncertainty") else None,
        confidence=float(read.get("confidence", 0.86)),
    )


def _target_id_for_display(candidate_targets: list[dict[str, Any]], display_name: str) -> str | None:
    display_key = _key(display_name)
    for candidate in candidate_targets:
        if _key(str(candidate.get("display_name") or "")) == display_key:
            return str(candidate.get("target_id"))
    for candidate in candidate_targets:
        candidate_key = _key(str(candidate.get("display_name") or ""))
        if candidate_key and display_key and (candidate_key in display_key or display_key in candidate_key):
            return str(candidate.get("target_id"))
    return None


def _evidence_for_quote(events: list[dict[str, Any]], quote: str) -> tuple[str | None, str]:
    quote_key = _key(quote)
    if quote_key:
        for event in events:
            text = str(event.get("text") or "")
            if quote_key in _key(text):
                return str(event.get("event_id")), quote
    for event in reversed(events):
        text = " ".join(str(event.get("text") or "").split())
        if text:
            return str(event.get("event_id")), text[:220].rsplit(" ", 1)[0]
    return None, ""


def _move_value(value: str) -> str:
    if value in ICMove._value2member_map_:
        return value
    aliases = MOVE_FAMILY_ALIASES.get(value)
    if aliases:
        return sorted(aliases)[0]
    return value


def _move_family_values(families: list[str]) -> set[str]:
    values: set[str] = set()
    for family in families:
        values.update(MOVE_FAMILY_ALIASES.get(family, {family}))
    return values


def _key(value: str | None) -> str:
    return " ".join(re.sub(r"[^a-z0-9@_./-]+", " ", str(value or "").lower()).split()).lstrip("@")


def _contains(text: str, term: str) -> bool:
    if "/" in term:
        parts = [part.strip() for part in term.split("/") if part.strip()]
        if parts and all(_contains(text, part) for part in parts):
            return True
    terms = RAW_TERM_ALIASES.get(term, (term,))
    return any(_key(candidate) in _key(text) for candidate in terms)


def _fact_search_text(facts: list[Any]) -> str:
    pieces: list[str] = []
    for fact in facts:
        if not isinstance(fact, dict):
            continue
        pieces.extend(
            str(fact.get(key) or "")
            for key in ("fact_id", "fact_label", "matched_term", "excerpt")
            if fact.get(key)
        )
        pieces.extend(str(term) for term in fact.get("present_terms", []) if str(term).strip())
    return " ".join(pieces)


def _directly_addresses(text: str, target_name: str) -> bool:
    target = target_name.strip()
    if not target:
        return False
    escaped = re.escape(target)
    if re.search(rf"(?i)(?:^|\n|\s)@?{escaped}\b\s*(?:,|:|\bcan\b|\bcould\b|\bplease\b)", text):
        return True
    visible = re.sub(r"\s+", " ", text.strip())
    return _key(visible[: max(80, len(target) + 40)]).startswith(_key(target))


def _visible_text(result: dict[str, Any]) -> str:
    decision = result.get("decision")
    if decision is not None:
        output = getattr(decision, "output", {}) or {}
        return "\n".join(str(output.get(key) or "") for key in ("say_this", "next_line", "command"))
    return str(result.get("final_output") or "")


def _selected_target_names(result: dict[str, Any]) -> list[str]:
    decision = result.get("decision")
    if decision is None:
        return []
    names = [target.display_name for target in getattr(decision, "targets", [])]
    deduped: list[str] = []
    seen: set[str] = set()
    for name in names:
        key = _key(name)
        if key and key not in seen:
            seen.add(key)
            deduped.append(name)
    return deduped


def score_raw_paste_product_result(
    fixture: RawPasteProductEvalFixture,
    result: dict[str, Any],
    *,
    latency_ms: int,
) -> dict[str, Any]:
    trace = result.get("trace")
    decision = result.get("decision")
    verifier = result.get("verifier_result")
    safety = getattr(trace, "safety_summary", {}) if trace is not None else {}
    diagnosis_summary = summarize_run_diagnosis(getattr(trace, "run_diagnosis", {}) if trace is not None else {})
    context_summary = getattr(trace, "context_pack_summary", {}) if trace is not None else {}
    visible_text = _visible_text(result)
    visible_lower = visible_text.lower()
    selected_target_names = _selected_target_names(result)
    selected_target_text = " ".join(selected_target_names)
    move = getattr(decision, "move", "") if decision is not None else ""
    move_value = move.value if isinstance(move, ICMove) else str(move or "")
    fallback_used = bool(safety.get("fallback_used")) if isinstance(safety, dict) else move_value == ICMove.NO_SAFE_RECOMMENDATION.value
    reasons: list[str] = []
    warnings: list[str] = []

    if not verifier or not verifier.passed:
        reasons.append("verifier_not_passed")
    if fallback_used and not fixture.allow_no_safe:
        reasons.append("unexpected_no_safe")
    if move_value not in _move_family_values(fixture.expected_move_families):
        reasons.append(f"move_not_expected:{move_value}")
    if fixture.acceptable_target_names and not any(
        _contains(selected_target_text, name) for name in fixture.acceptable_target_names
    ):
        reasons.append("selected_target_not_acceptable")
    bad_targets = [
        name
        for name in fixture.unacceptable_target_names
        if _contains(selected_target_text, name) or _directly_addresses(visible_text, name)
    ]
    if bad_targets:
        reasons.append(f"wrong_target:{','.join(bad_targets)}")

    missing_visible = [term for term in fixture.required_visible_ask_terms if term.lower() not in visible_lower]
    if missing_visible:
        reasons.append(f"missing_visible_terms:{','.join(missing_visible)}")
    forbidden_visible = [term for term in fixture.forbidden_visible_ask_terms if term.lower() in visible_lower]
    if forbidden_visible:
        reasons.append(f"forbidden_visible_terms:{','.join(forbidden_visible)}")

    final_output = str(result.get("final_output") or "")
    evidence_text = "\n".join(
        str(event.get("text") or "")
        for event in (context_summary.get("latest_window_events") or [])
        if isinstance(event, dict)
    )
    retained_fact_search_text = _fact_search_text(
        context_summary.get("retained_diagnostic_facts", [])
        or safety.get("retained_diagnostic_facts", [])
        or []
    )
    if not evidence_text and trace is not None:
        evidence_text = retained_fact_search_text
    missing_anchors = [
        term for term in fixture.expected_normalized_evidence_anchors if not _contains(evidence_text + final_output, term)
    ]
    if missing_anchors:
        reasons.append(f"missing_evidence_anchors:{','.join(missing_anchors)}")
    retained_fact_ids = set(context_summary.get("retained_diagnostic_fact_ids") or safety.get("retained_diagnostic_fact_ids") or [])
    missing_fact_ids = [fact_id for fact_id in fixture.expected_retained_diagnostic_fact_ids if fact_id not in retained_fact_ids]
    if missing_fact_ids:
        reasons.append(f"missing_retained_diagnostic_facts:{','.join(missing_fact_ids)}")
    forbidden_fact_ids = [
        fact_id for fact_id in fixture.forbidden_retained_diagnostic_fact_ids if fact_id in retained_fact_ids
    ]
    if forbidden_fact_ids:
        reasons.append(f"forbidden_retained_diagnostic_facts:{','.join(forbidden_fact_ids)}")
    retained_fact_text = retained_fact_search_text
    missing_retained_terms = [
        term for term in fixture.expected_retained_diagnostic_terms if not _contains(retained_fact_text + evidence_text, term)
    ]
    if missing_retained_terms:
        reasons.append(f"missing_retained_diagnostic_terms:{','.join(missing_retained_terms)}")
    accepted_memory_ids = set(getattr(trace, "accepted_memory_ids", []) if trace is not None else [])
    missing_memories = [memory_id for memory_id in fixture.expected_accepted_memory_ids if memory_id not in accepted_memory_ids]
    if missing_memories:
        reasons.append(f"missing_accepted_memory:{','.join(missing_memories)}")
    target_class_rows = (
        safety.get("candidate_target_classes")
        or context_summary.get("candidate_target_classes")
        or safety.get("candidate_targets")
        or []
    )
    target_classes = {
        str(row.get("target_class") or "")
        for row in target_class_rows
        if any(_contains(str(row.get("display_name") or ""), name) for name in selected_target_names)
    }
    if fixture.expected_target_classes and not target_classes.intersection(fixture.expected_target_classes):
        reasons.append(f"target_class_not_expected:{','.join(sorted(target_classes) or ['unknown'])}")
    if context_summary.get("dropped_diagnostic_fact_ids"):
        dropped = [fact_id for fact_id in context_summary.get("dropped_diagnostic_fact_ids", []) if fact_id in fixture.expected_retained_diagnostic_fact_ids]
        if dropped:
            reasons.append(f"diagnostic_evidence_dropped:{','.join(dropped)}")
    if diagnosis_summary.get("likely_failure_category") == "none" and (fallback_used or reasons):
        reasons.append("weak_output_without_diagnosis")
    if latency_ms > fixture.latency_warning_ms:
        warnings.append(f"latency_warning:{latency_ms}ms")

    passed = not reasons
    return {
        "fixture_id": fixture.fixture_id,
        "passed": passed,
        "status": "pass" if passed else "fail",
        "reasons": reasons,
        "warnings": warnings,
        "say_this": _extract_say_this(result.get("final_output", "")) or visible_text.splitlines()[0],
        "final_output": result.get("final_output", ""),
        "selected_target_names": selected_target_names,
        "selected_target_classes": sorted(target_classes),
        "expected_target_classes": fixture.expected_target_classes,
        "move": move_value,
        "verifier_status": getattr(verifier, "final_status", None) if verifier is not None else None,
        "verifier_passed": bool(verifier and verifier.passed),
        "fallback_used": fallback_used,
        "latency_ms": latency_ms,
        "accepted_memory_ids": sorted(accepted_memory_ids),
        "expected_accepted_memory_ids": fixture.expected_accepted_memory_ids,
        "retained_diagnostic_fact_ids": sorted(retained_fact_ids),
        "dropped_diagnostic_fact_ids": context_summary.get("dropped_diagnostic_fact_ids", []),
        "retained_high_signal_diagnostic_event_ids": context_summary.get("retained_high_signal_diagnostic_event_ids", []),
        "dropped_high_signal_diagnostic_event_ids": context_summary.get("dropped_high_signal_diagnostic_event_ids", []),
        "diagnosis": diagnosis_summary,
        "notes": fixture.notes,
    }


def _extract_say_this(output: str) -> str:
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == "SAY THIS:" and index + 1 < len(lines):
            return lines[index + 1].strip()
    return ""


def run_raw_paste_product_eval(
    fixtures: list[RawPasteProductEvalFixture],
    *,
    catalog_path: str | Path = "local_knowledge/service_catalog.yaml",
    command_registry_path: str | Path = "local_knowledge/command_registry.yaml",
    memory_path: str | Path = "local_knowledge/decision_moments.jsonl",
) -> dict[str, Any]:
    from ic_copilot.pipeline import run_pipeline

    fixtures_by_id = {fixture.fixture_id: fixture for fixture in fixtures}
    client = RawPasteScriptedReadClient(fixtures_by_id)
    case_results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="raw-paste-product-eval-") as tmp:
        tmp_dir = Path(tmp)
        for fixture in fixtures:
            incident_path = tmp_dir / f"{fixture.fixture_id}.txt"
            incident_path.write_text(fixture.raw_paste_input)
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
            case_results.append(score_raw_paste_product_result(fixture, result, latency_ms=latency_ms))
    return _summary(case_results)


def _summary(case_results: list[dict[str, Any]]) -> dict[str, Any]:
    latencies = [int(case["latency_ms"]) for case in case_results]
    p50 = int(statistics.median(latencies)) if latencies else 0
    p95 = int(statistics.quantiles(latencies, n=20)[18]) if len(latencies) >= 2 else (latencies[0] if latencies else 0)
    passed = sum(1 for case in case_results if case["passed"])
    return {
        "eval_name": "raw_paste_product_eval",
        "mode": "scripted_incident_read",
        "total_cases": len(case_results),
        "passed": passed == len(case_results),
        "useful_pass_count": passed,
        "failed_count": len(case_results) - passed,
        "verifier_pass_count": sum(1 for case in case_results if case["verifier_passed"]),
        "fallback_count": sum(1 for case in case_results if case["fallback_used"]),
        "wrong_target_class_count": sum(
            1 for case in case_results if any(reason.startswith("target_class_not_expected") for reason in case["reasons"])
        ),
        "accepted_memory_intent_mismatch_count": sum(
            1 for case in case_results if any("accepted_memory" in reason for reason in case["reasons"])
        ),
        "diagnostic_evidence_dropped_count": sum(
            1 for case in case_results if any(reason.startswith("diagnostic_evidence_dropped") for reason in case["reasons"])
        ),
        "latency_p50_ms": p50,
        "latency_p95_ms": p95,
        "cases": case_results,
    }


def format_raw_paste_product_eval_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Raw Paste Product Eval",
        "",
        f"- mode: {report['mode']}",
        f"- total_cases: {report['total_cases']}",
        f"- useful_pass_count: {report['useful_pass_count']}",
        f"- verifier_pass_count: {report['verifier_pass_count']}",
        f"- fallback_count: {report['fallback_count']}",
        f"- wrong_target_class_count: {report['wrong_target_class_count']}",
        f"- accepted_memory_intent_mismatch_count: {report['accepted_memory_intent_mismatch_count']}",
        f"- diagnostic_evidence_dropped_count: {report['diagnostic_evidence_dropped_count']}",
        f"- latency_p50_ms: {report['latency_p50_ms']}",
        f"- latency_p95_ms: {report['latency_p95_ms']}",
        "",
        "## Cases",
        "",
        "| Case | Status | SAY THIS | Target | Target class | Move | Verifier | Fallback | Latency | Reasons |",
        "|---|---|---|---|---|---|---|---|---:|---|",
    ]
    for case in report["cases"]:
        lines.append(
            "| {case} | {status} | {say_this} | {target} | {target_class} | {move} | {verifier} | {fallback} | {latency} | {reasons} |".format(
                case=_md(case["fixture_id"]),
                status="PASS" if case["passed"] else "FAIL",
                say_this=_md(case["say_this"]),
                target=_md(", ".join(case["selected_target_names"]) or "none"),
                target_class=_md(", ".join(case["selected_target_classes"]) or "unknown"),
                move=_md(case["move"]),
                verifier=_md(str(case["verifier_status"])),
                fallback=str(case["fallback_used"]),
                latency=case["latency_ms"],
                reasons=_md(", ".join(case["reasons"]) if case["reasons"] else "ok"),
            )
        )
    return "\n".join(lines) + "\n"


def format_full_product_audit_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Full Product Raw Paste Audit",
        "",
        "## Summary",
        "",
        f"- recommendation: {report.get('recommendation')}",
        f"- total_cases: {report.get('total_cases')}",
        f"- useful_pass_count: {report.get('useful_pass_count')}",
        f"- fallback_count: {report.get('fallback_count')}",
        f"- wrong_target_class_count: {report.get('wrong_target_class_count')}",
        f"- diagnostic_evidence_dropped_count: {report.get('diagnostic_evidence_dropped_count')}",
        "",
        "## Per-Case Results",
        "",
        "| Case | Status | Diagnostic facts retained | Memory IDs | Target | Class | Output | Reason |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for case in report.get("cases", []):
        lines.append(
            "| {case} | {status} | {facts} | {memories} | {target} | {target_class} | {output} | {reason} |".format(
                case=_md(case["fixture_id"]),
                status="PASS" if case["passed"] else "FAIL",
                facts=_md(", ".join(case.get("retained_diagnostic_fact_ids", [])) or "none"),
                memories=_md(", ".join(case.get("accepted_memory_ids", [])) or "none"),
                target=_md(", ".join(case.get("selected_target_names", [])) or "none"),
                target_class=_md(", ".join(case.get("selected_target_classes", [])) or "unknown"),
                output=_md(case.get("say_this", "")),
                reason=_md(", ".join(case.get("reasons", [])) if case.get("reasons") else "ok"),
            )
        )
    lines.extend(
        [
            "",
            "## Remaining Risks",
            "",
            "- Scripted evals prove the deterministic product envelope and context contracts; they do not claim live-provider stability.",
            "- Target-class labels are debug/envelope metadata, not a deterministic target picker.",
            "",
            "## Recommendation",
            "",
            str(report.get("recommendation")),
        ]
    )
    return "\n".join(lines) + "\n"


def full_audit_report(eval_report: dict[str, Any]) -> dict[str, Any]:
    recommendation = "keep" if eval_report.get("passed") else "keep_with_monitoring"
    return {
        **eval_report,
        "audit_name": "full_product_raw_paste_audit",
        "recommendation": recommendation,
        "safety_invariants": [
            "simplified IncidentReadAndWhisper spine",
            "manual-copy only",
            "no Slack posting, paging, command execution, or remediation",
            "local_knowledge read-only during eval",
        ],
    }


def _md(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")
