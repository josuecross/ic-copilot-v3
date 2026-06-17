from __future__ import annotations

import json
import re
import statistics
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from ic_copilot.incident_read_v2 import incident_read_v2_from_v1_fixture
from ic_copilot.run_diagnosis import summarize_run_diagnosis
from ic_copilot.schemas import ICMove, IncidentReadAndWhisper, WhisperEvidenceRef


DEFAULT_FIXTURE_PATH = Path("data/sample/simplified_product_eval_cases.jsonl")
DEFAULT_OUTPUT_JSON = Path(".ic_copilot/product_eval/simplified_product_eval.json")
DEFAULT_OUTPUT_MD = Path(".ic_copilot/product_eval/simplified_product_eval.md")

MOVE_FAMILY_ALIASES: dict[str, set[str]] = {
    "ask_status_eta": {ICMove.ASK_STATUS_ETA.value, ICMove.REQUEST_STATUS_OR_ETA.value},
    "request_status_or_eta": {ICMove.ASK_STATUS_ETA.value, ICMove.REQUEST_STATUS_OR_ETA.value},
    "engage_owner": {ICMove.ENGAGE_OWNER.value, ICMove.CONFIRM_OWNERSHIP.value},
    "ask_next_validation": {ICMove.ASK_NEXT_VALIDATION.value},
    "ask_impact": {ICMove.ASK_IMPACT.value},
    "request_mitigation_option": {ICMove.REQUEST_MITIGATION_OPTION.value},
    "request_monitoring_signal": {ICMove.REQUEST_MONITORING_SIGNAL.value},
    "no_safe_recommendation": {ICMove.NO_SAFE_RECOMMENDATION.value},
}
VALIDATION_INTENT_ALIASES = ("validation", "validate", "verification", "verify", "confirm", "confirmation")


@dataclass(frozen=True)
class SimplifiedProductEvalFixture:
    fixture_id: str
    sanitized_slack_paste: str
    expected_usefulness_tags: list[str]
    forbidden_output_patterns: list[str]
    acceptable_target_names: list[str]
    unacceptable_target_names: list[str]
    acceptable_move_families: list[str]
    unacceptable_move_families: list[str]
    required_visible_terms: list[str]
    required_visible_term_groups: list[list[str]]
    forbidden_visible_terms: list[str]
    notes: str
    expected_read: dict[str, Any]
    allow_fallback: bool = False
    latency_warning_ms: int = 15_000
    latency_severe_ms: int = 45_000

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SimplifiedProductEvalFixture":
        missing = [
            key
            for key in (
                "fixture_id",
                "sanitized_slack_paste",
                "expected_usefulness_tags",
                "forbidden_output_patterns",
                "acceptable_target_names",
                "unacceptable_target_names",
                "acceptable_move_families",
                "unacceptable_move_families",
                "required_visible_terms",
                "forbidden_visible_terms",
                "notes",
            )
            if key not in raw
        ]
        if missing:
            raise ValueError(f"simplified product eval fixture missing fields: {', '.join(missing)}")
        return cls(
            fixture_id=str(raw["fixture_id"]),
            sanitized_slack_paste=str(raw["sanitized_slack_paste"]),
            expected_usefulness_tags=[str(item) for item in raw.get("expected_usefulness_tags", [])],
            forbidden_output_patterns=[str(item) for item in raw.get("forbidden_output_patterns", [])],
            acceptable_target_names=[str(item) for item in raw.get("acceptable_target_names", [])],
            unacceptable_target_names=[str(item) for item in raw.get("unacceptable_target_names", [])],
            acceptable_move_families=[str(item) for item in raw.get("acceptable_move_families", [])],
            unacceptable_move_families=[str(item) for item in raw.get("unacceptable_move_families", [])],
            required_visible_terms=[str(item) for item in raw.get("required_visible_terms", [])],
            required_visible_term_groups=_required_visible_term_groups(raw),
            forbidden_visible_terms=[str(item) for item in raw.get("forbidden_visible_terms", [])],
            notes=str(raw.get("notes", "")),
            expected_read=dict(raw.get("expected_read") or {}),
            allow_fallback=bool(raw.get("allow_fallback", False)),
            latency_warning_ms=int(raw.get("latency_warning_ms", 15_000)),
            latency_severe_ms=int(raw.get("latency_severe_ms", 45_000)),
        )


class ScriptedIncidentReadClient:
    """Eval-only client that supplies the single AI semantic read for a fixture.

    The normal product pipeline still performs normalization, target extraction,
    context packing, verifier checks, formatting-only repair, and rendering.
    """

    def __init__(self, fixtures_by_id: dict[str, SimplifiedProductEvalFixture]) -> None:
        self.fixtures_by_id = fixtures_by_id
        self.payloads: list[dict[str, Any]] = []

    def generate_json(self, prompt_name: str, input_payload: dict, response_model: type[BaseModel]):
        self.payloads.append(input_payload)
        fixture_id = str(input_payload.get("incident_id") or "")
        fixture = self.fixtures_by_id[fixture_id]
        read = _incident_read_for_fixture(fixture, input_payload)
        if response_model is IncidentReadAndWhisper or response_model.__name__ == "IncidentReadAndWhisper":
            return read
        if response_model.__name__ == "IncidentReadAndWhisperV2":
            return incident_read_v2_from_v1_fixture(read=read, context_pack=input_payload)
        raise AssertionError(f"simplified product eval should only call IncidentReadAndWhisper/V2: {prompt_name}")


def load_simplified_product_eval_fixtures(path: str | Path = DEFAULT_FIXTURE_PATH) -> list[SimplifiedProductEvalFixture]:
    source = Path(path)
    fixtures: list[SimplifiedProductEvalFixture] = []
    for line_number, line in enumerate(source.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{source}:{line_number}: invalid JSONL: {exc}") from exc
        try:
            fixtures.append(SimplifiedProductEvalFixture.from_dict(raw))
        except Exception as exc:
            raise ValueError(f"{source}:{line_number}: invalid simplified product fixture: {exc}") from exc
    return fixtures


def _incident_read_for_fixture(fixture: SimplifiedProductEvalFixture, payload: dict[str, Any]) -> IncidentReadAndWhisper:
    read = fixture.expected_read
    target_display = str(read.get("selected_target_display_name") or "")
    target_id = _target_id_for_display(payload.get("candidate_targets", []), target_display)
    evidence_quote = str(read.get("evidence_quote") or "")
    evidence_event_id, canonical_quote = _evidence_for_quote(payload.get("latest_window_events", []), evidence_quote)
    selected_move = _move_value(str(read.get("selected_move") or "request_status_or_eta"))
    return IncidentReadAndWhisper(
        incident_id=str(payload.get("incident_id") or fixture.fixture_id),
        current_read=str(read.get("current_read") or fixture.notes),
        latest_open_loop=str(read.get("latest_open_loop") or read.get("say_this") or ""),
        already_answered=[str(item) for item in read.get("already_answered", [])],
        selected_move=ICMove(selected_move),
        selected_target_id=target_id,
        selected_target_display_name=target_display or None,
        say_this=str(read.get("say_this") or ""),
        next_line=str(read["next_line"]) if read.get("next_line") else None,
        evidence=[
            WhisperEvidenceRef(
                event_id=evidence_event_id,
                quote=canonical_quote,
                confidence=float(read.get("evidence_confidence", 0.84)),
            )
        ]
        if evidence_event_id
        else [],
        uncertainty=str(read["uncertainty"]) if read.get("uncertainty") else None,
        confidence=float(read.get("confidence", 0.84)),
    )


def _target_id_for_display(candidate_targets: list[dict[str, Any]], display_name: str) -> str | None:
    display_key = _norm(display_name)
    if not display_key:
        return None
    for candidate in candidate_targets:
        if _norm(str(candidate.get("display_name") or "")) == display_key:
            return str(candidate.get("target_id"))
    for candidate in candidate_targets:
        candidate_key = _norm(str(candidate.get("display_name") or ""))
        if candidate_key and (candidate_key in display_key or display_key in candidate_key):
            return str(candidate.get("target_id"))
    return None


def _evidence_for_quote(events: list[dict[str, Any]], quote: str) -> tuple[str | None, str]:
    if quote:
        quote_key = _norm(quote)
        for event in events:
            text = str(event.get("text") or event.get("message") or "")
            if quote_key and quote_key in _norm(text):
                return str(event.get("event_id")), quote
    for event in reversed(events):
        text = str(event.get("text") or event.get("message") or "")
        if text.strip():
            return str(event.get("event_id")), _short_quote(text)
    return None, ""


def _short_quote(text: str, limit: int = 220) -> str:
    compact = " ".join(text.split())
    return compact if len(compact) <= limit else compact[:limit].rsplit(" ", 1)[0]


def _move_value(value: str) -> str:
    normalized = value.strip()
    if normalized in ICMove._value2member_map_:
        return normalized
    aliases = MOVE_FAMILY_ALIASES.get(normalized)
    if aliases:
        return sorted(aliases)[0]
    return normalized


def _move_family_values(families: list[str]) -> set[str]:
    values: set[str] = set()
    for family in families:
        normalized = family.strip()
        values.update(MOVE_FAMILY_ALIASES.get(normalized, {normalized}))
    return values


def _required_visible_term_groups(raw: dict[str, Any]) -> list[list[str]]:
    groups: list[list[str]] = []
    for raw_group in raw.get("required_visible_term_groups", []) or []:
        if isinstance(raw_group, dict):
            terms = raw_group.get("terms", [])
        else:
            terms = raw_group
        if not isinstance(terms, list):
            continue
        group = [str(item).strip() for item in terms if str(item).strip()]
        if group:
            groups.append(group)
    if _should_expand_validation_aliases(raw, groups):
        groups = _with_validation_alias_group(groups)
    return groups


def _should_expand_validation_aliases(raw: dict[str, Any], groups: list[list[str]]) -> bool:
    required_terms = {str(item).strip().lower() for item in raw.get("required_visible_terms", [])}
    if "validation" not in required_terms and not any(
        "validation" in {item.strip().lower() for item in group} for group in groups
    ):
        return False
    tags = {str(item).strip().lower() for item in raw.get("expected_usefulness_tags", [])}
    moves = {str(item).strip().lower() for item in raw.get("acceptable_move_families", [])}
    fixture_id = str(raw.get("fixture_id") or "").lower()
    return bool(
        {
            "pipeline_validation",
            "technical_validation",
            "scope_answer_superseded",
            "owner_aligned",
        }
        & tags
        or "ask_next_validation" in moves
        or "validation" in fixture_id
    )


def _with_validation_alias_group(groups: list[list[str]]) -> list[list[str]]:
    aliases = list(VALIDATION_INTENT_ALIASES)
    updated: list[list[str]] = []
    inserted = False
    for group in groups:
        lowered = {item.strip().lower() for item in group}
        if lowered & set(VALIDATION_INTENT_ALIASES):
            merged = list(dict.fromkeys([*group, *aliases]))
            updated.append(merged)
            inserted = True
        else:
            updated.append(group)
    if not inserted:
        updated.append(aliases)
    return updated


def _norm(value: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9@_./-]+", " ", str(value).lower()).split()).lstrip("@")


def _contains_name(text: str, name: str) -> bool:
    text_key = _norm(text)
    name_key = _norm(name)
    if not text_key or not name_key:
        return False
    return bool(re.search(rf"(?<![a-z0-9])@?{re.escape(name_key)}(?![a-z0-9])", text_key))


def _selected_target_names(result: dict[str, Any]) -> list[str]:
    decision = result.get("decision")
    if decision is None:
        return []
    names = [target.display_name for target in getattr(decision, "targets", [])]
    return _dedup_strings(names)


def _dedup_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        key = _norm(value)
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(value)
    return deduped


def _visible_text(result: dict[str, Any]) -> str:
    decision = result.get("decision")
    if decision is not None:
        output = getattr(decision, "output", {}) or {}
        return "\n".join(str(output.get(key) or "") for key in ("say_this", "next_line", "command"))
    return str(result.get("final_output") or "")


def _missing_visible_terms_with_aliases(
    required_terms: list[str],
    required_term_groups: list[list[str]],
    visible_lower: str,
) -> tuple[list[str], list[dict[str, Any]]]:
    missing: list[str] = []
    summary: list[dict[str, Any]] = []
    for term in required_terms:
        term_lower = term.lower()
        if term_lower in visible_lower:
            summary.append({"required": term, "matched": term, "match_type": "exact"})
            continue
        group = next(
            (items for items in required_term_groups if any(item.lower() == term_lower for item in items)),
            [],
        )
        alias_match = next((item for item in group if item.lower() in visible_lower), None)
        if alias_match:
            summary.append(
                {
                    "required": term,
                    "matched": alias_match,
                    "match_type": "alias_group",
                    "aliases": group,
                }
            )
            continue
        missing.append(term)
        if group:
            summary.append({"required": term, "matched": None, "match_type": "missing_alias_group", "aliases": group})
        else:
            summary.append({"required": term, "matched": None, "match_type": "missing_exact"})
    return missing, summary


def score_simplified_product_result(
    fixture: SimplifiedProductEvalFixture,
    result: dict[str, Any],
    *,
    latency_ms: int,
) -> dict[str, Any]:
    decision = result.get("decision")
    verifier = result.get("verifier_result")
    trace = result.get("trace")
    safety = getattr(trace, "safety_summary", {}) if trace is not None else {}
    run_diagnosis = getattr(trace, "run_diagnosis", {}) if trace is not None else {}
    diagnosis_summary = summarize_run_diagnosis(run_diagnosis)
    visible_text = _visible_text(result)
    visible_lower = visible_text.lower()
    raw_target_names = [
        target.display_name for target in getattr(decision, "targets", []) or []
    ] if decision is not None else []
    selected_target_names = _selected_target_names(result)
    target_dedup_applied = len(selected_target_names) < len(raw_target_names)
    selected_target_text = " ".join(selected_target_names + [visible_text])
    raw_move = getattr(decision, "move", "") if decision is not None else ""
    move = raw_move.value if isinstance(raw_move, ICMove) else str(raw_move or "")
    fallback_used = bool(safety.get("fallback_used")) if safety else move == ICMove.NO_SAFE_RECOMMENDATION.value
    fallback_trigger_detail = ""
    if isinstance(safety, dict):
        fallback_trigger_detail = ",".join(
            str(item)
            for item in (
                safety.get("original_blocked_claims")
                or safety.get("repair_blocked_claims")
                or safety.get("failed_checks")
                or []
            )
        )
    reasons: list[str] = []
    warnings: list[str] = []

    if not verifier or not verifier.passed:
        reasons.append("verifier_not_passed")
    if fallback_used and not fixture.allow_fallback:
        reasons.append("unexpected_fallback")
    if not fallback_used and fixture.allow_fallback:
        warnings.append("fallback_was_allowed_but_not_used")

    acceptable_moves = _move_family_values(fixture.acceptable_move_families)
    unacceptable_moves = _move_family_values(fixture.unacceptable_move_families)
    if acceptable_moves and move not in acceptable_moves:
        reasons.append(f"move_not_acceptable:{move}")
    if move in unacceptable_moves:
        reasons.append(f"move_forbidden:{move}")

    if fixture.acceptable_target_names and not any(
        _contains_name(selected_target_text, target) for target in fixture.acceptable_target_names
    ):
        reasons.append("selected_target_not_acceptable")
    bad_targets = [
        target for target in fixture.unacceptable_target_names if _contains_name(selected_target_text, target)
    ]
    if bad_targets:
        reasons.append(f"wrong_owner:{','.join(bad_targets)}")

    missing_terms, alias_summary = _missing_visible_terms_with_aliases(
        fixture.required_visible_terms,
        fixture.required_visible_term_groups,
        visible_lower,
    )
    if missing_terms:
        reasons.append(f"missing_visible_terms:{','.join(missing_terms)}")

    forbidden_terms = [term for term in fixture.forbidden_visible_terms if term.lower() in visible_lower]
    if forbidden_terms:
        reasons.append(f"forbidden_visible_terms:{','.join(forbidden_terms)}")
    pattern_hits = [
        pattern
        for pattern in fixture.forbidden_output_patterns
        if re.search(pattern, visible_text, flags=re.IGNORECASE)
    ]
    if pattern_hits:
        reasons.append(f"forbidden_output_patterns:{','.join(pattern_hits)}")

    blocked_claims = []
    if verifier is not None:
        blocked_claims.extend(getattr(verifier, "blocked_claims", []) or [])
    blocked_claims.extend(safety.get("original_blocked_claims", []) if isinstance(safety, dict) else [])
    blocked_text = "\n".join(str(item).lower() for item in blocked_claims)
    unsafe_action = any(
        term in visible_lower
        for term in (
            "restart",
            "execute",
            "page team",
            "page user",
            "run ",
            "delete ",
            "rotate keys",
            "disable ",
            "rollback",
            "remediate",
        )
    ) or "unsafe executable action" in blocked_text
    fake_entity = any(term in blocked_text for term in ("fake", "ungrounded", "url path", "historical fact leaked"))
    stale_question = any(term in visible_lower for term in ("looped in again", "already answered")) or any(
        term in blocked_text for term in ("stale", "already_answered repeats say this")
    )

    if latency_ms > fixture.latency_warning_ms:
        warnings.append(f"latency_warning:{latency_ms}ms")
    if latency_ms > fixture.latency_severe_ms:
        reasons.append(f"latency_severe:{latency_ms}ms")

    passed = not reasons
    return {
        "fixture_id": fixture.fixture_id,
        "passed": passed,
        "status": "pass" if passed else "fail",
        "reasons": reasons,
        "warnings": warnings,
        "final_output": result.get("final_output", ""),
        "say_this": _extract_section(result.get("final_output", ""), "SAY THIS") or visible_text.splitlines()[0],
        "selected_target_names": selected_target_names,
        "move": move,
        "verifier_status": getattr(verifier, "final_status", None) if verifier is not None else None,
        "verifier_passed": bool(verifier and verifier.passed),
        "fallback_used": fallback_used,
        "latency_ms": latency_ms,
        "expected_usefulness_tags": fixture.expected_usefulness_tags,
        "allow_fallback": fixture.allow_fallback,
        "wrong_owner": any(reason.startswith("wrong_owner") for reason in reasons),
        "stale_question": stale_question,
        "unsafe_action_wording": unsafe_action,
        "fake_entity": fake_entity,
        "notes": fixture.notes,
        "metadata_warnings": [
            key
            for key in (
                "metadata_only_stale_open_loop_repaired",
                "target_id_canonicalized",
                "evidence_quote_canonicalized",
            )
            if isinstance(safety, dict) and safety.get(key)
        ],
        "run_diagnosis_summary": diagnosis_summary,
        "final_output_quality": (run_diagnosis.get("final_output_quality") if isinstance(run_diagnosis, dict) else {})
        or {},
        "accepted_memory_ids": getattr(trace, "accepted_memory_ids", []) if trace is not None else [],
        "rejected_memory_ids": diagnosis_summary.get("rejected_memory_ids", []),
        "eval_alias_match_summary": alias_summary,
        "target_dedup_applied": target_dedup_applied or bool(diagnosis_summary.get("target_dedup_applied")),
        "fallback_trigger_check": fallback_trigger_detail,
        "live_failed_reason": ",".join(reasons),
        "no_safe_wording_quality": diagnosis_summary.get("no_safe_wording_quality", "not_applicable"),
        "move_normalized_from": diagnosis_summary.get("move_normalized_from"),
        "move_normalized_to": diagnosis_summary.get("move_normalized_to"),
    }


def _extract_section(output: str, label: str) -> str:
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == f"{label}:":
            return lines[index + 1].strip() if index + 1 < len(lines) else ""
    return ""


def run_simplified_product_eval(
    fixtures: list[SimplifiedProductEvalFixture],
    *,
    live: bool = False,
    catalog_path: str | Path = "data/contract/service_catalog.yaml",
    command_registry_path: str | Path = "data/contract/command_registry.yaml",
    memory_path: str | Path = "data/contract/decision_moments.jsonl",
) -> dict[str, Any]:
    from ic_copilot.pipeline import run_pipeline

    fixtures_by_id = {fixture.fixture_id: fixture for fixture in fixtures}
    llm_client = None if live else ScriptedIncidentReadClient(fixtures_by_id)
    case_results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="simplified-product-eval-") as tmp:
        tmp_dir = Path(tmp)
        for fixture in fixtures:
            incident_path = tmp_dir / f"{fixture.fixture_id}.txt"
            incident_path.write_text(fixture.sanitized_slack_paste)
            started = time.perf_counter()
            result = run_pipeline(
                incident_path,
                catalog_path=catalog_path,
                command_registry_path=command_registry_path,
                memory_path=memory_path,
                save_trace=False,
                llm_client=llm_client,
            )
            latency_ms = int((time.perf_counter() - started) * 1000)
            case_results.append(score_simplified_product_result(fixture, result, latency_ms=latency_ms))
    return _summarize_results(case_results, live=live)


def _summarize_results(case_results: list[dict[str, Any]], *, live: bool) -> dict[str, Any]:
    latencies = [int(case["latency_ms"]) for case in case_results]
    p50 = int(statistics.median(latencies)) if latencies else 0
    if len(latencies) >= 2:
        p95 = int(statistics.quantiles(latencies, n=20)[18])
    else:
        p95 = latencies[0] if latencies else 0
    passed = sum(1 for case in case_results if case["passed"])
    return {
        "eval_name": "simplified_product_eval",
        "mode": "live_product_provider" if live else "scripted_incident_read",
        "total_cases": len(case_results),
        "useful_pass_count": passed,
        "failed_count": len(case_results) - passed,
        "verifier_pass_count": sum(1 for case in case_results if case["verifier_passed"]),
        "fallback_count": sum(1 for case in case_results if case["fallback_used"]),
        "wrong_owner_count": sum(1 for case in case_results if case["wrong_owner"]),
        "stale_question_count": sum(1 for case in case_results if case["stale_question"]),
        "unsafe_action_wording_count": sum(1 for case in case_results if case["unsafe_action_wording"]),
        "fake_entity_count": sum(1 for case in case_results if case["fake_entity"]),
        "latency_p50_ms": p50,
        "latency_p95_ms": p95,
        "passed": passed == len(case_results),
        "cases": case_results,
    }


def format_simplified_product_eval_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Simplified Product Eval",
        "",
        f"- mode: {report['mode']}",
        f"- total_cases: {report['total_cases']}",
        f"- useful_pass_count: {report['useful_pass_count']}",
        f"- verifier_pass_count: {report['verifier_pass_count']}",
        f"- fallback_count: {report['fallback_count']}",
        f"- wrong_owner_count: {report['wrong_owner_count']}",
        f"- stale_question_count: {report['stale_question_count']}",
        f"- unsafe_action_wording_count: {report['unsafe_action_wording_count']}",
        f"- fake_entity_count: {report['fake_entity_count']}",
        f"- latency_p50_ms: {report['latency_p50_ms']}",
        f"- latency_p95_ms: {report['latency_p95_ms']}",
        "",
        "## Fixtures",
        "",
        "| Fixture | Status | SAY THIS | Target | Move | Verifier | Fallback | Latency | Reasons |",
        "|---|---|---|---|---|---|---|---:|---|",
    ]
    for case in report["cases"]:
        lines.append(
            "| {fixture} | {status} | {say_this} | {target} | {move} | {verifier} | {fallback} | {latency} | {reasons} |".format(
                fixture=_md_cell(case["fixture_id"]),
                status="PASS" if case["passed"] else "FAIL",
                say_this=_md_cell(case["say_this"]),
                target=_md_cell(", ".join(case["selected_target_names"]) or "none"),
                move=_md_cell(case["move"]),
                verifier=_md_cell(str(case["verifier_status"])),
                fallback=str(case["fallback_used"]),
                latency=case["latency_ms"],
                reasons=_md_cell(", ".join(case["reasons"]) if case["reasons"] else "ok"),
            )
        )
    return "\n".join(lines) + "\n"


def _md_cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")
