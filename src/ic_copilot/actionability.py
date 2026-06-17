from __future__ import annotations

import re
from typing import Any

from ic_copilot.schemas import AllowedTarget, ICDecision, ICMove


DIRECT_ASK_PHRASES = (
    "can you",
    "could you",
    "please confirm",
    "please share",
    "please provide",
    "confirm",
    "share",
    "provide",
)

VALIDATION_TERMS = ("validation", "validate", "verification", "row-count", "row count", "iceberg", "pipeline")
MONITORING_TERMS = ("monitor", "monitoring", "signal", "catch-up", "catch up", "trend", "queue depth", "oldest job age")
STATUS_TERMS = ("status", "eta", "blocker", "update")
IMPACT_TERMS = ("impact", "scope", "customer", "affected")
BROAD_OWNER_MOVES = {
    ICMove.ESCALATE_SEVERITY_OR_OWNER,
    ICMove.HANDOFF_OR_ASSIGN_DRI,
}
ADJACENT_DIRECT_ASK_NORMALIZATIONS: dict[ICMove, set[ICMove]] = {
    ICMove.REQUEST_MONITORING_SIGNAL: {
        ICMove.ASK_NEXT_VALIDATION,
        ICMove.REQUEST_STATUS_OR_ETA,
    },
    ICMove.REQUEST_STATUS_OR_ETA: {
        ICMove.ASK_NEXT_VALIDATION,
        ICMove.REQUEST_MONITORING_SIGNAL,
    },
    ICMove.ASK_STATUS_ETA: {
        ICMove.ASK_NEXT_VALIDATION,
        ICMove.REQUEST_MONITORING_SIGNAL,
    },
}
WEAK_NO_SAFE_FINALITY_PATTERNS = (
    "no further action needed",
    "nothing else to do",
    "no action required",
    "no action needed",
    "no follow-up needed",
    "no further follow-up",
)


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").lower()).strip()


def _name_norm(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", " ", _norm(value)).strip()


def _output_text(decision: ICDecision | dict[str, Any]) -> str:
    if isinstance(decision, ICDecision):
        output = decision.output
    else:
        output = decision.get("output") or {}
    return " ".join(str(output.get(key) or "") for key in ("say_this", "next_line")).strip()


def _decision_move(decision: ICDecision | dict[str, Any]) -> ICMove | str | None:
    move = decision.move if isinstance(decision, ICDecision) else decision.get("move")
    try:
        return ICMove(move)
    except (TypeError, ValueError):
        return move


def _move_value(move: ICMove | str | None) -> str | None:
    if isinstance(move, ICMove):
        return move.value
    return str(move) if move is not None else None


def _selected_target_names(decision: ICDecision | dict[str, Any]) -> set[str]:
    selected: set[str] = set()
    if isinstance(decision, ICDecision):
        for target in decision.targets:
            if target.display_name:
                selected.add(_name_norm(target.display_name))
        metadata = decision.model_metadata or {}
    else:
        for target in decision.get("targets") or []:
            display = target.get("display_name")
            if display:
                selected.add(_name_norm(display))
        metadata = decision.get("model_metadata") or {}
    display = metadata.get("selected_target_display_name")
    if display:
        selected.add(_name_norm(display))
    return {item for item in selected if item}


def is_direct_ask(text: str) -> bool:
    text_norm = _norm(text)
    return "?" in text or any(phrase in text_norm for phrase in DIRECT_ASK_PHRASES)


def visible_intent_move(text: str) -> ICMove | None:
    text_norm = _norm(text)
    if not is_direct_ask(text):
        return None
    has_validation = any(term in text_norm for term in VALIDATION_TERMS)
    has_monitoring = any(term in text_norm for term in MONITORING_TERMS)
    has_status = any(term in text_norm for term in STATUS_TERMS)
    has_impact = any(term in text_norm for term in IMPACT_TERMS)
    if "eta" in text_norm:
        return ICMove.REQUEST_STATUS_OR_ETA
    if has_validation and (has_status or has_impact or "owner" in text_norm):
        return ICMove.ASK_NEXT_VALIDATION
    if has_monitoring:
        return ICMove.REQUEST_MONITORING_SIGNAL
    if has_validation:
        return ICMove.ASK_NEXT_VALIDATION
    if has_status:
        return ICMove.REQUEST_STATUS_OR_ETA
    if has_impact:
        return ICMove.ASK_IMPACT
    return None


def no_safe_wording_quality(text: str, move: ICMove | str | None) -> str:
    if move != ICMove.NO_SAFE_RECOMMENDATION:
        return "not_applicable"
    text_norm = _norm(text)
    if any(pattern in text_norm for pattern in WEAK_NO_SAFE_FINALITY_PATTERNS):
        return "weak_finality"
    if "safe" in text_norm and "grounded" in text_norm and "next move" in text_norm:
        return "canonical"
    return "noncanonical"


def _allowed_target_quality_by_name(allowed_targets: list[AllowedTarget] | list[dict[str, Any]]) -> dict[str, str]:
    quality: dict[str, str] = {}
    for raw in allowed_targets or []:
        target = raw if isinstance(raw, AllowedTarget) else AllowedTarget.model_validate(raw)
        key = _name_norm(target.display_name)
        if key:
            quality[key] = target.target_quality if target.targetable else "rejected"
    return quality


def _owner_terms_from_passive_statement(text: str) -> list[str]:
    terms: list[str] = []
    patterns = (
        r"\bwe need\s+(?P<owner>[A-Z][A-Za-z .'-]{1,40}?)\s+(?:or|/)\s+(?:the\s+)?[\w .'-]{0,50}?\bowner\b\s+to\b",
        r"\bneed\s+(?P<owner>[A-Z][A-Za-z .'-]{1,40}?)\s+(?:or|/)\s+(?:the\s+)?[\w .'-]{0,50}?\bowner\b\s+to\b",
        r"\b(?P<owner>[A-Z][A-Za-z .'-]{1,40}?)\s+(?:or|/)\s+(?:the\s+)?[\w .'-]{0,50}?\bowner\b\s+(?:should|needs to|to)\b",
        r"\b(?:page|get)\s+(?P<owner>[A-Z][A-Za-z .'-]{1,40}?)\b",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            owner = " ".join(match.group("owner").split()).strip(" ,.;:")
            if owner and owner.lower() not in {"we", "current", "need", "the"}:
                terms.append(owner)
    return list(dict.fromkeys(terms))


def _has_passive_owner_statement(text: str) -> bool:
    text_norm = _norm(text)
    return bool(
        re.search(r"\bwe need\b.{0,80}\b(?:or|/)\b.{0,80}\bto\b", text, re.I)
        or re.search(r"\b(?:or|/)\b.{0,60}\bowner\b\s+(?:should|needs to|to|decide)\b", text, re.I)
        or "decide next steps" in text_norm
        and not is_direct_ask(text)
    )


def analyze_visible_actionability(
    decision: ICDecision | dict[str, Any],
    *,
    allowed_targets: list[AllowedTarget] | list[dict[str, Any]] | None = None,
    unresolved_open_loops: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    text = _output_text(decision)
    text_norm = _norm(text)
    move = _decision_move(decision)
    direct_ask = is_direct_ask(text)
    no_safe_quality = no_safe_wording_quality(text, move)
    passive_owner_statement = _has_passive_owner_statement(text)
    selected_names = _selected_target_names(decision)
    target_quality_by_name = _allowed_target_quality_by_name(list(allowed_targets or []))
    owner_terms = _owner_terms_from_passive_statement(text)
    low_quality_terms = []
    for term in owner_terms:
        key = _name_norm(term)
        if key in selected_names:
            continue
        quality = target_quality_by_name.get(key)
        if quality in {None, "low", "rejected", "invalid"}:
            low_quality_terms.append(term)
        elif passive_owner_statement:
            low_quality_terms.append(term)
    visible_move = visible_intent_move(text)
    move_visible_intent_mismatch = bool(
        move in BROAD_OWNER_MOVES and visible_move is not None and visible_move != move
    )
    unresolved_requires_question = bool(unresolved_open_loops) and move not in {
        ICMove.SUMMARIZE_CURRENT_STATE,
        ICMove.NO_SAFE_RECOMMENDATION,
    }
    unresolved_loop_without_question = unresolved_requires_question and not direct_ask and (
        passive_owner_statement
        or text_norm.startswith(("current findings", "current status", "findings show"))
        or "we need" in text_norm
    )
    hard_fail_reasons: list[str] = []
    if passive_owner_statement:
        hard_fail_reasons.append("visible output uses passive owner statement instead of direct IC ask")
    if low_quality_terms:
        hard_fail_reasons.append(
            "visible output assigns owner/action to unselected or low-quality named person: "
            + ", ".join(low_quality_terms)
        )
    if move_visible_intent_mismatch and not direct_ask:
        hard_fail_reasons.append("visible output move label does not match a useful direct visible ask")
    if unresolved_loop_without_question:
        hard_fail_reasons.append("unresolved open loop remains but visible output is not a concrete question")
    if no_safe_quality == "weak_finality":
        hard_fail_reasons.append("no_safe_recommendation visible wording implies closure without grounded closure evidence")
    if low_quality_terms:
        actionability_failure_category = "low_quality_named_owner"
    elif passive_owner_statement:
        actionability_failure_category = "passive_owner_statement"
    elif no_safe_quality == "weak_finality":
        actionability_failure_category = "no_safe_weak_finality"
    elif move_visible_intent_mismatch and not direct_ask:
        actionability_failure_category = "move_visible_intent_mismatch"
    elif unresolved_loop_without_question:
        actionability_failure_category = "unresolved_loop_without_question"
    else:
        actionability_failure_category = "none"
    return {
        "direct_ask": direct_ask,
        "passive_owner_statement": passive_owner_statement,
        "low_quality_named_owner_terms": low_quality_terms,
        "visible_intent_move": visible_move.value if isinstance(visible_move, ICMove) else visible_move,
        "move_visible_intent_mismatch": move_visible_intent_mismatch,
        "unresolved_loop_without_question": unresolved_loop_without_question,
        "actionability_failure_category": actionability_failure_category,
        "no_safe_wording_quality": no_safe_quality,
        "hard_fail_reasons": hard_fail_reasons,
    }


def normalize_move_for_visible_ask(decision: ICDecision) -> tuple[ICDecision, bool, str | None]:
    text = _output_text(decision)
    visible_move = visible_intent_move(text)
    decision_move = _decision_move(decision)
    if visible_move is None:
        return decision, False, None
    normalizable = decision_move in BROAD_OWNER_MOVES
    if isinstance(decision_move, ICMove):
        normalizable = normalizable or visible_move in ADJACENT_DIRECT_ASK_NORMALIZATIONS.get(decision_move, set())
    if not normalizable:
        return decision, False, None
    if visible_move == decision_move:
        return decision, False, None
    updated_metadata = {
        **decision.model_metadata,
        "actionability_move_normalization": {
            "from_move": _move_value(decision_move),
            "to_move": visible_move.value,
            "reason": "visible_direct_ask_intent",
        },
    }
    return decision.model_copy(update={"move": visible_move, "model_metadata": updated_metadata}), True, (
        f"visible_direct_ask_intent:{_move_value(decision_move)}->{visible_move.value}"
    )
