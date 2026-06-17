from __future__ import annotations

import re

from ic_copilot.schemas import ICDecision, VerifierResult


ASK_TERMS = ("can you", "could you", "please", "confirm", "provide", "share")
STOPWORDS = {
    "and",
    "any",
    "are",
    "can",
    "confirm",
    "current",
    "latest",
    "please",
    "provide",
    "share",
    "status",
    "the",
    "this",
    "you",
}


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _tokens(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", _norm(value))
        if token not in STOPWORDS
    }


def _is_duplicate_ask(say_this: str, next_line: str) -> bool:
    say_norm = _norm(say_this)
    next_norm = _norm(next_line)
    if not say_norm or not next_norm:
        return False
    if not any(term in say_norm for term in ASK_TERMS) or not any(term in next_norm for term in ASK_TERMS):
        return False
    if next_norm in say_norm or say_norm in next_norm:
        return True
    say_tokens = _tokens(say_this)
    next_tokens = _tokens(next_line)
    if len(next_tokens) < 4:
        return False
    overlap = len(say_tokens & next_tokens) / max(1, len(next_tokens))
    return overlap >= 0.62


def lint_manual_copy_output(decision: ICDecision) -> tuple[ICDecision, bool, str | None]:
    """Keep SAY THIS/NEXT LINE short without changing move, targets, command, or facts."""
    say_this = str(decision.output.get("say_this") or "")
    next_line = str(decision.output.get("next_line") or "")
    if not _is_duplicate_ask(say_this, next_line):
        return decision, False, None
    output = dict(decision.output)
    output.pop("next_line", None)
    metadata = dict(decision.model_metadata)
    metadata["wording_lint_reason"] = "duplicate_next_line_removed"
    return decision.model_copy(update={"output": output, "model_metadata": metadata}), True, "duplicate_next_line_removed"


PRIVATE_ID_PLACEHOLDER_RE = re.compile(
    r"\[(?:REDACTED_)?(?:TENANT|ACCOUNT|CUSTOMER|ORG)(?:_ID)?\]|\b(?:TENANT_ID|ACCOUNT_ID|CUSTOMER_ID|ORG_ID)\b",
    re.IGNORECASE,
)
PRIVATE_ID_CONTEXT_RE = re.compile(
    r"\b(?:tenant|tenant id|account|account id|customer account|org id)\s*(?:[:=#-]|\bis\b)?\s*(?:\d{5,}|\[(?:REDACTED_)?(?:TENANT|ACCOUNT|CUSTOMER|ORG)(?:_ID)?\])\b",
    re.IGNORECASE,
)


def _redact_visible_private_ids(value: str) -> tuple[str, bool]:
    repaired = PRIVATE_ID_CONTEXT_RE.sub("affected tenant", value)
    repaired = PRIVATE_ID_PLACEHOLDER_RE.sub("affected tenant", repaired)
    repaired = re.sub(r"\baffected tenant\s+affected tenant\b", "affected tenant", repaired, flags=re.IGNORECASE)
    return repaired, repaired != value


def formatting_only_repair(
    decision: ICDecision,
    verifier_result: VerifierResult,
) -> tuple[ICDecision, bool, str | None]:
    """Repair product-envelope issues without changing semantic move, target, or evidence."""
    output = dict(decision.output)
    reasons: list[str] = []
    failed = {name for name, passed in verifier_result.checks.items() if not passed}
    if "valid_command" in failed and output.get("command"):
        output.pop("command", None)
        reasons.append("unsafe_or_unregistered_command_removed")
    if "no_private_identifier_in_visible_output" in failed:
        for key in ("say_this", "next_line"):
            if not output.get(key):
                continue
            repaired_value, changed = _redact_visible_private_ids(str(output.get(key) or ""))
            if changed:
                output[key] = repaired_value
                reasons.append("visible_private_identifier_redacted")
    say_this = str(output.get("say_this") or "")
    next_line = str(output.get("next_line") or "")
    if len(say_this) > 420:
        output["say_this"] = say_this[:417].rstrip() + "..."
        reasons.append("say_this_trimmed")
    if len(next_line) > 260:
        output["next_line"] = next_line[:257].rstrip() + "..."
        reasons.append("next_line_trimmed")
    repaired = decision.model_copy(update={"output": output})
    repaired, lint_changed, lint_reason = lint_manual_copy_output(repaired)
    if lint_changed and lint_reason:
        reasons.append(lint_reason)
    if not reasons:
        return decision, False, None
    metadata = dict(repaired.model_metadata)
    metadata["formatting_repair_reason"] = ",".join(reasons)
    metadata.setdefault("repaired_from_move", decision.move)
    metadata.setdefault("repaired_to_move", decision.move)
    return repaired.model_copy(update={"model_metadata": metadata}), True, ",".join(reasons)
