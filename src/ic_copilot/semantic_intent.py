from __future__ import annotations

import re

from ic_copilot.llm.base import LLMClient
from ic_copilot.schema_repair import validate_with_repair
from ic_copilot.schemas import (
    CleanIncidentContext,
    CurrentIncidentState,
    ICDecision,
    SemanticDetectedIntent,
    SemanticIntentAssessment,
    SemanticStaleIntentMatch,
)
from ic_copilot.verifier import final_output_text


DETAILS_REQUEST_INTENTS = {
    "ask_reporter_for_more_details",
    "ask_reporter_observations_next_actions",
    "ask_security_reporter_for_details",
    "request_details_from_researcher",
    "request_next_actions_from_reporter",
    "request_observations",
    "request_vulnerability_details",
}


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _details_already_provided(state: CurrentIncidentState, clean_context: CleanIncidentContext) -> bool:
    stale = {_norm(intent) for intent in state.stale_question_intents}
    stale.update(_norm(intent) for intent in clean_context.question_ledger.stale_question_intents)
    if stale.intersection(DETAILS_REQUEST_INTENTS):
        return True
    for question in state.answered_questions + clean_context.question_ledger.answered_questions:
        text = _norm(f"{question.intent} {question.text} {question.answer or ''}")
        if any(intent in text for intent in DETAILS_REQUEST_INTENTS):
            return True
        if any(term in text for term in ("details link", "jira", "wf-", "vulnerability")):
            return True
    text = _norm(f"{clean_context.clean_summary} {clean_context.source_summary}")
    return "details link" in text or "wf-" in text or "jira" in text


def _semantic_details_request(text: str) -> str | None:
    text_norm = _norm(text)
    if any(term in text_norm for term in ("exposure scope", "containment", "mitigation", "validation step", "owner")):
        if not any(term in text_norm for term in ("observations", "proposed actions", "more details", "additional details")):
            return None
    patterns = (
        ("request_observations", r"\b(?:provide|share|what are)\b.{0,40}\bobservations\b"),
        ("request_next_actions_from_reporter", r"\b(?:next proposed actions|proposed next actions|proposed actions|your next actions)\b"),
        ("request_details_from_researcher", r"\b(?:more details|additional details|share details|provide details|vulnerability details|researcher report|provide context)\b"),
    )
    for intent, pattern in patterns:
        if re.search(pattern, text_norm):
            return intent
    return None


def _deterministic_assessment(
    decision: ICDecision,
    current_state: CurrentIncidentState,
    clean_context: CleanIncidentContext,
) -> SemanticIntentAssessment:
    text = final_output_text(decision)
    detected: list[SemanticDetectedIntent] = []
    stale: list[SemanticStaleIntentMatch] = []
    candidate_intent = _semantic_details_request(text)
    if candidate_intent:
        detected.append(SemanticDetectedIntent(intent=candidate_intent, confidence=0.86, evidence_or_text=text))
        if _details_already_provided(current_state, clean_context):
            stale_intents = set(current_state.stale_question_intents)
            stale_intents.update(clean_context.question_ledger.stale_question_intents)
            matched = next((intent for intent in DETAILS_REQUEST_INTENTS if intent in stale_intents), "request_details_from_researcher")
            stale.append(
                SemanticStaleIntentMatch(
                    candidate_intent=candidate_intent,
                    matched_stale_intent=matched,
                    confidence=0.9,
                    reason="Reporter already provided vulnerability/details link after the ask.",
                )
            )
    return SemanticIntentAssessment(
        incident_id=current_state.incident_id,
        candidate_output_text=text,
        detected_intents=detected,
        stale_intent_matches=stale,
        unsafe_or_repeated_questions=[
            match.reason for match in stale if match.confidence >= 0.75
        ],
        allowed_next_step_intents=[
            "confirm_owner",
            "confirm_exposure_scope",
            "request_containment_or_validation",
        ]
        if _details_already_provided(current_state, clean_context)
        else [],
        recommended_repair_direction=(
            "Ask for owner, exposure scope, containment, mitigation, or next validation step."
            if stale
            else None
        ),
    )


def assess_output_intent(
    decision: ICDecision,
    current_state: CurrentIncidentState,
    clean_context: CleanIncidentContext,
    llm_client: LLMClient,
) -> SemanticIntentAssessment:
    payload = {
        "incident_id": current_state.incident_id,
        "candidate_output_text": final_output_text(decision),
        "decision": decision.model_dump(mode="json"),
        "current_state": current_state.model_dump(mode="json"),
        "clean_context": clean_context.model_dump(mode="json"),
        "rules": [
            "Classify candidate output intent semantically.",
            "A stale match can only add a block or repair direction; it cannot bypass deterministic safety.",
            "Do not invent facts or new evidence.",
        ],
    }
    try:
        assessment = llm_client.generate_json("semantic_intent_assessment", payload, SemanticIntentAssessment)
    except Exception:
        assessment = _deterministic_assessment(decision, current_state, clean_context)
    validated = validate_with_repair(assessment, SemanticIntentAssessment, context="semantic_intent_assessment")
    return validated


def build_deterministic_semantic_intent_assessment(
    decision: ICDecision,
    current_state: CurrentIncidentState,
    clean_context: CleanIncidentContext,
) -> SemanticIntentAssessment:
    return _deterministic_assessment(decision, current_state, clean_context)


def high_confidence_stale_matches(assessment: SemanticIntentAssessment, threshold: float = 0.75) -> list[SemanticStaleIntentMatch]:
    return [match for match in assessment.stale_intent_matches if match.confidence >= threshold]
