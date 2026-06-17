from __future__ import annotations

from pathlib import Path

from ic_copilot.extractor import extract_state_delta
from ic_copilot.incident_loader import load_incident_events
from ic_copilot.normalizers.slack_paste import normalize_slack_paste
from ic_copilot.planner import plan_ic_decision
from ic_copilot.schema_repair import normalize_move
from ic_copilot.schemas import CurrentIncidentState, EntityRef, EntityType, EvidenceRef, ICDecision, ICMove, LinkRef
from ic_copilot.state_merge import merge_state_delta
from ic_copilot.verifier import verify_ic_decision


class _TrustPostStateClient:
    def generate_json(self, _prompt_name, input_payload, response_model):
        return {"incident_id": input_payload["incident_id"], "phase": "investigation"}


class _TrustPostDecisionClient:
    def generate_json(self, _prompt_name, input_payload, response_model):
        return {
            "decision_id": "d-trust",
            "incident_id": input_payload["current_state"]["incident_id"],
            "move": "ask_trust_post_confirmation",
            "phase": "investigation",
            "output": {"say_this": "Trust/customer comms needs a confirmation."},
        }


def test_trust_post_move_alias_repairs_to_customer_comms() -> None:
    assert normalize_move("ask_trust_post_confirmation") == "confirm_customer_comms"
    decision = plan_ic_decision(
        CurrentIncidentState(incident_id="trust"),
        [],
        [],
        llm_client=_TrustPostDecisionClient(),
        command_registry=[],
    )
    assert decision.move == ICMove.CONFIRM_CUSTOMER_COMMS


def test_trust_post_no_need_becomes_answered_and_stale() -> None:
    events = load_incident_events(
        "data/personal_regression/incidents/p3_ocs_lag_trust_post_static.txt",
        incident_id="p3_ocs_lag",
    )
    delta = extract_state_delta(events, CurrentIncidentState(incident_id="p3_ocs_lag"), _TrustPostStateClient())
    state = merge_state_delta(CurrentIncidentState(incident_id="p3_ocs_lag"), delta)
    assert "ask_trust_post_needed" in state.stale_question_intents
    assert any(question.intent == "ask_trust_post_needed" for question in state.answered_questions)
    assert any("Trust Post answered as not needed" in action.summary for action in state.actions_completed)


def test_verifier_blocks_stale_trust_post_question_after_no_need() -> None:
    state = CurrentIncidentState(
        incident_id="trust",
        stale_question_intents=["ask_trust_post_needed", "confirm_trust_post_needed"],
    )
    decision = ICDecision(
        decision_id="d1",
        incident_id="trust",
        move=ICMove.CONFIRM_CUSTOMER_COMMS,
        phase="investigation",
        output={"say_this": "Can Support confirm whether Trust Post is needed?"},
    )
    result = verify_ic_decision(decision, state, catalog=[], accepted_memories=[], command_registry=[])
    assert not result.passed
    assert not result.checks["no_stale_question"]
    assert any("ask_trust_post_needed" in claim for claim in result.blocked_claims)


def test_ocs_lag_static_regression_blocks_url_tenant_and_default_agent() -> None:
    text = Path("data/personal_regression/incidents/p3_ocs_lag_trust_post_static.txt").read_text()
    events = normalize_slack_paste(text, incident_id="p3_ocs_lag")
    assert not events[0].extracted_tokens.get("command_candidates")

    state = CurrentIncidentState(
        incident_id="p3_ocs_lag",
        links_seen=[LinkRef(url="https://docs.example.invalid/document/d/9863631/edit")],
        rejected_entities=[
            EntityRef(
                entity_type=EntityType.TENANT,
                display_name="9863631",
                status="rejected:url_path_number",
                evidence=[EvidenceRef(event_id="m004", quote="https://docs.example.invalid/document/d/9863631/edit")],
            ),
            EntityRef(
                entity_type=EntityType.TEAM,
                display_name="Default_Agent",
                status="rejected:bot_system_message",
                evidence=[EvidenceRef(event_id="m002", quote="Default_Agent joined")],
            ),
        ],
        stale_question_intents=["ask_trust_post_needed"],
    )
    decision = ICDecision(
        decision_id="d2",
        incident_id="p3_ocs_lag",
        move=ICMove.CONFIRM_CUSTOMER_COMMS,
        phase="investigation",
        output={
            "say_this": "Default_Agent should confirm Trust Post for tenant 9863631.",
            "next_line": "Do we need a Trust Post?",
        },
    )
    result = verify_ic_decision(decision, state, catalog=[], accepted_memories=[], command_registry=[])
    blocked = "\n".join(result.blocked_claims)
    assert not result.passed
    assert "9863631" in blocked
    assert "Default_Agent" in blocked
    assert "ask_trust_post_needed" in blocked
