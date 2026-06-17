from ic_copilot.normalizers.slack_paste import normalize_slack_paste
from ic_copilot.schemas import (
    CurrentIncidentState,
    EntityRef,
    EntityType,
    EvidenceRef,
    ICDecision,
    ImpactState,
    LinkRef,
)
from ic_copilot.verifier import verify_ic_decision


def _p3_state() -> CurrentIncidentState:
    return CurrentIncidentState(
        incident_id="p3_in_11084",
        impact=ImpactState(description="Central SBX DataConnectSalesforceSync latency"),
        current_blocker="missing_owner",
        rejected_entities=[
            EntityRef(
                entity_type=EntityType.TENANT,
                display_name="9863631",
                status="rejected:url_path_number",
                evidence=[EvidenceRef(event_id="m001", quote="docs URL /9863631/edit")],
            ),
            EntityRef(
                entity_type=EntityType.TEAM,
                display_name="Default_Agent",
                status="rejected:not_supported_by_evidence",
                evidence=[EvidenceRef(event_id="m002", quote="Default_Agent bot placeholder")],
            ),
        ],
    )


def test_p3_in11084_blocks_docs_url_number_as_tenant() -> None:
    decision = ICDecision.model_validate(
        {
            "decision_id": "d1",
            "incident_id": "p3_in_11084",
            "move": "summarize_current_state",
            "phase": "engagement",
            "output": {"say_this": "Tenant 9863631 is impacted."},
        }
    )
    result = verify_ic_decision(decision, _p3_state(), catalog=[], accepted_memories=[])
    assert not result.passed
    assert any("9863631" in claim for claim in result.blocked_claims)


def test_p3_in11084_blocks_default_agent_as_real_team() -> None:
    decision = ICDecision.model_validate(
        {
            "decision_id": "d2",
            "incident_id": "p3_in_11084",
            "move": "engage_owner",
            "phase": "engagement",
            "output": {"say_this": "Default_Agent should own this."},
            "targets": [{"entity_type": "team", "display_name": "Default_Agent", "evidence": []}],
        }
    )
    result = verify_ic_decision(decision, _p3_state(), catalog=[], accepted_memories=[])
    assert not result.passed
    assert any("Default_Agent" in claim for claim in result.blocked_claims)


def test_p3_in11084_blocks_unregistered_command_suggestion() -> None:
    decision = ICDecision.model_validate(
        {
            "decision_id": "d3",
            "incident_id": "p3_in_11084",
            "move": "request_status_or_eta",
            "phase": "engagement",
            "output": {
                "say_this": "Dharani needs someone with access to help.",
                "command": "@zsrebot daco dedicated topic lookup tenantId 10000719",
            },
        }
    )
    result = verify_ic_decision(decision, _p3_state(), catalog=[], accepted_memories=[], command_registry=[])
    assert not result.passed
    assert any("command" in claim.lower() for claim in result.blocked_claims)


def test_p3_in11084_channel_created_message_is_not_command() -> None:
    events = normalize_slack_paste(
        "Slackbot: created this channel\n"
        "Faisal: @zsrebot daco dedicated topic lookup tenantId 10000719",
        incident_id="p3_in_11084",
    )
    assert events[0].source == "slack_system"
    assert events[0].extracted_tokens["command_candidates"] == []
    assert events[1].extracted_tokens["command_candidates"]


def test_p3_in11084_no_fake_customer_from_docs_url() -> None:
    state = _p3_state().model_copy(
        update={
            "links_seen": [
                LinkRef(
                    url="https://zuora.atlassian.net/wiki/spaces/DACO/pages/9863631/runbook",
                    evidence=[EvidenceRef(event_id="m001", quote="docs link")],
                )
            ]
        }
    )
    decision = ICDecision.model_validate(
        {
            "decision_id": "d4",
            "incident_id": "p3_in_11084",
            "move": "summarize_current_state",
            "phase": "engagement",
            "output": {"say_this": "Atlassian customer appears impacted."},
        }
    )
    result = verify_ic_decision(decision, state, catalog=[], accepted_memories=[])
    assert not result.passed
    assert any("customer" in claim.lower() for claim in result.blocked_claims)
