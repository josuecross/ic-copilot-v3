import pytest
from pydantic import ValidationError

from ic_copilot.extractor import extract_state_delta
from ic_copilot.planner import plan_ic_decision
from ic_copilot.schema_repair import (
    normalize_move,
    normalize_phase,
    normalize_severity,
    validate_with_repair,
)
from ic_copilot.schemas import CurrentIncidentState, ICDecision, IncidentEvent, StateDelta


def test_schema_repair_normalizes_known_aliases() -> None:
    assert normalize_phase("acknowledgement") == "engagement"
    assert normalize_phase("Phase 1 - Acknowledge") == "engagement"
    assert normalize_phase("initial investigation") == "investigation"
    assert normalize_move("ask_eta") == "request_status_or_eta"
    assert normalize_move("ask_trust_post_confirmation") == "confirm_customer_comms"
    assert normalize_move("request_details_from_researcher") == "ask_next_validation"
    assert normalize_move("engage_target") == "engage_owner"
    assert normalize_move("check_ownership") == "confirm_ownership"
    assert normalize_move("request_ownership_confirmation") == "confirm_ownership"
    assert normalize_severity("sev3") == "P3"


def test_schema_repair_fails_closed_on_unknown_phase() -> None:
    with pytest.raises(ValidationError):
        validate_with_repair(
            {"incident_id": "i1", "phase": "totally_new_phase"},
            StateDelta,
            context="test",
        )


def test_schema_repair_does_not_add_facts() -> None:
    payload = {"incident_id": "i1", "phase": "acknowledgement"}
    repaired = validate_with_repair(payload, StateDelta, context="test")
    assert repaired.phase == "engagement"
    assert repaired.engaged_entities == []
    assert repaired.impact is None
    assert repaired.commands_seen == []


class _StateAliasClient:
    def generate_json(self, *_args, **_kwargs):
        return {"incident_id": "i1", "phase": "acknowledgement"}


class _DecisionAliasClient:
    def generate_json(self, *_args, **_kwargs):
        return {
            "decision_id": "d1",
            "incident_id": "i1",
            "move": "ask_eta",
            "phase": "Phase 1 - Acknowledge",
            "output": {"say_this": "Owner, please share status and ETA."},
        }


def test_extractor_handles_repairable_phase_alias() -> None:
    event = IncidentEvent(
        event_id="m001",
        incident_id="i1",
        sequence=1,
        source="slack_paste",
        message="IC: P3 acknowledgement is underway.",
        hash="h",
    )
    delta = extract_state_delta([event], CurrentIncidentState(incident_id="i1"), _StateAliasClient())
    assert delta.phase == "engagement"


def test_planner_handles_repairable_decision_alias() -> None:
    decision = plan_ic_decision(
        CurrentIncidentState(incident_id="i1"),
        [],
        [],
        llm_client=_DecisionAliasClient(),
        command_registry=[],
    )
    assert isinstance(decision, ICDecision)
    assert decision.move == "request_status_or_eta"
    assert decision.phase == "engagement"
