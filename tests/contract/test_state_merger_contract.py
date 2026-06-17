from pathlib import Path

from ic_copilot.extractor import extract_state_delta
from ic_copilot.llm.fixture_client import FixtureLLMClient
from ic_copilot.normalizers.slack_paste import normalize_slack_text
from ic_copilot.schemas import CurrentIncidentState, EntityRef, EntityType, EvidenceRef, StateDelta
from ic_copilot.state_merge import merge_state_delta


CONTRACT = Path("data/contract")


def _state(file_name: str, incident_id: str):
    raw = (CONTRACT / "incidents" / file_name).read_text()
    events = normalize_slack_text(raw, incident_id=incident_id)
    delta = extract_state_delta(events, CurrentIncidentState(incident_id=incident_id), FixtureLLMClient())
    return merge_state_delta(None, delta)


def test_rejected_entity_ledger_and_stale_questions_survive_merge():
    negative = _state("06_negative_fake_entities.txt", "INC-9006")
    assert {entity.display_name for entity in negative.rejected_entities} >= {"Atlassian", "9863631"}

    stale = _state("07_stale_looped_in_question.txt", "INC-9007")
    assert any("looped in" in intent for intent in stale.stale_question_intents)
    assert any(entity.display_name == "RevPro Support" for entity in stale.suggested_but_not_engaged)


def test_suggested_target_removed_after_ack_and_evidence_preserved():
    evidence1 = EvidenceRef(event_id="m001", quote="RevPro Support should be engaged")
    evidence2 = EvidenceRef(event_id="m002", quote="RevPro Support: we are checking")
    state = CurrentIncidentState(
        incident_id="INC",
        suggested_but_not_engaged=[
            EntityRef(
                entity_type=EntityType.TEAM,
                display_name="RevPro Support",
                canonical_id="revpro-support",
                evidence=[evidence1],
            )
        ],
    )
    merged = merge_state_delta(
        state,
        StateDelta(
            incident_id="INC",
            engaged_entities=[
                EntityRef(
                    entity_type=EntityType.TEAM,
                    display_name="RevPro Support",
                    canonical_id="revpro-support",
                    status="responded",
                    evidence=[evidence2],
                )
            ],
        ),
    )
    assert not merged.suggested_but_not_engaged
    assert {ref.event_id for ref in merged.engaged_entities[0].evidence} == {"m001", "m002"}
