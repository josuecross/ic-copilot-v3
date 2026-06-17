from ic_copilot.schemas import (
    CurrentIncidentState,
    EntityRef,
    EntityType,
    EvidenceRef,
    QuestionRecord,
    StateDelta,
)
from ic_copilot.state_merge import merge_state_delta


def ev():
    return EvidenceRef(event_id="m001", quote="RevPro Support should be engaged")


def entity(name, status="suggested_not_engaged", confidence=0.8):
    return EntityRef(
        entity_type=EntityType.TEAM,
        display_name=name,
        canonical_id=name.lower().replace(" ", "-"),
        status=status,
        evidence=[ev()],
        confidence=confidence,
    )


def test_merges_suggested_but_not_engaged():
    state = CurrentIncidentState(incident_id="i1")
    merged = merge_state_delta(
        state,
        StateDelta(incident_id="i1", suggested_but_not_engaged=[entity("RevPro Support")]),
    )
    assert [item.display_name for item in merged.suggested_but_not_engaged] == ["RevPro Support"]


def test_removes_target_when_target_responds():
    state = CurrentIncidentState(incident_id="i1", suggested_but_not_engaged=[entity("RevPro Support")])
    merged = merge_state_delta(
        state,
        StateDelta(incident_id="i1", engaged_entities=[entity("RevPro Support", status="engaged")]),
    )
    assert not merged.suggested_but_not_engaged
    assert merged.engaged_entities[0].display_name == "RevPro Support"


def test_adds_stale_question_intent_when_state_already_knows_answer():
    state = CurrentIncidentState(incident_id="i1", suggested_but_not_engaged=[entity("RevPro Support")])
    question = QuestionRecord(
        question_id="q1",
        intent="already_looped_in",
        text="Is RevPro Support already looped in?",
        target="RevPro Support",
        evidence=[ev()],
    )
    merged = merge_state_delta(state, StateDelta(incident_id="i1", open_questions=[question]))
    assert "already_looped_in" in merged.stale_question_intents
    assert not merged.open_questions


def test_promotes_rejected_entity_only_with_new_explicit_evidence():
    state = CurrentIncidentState(incident_id="i1", rejected_entities=[entity("Default_Agent")])
    weak = merge_state_delta(
        state,
        StateDelta(incident_id="i1", candidate_services=[entity("Default_Agent", confidence=0.4)]),
    )
    assert weak.rejected_entities
    strong = merge_state_delta(
        state,
        StateDelta(incident_id="i1", candidate_services=[entity("Default_Agent", confidence=0.95)]),
    )
    assert not strong.rejected_entities


def test_rejected_url_domain_customer_is_not_promoted_by_name_only():
    rejected = EntityRef(
        entity_type=EntityType.CUSTOMER,
        display_name="Atlassian",
        status="rejected:url_domain",
        evidence=[ev()],
        confidence=0.8,
    )
    promoted_candidate = EntityRef(
        entity_type=EntityType.CUSTOMER,
        display_name="Atlassian",
        status="mentioned",
        evidence=[ev()],
        confidence=0.95,
    )
    state = CurrentIncidentState(incident_id="i1", rejected_entities=[rejected])
    merged = merge_state_delta(
        state,
        StateDelta(incident_id="i1", candidate_services=[promoted_candidate]),
    )
    assert merged.rejected_entities[0].display_name == "Atlassian"
