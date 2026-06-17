from pathlib import Path

from ic_copilot.memory import (
    build_memory_query,
    hydrate_decision_moments,
    judge_applicability,
    load_decision_moments,
    retrieve_decision_moment_ids,
)
from ic_copilot.schemas import CurrentIncidentState, EntityRef, EntityType, EvidenceRef, IncidentPhase


CONTRACT = Path("data/contract")


def test_jsonl_decision_moment_loading_and_id_hydration():
    moments = load_decision_moments(CONTRACT / "decision_moments.jsonl")
    assert len(moments) >= 8
    state = CurrentIncidentState(
        incident_id="INC",
        phase=IncidentPhase.ENGAGEMENT,
        current_blocker="missing_owner",
        suggested_but_not_engaged=[
            EntityRef(
                entity_type=EntityType.TEAM,
                display_name="RevPro Support",
                evidence=[EvidenceRef(event_id="m001", quote="RevPro Support should check")],
            )
        ],
        compact_summary="owner/team suggested in current incident; no observed acknowledgement from target",
    )
    ids = retrieve_decision_moment_ids(build_memory_query(state), moments)
    assert ids and all(isinstance(item, str) for item in ids)
    hydrated = hydrate_decision_moments(ids, moments)
    assert hydrated and hydrated[0].decision_id in ids


def test_applicability_rejects_wrong_blocker_missing_evidence_and_engaged_target():
    moments = load_decision_moments(CONTRACT / "decision_moments.jsonl")
    owner = hydrate_decision_moments(["DM_missing_owner_after_support_signal"], moments)

    wrong = CurrentIncidentState(
        incident_id="INC",
        phase=IncidentPhase.ENGAGEMENT,
        current_blocker="waiting_on_code_fix",
    )
    assert not judge_applicability(wrong, owner)[0].accepted

    missing = CurrentIncidentState(
        incident_id="INC",
        phase=IncidentPhase.ENGAGEMENT,
        current_blocker="missing_owner",
    )
    assert not judge_applicability(missing, owner)[0].accepted

    engaged = CurrentIncidentState(
        incident_id="INC",
        phase=IncidentPhase.ENGAGEMENT,
        current_blocker="missing_owner",
        engaged_entities=[
            EntityRef(entity_type=EntityType.TEAM, display_name="RevPro Support", evidence=[])
        ],
        compact_summary="owner/team suggested in current incident; no observed acknowledgement from target",
    )
    assert not judge_applicability(engaged, owner)[0].accepted

