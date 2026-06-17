from __future__ import annotations

from pathlib import Path

from ic_copilot.memory import hydrate_decision_moments, judge_applicability, load_decision_moments
from ic_copilot.schemas import CurrentIncidentState, DecisionMoment, EntityRef, EntityType, EvidenceRef, IncidentPhase


CONTRACT = Path("data/contract")


def test_wrong_phase_rejection_is_traceable():
    moments = load_decision_moments(CONTRACT / "decision_moments.jsonl")
    moment = hydrate_decision_moments(["DM_missing_owner_after_support_signal"], moments)
    result = judge_applicability(
        CurrentIncidentState(incident_id="i", phase=IncidentPhase.INVESTIGATION, current_blocker="missing_owner"),
        moment,
    )[0]
    assert not result.accepted
    assert result.rejected_because_wrong_phase
    assert "wrong_phase" in result.reasons


def test_missing_required_evidence_rejection_lists_missing_terms():
    moments = load_decision_moments(CONTRACT / "decision_moments.jsonl")
    moment = hydrate_decision_moments(["DM_codefix_eta_blocker"], moments)
    result = judge_applicability(
        CurrentIncidentState(incident_id="i", phase=IncidentPhase.INVESTIGATION, current_blocker="waiting_on_code_fix"),
        moment,
    )[0]
    assert not result.accepted
    assert result.required_current_evidence_missing
    assert any("hotfix" in term.lower() or "person/team" in term.lower() for term in result.required_current_evidence_missing)


def test_target_already_engaged_rejection_is_traceable():
    moment = DecisionMoment(
        decision_id="dm-engage",
        source_incident_id="fixture",
        review_status="approved",
        quality_score=0.9,
        phase_before=IncidentPhase.ENGAGEMENT,
        phase_after=IncidentPhase.ENGAGEMENT,
        move="engage_owner",
        situation_before="Owner suggested.",
        trigger="No acknowledgement.",
        ic_action="Engage owner.",
        why_it_worked="Creates clear DRI.",
        applicability={"current_blocker": "missing_owner", "target_must_not_be_engaged": True},
    )
    result = judge_applicability(
        CurrentIncidentState(
            incident_id="i",
            phase=IncidentPhase.ENGAGEMENT,
            current_blocker="missing_owner",
            engaged_entities=[
                EntityRef(entity_type=EntityType.TEAM, display_name="RevPro Support", evidence=[])
            ],
        ),
        [moment],
    )[0]
    assert not result.accepted
    assert result.rejected_because_already_engaged
    assert "target_already_engaged" in result.reasons


def test_accepted_owner_memory_includes_allowed_pattern_and_satisfied_evidence():
    moments = load_decision_moments(CONTRACT / "decision_moments.jsonl")
    moment = hydrate_decision_moments(["DM_missing_owner_after_support_signal"], moments)
    result = judge_applicability(
        CurrentIncidentState(
            incident_id="i",
            phase=IncidentPhase.ENGAGEMENT,
            current_blocker="missing_owner",
            suggested_but_not_engaged=[
                EntityRef(
                    entity_type=EntityType.TEAM,
                    display_name="RevPro Support",
                    evidence=[EvidenceRef(event_id="m001", quote="RevPro Support should be engaged")],
                )
            ],
        ),
        moment,
    )[0]
    assert result.accepted
    assert result.allowed_patterns
    assert result.required_current_evidence_satisfied


def test_historical_forbidden_facts_are_preserved_for_verifier():
    moments = load_decision_moments(CONTRACT / "decision_moments.jsonl")
    moment = hydrate_decision_moments(["DM_uno_revenue_mapping_validation"], moments)[0]
    result = judge_applicability(
        CurrentIncidentState(
            incident_id="i",
            phase=IncidentPhase.INVESTIGATION,
            current_blocker="missing_validation",
            compact_summary="UNO Revenue RevenueOrgMapping=0 tenant mapping evidence",
        ),
        [moment],
    )[0]
    assert result.forbidden_fact_leakage
    assert {"10005051", "Google Fiber"}.issubset(set(result.forbidden_fact_leakage))
