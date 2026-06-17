from __future__ import annotations

from ic_copilot.decision_repair import repair_blocked_decision
from ic_copilot.extractor import extract_state_delta
from ic_copilot.incident_brief import build_target_shortlist
from ic_copilot.incident_loader import load_incident_events
from ic_copilot.llm.fixture_client import FixtureLLMClient
from ic_copilot.pipeline import run_pipeline
from ic_copilot.planner import plan_ic_decision
from ic_copilot.schemas import (
    AllowedTarget,
    CurrentIncidentState,
    ICDecision,
    ICMove,
    IncidentBrief,
    IncidentBriefBlocker,
    IncidentBriefFocus,
    IncidentBriefRoleCandidate,
    IncidentBriefValue,
    IncidentPhase,
)
from ic_copilot.verifier import verify_ic_decision


OCS_FIXTURE = "data/personal_regression/incidents/p3_ocs_lag_trust_post_static.txt"


class _GenericPlannerClient(FixtureLLMClient):
    def generate_json(self, prompt_name, input_payload, response_model):
        if response_model is IncidentBrief or response_model.__name__ == "IncidentBrief":
            allowed = [AllowedTarget.model_validate(target) for target in input_payload["allowed_targets"]]
            target = next(target for target in allowed if target.targetable and target.display_name == "Engineer")
            return IncidentBrief(
                incident_id=input_payload["incident_id"],
                based_on_event_ids=["m001", "m002"],
                latest_window_event_ids=["m001", "m002"],
                latest_window_used=True,
                current_summary="Engineer is investigating dashboard lag and status is pending.",
                phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, confidence=0.82, evidence_ids=["m001"]),
                latest_blocker=IncidentBriefBlocker(
                    blocker_type="status_eta_needed",
                    summary="Need latest dashboard interpretation and recovery validation signal.",
                    evidence_ids=["m002"],
                    confidence=0.86,
                ),
                role_candidates=[
                    IncidentBriefRoleCandidate(
                        target_id=target.target_id,
                        name=target.display_name,
                        role_hint="technical_investigator",
                        confidence=0.9,
                        evidence_ids=["m002"],
                    )
                ],
                recommended_ic_focus=IncidentBriefFocus(
                    summary="Ask the active investigator for status and recovery validation signal.",
                    preferred_target_ids=[target.target_id],
                    acceptable_move_types=[ICMove.REQUEST_STATUS_OR_ETA, ICMove.ASK_NEXT_VALIDATION],
                    evidence_ids=["m002"],
                ),
            )
        if response_model is ICDecision or response_model.__name__ == "ICDecision":
            return ICDecision(
                decision_id="generic-model-output",
                incident_id=input_payload["current_state"]["incident_id"],
                move=ICMove.SUMMARIZE_CURRENT_STATE,
                phase=IncidentPhase.INVESTIGATION,
                output={"say_this": "I do not have a safe, grounded next move yet."},
                target_ids=[],
            )
        return super().generate_json(prompt_name, input_payload, response_model)


def test_ocs_lag_pipeline_uses_target_shortlist_and_not_no_safe() -> None:
    result = run_pipeline(
        OCS_FIXTURE,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=FixtureLLMClient(),
    )
    decision = result["decision"]
    output = result["final_output"].lower()
    trace = result["trace"]

    assert result["verifier_result"].passed
    assert decision.move in {ICMove.REQUEST_STATUS_OR_ETA, ICMove.ASK_NEXT_VALIDATION, ICMove.REQUEST_MONITORING_SIGNAL}
    assert decision.target_ids
    assert result["target_shortlist"] == []
    assert trace.processing_strategy in {"incident_read_and_whisper", "incident_read_and_whisper_v2"}
    assert trace.safety_summary["context_pack_summary"]["candidate_target_count"] > 0
    assert trace.safety_summary["selected_target_ids"] == decision.target_ids
    assert "no safe, grounded next move" not in output
    assert "trust post" not in output
    assert "share" not in output or "ticket" not in output
    assert any(term in output for term in ("lookup", "metric", "lag", "validation", "recovery"))
    assert "9863631" in {target.display_name for target in result["allowed_targets"] if not target.targetable}


def test_target_shortlist_prefers_active_technical_targets_over_support_and_generic() -> None:
    allowed = [
        AllowedTarget(
            target_id="t001",
            display_name="Support",
            target_type="team",
            role_hint="support_team",
            source="current_evidence",
            evidence_ids=["m001"],
        ),
        AllowedTarget(
            target_id="t002",
            display_name="Engineer",
            target_type="person",
            role_hint="technical_investigator",
            source="slack_author",
            evidence_ids=["m004"],
        ),
        AllowedTarget(
            target_id="t003",
            display_name="Investigation Team",
            target_type="team",
            role_hint="owner_team",
            source="current_evidence",
            evidence_ids=["m002"],
        ),
        AllowedTarget(
            target_id="t004",
            display_name="9863631",
            target_type="non_targetable_noise",
            source="current_evidence",
            targetable=False,
            evidence_ids=["m003"],
            reason="URL path number is not targetable",
        ),
    ]
    brief = IncidentBrief(
        incident_id="i",
        based_on_event_ids=["m001", "m002", "m003", "m004"],
        latest_window_event_ids=["m001", "m002", "m003", "m004"],
        current_summary="Dashboard lookup is active and status is pending.",
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, confidence=0.8, evidence_ids=["m004"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="status_eta_needed",
            summary="Need dashboard lookup interpretation and recovery signal.",
            evidence_ids=["m004"],
            confidence=0.88,
        ),
        role_candidates=[
            IncidentBriefRoleCandidate(
                target_id="t002",
                name="Engineer",
                role_hint="technical_investigator",
                confidence=0.9,
                evidence_ids=["m004"],
            )
        ],
        recommended_ic_focus=IncidentBriefFocus(
            summary="Ask Engineer for status and recovery signal.",
            preferred_target_ids=["t002"],
            acceptable_move_types=[ICMove.REQUEST_STATUS_OR_ETA],
            evidence_ids=["m004"],
        ),
    )
    shortlist = build_target_shortlist(allowed, brief, [])
    assert shortlist[0].target_id == "t002"
    assert all(target.display_name != "9863631" for target in shortlist)
    assert all(target.display_name != "Investigation Team" for target in shortlist)


def test_explicit_tenant_id_wins_over_url_number_rejection() -> None:
    delta = extract_state_delta(
        load_incident_events(OCS_FIXTURE, incident_id="p3_ocs_lag"),
        CurrentIncidentState(incident_id="p3_ocs_lag"),
        FixtureLLMClient(),
    )
    assert "30000091" in {fact.value for fact in (delta.impact.affected_tenants if delta.impact else [])}
    assert not any(
        entity.display_name == "30000091" and entity.status == "rejected:url_path_number"
        for entity in delta.rejected_entities
    )
    assert any(entity.display_name == "9863631" and entity.status == "rejected:url_path_number" for entity in delta.rejected_entities)


def test_generic_model_output_repairs_to_preferred_target_when_brief_has_blocker(tmp_path) -> None:
    incident = tmp_path / "generic_status.txt"
    incident.write_text(
        "Engineer 10:01 AM\nDashboard lookup shows lag is still growing; need status and validation signal."
    )
    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_GenericPlannerClient(),
    )
    decision = result["decision"]
    output = result["final_output"].lower()
    assert result["verifier_result"].passed
    assert decision.move == ICMove.NO_SAFE_RECOMMENDATION
    assert not decision.target_ids
    assert "safe, grounded next move" in output
    assert result["trace"].processing_strategy in {"incident_read_and_whisper", "incident_read_and_whisper_v2"}


def test_no_safe_recommendation_allowed_when_brief_has_no_blocker_or_target() -> None:
    state = CurrentIncidentState(incident_id="empty", phase=IncidentPhase.UNKNOWN)
    brief = IncidentBrief(
        incident_id="empty",
        based_on_event_ids=[],
        phase=IncidentBriefValue(primary=IncidentPhase.UNKNOWN, confidence=0.1, evidence_ids=[]),
        latest_blocker=IncidentBriefBlocker(blocker_type="unknown", summary="unknown", evidence_ids=[], confidence=0.1),
        recommended_ic_focus=IncidentBriefFocus(summary="", preferred_target_ids=[], acceptable_move_types=[], evidence_ids=[]),
    )
    decision = ICDecision(
        decision_id="no-safe",
        incident_id="empty",
        move=ICMove.NO_SAFE_RECOMMENDATION,
        phase=IncidentPhase.UNKNOWN,
        output={"say_this": "I do not have a safe, grounded next move yet."},
    )
    result = verify_ic_decision(decision, state, [], [], incident_brief=brief, allowed_targets=[])
    assert result.passed


def test_repair_does_not_keep_no_safe_when_preferred_target_and_blocker_are_valid() -> None:
    target = AllowedTarget(
        target_id="t001",
        display_name="Engineer",
        target_type="person",
        role_hint="technical_investigator",
        evidence_ids=["m001"],
    )
    state = CurrentIncidentState(incident_id="repair", phase=IncidentPhase.INVESTIGATION)
    brief = IncidentBrief(
        incident_id="repair",
        based_on_event_ids=["m001"],
        latest_window_event_ids=["m001"],
        current_summary="Engineer is checking dashboard status.",
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, confidence=0.8, evidence_ids=["m001"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="status_eta_needed",
            summary="Need dashboard status and validation signal.",
            evidence_ids=["m001"],
            confidence=0.85,
        ),
        role_candidates=[
            IncidentBriefRoleCandidate(
                target_id="t001",
                name="Engineer",
                role_hint="technical_investigator",
                confidence=0.9,
                evidence_ids=["m001"],
            )
        ],
        recommended_ic_focus=IncidentBriefFocus(
            summary="Ask Engineer for status and validation signal.",
            preferred_target_ids=["t001"],
            acceptable_move_types=[ICMove.REQUEST_STATUS_OR_ETA],
            evidence_ids=["m001"],
        ),
    )
    original = ICDecision(
        decision_id="bad",
        incident_id="repair",
        move=ICMove.NO_SAFE_RECOMMENDATION,
        phase=IncidentPhase.INVESTIGATION,
        output={"say_this": "I do not have a safe, grounded next move yet."},
    )
    verifier_result = verify_ic_decision(original, state, [], [], incident_brief=brief, allowed_targets=[target])
    assert not verifier_result.passed
    repaired = repair_blocked_decision(
        original_decision=original,
        verifier_result=verifier_result,
        current_state=state,
        catalog_matches=[],
        command_registry=[],
        accepted_memories=[],
        incident_brief=brief,
        allowed_targets=[target],
    )
    assert repaired is not None
    assert repaired.move == ICMove.REQUEST_STATUS_OR_ETA
    assert repaired.target_ids == ["t001"]


def test_status_eta_fallback_does_not_select_unknown_context_target_as_technical_owner() -> None:
    allowed = [
        AllowedTarget(
            target_id="t001",
            display_name="CustomerOrg",
            target_type="person",
            role_hint="unknown",
            source="slack_author",
            evidence_ids=["m001"],
        ),
        AllowedTarget(
            target_id="t002",
            display_name="Engineer",
            target_type="person",
            role_hint="technical_investigator",
            source="slack_author",
            evidence_ids=["m002"],
        ),
        AllowedTarget(
            target_id="t003",
            display_name="Owner Team",
            target_type="team",
            role_hint="owner_team",
            source="current_evidence",
            evidence_ids=["m003"],
        ),
    ]
    brief = IncidentBrief(
        incident_id="i",
        based_on_event_ids=["m001", "m002", "m003"],
        latest_window_event_ids=["m001", "m002", "m003"],
        current_summary="CustomerOrg reported symptoms; Engineer is checking logs for Owner Team.",
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, confidence=0.8, evidence_ids=["m002"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="status_eta_needed",
            summary="Need status from Engineer on the CustomerOrg validation signal.",
            evidence_ids=["m002"],
            confidence=0.8,
        ),
        role_candidates=[
            IncidentBriefRoleCandidate(
                target_id="t002",
                name="Engineer",
                role_hint="technical_investigator",
                confidence=0.9,
                evidence_ids=["m002"],
            ),
            IncidentBriefRoleCandidate(
                target_id="t003",
                name="Owner Team",
                role_hint="owner_team",
                confidence=0.8,
                evidence_ids=["m003"],
            ),
        ],
        recommended_ic_focus=IncidentBriefFocus(
            summary="Ask Engineer for status and validation signal.",
            preferred_target_ids=["t003"],
            acceptable_move_types=[ICMove.REQUEST_STATUS_OR_ETA],
            evidence_ids=["m002"],
        ),
    )
    decision = plan_ic_decision(
        CurrentIncidentState(incident_id="i", phase=IncidentPhase.INVESTIGATION),
        [],
        [],
        llm_client=None,
        incident_brief=brief,
        allowed_targets=allowed,
    )
    assert "t001" not in decision.target_ids
    assert any(target_id in decision.target_ids for target_id in {"t002", "t003"})
