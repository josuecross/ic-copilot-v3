from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from ic_copilot.catalog import load_command_registry, load_service_catalog
from ic_copilot.incident_brief import build_allowed_targets
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
    IncidentEvent,
    IncidentBriefFocus,
    IncidentBriefRoleCandidate,
    IncidentBriefValue,
    IncidentPhase,
)
from ic_copilot.verifier import verify_ic_decision


API_504_FIXTURE = "data/personal_regression/incidents/p3_api_504_revenue_timeout_static.txt"


def test_incident_brief_schema_is_strict_and_requires_blocker_evidence() -> None:
    with pytest.raises(ValidationError):
        IncidentBrief.model_validate(
            {
                "incident_id": "i",
                "phase": {"primary": "investigation"},
                "latest_blocker": {
                    "blocker_type": "validation_needed",
                    "summary": "validation pending",
                    "evidence_ids": [],
                },
                "extra": "not allowed",
            }
        )
    brief = IncidentBrief(
        incident_id="i",
        based_on_event_ids=["m001"],
        phase=IncidentBriefValue(primary=IncidentPhase.INVESTIGATION, confidence=0.8, evidence_ids=["m001"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="validation_needed",
            summary="validation pending",
            evidence_ids=["m001"],
            confidence=0.8,
        ),
        role_candidates=[
            IncidentBriefRoleCandidate(
                target_id="t001",
                name="Reporter",
                role_hint="reporter_or_validator",
                evidence_ids=["m001"],
                confidence=0.8,
            )
        ],
        recommended_ic_focus=IncidentBriefFocus(
            summary="confirm validation",
            preferred_target_ids=["t001"],
            acceptable_move_types=[ICMove.ASK_NEXT_VALIDATION],
            evidence_ids=["m001"],
        ),
    )
    assert brief.latest_blocker.blocker_type == "validation_needed"


def test_allowed_targets_filter_noise_and_keep_current_slack_authors() -> None:
    events = load_incident_events(API_504_FIXTURE)
    catalog = load_service_catalog("data/contract/service_catalog.yaml")
    registry = load_command_registry("data/contract/command_registry.yaml", catalog)
    targets = build_allowed_targets(events, catalog, registry)
    by_name = {target.display_name: target for target in targets}
    assert by_name["Sriram"].targetable
    assert by_name["Aditya"].targetable
    assert by_name["9863631"].targetable is False
    assert by_name["Default_Agent"].targetable is False
    assert any(target.source == "catalog" for target in targets)


def test_allowed_targets_do_not_promote_question_fragments() -> None:
    events = [
        IncidentEvent(
            incident_id="frag",
            event_id="m001",
            sequence=1,
            author="IC",
            message="Can SRE disable the noisy service? Please Revenue Engineering confirm status.",
            hash="h001",
        )
    ]
    targets = build_allowed_targets(events, [], [])
    names = {target.display_name for target in targets}
    assert "Can SRE" not in names
    assert "Please Revenue Engineering" not in names


def test_planner_uses_incident_brief_target_ids() -> None:
    allowed = [
        AllowedTarget(target_id="t001", display_name="Engineer", target_type="person", role_hint="technical_investigator", evidence_ids=["m001"]),
        AllowedTarget(target_id="t002", display_name="Reporter", target_type="person", role_hint="reporter_or_validator", evidence_ids=["m002"]),
    ]
    brief = IncidentBrief(
        incident_id="i",
        based_on_event_ids=["m001", "m002"],
        phase=IncidentBriefValue(primary=IncidentPhase.MONITORING, confidence=0.8, evidence_ids=["m001"]),
        latest_blocker=IncidentBriefBlocker(
            blocker_type="validation_needed",
            summary="restart happened; validation is pending",
            evidence_ids=["m001", "m002"],
            confidence=0.8,
        ),
        role_candidates=[
            IncidentBriefRoleCandidate(target_id="t001", name="Engineer", role_hint="technical_investigator", evidence_ids=["m001"], confidence=0.8),
            IncidentBriefRoleCandidate(target_id="t002", name="Reporter", role_hint="reporter_or_validator", evidence_ids=["m002"], confidence=0.8),
        ],
        recommended_ic_focus=IncidentBriefFocus(
            summary="restart happened; validation is pending",
            preferred_target_ids=["t001", "t002"],
            acceptable_move_types=[ICMove.ASK_NEXT_VALIDATION],
            evidence_ids=["m001", "m002"],
        ),
    )
    decision = plan_ic_decision(
        CurrentIncidentState(incident_id="i", phase=IncidentPhase.MONITORING),
        [],
        [],
        llm_client=None,
        incident_brief=brief,
        allowed_targets=allowed,
    )
    assert decision.target_ids == ["t001", "t002"]
    output = " ".join(str(value) for value in decision.output.values()).lower()
    assert "engineer" in output and "reporter" in output


def test_verifier_blocks_unallowed_and_non_targetable_targets() -> None:
    allowed = [
        AllowedTarget(target_id="t001", display_name="Engineer", target_type="person", evidence_ids=["m001"]),
        AllowedTarget(
            target_id="t002",
            display_name="9863631",
            target_type="non_targetable_noise",
            targetable=False,
            evidence_ids=["m001"],
            reason="URL path number is not a target",
        ),
    ]
    state = CurrentIncidentState(incident_id="i", phase=IncidentPhase.INVESTIGATION, compact_summary="validation pending")
    decision = ICDecision(
        decision_id="d",
        incident_id="i",
        move=ICMove.ASK_NEXT_VALIDATION,
        phase=IncidentPhase.INVESTIGATION,
        target_ids=["t002"],
        output={"say_this": "9863631, can you validate?"},
    )
    result = verify_ic_decision(decision, state, [], [], allowed_targets=allowed)
    assert not result.checks["no_non_targetable_target"]


def test_product_pipeline_is_incident_brief_first_for_api_504() -> None:
    result = run_pipeline(
        API_504_FIXTURE,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=FixtureLLMClient(),
    )
    assert result["incident_brief"] is None
    assert result["incident_read_and_whisper"] is not None
    assert result["trace"].processing_strategy in {"incident_read_and_whisper", "incident_read_and_whisper_v2"}
    assert result["allowed_targets"]
    assert result["decision"].target_ids
    output = result["final_output"].lower()
    assert "sriram" in output
    assert "monitoring signal" in output
    assert "9863631" not in output


def test_no_regression_specific_branching_in_product_source() -> None:
    terms = (
        "sriram",
        "aditya",
        "trimble",
        "semrush",
        "dentsply",
        "srerev-1864",
        "q3xzuz7cgv3ew2",
        "p3_in-11009",
        "ria-sandbox-rest",
    )
    product_paths = [
        "src/ic_copilot/incident_brief.py",
        "src/ic_copilot/planner.py",
        "src/ic_copilot/verifier.py",
        "src/ic_copilot/pipeline.py",
        "src/ic_copilot/llm/prompts.py",
    ]
    offenders: list[str] = []
    for path in product_paths:
        text = Path(path).read_text(errors="replace").lower()
        offenders.extend(f"{path}:{term}" for term in terms if term in text)
    assert offenders == []
