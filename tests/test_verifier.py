from pathlib import Path

from ic_copilot.catalog import build_command_registry, load_service_catalog
from ic_copilot.actionability import normalize_move_for_visible_ask
from ic_copilot.render import render_ic_whisper
from ic_copilot.schemas import (
    CurrentIncidentState,
    AllowedTarget,
    EntityRef,
    EntityType,
    EvidenceRef,
    ICDecision,
    ICMove,
    ImpactState,
    IncidentEvent,
    IncidentPhase,
    LinkRef,
    MemoryApplicabilityResult,
)
from ic_copilot.verifier import verify_ic_decision
from tests.helpers import fixture_run_pipeline


CATALOG = Path("data/sample/service_catalog.yaml")


def catalog():
    return load_service_catalog(CATALOG)


def decision(text, move=ICMove.ASK_IMPACT, targets=None, command=None):
    output = {"say_this": text}
    if command:
        output["command"] = command
    return ICDecision(
        decision_id="d1",
        incident_id="i1",
        move=move,
        phase=IncidentPhase.TRIAGE,
        output=output,
        targets=targets or [],
        grounding=[EvidenceRef(event_id="m001", quote=text)] if targets else [],
    )


def verify(decision_obj, state, memories=None):
    cat = catalog()
    return verify_ic_decision(decision_obj, state, cat, memories or [], build_command_registry(cat))


def test_blocks_fake_customer_from_atlassian_url():
    state = CurrentIncidentState(
        incident_id="i1",
        links_seen=[LinkRef(url="https://zuora.atlassian.net/browse/INC-1")],
        current_blocker="missing_impact",
    )
    result = verify(decision("Atlassian customer appears impacted."), state)
    assert not result.passed
    assert not result.checks["no_fake_customer"]


def test_blocks_fake_tenant_from_docs_url_number():
    state = CurrentIncidentState(
        incident_id="i1",
        links_seen=[LinkRef(url="https://docs.example.invalid/document/d/9863631/edit")],
        current_blocker="missing_impact",
    )
    result = verify(decision("Tenant 9863631 appears impacted."), state)
    assert not result.passed
    assert not result.checks["no_fake_tenant"]


def test_blocks_fake_person_fragments():
    state = CurrentIncidentState(incident_id="i1")
    result = verify(decision("Gaurav Could you confirm the owner?"), state)
    assert not result.passed
    assert not result.checks["no_fake_person"]


def test_blocks_page_confirmation_after_operational_completion() -> None:
    events = [
        IncidentEvent(
            event_id="m001",
            incident_id="i1",
            sequence=1,
            author="Sriram",
            message="@Vignesh could you page engineering?",
            hash="m001",
        ),
        IncidentEvent(
            event_id="m002",
            incident_id="i1",
            sequence=2,
            author="Irfan",
            message="Vignesh is on the way home. Let me page.",
            hash="m002",
        ),
        IncidentEvent(
            event_id="m003",
            incident_id="i1",
            sequence=3,
            author="Irfan",
            message="@zsrebot page team revenue",
            hash="m003",
        ),
        IncidentEvent(
            event_id="m004",
            incident_id="i1",
            sequence=4,
            author="zsrebot",
            message="Done.",
            hash="m004",
        ),
        IncidentEvent(
            event_id="m005",
            incident_id="i1",
            sequence=5,
            author="Sriram",
            message="RIA connection limit warning is showing in the current logs.",
            hash="m005",
        ),
    ]
    target = EntityRef(
        entity_type=EntityType.PERSON,
        display_name="Vignesh",
        evidence=[EvidenceRef(event_id="m001", quote="@Vignesh could you page engineering?")],
    )
    bad = decision(
        "@Vignesh, can you confirm if you paged engineering?",
        move=ICMove.CONFIRM_OWNERSHIP,
        targets=[target],
    )

    result = verify_ic_decision(
        bad,
        CurrentIncidentState(incident_id="i1"),
        catalog(),
        [],
        build_command_registry(catalog()),
        current_events=events,
    )

    assert not result.passed
    assert result.checks["stale_answered_open_loop"] is False


def test_blocks_historical_fact_leakage():
    state = CurrentIncidentState(incident_id="i1")
    memory = MemoryApplicabilityResult(
        decision_id="dm",
        accepted=True,
        score=0.9,
        forbidden_fact_leakage=["Google Fiber", "10005051"],
    )
    result = verify(decision("Google Fiber tenant 10005051 needs the same move."), state, [memory])
    assert not result.passed
    assert not result.checks["no_historical_fact_leakage"]


def test_allows_memory_forbidden_fact_when_current_event_supports_it():
    state = CurrentIncidentState(incident_id="i1")
    memory = MemoryApplicabilityResult(
        decision_id="dm",
        accepted=True,
        score=0.9,
        forbidden_fact_leakage=["Google Fiber", "10005051"],
    )
    event = IncidentEvent(
        event_id="m001",
        incident_id="i1",
        sequence=1,
        author="Support",
        message="Tenant 10005051 for Google Fiber currently has RevenueOrgMapping=0.",
        hash="fixture",
    )
    cat = catalog()
    result = verify_ic_decision(
        decision("Google Fiber tenant 10005051 needs validation."),
        state,
        cat,
        [memory],
        build_command_registry(cat),
        current_events=[event],
    )

    assert result.checks["no_historical_fact_leakage"]
    assert not any("historical fact leaked" in claim for claim in result.blocked_claims)


def test_blocks_stale_already_looped_in_question():
    evidence = EvidenceRef(event_id="m001", quote="RevPro Support should be engaged")
    state = CurrentIncidentState(
        incident_id="i1",
        suggested_but_not_engaged=[
            EntityRef(
                entity_type=EntityType.TEAM,
                display_name="RevPro Support",
                canonical_id="revpro-support",
                evidence=[evidence],
            )
        ],
        stale_question_intents=["already_looped_in"],
    )
    target = state.suggested_but_not_engaged[0]
    result = verify(
        decision(
            "Do we know if RevPro Support is already looped in?",
            move=ICMove.ENGAGE_OWNER,
            targets=[target],
        ),
        state,
    )
    assert not result.passed
    assert not result.checks["no_stale_question"]


def test_blocks_generic_clarify_impact_when_impact_known_and_blocker_is_owner():
    state = CurrentIncidentState(
        incident_id="i1",
        current_blocker="missing_owner",
        impact=ImpactState(description="27 customers affected", affected_count=27, confidence=0.9),
    )
    result = verify(decision("Can someone clarify impact/scope?"), state)
    assert not result.passed
    assert not result.checks["not_too_generic"]


def test_allows_revpro_owner_engagement_with_verified_command():
    result = fixture_run_pipeline(
        "data/sample/incidents/revpro_early_engage.txt",
        "data/sample/service_catalog.yaml",
        "data/sample/decision_moments",
        save_trace=False,
    )
    assert result["verifier_result"].passed
    if result["trace"].processing_strategy == "incident_read_and_whisper":
        assert "@zsrebot oncall RevPro support" in result["final_output"]
    else:
        assert "COMMAND:" not in result["final_output"]


def test_renderer_supports_command_object_payload():
    decision_obj = decision(
        "Use the verified lookup.",
        command={"command_text": "@zsrebot oncall RevPro support"},
    )
    assert "COMMAND:\n@zsrebot oncall RevPro support" in render_ic_whisper(decision_obj)


def test_no_safe_weak_finality_wording_is_blocked() -> None:
    result = verify(
        decision(
            "No current owner or impact identified; no further action needed at this time.",
            move=ICMove.NO_SAFE_RECOMMENDATION,
        ),
        CurrentIncidentState(incident_id="i1"),
    )

    assert not result.passed
    assert result.checks["no_safe_wording_quality"] is False
    assert any("no_safe_recommendation visible wording" in claim for claim in result.blocked_claims)


def test_no_safe_canonical_grounded_uncertainty_wording_passes() -> None:
    result = verify(
        decision(
            "I do not have a safe, grounded next move yet.",
            move=ICMove.NO_SAFE_RECOMMENDATION,
        ),
        CurrentIncidentState(incident_id="i1"),
    )

    assert result.passed


def test_adjacent_direct_ask_move_normalization_is_metadata_only() -> None:
    original = decision(
        "@Nora, can you share order API status, impact scope, and the first validation signal?",
        move=ICMove.REQUEST_MONITORING_SIGNAL,
    )

    normalized, changed, reason = normalize_move_for_visible_ask(original)

    assert changed
    assert normalized.move == ICMove.ASK_NEXT_VALIDATION
    assert normalized.output == original.output
    assert reason == "visible_direct_ask_intent:request_monitoring_signal->ask_next_validation"


def test_megastore_stale_scope_ask_fails_after_later_scope_answer() -> None:
    events = [
        IncidentEvent(
            event_id="m020",
            incident_id="i1",
            sequence=20,
            author="Navneeth",
            message="This should be P1 since the customer is blocked from running Megastore enabled reports.",
            hash="m020",
        ),
        IncidentEvent(
            event_id="m021",
            incident_id="i1",
            sequence=21,
            author="Kenneth",
            message="Are multiple customers impacted? How many customers are impacted?",
            hash="m021",
        ),
        IncidentEvent(
            event_id="m022",
            incident_id="i1",
            sequence=22,
            author="Zeenie Louis",
            message="The issue reported is only for Toast. No other customer has reported it. Row count mismatch exists on the Iceberg side.",
            hash="m022",
        ),
    ]
    navneeth = EntityRef(entity_type=EntityType.PERSON, display_name="Navneeth")
    result = verify_ic_decision(
        decision(
            "@Navneeth, can you confirm whether this is isolated to one customer or if more production customers are affected before we change severity?",
            move=ICMove.ASK_IMPACT,
            targets=[navneeth],
        ),
        CurrentIncidentState(incident_id="i1"),
        catalog(),
        [],
        build_command_registry(catalog()),
        current_events=events,
        allowed_targets=[
            AllowedTarget(target_id="person:navneeth", display_name="Navneeth", target_type="person"),
            AllowedTarget(target_id="person:zeenie-louis", display_name="Zeenie Louis", target_type="person"),
        ],
    )

    assert not result.passed
    assert result.checks["stale_answered_open_loop"] is False
    assert any("stale_scope" in claim or "answered by later human evidence" in claim for claim in result.blocked_claims)


def test_megastore_direct_validation_ask_passes_after_scope_answer() -> None:
    events = [
        IncidentEvent(
            event_id="m022",
            incident_id="i1",
            sequence=22,
            author="Zeenie Louis",
            message="Only Toast has reported impact. No other customer has reported it. Current findings show row-count mismatch on the Iceberg side.",
            hash="m022",
        ),
    ]
    zeenie = EntityRef(entity_type=EntityType.PERSON, display_name="Zeenie Louis", canonical_id="person:zeenie-louis")
    result = verify_ic_decision(
        ICDecision(
            decision_id="d1",
            incident_id="i1",
            move=ICMove.ASK_NEXT_VALIDATION,
            phase=IncidentPhase.TRIAGE,
            target_ids=["person:zeenie-louis"],
            output={
                "say_this": (
                    "@Zeenie Louis, since current evidence says only Toast has reported impact, can you confirm "
                    "what validation the Megastore Reporting Pipeline owner needs next for the Iceberg row-count mismatch?"
                )
            },
            targets=[zeenie],
            grounding=[
                EvidenceRef(
                    event_id="m022",
                    quote=(
                        "Only Toast has reported impact. No other customer has reported it. Current findings "
                        "show row-count mismatch on the Iceberg side."
                    ),
                )
            ],
        ),
        CurrentIncidentState(incident_id="i1"),
        catalog(),
        [],
        build_command_registry(catalog()),
        current_events=events,
        allowed_targets=[
            AllowedTarget(target_id="person:zeenie-louis", display_name="Zeenie Louis", target_type="person"),
            AllowedTarget(
                target_id="service:megastore-reporting-pipeline",
                display_name="Megastore Reporting Pipeline",
                target_type="service",
                source="catalog",
                role_hint="owner_team",
            ),
        ],
    )

    assert result.passed
