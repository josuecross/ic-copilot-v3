from __future__ import annotations

from pathlib import Path

from ic_copilot.catalog import load_command_registry, load_service_catalog
from ic_copilot.evals import load_eval_cases, run_eval_suite
from ic_copilot.schemas import (
    CommandRegistryEntry,
    CurrentIncidentState,
    EntityRef,
    EntityType,
    EvidenceRef,
    ICDecision,
    ICMove,
    IncidentPhase,
)
from ic_copilot.verifier import (
    collect_forbidden_historical_facts,
    detect_generic_impact,
    detect_stale_question,
    detect_unregistered_commands,
    verify_ic_decision,
)


CONTRACT = Path("data/contract")
ADVERSARIAL = CONTRACT / "adversarial"


def test_adversarial_replay_cases_load_and_pass():
    cases = load_eval_cases(ADVERSARIAL)
    assert len(cases) == 10
    results = run_eval_suite(
        ADVERSARIAL,
        catalog_path=CONTRACT / "service_catalog.yaml",
        memory_dir=CONTRACT / "decision_moments.jsonl",
        command_registry_path=CONTRACT / "command_registry.yaml",
    )
    assert all(result.passed for result in results), [
        (result.case_id, result.failure_reasons, result.final_output)
        for result in results
        if not result.passed
    ]


def test_verifier_helper_detects_stale_known_target_question():
    state = CurrentIncidentState(
        incident_id="i",
        suggested_but_not_engaged=[
            EntityRef(
                entity_type=EntityType.TEAM,
                display_name="RevPro Support",
                evidence=[EvidenceRef(event_id="m001", quote="RevPro Support should engage")],
            )
        ],
        stale_question_intents=["already_looped_in"],
    )
    reasons = detect_stale_question("Do we know if RevPro Support is already looped in?", state)
    assert reasons


def test_verifier_helper_detects_generic_impact_variants():
    assert detect_generic_impact("Can we clarify impact/scope?")
    assert detect_generic_impact("What customers are impacted right now?")


def test_verifier_helper_detects_unregistered_remediation_command():
    registry = [
        CommandRegistryEntry(
            command="@zsrebot oncall RevPro support",
            target="RevPro Support",
            source_service_id="revpro-support",
            requires_human_approval=True,
        )
    ]
    assert not detect_unregistered_commands("COMMAND:\n@zsrebot oncall RevPro support", registry)
    assert detect_unregistered_commands("COMMAND:\n/rollback-prod now", registry)


def test_verifier_blocks_command_without_human_approval():
    catalog = load_service_catalog(CONTRACT / "service_catalog.yaml")
    registry = [
        CommandRegistryEntry(
            command="@zsrebot oncall RevPro support",
            target="RevPro Support",
            source_service_id="revpro-support",
            requires_human_approval=False,
        )
    ]
    decision = ICDecision(
        decision_id="d",
        incident_id="i",
        move=ICMove.ENGAGE_OWNER,
        phase=IncidentPhase.ENGAGEMENT,
        output={"say_this": "Use lookup only.", "command": "@zsrebot oncall RevPro support"},
    )
    result = verify_ic_decision(decision, CurrentIncidentState(incident_id="i"), catalog, [], registry)
    assert not result.passed
    assert not result.checks["valid_command"]


def test_forbidden_historical_facts_collector_carries_memory_restrictions():
    facts = collect_forbidden_historical_facts(
        [
            type(
                "Memory",
                (),
                {
                    "accepted": True,
                    "forbidden_fact_leakage": ["Google Fiber", "10005051"],
                },
            )()
        ]
    )
    assert {"Google Fiber", "10005051"}.issubset(set(facts))


def test_command_registry_loads_contract_entries():
    catalog = load_service_catalog(CONTRACT / "service_catalog.yaml")
    registry = load_command_registry(CONTRACT / "command_registry.yaml", catalog)
    assert any(entry.command == "@zsrebot oncall RevPro support" for entry in registry)
