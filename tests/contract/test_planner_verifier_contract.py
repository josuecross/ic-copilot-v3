from pathlib import Path

from ic_copilot.catalog import load_command_registry, load_service_catalog
from ic_copilot.schemas import ICDecision, ICMove, IncidentPhase
from ic_copilot.verifier import verify_ic_decision
from tests.helpers import fixture_run_pipeline


CONTRACT = Path("data/contract")


def _run(file_name: str):
    return fixture_run_pipeline(
        CONTRACT / "incidents" / file_name,
        CONTRACT / "service_catalog.yaml",
        CONTRACT / "decision_moments.jsonl",
        CONTRACT / "command_registry.yaml",
        save_trace=False,
    )


def test_positive_contract_decisions_are_specific_and_verified():
    revpro = _run("01_revpro_early_engage.txt")
    assert revpro["verifier_result"].passed
    if revpro["trace"].processing_strategy == "incident_read_and_whisper":
        assert "@zsrebot oncall RevPro support" in revpro["final_output"]
    else:
        assert "COMMAND:" not in revpro["final_output"]
    assert "looped in" not in revpro["final_output"].lower()

    payment = _run("02_payment_stripe_codefix.txt")
    assert payment["verifier_result"].passed
    assert "Trisha" in payment["final_output"]
    assert "hotfix ETA" in payment["final_output"]
    assert "Guo Qing" in payment["final_output"]

    ocm = _run("03_ocm_order_creation.txt")
    assert ocm["verifier_result"].passed
    assert "deployment" in ocm["final_output"].lower()
    assert "RevPro" not in ocm["final_output"]

    uno = _run("04_uno_revenue_mapping.txt")
    assert uno["verifier_result"].passed
    assert "RevenueOrgMapping=0" in uno["final_output"]
    assert "affected tenant" in uno["final_output"]
    assert "10005051" not in uno["final_output"]

    db = _run("05_db_high_cpu_queue.txt")
    assert db["verifier_result"].passed
    assert "CPU did not decrease" in db["final_output"]
    assert "tenant/workload bulk operation" in db["final_output"]
    assert "is DBA engaged" not in db["final_output"]

    monitoring = _run("08_monitoring_after_mitigation.txt")
    assert monitoring["verifier_result"].passed
    assert "order API error rate" in monitoring["final_output"]


def test_negative_contract_decision_is_blocked_and_safe_fallback_omits_fake_entities():
    negative = _run("06_negative_fake_entities.txt")
    assert negative["verifier_result"].passed
    assert "Atlassian" not in negative["final_output"]
    assert "9863631" not in negative["final_output"]
    assert "Default_Agent" not in negative["final_output"]

    state = negative["state"]
    catalog = load_service_catalog(CONTRACT / "service_catalog.yaml")
    registry = load_command_registry(CONTRACT / "command_registry.yaml", catalog)
    bad = {
        "move": "engage_owner",
        "phase": "triage",
        "say_this": "Atlassian tenant 9863631 seems affected; can Default_Agent confirm?",
        "next_line": "Default_Agent, please confirm ownership.",
        "command_suggestion": "@zsrebot oncall Default_Agent",
        "target_team": "Default_Agent",
        "confidence": 0.5,
        "evidence_ids": [],
    }
    result = verify_ic_decision(bad, state, catalog, [], registry)
    assert not result.passed
    assert not result.checks["no_fake_tenant"]
    assert not result.checks["no_fake_team"]
    assert not result.checks["target_exists"]
    assert not result.checks["valid_command"]


def test_unsupported_monitoring_and_generic_impact_are_blocked():
    revpro = _run("01_revpro_early_engage.txt")
    state = revpro["state"]
    catalog = load_service_catalog(CONTRACT / "service_catalog.yaml")
    registry = load_command_registry(CONTRACT / "command_registry.yaml", catalog)
    monitor = ICDecision(
        decision_id="bad-monitor",
        incident_id=state.incident_id,
        move=ICMove.REQUEST_MONITORING_SIGNAL,
        phase=IncidentPhase.ENGAGEMENT,
        output={"say_this": "Move to monitoring.", "next_line": "Monitor the success signal."},
        targets=[],
    )
    assert not verify_ic_decision(monitor, state, catalog, [], registry).passed

    generic = ICDecision(
        decision_id="bad-impact",
        incident_id=state.incident_id,
        move=ICMove.ASK_IMPACT,
        phase=IncidentPhase.ENGAGEMENT,
        output={"say_this": "Can someone clarify impact/scope?"},
    )
    state_with_sharp_blocker = state.model_copy(update={"current_blocker": "waiting_on_owner_status"})
    result = verify_ic_decision(generic, state_with_sharp_blocker, catalog, [], registry)
    assert not result.passed
    assert not result.checks["not_too_generic"]
