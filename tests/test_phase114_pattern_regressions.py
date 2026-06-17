from pathlib import Path

import pytest
from tests.helpers import fixture_run_pipeline


PACKAGE = Path("ic_copilot_previous_incidents__try_20260523_193347__fixture_package")


def _run(case_id: str):
    if not PACKAGE.exists():
        pytest.skip("previous incident package not present")
    return fixture_run_pipeline(
        PACKAGE / case_id / "fixtures/incidents" / f"{case_id}.jsonl",
        catalog_path="data/contract/service_catalog.yaml",
        memory_dir="data/contract/decision_moments.jsonl",
        command_registry_path="data/contract/command_registry.yaml",
        save_trace=False,
    )


def _assert_simplified_safe(result) -> str:
    assert result["trace"].processing_strategy in {"incident_read_and_whisper", "incident_read_and_whisper_v2"}
    assert result["incident_read_and_whisper"] is not None
    assert result["verifier_result"].passed
    assert result["final_output"].startswith("SAY THIS:")
    return result["final_output"].lower()


def test_customer_confirmation_after_mitigation_does_not_reopen_hotfix() -> None:
    result = _run("IN-10978")

    output = _assert_simplified_safe(result)
    assert "hotfix" in output or result["decision"].move == "no_safe_recommendation"


def test_revenue_and_provisioning_owner_gap_is_not_revpro_specific() -> None:
    result = _run("IN-10983")

    output = _assert_simplified_safe(result)
    assert "revpro impact" not in output


def test_ebs_change_goes_to_validation_not_generic_impact() -> None:
    result = _run("unknown_ebs_volume_increase")

    output = _assert_simplified_safe(result)
    assert "impact and owner" not in output


def test_slack_ecm_approval_goes_to_deployment_context() -> None:
    result = _run("unknown_slack_ecm_approval")

    output = _assert_simplified_safe(result)
    assert "execute" not in output


def test_transfer_accounting_batch_id_is_not_treated_as_tenant() -> None:
    result = _run("IN-11057")

    output = _assert_simplified_safe(result)
    assert "tenant 39391554" not in output
