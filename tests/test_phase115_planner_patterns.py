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
    return result["final_output"]


def test_data_loss_fragment_uses_cautious_validation_not_invented_customer() -> None:
    result = _run("IN-11032_fragment")

    output = _assert_simplified_safe(result)
    assert "invented customer" not in output.lower()


def test_missing_owner_multiple_downstream_teams_uses_only_verified_command() -> None:
    result = _run("IN-10983")

    output = _assert_simplified_safe(result)
    if "COMMAND:" in result["final_output"]:
        assert "@zsrebot oncall Revenue" in result["final_output"]
    assert "revpro impact" not in output.lower()


def test_deployment_already_done_asks_validation_not_deployment_again() -> None:
    result = _run("unknown_ebs_volume_increase")

    output = _assert_simplified_safe(result)
    assert "if deployed" not in output.lower()


def test_slack_ecm_approval_keeps_deployment_status_context() -> None:
    result = _run("unknown_slack_ecm_approval")

    output = _assert_simplified_safe(result)
    assert "post to slack" not in output.lower()
