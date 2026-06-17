from tests.helpers import fixture_run_pipeline


def test_revpro_end_to_end_returns_expected_short_output():
    result = fixture_run_pipeline(
        "data/sample/incidents/revpro_early_engage.txt",
        "data/sample/service_catalog.yaml",
        "data/sample/decision_moments",
        save_trace=False,
    )
    output = result["final_output"]
    assert "Support is pointing this toward RevPro Support" in output
    assert "I do not see RevPro Support engaged yet" in output
    assert "confirm ownership and the next validation step" in output
    if result["trace"].processing_strategy == "incident_read_and_whisper":
        assert "@zsrebot oncall RevPro support" in output
    else:
        assert "COMMAND:" not in output
    assert "looped in" not in output.lower()
