from pathlib import Path

from ic_copilot.web.models import RunRequest


def test_web_run_request_has_no_shadow_product_fields() -> None:
    fields = set(RunRequest.model_fields)
    assert "openai_shadow_enabled" not in fields
    assert "openai_model" not in fields


def test_web_product_flow_has_no_shadow_import() -> None:
    text = Path("src/ic_copilot/web/app.py").read_text()
    assert "ic_copilot.shadow" not in text
    assert "run_shadow" not in text


def test_cli_run_is_thin_shared_pipeline_wrapper() -> None:
    text = Path("src/ic_copilot/cli.py").read_text()
    assert "run_pipeline as _shared_run_pipeline" in text
    assert "_shared_run_pipeline(" in text
    assert "def run_pipeline(" not in text
    assert "FixtureLLMClient" not in text
