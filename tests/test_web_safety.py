from __future__ import annotations

from pathlib import Path

from ic_copilot.web.app import create_app


def test_no_dangerous_action_routes():
    app = create_app()
    route_text = "\n".join(getattr(route, "path", "") for route in app.routes)
    for forbidden in ("execute", "page", "slack-post", "remediate", "pagerduty", "incident-io"):
        assert forbidden not in route_text


def test_local_server_script_defaults_to_localhost():
    script = Path("scripts/run_local_web.py").read_text()
    assert 'default="127.0.0.1"' in script
    assert "--allow-non-localhost-dangerous-dev-only" in script


def test_product_runtime_panel_and_command_warning_in_ui():
    html = Path("src/ic_copilot/web/templates/index.html").read_text()
    assert "Product Runtime Status" in html
    assert "Enable OpenAI shadow" not in html
    assert "manual copy only · not executed" in html


def test_curation_controls_are_not_in_product_ui():
    html = Path("src/ic_copilot/web/templates/index.html").read_text()
    assert "Knowledge Corrections" not in html
    assert "Artifact Curation" not in html
    assert "Promotion Buttons" not in html
