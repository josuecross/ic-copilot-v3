from __future__ import annotations

from fastapi import FastAPI

from ic_copilot.web.app import create_app
from ic_copilot.runtime_config import ProductRuntimeConfig
from ic_copilot.web.safety import run_web_safety_audit


def test_web_safety_audit_passes() -> None:
    result = run_web_safety_audit(create_app())
    assert result.passed
    assert [finding for finding in result.findings if finding.severity == "error"] == []


def test_web_safety_audit_flags_fake_unsafe_route() -> None:
    app = FastAPI()

    @app.post("/api/execute-command")
    def execute_command():
        return {"ok": True}

    result = run_web_safety_audit(app)

    assert not result.passed
    assert any(finding.category == "unsafe_route_path" for finding in result.findings)


def test_web_safety_audit_allows_local_run_delete_route() -> None:
    result = run_web_safety_audit(create_app())
    assert not any(
        finding.category == "unsafe_route_path" and finding.path_or_route == "/api/runs/{run_id}"
        for finding in result.findings
    )


def test_product_safety_toggles_default_false() -> None:
    config = ProductRuntimeConfig()
    assert config.runtime.command_execution_enabled is False
    assert config.runtime.slack_posting_enabled is False
    assert config.runtime.paging_enabled is False
