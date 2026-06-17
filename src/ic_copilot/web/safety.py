from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field

from ic_copilot.runtime_config import ProductRuntimeConfig


class WebSafetyFinding(BaseModel):
    severity: Literal["info", "warning", "error"]
    category: str
    message: str
    path_or_route: str | None = None


class WebSafetyAuditResult(BaseModel):
    passed: bool
    findings: list[WebSafetyFinding] = Field(default_factory=list)


FORBIDDEN_ROUTE_TERMS = (
    "execute",
    "page",
    "post",
    "remediate",
    "rollback",
    "deploy",
    "restart",
    "delete-command",
    "slack",
    "pagerduty",
    "incidentio",
)
FORBIDDEN_HANDLER_TERMS = (
    "execute",
    "page",
    "remediate",
    "post_to_slack",
    "write_pagerduty",
    "write_incident_io",
)


def _add(findings: list[WebSafetyFinding], severity: str, category: str, message: str, route: str | None = None) -> None:
    findings.append(WebSafetyFinding(severity=severity, category=category, message=message, path_or_route=route))


def _is_allowed_delete_run(route_path: str, methods: set[str]) -> bool:
    return "DELETE" in methods and route_path in {"/api/runs/{run_id}", "/api/runs"}


def run_web_safety_audit(app: FastAPI) -> WebSafetyAuditResult:
    findings: list[WebSafetyFinding] = []
    for route in app.routes:
        route_path = getattr(route, "path", "")
        methods = set(getattr(route, "methods", set()) or set())
        endpoint = getattr(route, "endpoint", None)
        handler_name = getattr(endpoint, "__name__", "")
        if route_path.startswith("/static"):
            continue
        if (
            route_path.startswith("/api/artifacts")
            or route_path.startswith("/api/corrections")
            or "/mark-reviewed" in route_path
            or "/export-regression-draft" in route_path
            or "promote" in route_path.lower()
            or "personal-corpus" in route_path.lower()
        ):
            _add(
                findings,
                "error",
                "curation_route_mounted_by_default",
                "Default product web app must not mount curation/review/promotion routes.",
                route_path,
            )
        for term in FORBIDDEN_ROUTE_TERMS:
            if term == "delete-command" and _is_allowed_delete_run(route_path, methods):
                continue
            if term == "delete" and _is_allowed_delete_run(route_path, methods):
                continue
            if term in route_path.lower():
                _add(
                    findings,
                    "error",
                    "unsafe_route_path",
                    f"Route path contains forbidden term {term!r}.",
                    route_path,
                )
        for term in FORBIDDEN_HANDLER_TERMS:
            if term in handler_name.lower():
                _add(
                    findings,
                    "error",
                    "unsafe_route_handler",
                    f"Route handler contains forbidden term {term!r}.",
                    route_path,
                )

    config = ProductRuntimeConfig()
    if config.runtime.command_execution_enabled or config.runtime.slack_posting_enabled or config.runtime.paging_enabled:
        _add(findings, "error", "product_safety_defaults", "Product runtime action toggles must default to false.")

    script = Path("scripts/run_local_web.py")
    if script.exists():
        text = script.read_text()
        if 'default="127.0.0.1"' not in text:
            _add(findings, "error", "localhost_bind", "Local web server must default to 127.0.0.1.")
        if "--allow-non-localhost-dangerous-dev-only" not in text:
            _add(
                findings,
                "error",
                "localhost_bind",
                "Non-localhost binding must require explicit dangerous dev flag.",
            )
    else:
        _add(findings, "error", "localhost_bind", "scripts/run_local_web.py is missing.")

    source_files = [
        Path("src/ic_copilot/web/app.py"),
        Path("src/ic_copilot/web/run_store.py"),
        Path("src/ic_copilot/web/pipeline_events.py"),
    ]
    runtime_load_terms = (
        "load_catalog_with_overlay",
        "load_command_registry_with_overlay",
        "load_decision_moments(correction",
        "corrections/drafts",
        "artifact_routes",
    )
    for path in source_files:
        if not path.exists():
            continue
        text = path.read_text()
        if path.name != "app.py" and "corrections/drafts" in text:
            _add(
                findings,
                "warning",
                "correction_runtime_loading",
                "Correction draft path appears outside web app storage wiring.",
                str(path),
            )
        for term in runtime_load_terms:
            if term in text:
                _add(
                    findings,
                    "error",
                    "correction_runtime_loading",
                    f"Web code appears to runtime-load correction drafts via {term}.",
                    str(path),
                )

    index = Path("src/ic_copilot/web/templates/index.html")
    app_js = Path("src/ic_copilot/web/static/app.js")
    for path in (index, app_js):
        if not path.exists():
            continue
        text = path.read_text(errors="replace").lower()
        for phrase in (
            "enable ai",
            "enable openai shadow",
            "fixture baseline",
            "trusted baseline",
            "artifact curation",
            "promotion buttons",
            "knowledge corrections",
            "personal calibration mode",
            "import previous incident package",
            "import artifact bundle",
            "mark run reviewed",
            "developer path overrides",
        ):
            if phrase in text:
                _add(
                    findings,
                    "error",
                    "main_ui_product_mode_confusion",
                    f"Main web UI contains stale mode/shadow wording: {phrase!r}.",
                    str(path),
                )
        if path == index:
            input_pos = text.find("incident-text")
            status_before_input = [
                marker
                for marker in ("runtime-status", "knowledge-status")
                if text.find(marker) != -1 and input_pos != -1 and text.find(marker) < input_pos
            ]
            if status_before_input:
                _add(
                    findings,
                    "error",
                    "main_ui_status_noise",
                    "Detailed product status rows must be collapsed below the incident input.",
                    str(path),
                )
            if 'id="copy-output"' in text and 'id="copy-output" type="button" disabled' not in text:
                _add(
                    findings,
                    "error",
                    "copy_empty_output",
                    "Copy full output must start disabled until a verified whisper exists.",
                    str(path),
                )
            if 'id="copy-error"' in text and 'id="copy-error" type="button" disabled hidden' not in text:
                _add(
                    findings,
                    "error",
                    "copy_empty_output",
                    "Copy error summary must start hidden so both copy buttons are not visible together.",
                    str(path),
                )
        if path == app_js:
            raw_text = path.read_text(errors="replace")
            if "step-artifacts" not in text or "View generated data" not in raw_text:
                _add(
                    findings,
                    "error",
                    "missing_pipeline_generated_artifacts_ui",
                    "Pipeline Progress must expose generated step artifacts for product audit.",
                    str(path),
                )

    passed = not any(finding.severity == "error" for finding in findings)
    return WebSafetyAuditResult(passed=passed, findings=findings)


def format_web_safety_audit(result: WebSafetyAuditResult) -> str:
    lines = ["# IC Copilot Web Safety Audit", "", f"- passed: {result.passed}", f"- findings: {len(result.findings)}"]
    if not result.findings:
        lines.extend(["", "No findings."])
        return "\n".join(lines)
    lines.append("")
    for finding in result.findings:
        route = f" ({finding.path_or_route})" if finding.path_or_route else ""
        lines.append(f"- [{finding.severity}] {finding.category}{route}: {finding.message}")
    return "\n".join(lines)
