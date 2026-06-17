from __future__ import annotations

from pathlib import Path

from ic_copilot.repo_audit import run_repo_audit
from ic_copilot.web.app import create_app
from ic_copilot.web.safety import run_web_safety_audit


def test_phase119_repo_and_web_audits_pass() -> None:
    repo = run_repo_audit(".")
    web = run_web_safety_audit(create_app())
    assert repo.passed, [finding.model_dump() for finding in repo.findings]
    assert web.passed, [finding.model_dump() for finding in web.findings]


def test_docs_current_status_mentions_product_knowledge_workflow() -> None:
    readme = Path("README.md").read_text()
    agents = Path("AGENTS.md").read_text()
    assert "Phase 1.36C" in readme
    assert "local_knowledge" in readme
    assert "Phase 1.36C" in agents
