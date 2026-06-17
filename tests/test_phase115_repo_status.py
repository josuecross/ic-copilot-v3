from pathlib import Path

from ic_copilot.repo_audit import run_repo_audit


def test_readme_current_status_mentions_current_product_runtime() -> None:
    text = Path("README.md").read_text()
    assert "Phase 1.36C" in text
    assert "real LLM" in text
    assert "local_knowledge" in text


def test_repo_audit_strict_has_no_errors() -> None:
    result = run_repo_audit(".")
    assert result.passed
    assert [finding for finding in result.findings if finding.severity == "error"] == []


def test_no_root_module_shadow_files() -> None:
    for name in ("cli.py", "schemas.py", "memory.py", "verifier.py", "planner.py", "shadow.py", "evals.py"):
        assert not Path(name).exists()
