from pathlib import Path

from ic_copilot.repo_audit import apply_safe_cleanup, run_repo_audit


def test_repo_audit_flags_direct_normalizer_call(tmp_path: Path) -> None:
    runtime = tmp_path / "src/ic_copilot/runtime_path.py"
    runtime.parent.mkdir(parents=True)
    runtime.write_text(
        "from ic_copilot.normalizers.slack_paste import normalize_slack_paste_file\n"
        "def load(path):\n"
        "    return normalize_slack_paste_file(path)\n"
    )

    result = run_repo_audit(tmp_path)

    assert not result.passed
    assert any(finding.category == "direct_slack_paste_runtime_path" for finding in result.findings)


def test_repo_audit_flags_legacy_openai_stringified_request(tmp_path: Path) -> None:
    provider = tmp_path / "src/ic_copilot/llm/providers/openai_json.py"
    provider.parent.mkdir(parents=True)
    provider.write_text("def call(client, request):\n    return client.responses.create(input=str(request))\n")

    result = run_repo_audit(tmp_path)

    assert not result.passed
    assert any(finding.category == "legacy_openai_stringified_request" for finding in result.findings)


def test_repo_audit_flags_yaml_only_loader(tmp_path: Path) -> None:
    loader = tmp_path / "src/ic_copilot/memory.py"
    loader.parent.mkdir(parents=True)
    loader.write_text("def load(path):\n    return list(path.glob(\"*.yaml\"))  # DecisionMoment loader\n")

    result = run_repo_audit(tmp_path)

    assert not result.passed
    assert any(finding.category == "yaml_only_memory_loader" for finding in result.findings)


def test_repo_audit_flags_root_module_shadowing(tmp_path: Path) -> None:
    (tmp_path / "cli.py").write_text("# stale root CLI shadow\n")

    result = run_repo_audit(tmp_path)

    assert not result.passed
    assert any(finding.category == "duplicate_runtime_module" for finding in result.findings)


def test_repo_audit_flags_stale_product_runtime_docs(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("Fixture mode remains authoritative for the product.\n")

    result = run_repo_audit(tmp_path)

    assert not result.passed
    assert any(finding.category == "stale_product_runtime_wording" for finding in result.findings)


def test_repo_audit_flags_fixture_client_in_product_module(tmp_path: Path) -> None:
    runtime = tmp_path / "src/ic_copilot/pipeline.py"
    runtime.parent.mkdir(parents=True)
    runtime.write_text(
        "from ic_copilot.llm.fixture_client import FixtureLLMClient\n"
        "def run_pipeline():\n"
        "    return FixtureLLMClient()\n"
    )

    result = run_repo_audit(tmp_path)

    assert not result.passed
    assert any(finding.category == "fixture_client_in_product_runtime" for finding in result.findings)


def test_repo_audit_flags_shadow_import_in_product_module(tmp_path: Path) -> None:
    runtime = tmp_path / "src/ic_copilot/pipeline.py"
    runtime.parent.mkdir(parents=True)
    runtime.write_text("from ic_copilot.shadow import run_shadow_pipeline\n")

    result = run_repo_audit(tmp_path)

    assert not result.passed
    assert any(finding.category == "shadow_import_in_product_runtime" for finding in result.findings)


def test_repo_audit_allows_dev_archive_shadow_docs(tmp_path: Path) -> None:
    doc = tmp_path / "docs/dev_archive/PERSONAL_SHADOW_CALIBRATION.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("OpenAI remains shadow-only for this historical workflow.\n")

    result = run_repo_audit(tmp_path)

    assert not any(finding.category == "stale_product_runtime_wording" for finding in result.findings)


def test_repo_audit_safe_cleanup_only_removes_cache_dirs(tmp_path: Path) -> None:
    cache = tmp_path / "src/ic_copilot/__pycache__"
    cache.mkdir(parents=True)
    source = tmp_path / "src/ic_copilot/real_module.py"
    source.write_text("x = 1\n")

    removed = apply_safe_cleanup(tmp_path)

    assert any("__pycache__" in path for path in removed)
    assert not cache.exists()
    assert source.exists()
