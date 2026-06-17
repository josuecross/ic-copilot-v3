from pathlib import Path

from tests.helpers import fixture_run_pipeline


def test_jsonl_pipeline_preserves_event_ids_for_run_pipeline():
    package = Path("ic_copilot_previous_incidents__try_20260523_193347__fixture_package")
    if not package.exists():
        return
    result = fixture_run_pipeline(
        package / "IN-10984/fixtures/incidents/IN-10984.jsonl",
        catalog_path="data/contract/service_catalog.yaml",
        memory_dir="data/contract/decision_moments.jsonl",
        command_registry_path="data/contract/command_registry.yaml",
        save_trace=False,
    )
    assert result["trace"].input_event_ids[0] == "m001"
    assert result["events"][0].source == "incident_jsonl"


def test_runtime_code_uses_shared_incident_loader_for_slack_paste():
    allowed = {
        Path("src/ic_copilot/incident_loader.py"),
        Path("src/ic_copilot/normalizers/incident_jsonl.py"),
        Path("src/ic_copilot/normalizers/slack_export.py"),
        Path("src/ic_copilot/normalizers/slack_paste.py"),
        Path("src/ic_copilot/repo_audit.py"),
    }
    offenders = []
    for path in Path("src/ic_copilot").rglob("*.py"):
        if path in allowed:
            continue
        text = path.read_text()
        if "normalize_slack_paste_file(" in text or "from ic_copilot.normalizers.slack_paste import" in text:
            offenders.append(str(path))
    assert offenders == []


def test_shadow_runtime_removed_from_product_package():
    assert not Path("src/ic_copilot/shadow.py").exists()


def test_openai_adapter_does_not_stringify_live_request():
    text = Path("src/ic_copilot/llm/providers/openai_json.py").read_text()
    assert "input=str(request)" not in text
    assert "input = str(request)" not in text


def test_memory_loader_remains_json_jsonl_yaml_capable():
    text = Path("src/ic_copilot/memory.py").read_text().lower()
    assert ".jsonl" in text
    assert ".json" in text
    assert ".yaml" in text or ".yml" in text


def test_eval_loader_remains_json_jsonl_yaml_capable():
    text = Path("src/ic_copilot/evals.py").read_text().lower()
    assert ".jsonl" in text
    assert ".json" in text
    assert ".yaml" in text or ".yml" in text
