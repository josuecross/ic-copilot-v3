from __future__ import annotations

import json
import shutil
from pathlib import Path

import yaml

from ic_copilot.product_knowledge import load_product_knowledge, product_knowledge_status, validate_product_knowledge


def _copy_example(tmp_path: Path) -> Path:
    target = tmp_path / "knowledge"
    shutil.copytree("data/product_knowledge_example", target)
    return target


def test_product_knowledge_example_validates_and_loads() -> None:
    result = validate_product_knowledge("data/product_knowledge_example")
    assert result.passed
    assert result.counts.services > 0
    assert result.counts.commands > 0
    assert result.counts.decision_moments > 0
    knowledge = load_product_knowledge("data/product_knowledge_example")
    assert knowledge.counts == result.counts


def test_missing_manifest_and_runtime_usable_false_fail(tmp_path) -> None:
    root = tmp_path / "knowledge"
    root.mkdir()
    assert not validate_product_knowledge(root).passed

    root = _copy_example(tmp_path / "runtime_false")
    manifest_path = root / "manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text())
    manifest["runtime_usable"] = False
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
    result = validate_product_knowledge(root)
    assert not result.passed
    assert any(finding.category == "runtime_usable_false" for finding in result.findings)


def test_command_safety_checks(tmp_path) -> None:
    root = _copy_example(tmp_path)
    registry = yaml.safe_load((root / "command_registry.yaml").read_text())
    registry["commands"].append(
        {
            "command": "kubectl delete pod bad",
            "target": "bad",
            "source_service_id": "bad",
            "requires_human_approval": True,
            "danger_level": "mutation",
        }
    )
    registry["commands"][0]["requires_human_approval"] = False
    (root / "command_registry.yaml").write_text(yaml.safe_dump(registry, sort_keys=False))
    result = validate_product_knowledge(root)
    categories = {finding.category for finding in result.findings}
    assert "command_requires_human_approval" in categories
    assert "dangerous_command" in categories


def test_draft_decision_moment_and_secret_fail_with_redaction(tmp_path) -> None:
    root = _copy_example(tmp_path)
    first = json.loads((root / "decision_moments.jsonl").read_text().splitlines()[0])
    first["decision_id"] = "dm-draft"
    first["review_status"] = "draft"
    with (root / "decision_moments.jsonl").open("a") as handle:
        handle.write(json.dumps(first) + "\n")
    (root / "notes.txt").write_text("api_key = sk-proj-" + "x" * 32)
    result = validate_product_knowledge(root)
    assert not result.passed
    text = json.dumps(result.model_dump(mode="json"))
    assert "sk-proj" not in text
    assert any(finding.category == "decision_moment_review_status" for finding in result.findings)
    assert any(finding.category == "secret_detected" for finding in result.findings)


def test_forbidden_runtime_source_paths_fail() -> None:
    result = validate_product_knowledge(".ic_copilot/personal_corpus")
    assert not result.passed
    assert any(finding.category == "forbidden_runtime_source" for finding in result.findings)


def test_product_knowledge_status_is_short_and_safe() -> None:
    status = product_knowledge_status("data/product_knowledge_example")
    assert status["passed"] is True
    assert status["counts"]["services"] > 0
