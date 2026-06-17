from __future__ import annotations

import ast
from pathlib import Path

from ic_copilot.catalog import load_command_registry, load_service_catalog
from ic_copilot.evals import run_eval_suite
from ic_copilot.memory import hydrate_decision_moments, load_decision_moments, retrieve_decision_moment_ids
from ic_copilot.render import render_ic_whisper
from ic_copilot.schemas import DecisionMoment, ICDecision, MemoryQuery
from tests.helpers import fixture_run_pipeline


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "ic_copilot"
CONTRACT = ROOT / "data" / "contract"


def _runtime_files() -> list[Path]:
    return sorted(path for path in SRC.rglob("*.py") if "__pycache__" not in path.parts)


def _module_name(node: ast.AST) -> str:
    if isinstance(node, ast.Import):
        return ",".join(alias.name for alias in node.names)
    if isinstance(node, ast.ImportFrom):
        return node.module or ""
    return ""


def test_runtime_has_no_forbidden_dependency_imports():
    forbidden = {
        "neo4j",
        "chromadb",
        "qdrant_client",
        "langgraph",
        "dspy",
        "openai",
        "anthropic",
        "google.generativeai",
    }
    for path in _runtime_files():
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            module = _module_name(node)
            if not module:
                continue
            assert not any(module == name or module.startswith(f"{name}.") for name in forbidden), (
                path,
                module,
            )
            if module.startswith("langchain") and "agent" in module:
                raise AssertionError(f"{path} imports LangChain agent runtime: {module}")


def test_runtime_has_no_auto_action_functions():
    forbidden_names = {
        "auto_page",
        "execute_command",
        "remediate",
        "post_to_slack",
        "write_pagerduty",
        "write_incident_io",
    }
    for path in _runtime_files():
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assert node.name not in forbidden_names, (path, node.name)


def test_memory_retrieval_returns_ids_and_hydration_returns_records():
    moments = load_decision_moments(CONTRACT / "decision_moments.jsonl")
    ids = retrieve_decision_moment_ids(
        MemoryQuery(incident_id="i", phase="engagement", current_blocker="missing_owner", labels=["missing_owner"]),
        moments,
    )
    assert ids
    assert all(isinstance(item, str) for item in ids)
    hydrated = hydrate_decision_moments(ids, moments)
    assert hydrated
    assert all(isinstance(item, DecisionMoment) for item in hydrated)


def test_planner_returns_one_verified_decision_and_renderer_is_short():
    result = fixture_run_pipeline(
        CONTRACT / "incidents/01_revpro_early_engage.txt",
        CONTRACT / "service_catalog.yaml",
        CONTRACT / "decision_moments.jsonl",
        CONTRACT / "command_registry.yaml",
        save_trace=False,
    )
    assert isinstance(result["raw_decision"], ICDecision)
    assert result["raw_decision"].verifier_result is result["verifier_result"]
    rendered = render_ic_whisper(result["decision"])
    labels = [line for line in rendered.splitlines() if line.endswith(":")]
    if result["trace"].processing_strategy == "incident_read_and_whisper_v2":
        assert labels == ["SAY THIS:", "NEXT LINE:"]
    else:
        assert labels == ["SAY THIS:", "NEXT LINE:", "COMMAND:"]


def test_positive_contract_evals_do_not_use_fallback():
    results = run_eval_suite(
        CONTRACT / "replay_cases.jsonl",
        catalog_path=CONTRACT / "service_catalog.yaml",
        memory_dir=CONTRACT / "decision_moments.jsonl",
        command_registry_path=CONTRACT / "command_registry.yaml",
    )
    positives = [result for result in results if result.case_type == "positive"]
    assert positives
    assert all(result.passed for result in positives)
    assert not any(result.used_fallback for result in positives)


def test_commands_require_human_approval():
    catalog = load_service_catalog(CONTRACT / "service_catalog.yaml")
    registry = load_command_registry(CONTRACT / "command_registry.yaml", catalog)
    exact_commands = [entry for entry in registry if entry.exact]
    assert exact_commands
    assert all(entry.requires_human_approval for entry in exact_commands)


def test_historical_forbidden_facts_do_not_appear_without_current_evidence():
    for incident in sorted((CONTRACT / "incidents").glob("*.txt")):
        result = fixture_run_pipeline(
            incident,
            CONTRACT / "service_catalog.yaml",
            CONTRACT / "decision_moments.jsonl",
            CONTRACT / "command_registry.yaml",
            save_trace=False,
        )
        output = result["final_output"].lower()
        current_evidence_text = "\n".join(
            [
                result["state"].model_dump_json(),
                *[event.model_dump_json() for event in result["events"]],
            ]
        ).lower()
        for applicability in result["trace"].applicability_results:
            if not applicability.accepted:
                continue
            for fact in applicability.forbidden_fact_leakage:
                if fact.lower() not in current_evidence_text:
                    assert fact.lower() not in output, (incident.name, fact, output)
