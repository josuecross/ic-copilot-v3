from __future__ import annotations

import json
from pathlib import Path

import typer

from ic_copilot.error_sanitizer import sanitize_provider_error
from ic_copilot.incident_loader import incident_id_from_path, load_incident_events
from ic_copilot.llm.product_client import ProductConfigurationError
from ic_copilot.llm.providers.base_json import ProviderJSONError
from ic_copilot.pipeline import catalog_matches_for_state, run_pipeline as _shared_run_pipeline
from ic_copilot.product_knowledge import (
    ProductKnowledgeError,
    product_knowledge_status,
    validate_product_knowledge,
)
from ic_copilot.schemas import CurrentIncidentState

app = typer.Typer(help="IC Copilot / local verified AI incident whisperer")


def _catalog_matches_for_state(state: CurrentIncidentState, catalog):
    return catalog_matches_for_state(state, catalog)


@app.command()
def normalize(incident_file: Path) -> None:
    events = load_incident_events(incident_file, incident_id=incident_id_from_path(incident_file))
    typer.echo(json.dumps([event.model_dump(mode="json") for event in events], indent=2))


@app.command()
def run(
    incident_file: Path,
    catalog: Path | None = typer.Option(None, "--catalog", help="Optional debug override. Defaults to product config."),
    memory: Path | None = typer.Option(None, "--memory", "--memory-dir", help="Optional debug override. Defaults to product config."),
    command_registry: Path | None = None,
    config: Path | None = typer.Option(None, "--config", help="Product runtime config path."),
    json_output: bool = typer.Option(False, "--json", help="Print run trace as JSON instead of whisper"),
    save_trace: bool = typer.Option(True, "--save-trace/--no-save-trace"),
) -> None:
    try:
        result = _shared_run_pipeline(
            incident_file,
            catalog_path=catalog,
            memory_path=memory,
            command_registry_path=command_registry,
            save_trace=save_trace,
            config_path=config,
        )
    except (ProductConfigurationError, ProductKnowledgeError, ProviderJSONError) as exc:
        typer.echo(sanitize_provider_error(exc), err=True)
        raise typer.Exit(2) from exc
    if json_output:
        trace = result["trace"]
        typer.echo(
            json.dumps(
                {
                    "final_output": result["final_output"],
                    "state": {
                        "incident_id": result["state"].incident_id,
                        "phase": result["state"].phase,
                        "current_blocker": result["state"].current_blocker,
                        "compact_summary": result["state"].compact_summary,
                    },
                    "decision": result["decision"].model_dump(mode="json"),
                    "verifier_result": result["verifier_result"].model_dump(mode="json"),
                    "trace_summary": {
                        "trace_id": trace.trace_id,
                        "pipeline_version": trace.pipeline_version,
                        "input_event_ids": trace.input_event_ids,
                        "retrieved_memory_ids": trace.retrieved_memory_ids,
                        "accepted_memory_ids": trace.accepted_memory_ids,
                        "catalog_match_ids": trace.catalog_match_ids,
                        "command_registry_size": trace.command_registry_size,
                        "safety_summary": trace.safety_summary,
                        "latency_ms": trace.latency_ms,
                    },
                },
                indent=2,
            )
        )
    else:
        typer.echo(result["final_output"])


@app.command("validate-knowledge")
def validate_knowledge(
    path: Path = typer.Argument(Path("local_knowledge")),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    result = validate_product_knowledge(path)
    if json_output:
        typer.echo(result.model_dump_json(indent=2))
    else:
        status = "passed" if result.passed else "failed"
        typer.echo(f"Product knowledge validation {status}: {path}")
        typer.echo(
            "counts: "
            f"services={result.counts.services} "
            f"commands={result.counts.commands} "
            f"decision_moments={result.counts.decision_moments} "
            f"verifier_regressions={result.counts.verifier_regressions} "
            f"rejected_entities={result.counts.rejected_entities} "
            f"stale_question_patterns={result.counts.stale_question_patterns}"
        )
        for finding in result.findings:
            typer.echo(f"[{finding.severity}] {finding.category}: {finding.message}")
    if not result.passed:
        raise typer.Exit(1)


@app.command("knowledge-status")
def knowledge_status(
    path: Path = typer.Argument(Path("local_knowledge")),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    status = product_knowledge_status(path)
    if json_output:
        typer.echo(json.dumps(status, indent=2))
        return
    verdict = "ready" if status["passed"] else "not ready"
    typer.echo(f"Product knowledge {verdict}: {status['path']}")
    counts = status["counts"]
    typer.echo(
        "counts: "
        f"services={counts['services']} "
        f"commands={counts['commands']} "
        f"decision_moments={counts['decision_moments']} "
        f"verifier_regressions={counts['verifier_regressions']} "
        f"rejected_entities={counts['rejected_entities']} "
        f"stale_question_patterns={counts['stale_question_patterns']}"
    )
    for error in status["errors"][:5]:
        typer.echo(f"[error] {error}", err=True)


@app.command("inspect-state")
def inspect_state(
    incident_file: Path,
    catalog: Path | None = typer.Option(None, "--catalog", help="Optional debug override. Defaults to product config."),
    memory: Path | None = typer.Option(None, "--memory", "--memory-dir", help="Optional debug override. Defaults to product config."),
    command_registry: Path | None = None,
    config: Path | None = typer.Option(None, "--config", help="Product runtime config path."),
) -> None:
    try:
        result = _shared_run_pipeline(
            incident_file,
            catalog_path=catalog,
            memory_path=memory,
            command_registry_path=command_registry,
            save_trace=False,
            config_path=config,
        )
    except (ProductConfigurationError, ProductKnowledgeError, ProviderJSONError) as exc:
        typer.echo(sanitize_provider_error(exc), err=True)
        raise typer.Exit(2) from exc
    typer.echo(result["state"].model_dump_json(indent=2))


if __name__ == "__main__":
    app()
