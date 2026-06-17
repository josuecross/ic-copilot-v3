# IC Copilot MVP: Architecture and File Structure (ChatGPT Handoff)

## 1) What this project is

IC Copilot is a local-first incident support assistant for Slack incident text.
It gives a junior SRE or Incident Commander one short, safe, grounded next move.

It is intentionally constrained:
- No autonomous remediation
- No Slack posting
- No paging
- No command execution
- Manual-copy guidance only

Main product interfaces:
- CLI (Typer)
- Local web console (FastAPI on localhost)

## 2) Core architecture

The core runtime pipeline is centralized in `src/ic_copilot/pipeline.py` and shared by CLI and web.

High-level flow:
1. Normalize raw incident input into ordered `IncidentEvent` records.
2. Apply trigger gating to decide if extraction/planning is needed.
3. Use configured LLM provider to extract `StateDelta`.
4. Deterministically merge into `CurrentIncidentState`.
5. Load service catalog and command registry; resolve relevant services.
6. Build memory query, retrieve `DecisionMoment` IDs, hydrate full records.
7. Run applicability gate and keep only accepted behavior patterns.
8. Plan exactly one `ICDecision`.
9. Run deterministic verifier checks.
10. Render final whisper output.
11. Persist trace (optional) to local SQLite.

Safety boundaries:
- Current facts must come from current incident evidence/state.
- Ownership/tool facts must come from catalog/registry.
- Historical memory contributes behavior patterns, not historical facts.
- Verifier blocks historical leakage, unsafe commands, fake entities, stale questions, and unsupported monitoring claims.

## 3) Runtime modes and execution paths

### Product path (normal)
- Uses real configured provider by default.
- Fails closed if provider is missing/misconfigured.
- No silent fallback to fixture in normal runs.

### Evaluation/developer paths
- Fixture/stub/shadow/prompt-variant flows are for test/eval/dev only.
- Replay and contract evaluation rely on deterministic fixtures.

## 4) Top-level directory purpose

- `.ic_copilot/`: Local runtime artifacts and generated state.
  - SQLite DBs, traces, staging/review folders, temporary eval inputs, local reports.
  - Not source-of-truth product code.
- `data/`: Source data, fixtures, contracts, and calibration assets.
- `docs/`: Operational design notes, workflows, and phase docs.
- `scripts/`: Operational entry points (gates, audits, imports/exports, reports, smoke runs).
- `src/`: Main Python package implementation.
- `tests/`: Unit, integration, contract, safety, web, and regression tests.
- `ic_copilot_previous_incidents__.../`: Previous-incident fixture package used for calibration and review workflows.

## 5) Data directory breakdown

- `data/sample/`: Baseline sample incidents, eval cases, service catalog, decision moments.
- `data/contract/`: Contract-grade replay fixtures and expected behavior.
  - Includes adversarial cases, replay cases JSONL, contract catalog/registry/memory.
- `data/calibration/`: Overlay examples for catalog/command review and reviewed variants.
- `data/corpus/`: Corpus manifests/templates for generated evaluation content.
- `data/generated/`: Generated incident/eval artifacts from corpus workflows.
- `data/prompt_variants/`: Prompt variant definitions for shadow/variant comparison.
- `data/review_templates/`: Reviewer label templates and review queue inputs.

## 6) Source code directory breakdown (`src/ic_copilot`)

### Core pipeline and domain logic
- `pipeline.py`: Shared end-to-end orchestration.
- `schemas.py`: Core data contracts (state, decision, trace, verifier outputs).
- `trigger.py`: Trigger decision logic.
- `extractor.py`: LLM-backed state delta extraction.
- `state_merge.py`: Deterministic state merging.
- `planner.py`: One-step IC decision planning.
- `verifier.py`: Deterministic safety and grounding checks.
- `render.py`: Final whisper rendering.
- `incident_loader.py`: Input loading/routing and event normalization entry points.
- `catalog.py`: Service catalog and command registry loading/resolution.
- `memory.py`: Decision moment load/retrieve/hydrate/applicability logic.

### Runtime configuration and diagnostics
- `runtime_config.py`: Product runtime config loading.
- `runtime_resources.py`: Loading catalog/registry/memory from product config paths.
- `provider_health.py`, `runtime_diagnostics.py`, `error_sanitizer.py`: Provider checks and safe diagnostics.
- `env.py`: Environment handling.

### Interface layers
- `cli.py`: Typer CLI commands (`run`, `eval`, `normalize`, shadow-related commands).
- `web/`: FastAPI web app.
  - `web/app.py`: Main app and routes.
  - `web/pipeline_events.py`: Progress event streaming for pipeline steps.
  - `web/run_store.py`: Run persistence and retrieval.
  - `web/safety.py`: Web safety checks and constraints.
  - `web/artifact_routes.py`: Artifact/correction/review related web routes.

### LLM abstraction
- `llm/base.py`: LLM client interface.
- `llm/product_client.py`: Product provider client creation.
- `llm/factory.py`, `llm/config.py`: Provider config and client factory.
- `llm/fixture_client.py`, `llm/stub_client.py`: Non-production testing clients.
- `llm/providers/`: Provider-specific adapters.
- `llm/prompts.py` and `llm/prompts/`: Prompt definitions/templates.

### Artifacts and calibration workflows
- `artifacts/`: Import/export, validation, diff, review, promotion, models.
- `calibration_overlay.py`, `overlay_*`: Overlay build/review/gate/impact tools.
- `review.py`, `review_queue.py`, `review_analysis.py`, `reviewer_agreement.py`: Review workflow logic.
- `previous_incident_*`: Previous incident package ingestion, analysis, calibration, and reporting.
- `shadow.py`, `shadow_evals.py`, `shadow_artifacts.py`: Shadow evaluation tooling.
- `prompt_variants.py`, `prompt_variant_report.py`, `prompt_versions.py`: Prompt variant experimentation/reporting.
- `corpus.py`, `corpus_generation.py`, `corpus_coverage.py`, `private_corpus.py`: Corpus management.

## 7) Scripts directory purpose (`scripts/`)

`/scripts` contains operational commands that orchestrate package modules. Main categories:

- Run paths:
  - `run_local_web.py`, `run_product_smoke.py`, `run_acceptance_gate.py`, `run_replay_eval.py`
- Provider/live checks:
  - `check_product_provider.py`, `run_openai_live_gate.py`, `run_openai_shadow_eval.py`
- Artifact workflows:
  - `import_artifact_bundle.py`, `validate_artifact_package.py`, `promote_artifact_package.py`
  - `build_artifact_review_report.py`, `run_reviewed_artifact_calibration.py`
- Calibration and overlays:
  - `build_calibration_overlay_draft.py`, `compare_calibration_overlay_impact.py`, `check_calibration_overlay_review.py`
- Previous-incident workflows:
  - import, coverage, candidate reports, remediation plan, calibration scripts
- Review analytics:
  - reviewer label templates, queue exports, agreement analysis, feedback export
- Safety/audit tools:
  - `audit_web_console.py`, `audit_repo_conflicts.py`, `scan_local_secrets.py`, `validate_fixture_shapes.py`

## 8) Tests directory purpose (`tests/`)

- `tests/contract/`: Contract-level behavior tests for extractor, merger, planner/verifier, replay fixtures, memory.
- `tests/live/`: Opt-in live shadow tests (provider-backed, not default local test path).
- `tests/test_*.py`: Broad regression coverage across pipeline, safety, web, artifacts, overlays, prompt variants, provider diagnostics, and phase-specific invariants.

Testing intent:
- Lock architecture invariants and safety boundaries.
- Catch regressions from new prompts, fixtures, overlays, and web routes.
- Keep product behavior deterministic and auditable.

## 9) Important config and metadata files

- `pyproject.toml`: Project metadata, dependencies, pytest and ruff settings.
- `.env` / `.env.example`: Environment variables (provider credentials and local config hints).
- `ic_copilot.local.example.yaml`: Example product runtime configuration (catalog/registry/memory/provider paths).
- `AGENTS.md`: Project constraints and guardrails for coding agent behavior.
- `README.md`: Main product overview, architecture summary, and run commands.

## 10) How to explain this repository to ChatGPT quickly

Use this short prompt:

"This repository is a local incident-copilot MVP in Python. The core is a shared pipeline in `src/ic_copilot/pipeline.py` used by both CLI (`src/ic_copilot/cli.py`) and web (`src/ic_copilot/web/app.py`). It normalizes Slack incident text, extracts and merges current state, retrieves applicable memory by ID+hydration, plans one IC move, verifies safety deterministically, and renders a manual-copy whisper. `data/` contains sample and contract fixtures; `scripts/` contains operational gates/reports/import-export workflows; `tests/` enforces safety and architecture invariants. Explain risks, extension points, and how to add a new verifier rule safely without violating architecture boundaries."

## 11) Project file hierarchy map (diagram)

The project-only diagram is provided in:

- `FILE_HIERARCHY_DIAGRAM.md`

This map intentionally excludes non-project/runtime-noise paths:
- `.venv`
- `.git` internals
- `.ic_copilot` runtime artifacts
- cache directories (`.pytest_cache`, `.ruff_cache`, `.mypy_cache`, `__pycache__`)
- compiled/log noise (`*.pyc`, `*.pyo`, `*.log`, `.DS_Store`)

Preview:

```text
|-- .
|-- .env
|-- .env.example
|-- .gitignore
|-- AGENTS.md
|-- ARCHITECTURE_AND_STRUCTURE_FOR_CHATGPT.md
|-- FILE_HIERARCHY_DIAGRAM.md
|-- README.md
|-- data
||--    calibration
||--    |   catalog_overlay.example.yaml
||--    |   catalog_overlay.reviewed.example.yaml
||--    |   command_registry_overlay.example.yaml
||--    |   command_registry_overlay.reviewed.example.yaml
||--    contract
||--    |   adversarial
||--    |   |   incidents
||--    |   |   |   01_url_domain_customer.txt
||--    |   |   |   02_url_path_tenant.txt
```