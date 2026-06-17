# AGENTS

Current phase: simplified `IncidentReadAndWhisper` runtime following Phase 1.36C.

This repo is a personal local IC Copilot. Keep the product narrow: paste Slack text, use the configured real LLM, read validated `local_knowledge/`, run the deterministic verifier, and render a short manual-copy whisper.

## Hard Rules

- No Slack posting, paging, command execution, remediation, incident.io/PagerDuty writes, cloud deployment, auth, team workflow, vector DB, fine-tuning, Neo4j, DSPy, LangGraph, or multi-agent orchestration.
- No fixture fallback or shadow-as-product mode.
- No in-app artifact review, promotion, calibration, corpus, or previous-package workflow.
- No data/contract fallback in normal product mode.
- `local_knowledge/` is runtime knowledge. `data/contract`, `data/sample`, and `data/personal_regression` are tests/smoke/regression data only.
- Current incident evidence is authoritative. Historical memory is a behavior pattern only.
- Commands are suggestions only and must remain manual-copy.
- Long Slack pastes should use deterministic input assessment and latest-window context packing first. That machinery may control size and latency only; it must not infer incident facts.
- Collapsed Slack pastes may use turn reconstruction only as input help. Turn reconstruction is not semantic truth; `IncidentReadAndWhisper` is the operator-facing product semantic object.
- Pipeline step artifacts are product debug/audit metadata only. They must be redacted, local, and never become artifact review, promotion, curation, calibration, or knowledge editing UI.
- Event/evidence quality and target quality are deterministic safety gates. Preview cards, bot lifecycle text, logs/tables, field labels, policy IDs, URL path numbers, and generated fallback summaries must not become targets or primary grounding.
- Older semantic ledgers, `IncidentBrief`, blocker reselection, target scoring, sharp blocker, clean context, StateDelta, semantic intent, and content repair are legacy/debug-only in the normal product path.

## AI vs Deterministic Split

Use AI for semantic understanding:

- one `IncidentReadAndWhisper` call that reads the latest-window context and chooses the current open loop, move, target, wording, uncertainty, and evidence

Keep deterministic:

- schema validation
- event IDs and ordering
- event/noise quality labels
- URL/mention/command extraction
- allowed target candidate construction
- target eligibility
- catalog and command registry validation
- memory hydration by ID
- historical leakage blocks
- URL path number and fake customer/tenant blocks
- final verifier gate

Timeouts must end in a terminal run status. Preserve normalized event counts and sanitized failure context in debug when provider work fails after normalization.

The operator-facing output path is light normalizer -> input-size/latest-window context pack -> simple candidate target extraction -> `IncidentReadAndWhisper` -> deterministic verifier -> formatting/metadata-only repair -> render. Full-context enrichment and StateDelta compatibility are legacy/debug-only and must not block rendering.

Do not add incident-specific keyword routing. Regression names belong in fixtures/tests only; product logic must use general blocker/workstream/role concepts such as mitigation status, rollback/disable status, code-fix ETA, monitoring, validation, reporter/validator, technical investigator, owner team, Trust Post, and customer communications.

## Active Product Interfaces

- `python scripts/run_local_web.py`
- `python -m ic_copilot.cli run`
- `python -m ic_copilot.cli normalize`
- `python -m ic_copilot.cli inspect-state`
- `python -m ic_copilot.cli validate-knowledge`
- `python -m ic_copilot.cli knowledge-status`
- `python scripts/check_product_provider.py`
- `python scripts/run_product_smoke.py`
- `python scripts/run_product_latency_smoke.py`
- `python scripts/run_personal_product_trial_report.py`
- `python scripts/run_acceptance_gate.py`

## Acceptance

Run:

```bash
pytest -q
ruff check .
python scripts/validate_fixture_shapes.py
python scripts/run_replay_eval.py
python scripts/run_acceptance_gate.py
python scripts/audit_repo_conflicts.py --strict
python scripts/audit_web_console.py
```
