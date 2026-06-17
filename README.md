# IC Copilot

This is a local personal Incident Commander whisperer. Paste a Slack incident snippet, run the configured real LLM path, and copy one short verified response:

Current runtime: simplified `IncidentReadAndWhisper` path following the Phase 1.36C safety work.

- `SAY THIS`
- `NEXT LINE`
- `COMMAND` only when a safe human-approved lookup is available

It is not a Slack app, team workflow tool, artifact review UI, calibration workbench, command runner, pager, or remediation system.

## Product Path

Normal runs use one spine:

Slack paste or upload -> light normalizer -> deterministic input-size assessment and latest-window context pack -> simple candidate target extraction -> one AI `IncidentReadAndWhisper` call -> deterministic safety verifier -> formatting/metadata-only repair if needed -> manual-copy whisper.

`IncidentReadAndWhisper` is the product's semantic read of the messy Slack paste. It captures the current read, latest open loop, already-answered questions, selected move, selected target ID, concise wording, uncertainty, and current-event evidence quotes.

Allowed targets are built deterministically before the AI writes advice. The planner must choose target IDs from Slack authors, explicit mentions, current-evidence teams/services, catalog services/teams, or safe command-registry targets. URL path numbers, Jira IDs, log fragments, table headers, bot placeholders, preview-card fields, policy IDs, and generated summary fragments are non-targetable.

The verifier remains the final gate for schema validity, current-evidence grounding, target validity, command safety, URL-number/customer/tenant safety, historical leakage, fake entities, stale questions, output length, and no action execution.

Older compatibility objects such as `IncidentBrief`, typed semantic ledgers, `CleanIncidentContext`, `StateDelta`, `SharpBlockerAssessment`, blocker reselection, target scoring, and `SemanticIntentAssessment` may remain in legacy/debug modules or tests, but the normal product trace centers on `IncidentReadAndWhisper`. Regression fixtures such as rpcapd/Billing, API 504, Security Workflow, and RevPro are tests only, not keyword routing.

Repair is deliberately narrow: it may normalize expiration metadata, trim length, remove duplicate `NEXT LINE`, or remove unsafe/unregistered command text. It must not choose a new blocker, target, semantic move, workstream, customer, tenant, service, or person.

## Setup

1. Create a virtualenv and install the project dependencies.
2. Put your provider key in `.env` or your shell, usually `OPENAI_API_KEY`.
3. Create or bootstrap `local_knowledge/`.
4. Validate knowledge:

```bash
python -m ic_copilot.cli validate-knowledge local_knowledge
python -m ic_copilot.cli knowledge-status local_knowledge
```

`local_knowledge/` is ignored by git and is the only normal runtime knowledge source.

## Run

```bash
python scripts/run_local_web.py
```

Open the localhost URL, paste a sanitized incident snippet, run the whisper, and label the output. The UI is intentionally small: readiness badges, paste/upload/sample, IC whisper, progress, Do Not Ask / Why, feedback, recent runs, and collapsed advanced details.

## CLI

Product commands:

```bash
python -m ic_copilot.cli run data/sample/incidents/revpro_early_engage.txt
python -m ic_copilot.cli normalize data/sample/incidents/revpro_early_engage.txt
python -m ic_copilot.cli inspect-state data/sample/incidents/revpro_early_engage.txt
python -m ic_copilot.cli validate-knowledge local_knowledge
python -m ic_copilot.cli knowledge-status local_knowledge
```

## Trial

Run 20 real sanitized snippets, label usefulness and failure tags, then generate:

```bash
python scripts/run_personal_product_trial_report.py \
  --db .ic_copilot/web.sqlite3 \
  --output-md .ic_copilot/personal_trial/product_trial_report.md \
  --output-json .ic_copilot/personal_trial/product_trial_report.json
```

## Gates

```bash
pytest -q
ruff check .
python scripts/validate_fixture_shapes.py
python scripts/run_replay_eval.py
python scripts/run_acceptance_gate.py
python scripts/audit_repo_conflicts.py --strict
python scripts/audit_web_console.py
python scripts/run_product_latency_smoke.py --knowledge-dir local_knowledge \
  --output-json .ic_copilot/product_smoke/latency_phase136c.json \
  --output-md .ic_copilot/product_smoke/latency_phase136c.md
```
