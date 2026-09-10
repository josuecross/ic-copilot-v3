# IC Copilot V3

**Human-in-the-loop AI decision support built with Python, FastAPI, structured outputs, deterministic verification, and regression evaluation.**

IC Copilot V3 is a local-first application that turns noisy operational chat into one concise, evidence-grounded next-step recommendation. The project explores a practical engineering question: **how can an LLM be useful in a high-context workflow without giving it unrestricted authority or trusting its output blindly?**

The answer in this repository is a hybrid design: use the model for semantic interpretation, then apply deterministic software checks for structure, grounding, target validity, safety, and stale-context failures before anything is shown to the user.

> **Human control is a design requirement.** IC Copilot does not execute remediation, send Slack messages, page teams, or run arbitrary commands. The final output is guidance for manual review and use.

## Why this project matters

Many AI applications stop at `prompt -> model -> text`. IC Copilot adds an engineering layer around the model call:

- structured input processing and context selection;
- deterministic extraction of valid people, teams, services, and safe command targets;
- typed model outputs and schema validation;
- evidence-grounding and stale-context checks;
- explicit safety rules for generated commands and targets;
- narrow repair that can fix formatting/metadata without silently changing the recommendation;
- replay, regression, acceptance, and adversarial evaluation;
- local persistence and diagnostics for inspecting application behavior.

This makes the repository useful as a portfolio example of **applied AI, AI evaluation, backend engineering, developer tooling, and reliability-oriented software design**.

## Current runtime

The normal product path is centered on a simplified `IncidentReadAndWhisper` workflow:

```text
Sanitized operational text
        |
        v
Input normalization + size assessment
        |
        v
Latest-window context selection
        |
        v
Deterministic candidate/target extraction
        |
        v
One semantic LLM call
        |
        v
Deterministic verification
        |
        +---- blocked/unsafe ----> safe fallback
        |
        v
Formatting / metadata-only repair
        |
        v
Manual-copy recommendation
```

The semantic layer interprets the current situation and proposes a next move. The deterministic layer decides whether that output is safe and sufficiently grounded to display.

## Reliability and safety design

### Grounded output

The verifier checks that recommendations are supported by the current evidence rather than invented from unrelated or historical context.

### Deterministic target allowlisting

Targets are derived before the model writes its recommendation. Slack authors, explicit mentions, current-evidence teams/services, catalog entries, and registered safe-command targets can become candidates; incidental IDs, log fragments, URL numbers, or generated summary text cannot.

### Human-in-the-loop execution

The system produces guidance only. Operational actions stay with the user.

### Narrow repair

Repairs are intentionally constrained to presentation and metadata issues such as duplicate lines, length, expiration metadata, or unsafe command text. Repair logic is not allowed to silently choose a different owner, service, blocker, customer, tenant, or semantic action.

### Fail-safe behavior

Provider failures, invalid output, unsupported targets, stale questions, and unsafe recommendations can be routed to a safe fallback instead of being presented as confident guidance.

## Technology stack

- **Python 3.11+**
- **FastAPI** — local web interface and application routes
- **Pydantic** — structured contracts and validation
- **Typer** — CLI
- **Uvicorn** — local ASGI runtime
- **OpenAI API** — optional configured live semantic provider
- **PyYAML** — catalogs and configuration
- **SQLite** — local run/trace persistence
- **pytest** — unit, integration, contract, regression, and safety tests
- **Ruff** — static/lint checks

## Interfaces

### Local web application

```bash
python scripts/run_local_web.py
```

The web interface supports sanitized paste/upload input, readiness information, the generated recommendation, feedback, recent runs, and diagnostic details.

### CLI

```bash
python -m ic_copilot.cli run data/sample/incidents/revpro_early_engage.txt
python -m ic_copilot.cli normalize data/sample/incidents/revpro_early_engage.txt
python -m ic_copilot.cli inspect-state data/sample/incidents/revpro_early_engage.txt
python -m ic_copilot.cli validate-knowledge local_knowledge
python -m ic_copilot.cli knowledge-status local_knowledge
```

## Local setup

```bash
git clone https://github.com/josuecross/ic-copilot-v3.git
cd ic-copilot-v3

python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate

pip install -e ".[dev,live-openai]"
```

Copy `.env.example` to `.env` or configure the provider variables in your shell. For the live OpenAI path, set `OPENAI_API_KEY`.

The normal local knowledge directory is `local_knowledge/`, which is ignored by Git.

Validate it with:

```bash
python -m ic_copilot.cli validate-knowledge local_knowledge
python -m ic_copilot.cli knowledge-status local_knowledge
```

## Evaluation and quality gates

The repository includes multiple forms of validation rather than relying on a few manually inspected prompts:

```bash
pytest -q
ruff check .
python scripts/validate_fixture_shapes.py
python scripts/run_replay_eval.py
python scripts/run_acceptance_gate.py
python scripts/audit_repo_conflicts.py --strict
python scripts/audit_web_console.py
```

Evaluation assets include normal cases, adversarial cases, contract fixtures, replay data, and acceptance checks. The goal is to catch failures such as:

- unsupported or fabricated entities;
- stale questions resurfacing after they were answered;
- unsafe or unregistered commands;
- incorrect target selection;
- historical-context leakage;
- malformed structured output;
- recommendations that are syntactically valid but not grounded in current evidence.

## Engineering decisions demonstrated

This project is intentionally more than an LLM wrapper. It demonstrates:

- designing a typed boundary around probabilistic model output;
- separating semantic reasoning from deterministic policy checks;
- building fallback behavior for provider and schema failures;
- creating reproducible evaluation fixtures for AI behavior;
- debugging AI applications with observable intermediate state;
- preserving human control around potentially consequential actions;
- evolving an application while maintaining regression and architecture constraints.

## Project scope

IC Copilot is a **local portfolio / personal engineering project**, not a production incident-management platform. Sample and regression incidents in the repository are synthetic or sanitized evaluation material.

The project intentionally does **not**:

- execute remediation;
- post to Slack;
- page responders;
- act as a production monitoring platform;
- replace human operational judgment.

Those boundaries are part of the design, not missing features.

## Related documentation

- [`ARCHITECTURE_AND_STRUCTURE_FOR_CHATGPT.md`](ARCHITECTURE_AND_STRUCTURE_FOR_CHATGPT.md) — deeper repository architecture and file map
- [`FILE_HIERARCHY_DIAGRAM.md`](FILE_HIERARCHY_DIAGRAM.md) — project structure reference
- [`AGENTS.md`](AGENTS.md) — coding-agent constraints used while developing the repository

## Author

**Josue David Cruz Lopez**  
Costa Rica  
GitHub: [@josuecross](https://github.com/josuecross)  
LinkedIn: [josue-david-c](https://www.linkedin.com/in/josue-david-c/)
