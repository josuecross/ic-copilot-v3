# Test Fixture Policy

Current phase: simplified `IncidentReadAndWhisper` runtime.

The repository has two testing contexts:

- **Public CI** is network-free and runs the self-contained tests whose fixtures and dependencies are published in this repository.
- **Full local regression testing** can additionally exercise development/regression modules that depend on unpublished incident corpora or `local_knowledge/` inputs. Those inputs are intentionally kept outside the public repository.

Some test modules for the full local build remain visible because they document important product, safety, regression, and evaluation behavior. Public GitHub Actions excludes only modules whose required fixture inputs are not available in a clean public checkout, plus historical phase-status assertions that are no longer part of the portfolio-facing documentation contract.

Layers:

- unit tests use inline examples and `tmp_path` and are suitable for public CI
- contract tests use `data/contract`; tests that require unpublished incident-text corpora run only with the full local fixture set
- personal regression tests use `data/personal_regression`; sanitized metadata may be public while incident corpora can remain local-only
- web/CLI smoke tests use `data/sample`; modules that require unpublished sample incident text run only with the full local fixture set
- knowledge validation tests use the published `data/product_knowledge_example` where possible
- product/local regression paths may use private `local_knowledge/`, which is explicitly excluded from version control

The public CI gate still exercises hundreds of tests across parsing, schemas, configuration, safety, provider behavior, knowledge-bundle handling, runtime logic, web safety, and other self-contained components, alongside correctness-focused Ruff checks.

Default public CI must not require network access, private packages, secrets, or private fixture content. Local-only regression tests must not be represented as public CI coverage unless their required fixtures are published in sanitized form.

Default tests must not write to `data/contract` or mutate `local_knowledge/`.

Incident-specific terms belong in fixtures and tests only. Product code should be tested for general blocker behavior rather than branching on a service, person, change ID, or product name from a regression.

Large-input tests use regression fixtures plus fake timeout clients. They should prove latest-window context packing, terminal web failures, and debug preservation without requiring network access.

One-call semantic tests should use fake/fixture clients. They should prove `IncidentReadAndWhisper` preserves evidence IDs, rejects noise as targets through candidate filtering and verifier checks, fails terminally on provider timeout, and falls back safely on invalid schema.

Role-targeting tests use sanitized regression snippets and tiny generic fixtures. They should prove the product uses allowed target IDs and current evidence rather than branching on regression-specific people, products, teams, tickets, or error strings.

Simplified-runtime fixtures should include positive useful cases and degraded/failure cases: preview-card-only snippets, noisy target labels, stale expiration, invalid schema, provider timeout, DB high CPU style current validation asks, L3-converted incidents with PagerDuty cards, OCS lag/Trust Post, Security Workflow, API 504, RevPro, and rpcapd. Product code must not branch on those fixture strings. Legacy IncidentBrief/semantic-ledger/blocker-reselection tests may remain as unit tests, but normal pipeline tests should assert the `IncidentReadAndWhisper` path.

Longer term, local-only regression modules can be moved into public CI as equivalent synthetic or fully sanitized fixtures are added. The public/private boundary should be reduced by publishing safe substitutes, not by publishing proprietary or sensitive operational data.
