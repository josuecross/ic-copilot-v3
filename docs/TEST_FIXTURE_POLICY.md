# Test Fixture Policy

Current phase: simplified `IncidentReadAndWhisper` runtime.

The default suite is product/contract/regression focused and does not require network, private packages, or private `local_knowledge/`.

Layers:

- unit tests use inline examples and `tmp_path`
- contract tests use `data/contract`
- personal regression tests use `data/personal_regression`
- web/CLI smoke tests use `data/sample`
- knowledge validation tests use `data/product_knowledge_example`

Old workflow tests that only covered historical dev tools were removed from pytest collection. If a removed test protected a product safety invariant, port that invariant into a product, contract, or personal regression test.

Default tests must not write to `data/contract` or mutate `local_knowledge/`.

Incident-specific terms belong in fixtures and tests only. Product code should be tested for general blocker behavior rather than branching on a service, person, change ID, or product name from a regression.

Large-input tests use `data/personal_regression` plus fake timeout clients. They should prove latest-window context packing, terminal web failures, and debug preservation without requiring network access.

One-call semantic tests should use fake/fixture clients. They should prove `IncidentReadAndWhisper` preserves evidence IDs, rejects noise as targets through candidate filtering and verifier checks, fails terminally on provider timeout, and falls back safely on invalid schema.

Role-targeting tests use sanitized personal regression snippets and tiny generic fixtures. They should prove the product uses allowed target IDs and current evidence rather than branching on regression-specific people, products, teams, tickets, or error strings.

Simplified-runtime fixtures should include positive useful cases and degraded/failure cases: preview-card-only snippets, noisy target labels, stale expiration, invalid schema, provider timeout, DB high CPU style current validation asks, L3-converted incidents with PagerDuty cards, OCS lag/Trust Post, Security Workflow, API 504, RevPro, and rpcapd. Product code must not branch on those fixture strings. Legacy IncidentBrief/semantic-ledger/blocker-reselection tests may remain as unit tests, but normal pipeline tests should assert the `IncidentReadAndWhisper` path.
