# Product Core

Current phase: simplified `IncidentReadAndWhisper` runtime following Phase 1.36C.

The product has one runtime spine:

Slack paste/upload -> light normalizer -> deterministic input-size assessment and latest-window context pack -> simple candidate target extraction -> one AI `IncidentReadAndWhisper` call -> deterministic safety verifier -> formatting/metadata-only repair if needed -> short manual-copy whisper.

`IncidentReadAndWhisper` is the authoritative semantic object in the normal product path. It captures the current read, latest open loop, already-answered questions, selected move, selected target ID, `SAY THIS`, optional `NEXT LINE`, optional registry-backed command, uncertainty, confidence, and current-event evidence quotes.

`AllowedTarget` candidates are built deterministically before advice is generated. Slack authors, explicit mentions from human/operator events, current-evidence services/teams, catalog entries, and safe command-registry targets can become target IDs. URL path numbers, Jira IDs, policy IDs, preview-card fields, log/code fragments, table headers, bot/system placeholders, image filenames, and generated summary fragments are non-targetable unless catalog-confirmed.

The one AI call receives latest-window compact events, candidate targets, do-not-target entries, catalog/command hints, and accepted DecisionMoment behavior hints. It must choose one canonical move, a single selected target ID when naming a target, one short `SAY THIS`, optional `NEXT LINE`, and an optional safe command only when registry-backed and human-approved.

Product-safe step artifacts remain for audit/debug, but the normal runtime no longer uses parallel semantic ledgers, blocker reselection, fallback workstream builders, or target scoring as product truth. If the one AI read is invalid, the product may render a safe no-recommendation fallback; it must not synthesize a new semantic ask from deterministic templates.

Pipeline Progress may show generated summaries and expandable JSON for each step. This is audit/debug metadata only: no artifact curation, review, promotion, calibration, or knowledge editing workflow is part of the product UI.

The deterministic verifier remains final authority for schemas, target validity, commands, URL path numbers, fake customers/tenants/teams, historical leakage, stale questions, preview/noise grounding, output length, and no-action constraints. A repair attempt may only normalize metadata, trim/collapse formatting, remove duplicate `NEXT LINE`, or remove unsafe/unregistered command text.

`CleanIncidentContext`, `StateDelta`, typed semantic ledgers, `IncidentBrief`, `SharpBlockerAssessment`, blocker reselection, target shortlist scoring, and `SemanticIntentAssessment` may remain as legacy/debug or unit-test surfaces, but the normal product trace centers on context packing, `IncidentReadAndWhisper`, verifier results, formatting repair, and rendered output. They must not drive normal product advice.

Large paste handling is deliberately size/latency oriented. The deterministic input assessment chooses a latest high-signal window and packs compact evidence before the provider call. It must not infer incident facts; semantic interpretation comes from `IncidentReadAndWhisper` and all final advice still passes the deterministic verifier.

Regression-specific people, services, products, tickets, and error strings belong in fixtures/tests only. Product code must not branch on them.

Normal product modules must not import fixture/stub clients, shadow tooling, prompt variants, old curation packages, previous-package helpers, or calibration code.
