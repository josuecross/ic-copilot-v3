# Real LLM Readiness

Current phase: simplified `IncidentReadAndWhisper` runtime.

Normal runs use the configured real provider and fail closed if provider setup is invalid. Fixtures and stubs are explicit tests only.

Provider adapters implement `LLMClient.generate_json(prompt_name, input_payload, response_model)`. Every model output is validated against Pydantic schemas. Known enum-like labels may be normalized to canonical values and preserved as metadata; unknown behavior does not loosen schemas.

AI is responsible for semantic understanding:

- one `IncidentReadAndWhisper` call for the current read, latest open loop, selected move, target, wording, uncertainty, and evidence

Deterministic code is responsible for safety:

- schema acceptance
- allowed target construction and validation
- command registry checks
- current-evidence grounding
- fake entity rejection
- URL path number and URL domain safety
- historical leakage blocks
- final verifier pass/fallback
- formatting/metadata-only repair

Provider diagnostics and UI errors must never expose API keys or raw provider bodies. The main UI shows concise setup guidance; technical detail stays in trace/debug.

The normal product path makes one provider call after deterministic latest-window context packing. Older clean-context, StateDelta, IncidentBrief, semantic-ledger, sharp-blocker, blocker-reselection, target-scoring, and semantic-intent objects may remain in legacy/debug paths, but they are not normal product truth.

Large inputs use deterministic size assessment, stage timeouts, terminal timeout handling, event/noise quality labels, target quality gates, and product-safe step artifacts. If the one-call read times out, the run fails terminally with concise guidance. If the model returns invalid schema, the product may render a safe no-recommendation fallback; it must not synthesize a new semantic recommendation.
