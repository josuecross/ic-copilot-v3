"""Run the test subset that is reproducible from a clean public checkout.

The full local regression suite also contains modules whose incident corpora or
local knowledge inputs are intentionally not published. Keep the exclusions
explicit and reviewable instead of making missing private inputs look like
product failures in public CI.
"""

from __future__ import annotations

import pytest


# Modules below depend on unpublished incident corpora/local knowledge, or on
# historical phase-label assertions that are not part of the public portfolio
# documentation contract. As sanitized/synthetic equivalents are published,
# remove the corresponding module from this list and bring it into public CI.
PUBLIC_CI_EXCLUDED_MODULES = (
    "tests/contract/test_normalizer_contract.py",
    "tests/contract/test_planner_verifier_contract.py",
    "tests/contract/test_replay_fixtures.py",
    "tests/contract/test_state_extractor_contract.py",
    "tests/contract/test_state_merger_contract.py",
    "tests/test_architecture_invariants.py",
    "tests/test_eval_runner.py",
    "tests/test_incident_read_envelope_simplified.py",
    "tests/test_llm_readiness.py",
    "tests/test_memory.py",
    "tests/test_phase115_repo_status.py",
    "tests/test_phase119_repo_cleanup.py",
    "tests/test_phase120_docs_status.py",
    "tests/test_phase122_product_smoke.py",
    "tests/test_phase122_web_provider_failures.py",
    "tests/test_phase125_product_runtime.py",
    "tests/test_phase1261_security_move_robustness.py",
    "tests/test_phase126_trust_post.py",
    "tests/test_phase127_clean_context_semantic_intent.py",
    "tests/test_phase129_sharp_blocker.py",
    "tests/test_phase130_large_input_resilience.py",
    "tests/test_phase131_role_targeting.py",
    "tests/test_phase132_incident_brief.py",
    "tests/test_phase134_target_selection.py",
    "tests/test_phase135_bounded_incident_brief.py",
    "tests/test_phase136a_artifacts_semantic_read.py",
    "tests/test_phase136b_evidence_target_gating.py",
    "tests/test_phase16_adversarial.py",
    "tests/test_product_pipeline_defaults.py",
    "tests/test_raw_paste_product_eval.py",
    "tests/test_revpro_end_to_end.py",
    "tests/test_trace_contract.py",
    "tests/test_verifier.py",
    "tests/test_web_app.py",
    "tests/test_web_phase18_usability.py",
    "tests/test_web_pipeline_events.py",
)


def main() -> int:
    args = ["-q"]
    args.extend(f"--ignore={path}" for path in PUBLIC_CI_EXCLUDED_MODULES)
    return int(pytest.main(args))


if __name__ == "__main__":
    raise SystemExit(main())
