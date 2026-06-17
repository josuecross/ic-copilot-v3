# Personal Regression Fixtures

Phase 1.24 keeps personal regressions separate from contract/runtime data. This directory is a
generated sanitized regression view exported from `.ic_copilot/personal_corpus/`.

The exact sanitized Slack text for P3 IN-11084 is not present in this repo yet, so the current
coverage is static/unit regression coverage in `scripts/run_personal_regression_eval.py` and tests.
When the sanitized snippet is available, normalize it through the personal corpus first, then export
reviewed views here.

These files are not runtime memory, catalog, command registry, or reviewed overlays.
