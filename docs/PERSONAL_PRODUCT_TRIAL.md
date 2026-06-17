# Personal Product Trial

Current phase: simplified `IncidentReadAndWhisper` runtime.

Run 20 real sanitized Slack snippets through the local web console and label each output.

Workflow:

1. Review operational knowledge outside the app.
2. Write reviewed knowledge into `local_knowledge/`.
3. Run `python -m ic_copilot.cli validate-knowledge local_knowledge`.
4. Start `python scripts/run_local_web.py`.
5. Paste one sanitized snippet.
6. Use the whisper only if it is useful and safe.
7. Save feedback: useful, safe but generic, wrong, or unsafe, plus failure tags.
8. Repeat for 20 snippets.
9. Generate the report:

```bash
python scripts/run_personal_product_trial_report.py \
  --db .ic_copilot/web.sqlite3 \
  --output-md .ic_copilot/personal_trial/product_trial_report.md \
  --output-json .ic_copilot/personal_trial/product_trial_report.json
```

The report summarizes labeled snippets, useful/safe/wrong/unsafe counts, stale-question failures, fake-entity failures, invalid-command failures, unsupported-monitoring failures, too-generic failures, latency, common blockers, local knowledge gaps, and a recommendation.

For missed-blocker cases, label the output `wrong`, `missed blocker`, or `too generic`. A safe but wrong customer-comms ask when mitigation/rollback/status/validation is visible should be treated as a usefulness failure.

For wrong-target cases, label the output `wrong` and add the closest tag. A reporter/validator should not be asked for technical fix status or RCA when a technical investigator/owner is visible; they should be asked for validation/current symptom results. RCA is premature while validation or mitigation status is unresolved.

For timeout cases, label the run `wrong` or `no useful output` only if it fails to produce a terminal, actionable error. A clean timeout message that asks for a rerun or latest 30-50-message paste is safe but still a product reliability gap to track during the 20-snippet trial.

The simplified runtime should make wrong-output diagnosis easier: Pipeline Progress exposes redacted generated artifacts for normalization, event/noise quality, target extraction, latest-window context packing, `IncidentReadAndWhisper`, verifier, formatting repair, and rendering. Track whether failures start in noisy normalization, target pollution, weak one-call semantic read, verifier block, formatting repair, or render path. Track latency as part of the trial and run the latency smoke when provider health is OK:

```bash
python scripts/run_product_latency_smoke.py \
  --knowledge-dir local_knowledge \
  --output-json .ic_copilot/product_smoke/latency_phase136c.json \
  --output-md .ic_copilot/product_smoke/latency_phase136c.md
```

For fake-target cases, label the output `wrong` plus the nearest failure tag. URL path numbers, Jira IDs, log fragments, table headers, bot placeholders, and generated summary fragments should never become the final person/team/service target. Useful output should route through allowed Slack authors, explicit mentions, catalog teams/services, or current-evidence teams/services.
