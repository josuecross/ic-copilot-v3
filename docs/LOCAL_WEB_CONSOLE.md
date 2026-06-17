# Local Web Console

Current phase: simplified `IncidentReadAndWhisper` runtime.

Start:

```bash
python scripts/run_local_web.py
```

The server binds to `127.0.0.1` by default.

The UI is intentionally small:

- readiness badges for AI, knowledge, and verifier
- paste/upload/sample input
- run button
- IC Whisper Output
- compact Pipeline Progress with generated step summaries
- Do Not Ask / Why
- feedback labels and notes
- Recent Runs
- Advanced Details collapsed by default

The console does not edit runtime knowledge. Review incident-derived knowledge outside the app, write it into `local_knowledge/`, run `validate-knowledge`, then use the console.

Main output is manual-copy only. The app never posts to Slack, pages, executes commands, writes to incident systems, or remediates.

Long Slack pastes should not leave the UI pending forever. The backend records normalized event counts immediately, uses deterministic size assessment, selects and packs a latest high-signal window, calls `IncidentReadAndWhisper`, and marks provider timeouts terminally with a concise message. If a timeout repeats, paste the latest 30-50 messages around the current blocker as a temporary workaround.

Pipeline Progress shows local generated artifacts for product audit: normalized event counts, event/noise quality, input-size assessment, latest-window selection, allowed target quality, context pack summary, `IncidentReadAndWhisper`, verifier result, formatting repair summary, and rendered output summary. Use “View generated data” for compact redacted JSON. This is not curation, review, promotion, calibration, or knowledge editing.

Debug / Advanced shows normalized event count, latest-window event IDs, context pack summary, candidate targets, rejected targets, selected target ID, current read, latest open loop, timeout stage, legacy/debug-only status for old stages, and verifier checks. The main page stays compact.
