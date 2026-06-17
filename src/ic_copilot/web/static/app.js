const stepNames = [
  "input_saved",
  "normalize_input",
  "input_assessment",
  "trigger_decision",
  "product_runtime_config",
  "catalog_lookup",
  "command_registry_load",
  "allowed_targets",
  "latest_window_selection",
  "context_pack",
  "slack_turn_reconstruction",
  "semantic_read",
  "incident_brief",
  "clean_context",
  "state_extraction",
  "state_merge",
  "memory_load",
  "memory_retrieval",
  "applicability_gate",
  "sharp_blocker_assessment",
  "planning",
  "semantic_intent_check",
  "verification",
  "repair",
  "rendering",
  "run_diagnosis",
  "trace_saved",
  "complete",
];

let currentRunId = null;
let currentFinalOutput = "";
let currentError = "";
let currentDebugSummary = "";
let currentProgressEvents = [];
let currentStepArtifacts = {};

function qs(id) {
  return document.getElementById(id);
}

function setMessage(id, text) {
  const element = qs(id);
  if (element) element.textContent = text || "";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function formatValue(value) {
  if (value === null || value === undefined || value === "") return "";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(formatValue).filter(Boolean).join(", ");
  if (typeof value === "object") {
    return (
      value.summary ||
      value.value ||
      value.primary ||
      value.blocker_type ||
      value.current_blocker ||
      value.name ||
      value.display_name ||
      JSON.stringify(value)
    );
  }
  return String(value);
}

function safeUiError(value) {
  const text = String(value || "");
  if (!text) return "";
  if (text.includes("ValidationError") || text.includes("pydantic.dev")) {
    return "Model output did not match the required schema. The run was stopped safely.";
  }
  return text.replace(/https:\/\/errors\.pydantic\.dev\/\S+/g, "").slice(0, 420);
}

function renderDl(id, rows) {
  qs(id).innerHTML = Object.entries(rows)
    .map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(formatValue(value) || "n/a")}</dd>`)
    .join("");
}

function setBadge(id, label, state) {
  const element = qs(id);
  element.textContent = label;
  element.classList.remove("badge-good", "badge-warn", "badge-bad");
  element.classList.add(`badge-${state}`);
}

function artifactChips(summary) {
  return Object.entries(summary || {})
    .slice(0, 8)
    .map(([key, value]) => `<span class="artifact-chip">${escapeHtml(key)}: ${escapeHtml(formatValue(value) || "n/a")}</span>`)
    .join("");
}

function compactArtifactPayload(payload) {
  if (!payload || typeof payload !== "object") return payload;
  const compact = {};
  for (const [key, value] of Object.entries(payload)) {
    if (Array.isArray(value)) {
      compact[key] = value.length > 10 ? [...value.slice(0, 10), `... ${value.length - 10} more`] : value;
    } else if (value && typeof value === "object") {
      const entries = Object.entries(value);
      compact[key] = entries.length > 12 ? Object.fromEntries(entries.slice(0, 12)) : value;
      if (entries.length > 12) compact[key]._truncated = `${entries.length - 12} more keys`;
    } else {
      compact[key] = value;
    }
  }
  return compact;
}

async function fetchArtifact(artifactId) {
  if (!currentRunId) return;
  const response = await fetch(`/api/runs/${currentRunId}/step-artifacts/${artifactId}`);
  if (!response.ok) return;
  const data = await response.json();
  const artifact = data.artifact || {};
  const target = qs(`artifact-details-${artifactId}`);
  if (!target) return;
  target.hidden = !target.hidden;
  if (!target.hidden) {
    target.textContent = JSON.stringify(
      {
        step: artifact.step,
        artifact_type: artifact.artifact_type,
        summary_json: artifact.summary_json,
        warnings: artifact.warnings_json,
        error: artifact.error,
        payload_preview: compactArtifactPayload(artifact.payload_json),
        full_payload_available: true,
      },
      null,
      2,
    );
  }
}

function renderProgress(events = currentProgressEvents, artifactsByStep = currentStepArtifacts) {
  const latest = new Map();
  for (const event of events) latest.set(event.step, event);
  const hasRunning = events.some((event) => event.status === "running");
  const hasFailed = events.some((event) => event.status === "failed");
  qs("progress-details").open = hasRunning || hasFailed;
  qs("progress-list").innerHTML = stepNames
    .map((step) => {
      const event = latest.get(step) || { status: "pending", message: "", elapsed_ms: null };
      const elapsed = event.elapsed_ms === null || event.elapsed_ms === undefined ? "" : `${event.elapsed_ms} ms`;
      const artifacts = artifactsByStep[step] || [];
      const generated = artifacts.length
        ? `<div class="generated-row">
            <span class="generated-label">Generated</span>
            <div class="artifact-chips">${artifacts.map((artifact) => artifactChips(artifact.summary_json)).join("")}</div>
            <div class="artifact-actions">
              ${artifacts
                .map(
                  (artifact) =>
                    `<button type="button" class="artifact-button" data-artifact-id="${escapeHtml(artifact.id)}">View generated data</button>`,
                )
                .join("")}
            </div>
            ${artifacts
              .map((artifact) => `<pre class="artifact-json" id="artifact-details-${escapeHtml(artifact.id)}" hidden></pre>`)
              .join("")}
          </div>`
        : "";
      return `<li>
        <div class="progress-step-row"><span>${step.replaceAll("_", " ")}</span><span class="status-${event.status}">${event.status} ${elapsed}</span></div>
        ${generated}
      </li>`;
    })
    .join("");
  for (const button of document.querySelectorAll("[data-artifact-id]")) {
    button.addEventListener("click", () => fetchArtifact(button.dataset.artifactId));
  }
}

async function loadStepArtifacts(runId) {
  const response = await fetch(`/api/runs/${runId}/step-artifacts`);
  if (!response.ok) return;
  const data = await response.json();
  const grouped = {};
  for (const artifact of data.artifacts || []) {
    if (!grouped[artifact.step]) grouped[artifact.step] = [];
    grouped[artifact.step].push(artifact);
  }
  currentStepArtifacts = grouped;
  renderProgress(currentProgressEvents, currentStepArtifacts);
}

function showJson(id, value) {
  qs(id).textContent = value ? JSON.stringify(value, null, 2) : "";
}

function renderDiagnosisCards(summary) {
  const container = qs("diagnosis-cards");
  if (!container) return;
  const diagnosis = summary.run_diagnosis || {};
  const selected = diagnosis.selected_output || {};
  const openLoop = diagnosis.open_loop_diagnosis || {};
  const evidence = diagnosis.evidence_chain || {};
  const memory = diagnosis.memory_funnel || {};
  const quality = diagnosis.final_output_quality || {};
  const parsing = diagnosis.parsing_quality || summary.parsing_quality || {};
  const verifier = diagnosis.verifier_summary || {};
  const v2 = summary.v2_quality_gate || {};
  const runtimeKnowledgeCounts = summary.runtime_knowledge_counts || {};
  const likelyFailure = parsing.likely_failure_category || quality.likely_failure_category || summary.likely_failure_category || "none";
  const usefulnessStatus =
    v2.usefulness_status || summary.usefulness_status || (likelyFailure !== "none" ? "degraded" : "unknown");

  function list(items, mapper) {
    const rows = (items || []).slice(0, 8).map(mapper).filter(Boolean);
    if (!rows.length) return "<li>none</li>";
    return rows.map((row) => `<li>${row}</li>`).join("");
  }

  container.innerHTML = `
    <div class="diagnosis-card">
      <h3>Why this suggestion?</h3>
      <ul>
        <li>Product path: ${escapeHtml(summary.product_path || v2.product_path || "unknown")}</li>
        <li>Move: ${escapeHtml(selected.move || "unknown")}</li>
        <li>Target: ${escapeHtml((selected.target_display_names || []).join(", ") || "none")}</li>
        <li>V2 blocker: ${escapeHtml(summary.v2_blocker_type || v2.blocker_type || "n/a")}</li>
        <li>Safety: ${escapeHtml(summary.safety_status || v2.safety_status || "unknown")}</li>
        <li>Usefulness: ${escapeHtml(usefulnessStatus)}</li>
        <li>State quality: ${escapeHtml(summary.state_quality_status || v2.state_quality_status || "unknown")}</li>
        <li>Parser quality: ${escapeHtml(summary.parser_quality_status || v2.parser_quality_status || "unknown")}</li>
        <li>Verifier: ${escapeHtml(selected.verifier_status || verifier.status || "unknown")}</li>
        <li>Fallback used: ${selected.fallback_used ? "yes" : "no"}</li>
        <li>Loaded knowledge: services ${escapeHtml(runtimeKnowledgeCounts.services ?? "unknown")} · memories ${escapeHtml(
          runtimeKnowledgeCounts.decision_moments ?? "unknown"
        )}</li>
      </ul>
    </div>
    <div class="diagnosis-card">
      <h3>State-first read</h3>
      <ul>
        <li>IC: ${escapeHtml((summary.v2_state_summary || v2.state_summary || {}).incident_commander || "unknown")}</li>
        <li>Reporter: ${escapeHtml(((summary.v2_state_summary || v2.state_summary || {}).reporters || []).join(", ") || "unknown")}</li>
        <li>Open questions: ${escapeHtml((summary.v2_state_summary || v2.state_summary || {}).open_question_count ?? "unknown")}</li>
        <li>Answered questions: ${escapeHtml((summary.v2_state_summary || v2.state_summary || {}).answered_question_count ?? "unknown")}</li>
        <li>Do-not-ask: ${escapeHtml(((summary.v2_state_summary || v2.state_summary || {}).do_not_ask || []).join(", ") || "none")}</li>
        <li>Target reason: ${escapeHtml(v2.target_reason || "n/a")}</li>
        <li>Rejected targets: ${escapeHtml((v2.rejected_targets || []).map((item) => item.display_name).join(", ") || "none")}</li>
      </ul>
    </div>
    <div class="diagnosis-card">
      <h3>Evidence used</h3>
      <ul>${list(evidence.used_evidence, (item) =>
        `${escapeHtml(item.event_id || "")} ${escapeHtml(item.author || "")}: “${escapeHtml(item.quote || "")}”`
      )}</ul>
    </div>
    <div class="diagnosis-card">
      <h3>Answered questions</h3>
      <ul>${list(openLoop.later_answer_candidates, (item) =>
        `${escapeHtml(item.question_event_id || "")} ${escapeHtml(item.question_intent || "")} answered by ${escapeHtml(
          item.answer_event_id || ""
        )}: “${escapeHtml(item.answer_quote || "")}”`
      )}</ul>
    </div>
    <div class="diagnosis-card">
      <h3>Unresolved questions</h3>
      <ul>${list(openLoop.unresolved_open_loops, (item) =>
        `${escapeHtml(item.question_intent || "")}: ${escapeHtml(item.question_text || "")}`
      )}</ul>
    </div>
    <div class="diagnosis-card">
      <h3>Memory funnel</h3>
      <ul>
        <li>Accepted: ${escapeHtml((memory.accepted || []).map((item) => item.decision_id).join(", ") || "none")}</li>
        <li>Rejected: ${escapeHtml((memory.rejected || []).map((item) => item.decision_id).join(", ") || "none")}</li>
        <li>Possible gaps: ${escapeHtml((memory.possible_semantic_gaps || []).length)}</li>
      </ul>
    </div>
    <div class="diagnosis-card">
      <h3>Verifier checks</h3>
      <ul>${list(verifier.meaningful_checks, (item) =>
        `${escapeHtml(item.check || "")}: ${item.passed ? "pass" : "fail"}`
      )}</ul>
    </div>
    <div class="diagnosis-card">
      <h3>Parsing quality</h3>
      <ul>
        <li>Normalized events: ${escapeHtml(parsing.normalized_event_count ?? "unknown")}</li>
        <li>Recovered humans: ${escapeHtml(parsing.recovered_compact_author_count ?? 0)}</li>
        <li>Recovered examples: ${escapeHtml((parsing.compact_author_recovery_examples || []).join(", ") || "none")}</li>
        <li>Planner-grounding events: ${escapeHtml(parsing.planner_grounding_event_count ?? 0)}</li>
        <li>Human diagnostic events: ${escapeHtml(parsing.human_diagnostic_grounding_count ?? 0)}</li>
        <li>Retained diagnostics: ${escapeHtml((parsing.retained_high_signal_diagnostic_event_ids || []).join(", ") || "none")}</li>
        <li>Dropped diagnostics: ${escapeHtml((parsing.dropped_high_signal_diagnostic_event_ids || []).join(", ") || "none")}</li>
        <li>Likely failing step: ${escapeHtml(likelyFailure)}</li>
      </ul>
    </div>
    <div class="diagnosis-card">
      <h3>Diagnostic facts</h3>
      <ul>${list(parsing.diagnostic_fact_classifications || [], (item) =>
        `${escapeHtml(item.fact_id || "")}: ${escapeHtml(item.category || "")}; target=${item.allowed_for?.target_selection ? "yes" : "no"}, memory=${item.allowed_for?.memory_applicability ? "yes" : "no"}, grounding=${item.allowed_for?.model_grounding ? "yes" : "no"}, no-safe-block=${item.allowed_for?.verifier_no_safe_blocking ? "yes" : "no"}`
      )}</ul>
      <p>Contracts: ${escapeHtml((parsing.diagnostic_behavior_contracts || []).map((item) => item.decision_id).join(", ") || "none")}</p>
      <p>Safe asks: ${escapeHtml((parsing.diagnostic_actionability || []).map((item) => item.contract_id).join(", ") || "none")}</p>
    </div>
    <div class="diagnosis-card">
      <h3>Safe-but-weak diagnosis</h3>
      <ul>
        <li>Safe but weak: ${quality.safe_but_weak ? "yes" : "no"}</li>
        <li>Direct ask: ${quality.direct_ask ? "yes" : "no"}</li>
        <li>Passive owner statement: ${quality.passive_owner_statement ? "yes" : "no"}</li>
        <li>Low-quality owner terms: ${escapeHtml((quality.low_quality_named_owner_terms || []).join(", ") || "none")}</li>
        <li>Move/intent mismatch: ${quality.move_visible_intent_mismatch ? "yes" : "no"}</li>
        <li>Actionability category: ${escapeHtml(quality.actionability_failure_category || "none")}</li>
        <li>No-safe wording: ${escapeHtml(quality.no_safe_wording_quality || "not_applicable")}</li>
        <li>Provider output invalid: ${quality.provider_output_was_invalid ? "yes" : "no"}</li>
        <li>Planner failure: ${escapeHtml(quality.planning_failure_category || "none")}</li>
        <li>Planner reason: ${escapeHtml(quality.provider_output_invalid_reason || "none")}</li>
        <li>Target de-dup applied: ${quality.target_dedup_applied ? "yes" : "no"}</li>
        <li>Move normalized: ${escapeHtml(quality.move_normalized_from || "none")} -> ${escapeHtml(quality.move_normalized_to || "none")}</li>
        <li>Likely failing step: ${escapeHtml(quality.likely_failure_category || "none")}</li>
        <li>V2 quality reasons: ${escapeHtml((v2.failed_reasons || []).join("; ") || "none")}</li>
        <li>Reasons: ${escapeHtml((quality.weakness_reasons || []).join("; ") || "none")}</li>
      </ul>
    </div>
  `;
}

async function loadSamples() {
  const response = await fetch("/api/samples");
  const data = await response.json();
  const select = qs("sample-select");
  for (const sample of data.samples || []) {
    const option = document.createElement("option");
    option.value = sample.path;
    option.textContent = `${sample.source || sample.kind}: ${sample.display_name || sample.name}`;
    select.appendChild(option);
  }
}

function renderKnowledgeStatus(status) {
  const counts = status.counts || {};
  const ready = Boolean(status.passed && status.runtime_usable);
  const label = ready
    ? `Knowledge ready · services ${counts.services ?? 0} · commands ${counts.commands ?? 0} · memories ${
        counts.decision_moments ?? 0
      }`
    : "Knowledge missing";
  setBadge("knowledge-badge", label, ready ? "good" : "warn");
  renderDl("knowledge-status", {
    path: status.path,
    "manifest valid": status.manifest_valid ? "yes" : "no",
    "runtime usable": status.runtime_usable ? "yes" : "no",
    status: ready ? "ready" : "not ready",
    services: counts.services ?? 0,
    commands: counts.commands ?? 0,
    "decision moments": counts.decision_moments ?? 0,
    "verifier regressions": counts.verifier_regressions ?? 0,
    "rejected entities": counts.rejected_entities ?? 0,
    "stale question patterns": counts.stale_question_patterns ?? 0,
  });
  const errors = status.errors || [];
  const warnings = status.warnings || [];
  setMessage("knowledge-message", [...errors, ...warnings].slice(0, 3).join(" ") || "Knowledge folder status loaded.");
}

async function loadRuntimeConfig() {
  const response = await fetch("/api/config");
  const config = await response.json();
  const aiReady = Boolean(config.api_key_present);
  setBadge("ai-badge", aiReady ? `AI ready · ${config.provider}/${config.model}` : "AI setup needed", aiReady ? "good" : "warn");
  setBadge("verifier-badge", config.verifier_required ? "Safety verifier on" : "Safety verifier off", config.verifier_required ? "good" : "bad");
  renderDl("runtime-status", {
    provider: config.provider,
    model: config.model,
    "API key env": config.api_key_env,
    "API key present": config.api_key_present ? "yes" : "no",
    "key fingerprint": config.api_key_fingerprint || "n/a",
    "provider checked": config.api_key_validated_status || "unknown",
    "config path": config.config_path_used || "built-in defaults",
    "verifier required": config.verifier_required ? "yes" : "no",
    "command execution": config.action_execution ? "enabled" : "disabled",
    "Slack posting": config.slack_posting ? "enabled" : "disabled",
    paging: config.paging ? "enabled" : "disabled",
    "runtime knowledge source": config.runtime_knowledge_source || "local_knowledge",
  });
  const warnings = config.setup_warnings || [];
  qs("runtime-setup-warning").textContent = warnings.length
    ? warnings.join(" ")
    : "Configured means a key is present; use Check provider to validate it through the app adapter.";
  renderKnowledgeStatus(config.product_knowledge || {});
}

async function validateKnowledge() {
  setMessage("knowledge-message", "Validating knowledge...");
  const response = await fetch("/api/knowledge/validate", { method: "POST" });
  const data = await response.json();
  const validation = data.validation || {};
  renderKnowledgeStatus({
    ...validation,
    errors: (validation.findings || []).filter((item) => item.severity === "error").map((item) => item.message),
    warnings: (validation.findings || []).filter((item) => item.severity === "warning").map((item) => item.message),
  });
}

async function checkProvider() {
  qs("provider-check-message").textContent = "Checking provider...";
  const response = await fetch("/api/provider/health", { method: "GET" });
  const data = await response.json();
  const health = data.health || {};
  qs("provider-check-message").textContent = `${health.status || "unknown"}: ${health.safe_message || ""}`;
  await loadRuntimeConfig();
}

async function loadRecentRuns() {
  const response = await fetch("/api/runs?limit=20");
  const data = await response.json();
  qs("recent-runs").innerHTML = (data.runs || [])
    .map(
      (run) => `<li>
        <strong>${escapeHtml(run.input_name || run.run_id)}</strong>
        <span class="status-${escapeHtml(run.status)}">${escapeHtml(run.status)}</span>
        <div>${escapeHtml(run.created_at || "")}</div>
        <div>verifier: ${escapeHtml(run.verifier_status || "n/a")}</div>
        <div>${escapeHtml(run.final_output_preview || "")}</div>
        <button type="button" data-load-run="${escapeHtml(run.run_id)}">Load</button>
        <button type="button" data-delete-run="${escapeHtml(run.run_id)}">Delete</button>
      </li>`,
    )
    .join("");
  for (const button of document.querySelectorAll("[data-load-run]")) {
    button.addEventListener("click", () => {
      currentRunId = button.dataset.loadRun;
      loadRun(currentRunId);
    });
  }
  for (const button of document.querySelectorAll("[data-delete-run]")) {
    button.addEventListener("click", async () => {
      await fetch(`/api/runs/${button.dataset.deleteRun}`, { method: "DELETE" });
      await loadRecentRuns();
    });
  }
}

function requestBody() {
  return {
    pasted_text: qs("incident-text").value,
    sample_path: qs("sample-select").value || null,
    save_trace: qs("save-trace").checked,
  };
}

function clearOutput() {
  currentFinalOutput = "";
  currentError = "";
  currentProgressEvents = [];
  currentStepArtifacts = {};
  qs("say-this").textContent = "";
  qs("next-line").textContent = "";
  qs("command-output").textContent = "";
  qs("copy-output").disabled = true;
  qs("copy-output").textContent = "Copy full output";
  qs("copy-output").hidden = false;
  qs("copy-error").disabled = true;
  qs("copy-error").textContent = "Copy error summary";
  qs("copy-error").hidden = true;
}

async function startRun() {
  qs("run-button").disabled = true;
  qs("progress-details").open = true;
  setMessage("run-message", "Starting run...");
  clearOutput();
  renderProgress();
  const file = qs("file-input").files[0];
  let response;
  if (file) {
    const form = new FormData();
    form.append("file", file);
    form.append("save_trace", qs("save-trace").checked);
    response = await fetch("/api/runs/upload", { method: "POST", body: form });
  } else {
    response = await fetch("/api/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestBody()),
    });
  }
  if (!response.ok) {
    currentError = safeUiError(await response.text());
    setMessage("run-message", currentError);
    qs("copy-error").disabled = false;
    qs("copy-error").hidden = false;
    qs("copy-output").disabled = true;
    qs("copy-output").hidden = true;
    qs("run-button").disabled = false;
    return;
  }
  const data = await response.json();
  currentRunId = data.run_id;
  setMessage("run-message", `Run ${currentRunId} started.`);
  watchEvents(currentRunId);
  await loadRecentRuns();
}

function watchEvents(runId) {
  const events = [];
  const source = new EventSource(`/api/runs/${runId}/events`);
  source.addEventListener("step", (message) => {
    events.push(JSON.parse(message.data));
    currentProgressEvents = events;
    renderProgress(currentProgressEvents, currentStepArtifacts);
    loadStepArtifacts(runId);
  });
  source.addEventListener("complete", async () => {
    source.close();
    await loadRun(runId);
    qs("run-button").disabled = false;
  });
  source.addEventListener("error", async () => {
    source.close();
    await loadRun(runId);
    qs("run-button").disabled = false;
  });
}

async function loadRun(runId) {
  const response = await fetch(`/api/runs/${runId}`);
  const data = await response.json();
  const stepsResponse = await fetch(`/api/runs/${runId}/steps`);
  if (stepsResponse.ok) {
    const stepsData = await stepsResponse.json();
    currentProgressEvents = stepsData.steps || [];
    currentStepArtifacts = stepsData.artifacts_by_step || {};
    renderProgress(currentProgressEvents, currentStepArtifacts);
  }
  if (data.run?.error) {
    currentError = safeUiError(data.run.error);
    setMessage("run-message", currentError);
    qs("copy-error").disabled = false;
    qs("copy-error").hidden = false;
    qs("copy-output").disabled = true;
    qs("copy-output").hidden = true;
    qs("progress-details").open = true;
  }
  qs("total-runtime").textContent = data.run?.total_elapsed_ms
    ? `Total runtime: ${data.run.total_elapsed_ms} ms`
    : `Status: ${data.run?.status || "unknown"}`;
  if (!data.result) {
    await loadDebugSummary(runId);
    await loadRecentRuns();
    return;
  }
  const result = data.result;
  currentFinalOutput = result.final_output || "";
  qs("copy-output").disabled = !currentFinalOutput;
  qs("copy-output").hidden = !currentFinalOutput;
  qs("copy-error").disabled = true;
  qs("copy-error").hidden = true;
  qs("say-this").textContent = result.say_this || "";
  qs("next-line").textContent = result.next_line || "";
  qs("command-output").textContent = result.command || "";
  const doNotAsk = result.do_not_ask || [];
  qs("do-not-ask").innerHTML = doNotAsk.length
    ? doNotAsk.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
    : result.fallback_used
      ? "<li>Review original verifier claims in Why; fallback was used.</li>"
      : "<li>No stale questions shown for the rendered whisper</li>";
  qs("why-list").innerHTML = Object.entries(result.why || {})
    .map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(formatValue(value) || "none")}</dd>`)
    .join("");
  qs("why-details").open = Boolean(result.fallback_used || result.verifier_status === "fallback_required");
  await loadTrace(runId);
  await loadDebugSummary(runId);
  await loadRecentRuns();
}

async function loadTrace(runId) {
  const response = await fetch(`/api/runs/${runId}/trace`);
  if (!response.ok) return;
  const trace = await response.json();
  showJson("trace-json", trace);
  showJson("normalized-events", trace.input_event_ids);
  showJson("current-state", trace.current_state);
  showJson("verifier-result", trace.verifier_result);
}

async function loadDebugSummary(runId) {
  const response = await fetch(`/api/runs/${runId}/debug-summary`);
  if (!response.ok) return;
  const summary = await response.json();
  currentDebugSummary = JSON.stringify(summary, null, 2);
  renderDiagnosisCards(summary);
  qs("debug-summary").textContent = currentDebugSummary;
}

async function saveFeedback() {
  if (!currentRunId) return setMessage("feedback-message", "Run something first.");
  const usefulness = document.querySelector("input[name='usefulness']:checked")?.value || "safe_but_generic";
  const failure_tags = [...document.querySelectorAll(".tags input:checked")].map((item) => item.value);
  const response = await fetch(`/api/runs/${currentRunId}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      usefulness,
      failure_tags,
      reviewer_notes: qs("feedback-notes").value,
    }),
  });
  const data = await response.json();
  setMessage("feedback-message", response.ok ? `Saved ${data.label_id}` : JSON.stringify(data));
}

function setupTabs() {
  for (const button of document.querySelectorAll(".tab-button")) {
    button.addEventListener("click", () => {
      document.querySelectorAll(".tab-button").forEach((item) => item.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      qs(button.dataset.tab).classList.add("active");
    });
  }
}

qs("run-button").addEventListener("click", startRun);
qs("copy-output").addEventListener("click", () => navigator.clipboard.writeText(currentFinalOutput));
qs("copy-error").addEventListener("click", () => navigator.clipboard.writeText(currentError));
qs("copy-debug-summary").addEventListener("click", () => navigator.clipboard.writeText(currentDebugSummary));
qs("check-provider").addEventListener("click", checkProvider);
qs("validate-knowledge").addEventListener("click", validateKnowledge);
qs("download-trace").addEventListener("click", () => {
  if (currentRunId) window.location = `/api/runs/${currentRunId}/download-trace`;
});
qs("download-input").addEventListener("click", () => {
  if (currentRunId) window.location = `/api/runs/${currentRunId}/download-input`;
});
qs("delete-run").addEventListener("click", async () => {
  if (!currentRunId) return;
  await fetch(`/api/runs/${currentRunId}`, { method: "DELETE" });
  currentRunId = null;
  setMessage("run-message", "Deleted local run.");
  await loadRecentRuns();
});
qs("save-feedback").addEventListener("click", saveFeedback);
qs("export-feedback").addEventListener("click", () => {
  window.location = "/api/feedback/export?format=jsonl";
});
qs("refresh-runs").addEventListener("click", loadRecentRuns);
qs("delete-all-runs").addEventListener("click", async () => {
  if (!confirm("Delete all local web runs and web input files?")) return;
  await fetch("/api/runs?confirm=true", { method: "DELETE" });
  currentRunId = null;
  await loadRecentRuns();
});

renderProgress();
setupTabs();
loadRuntimeConfig();
loadSamples();
loadRecentRuns();
