from __future__ import annotations

import json
import re
import time
from typing import Any, TypeVar

from pydantic import BaseModel

from ic_copilot.error_sanitizer import (
    classify_provider_error,
    extract_safe_request_id,
    provider_safe_message,
    sanitize_provider_error,
)
from ic_copilot.llm import prompts
from ic_copilot.llm.config import LLMConfig
from ic_copilot.llm.redaction import redact_for_llm
from ic_copilot.schema_repair import validate_with_repair


ModelT = TypeVar("ModelT", bound=BaseModel)


class ProviderJSONError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        provider: str | None = None,
        model: str | None = None,
        error_type: str | None = None,
        request_id: str | None = None,
        raw_error_redacted: str | None = None,
    ) -> None:
        self.provider = provider
        self.model = model
        self.error_type = error_type or classify_provider_error(message)
        self.request_id = request_id or extract_safe_request_id(message)
        self.raw_error_redacted = raw_error_redacted or sanitize_provider_error(message)
        safe_message = (
            provider_safe_message(provider, message)
            if provider
            else sanitize_provider_error(message)
        )
        self.safe_message = safe_message
        super().__init__(safe_message)


class BaseJSONProviderClient:
    def __init__(self, config: LLMConfig, transport: Any | None = None) -> None:
        self.config = config
        self.transport = transport
        self.last_response_metadata: dict[str, Any] = {}

    def _prompt_contract(self, prompt_name: str) -> str:
        if self.config.prompt_overrides.get(prompt_name):
            return self.config.prompt_overrides[prompt_name]
        mapping = {
            "slack_turn_reconstruction": prompts.SLACK_TURN_RECONSTRUCTION_PROMPT,
            "clean_turn_ledger": prompts.CLEAN_TURN_LEDGER_PROMPT,
            "actor_workstream_ledger": prompts.ACTOR_WORKSTREAM_LEDGER_PROMPT,
            "incident_fact_ledger": prompts.INCIDENT_FACT_LEDGER_PROMPT,
            "question_intent_ledger": prompts.QUESTION_INTENT_LEDGER_PROMPT,
            "incident_read_and_whisper": prompts.INCIDENT_READ_AND_WHISPER_PROMPT,
            "incident_read_and_whisper_v2": prompts.INCIDENT_READ_AND_WHISPER_V2_PROMPT,
            "incident_brief_extractor": prompts.INCIDENT_BRIEF_PROMPT,
            "clean_incident_context_extractor": prompts.CLEAN_INCIDENT_CONTEXT_PROMPT,
            "state_delta_extractor": prompts.STATE_DELTA_EXTRACTOR_PROMPT,
            "sharp_blocker_assessment": prompts.SHARP_BLOCKER_ASSESSMENT_PROMPT,
            "ic_planner": prompts.IC_PLANNER_PROMPT,
            "memory_applicability": prompts.MEMORY_APPLICABILITY_PROMPT,
            "verifier_repair": prompts.VERIFIER_REPAIR_PROMPT,
            "semantic_intent_assessment": prompts.SEMANTIC_INTENT_ASSESSMENT_PROMPT,
        }
        return mapping.get(prompt_name, "")

    def _request_payload(
        self,
        prompt_name: str,
        input_payload: dict[str, Any],
        response_model: type[BaseModel],
    ) -> dict[str, Any]:
        payload = input_payload
        if self.config.redact_payload:
            payload = redact_for_llm(input_payload)
        return {
            "prompt_name": prompt_name,
            "prompt_contract": self._prompt_contract(prompt_name),
            "input_payload": payload,
            "response_schema": response_model.model_json_schema(),
            "model": self.config.model,
            "temperature": self.config.temperature,
        }

    def _schema_name(self, response_model: type[BaseModel]) -> str:
        return re.sub(r"[^A-Za-z0-9_-]", "_", response_model.__name__)[:64]

    def _schema_format(self, response_model: type[BaseModel], *, strict: bool = True) -> dict[str, Any]:
        schema = response_model.model_json_schema()
        if "$ref" in schema and "$defs" in schema:
            ref_name = str(schema["$ref"]).split("/")[-1]
            if ref_name in schema["$defs"]:
                schema = {"$defs": schema["$defs"], **schema["$defs"][ref_name]}
        return {
            "type": "json_schema",
            "name": self._schema_name(response_model),
            "schema": schema,
            "strict": strict,
        }

    def _messages_for_prompt(
        self,
        prompt_name: str,
        input_payload: dict[str, Any],
        response_model: type[BaseModel],
    ) -> list[dict[str, str]]:
        payload = input_payload
        if self.config.redact_payload:
            payload = redact_for_llm(input_payload)
        system_prompt = "\n\n".join(
            part.strip()
            for part in [
                self._prompt_contract(prompt_name),
                self._provider_contract(prompt_name, response_model),
            ]
            if part.strip()
        )
        user_payload = {
            "prompt_name": prompt_name,
            "response_model": response_model.__name__,
            "input_payload": payload,
            "instruction": "Return exactly one JSON object matching the requested schema.",
        }
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False, sort_keys=True)},
        ]

    def _provider_contract(self, prompt_name: str, response_model: type[BaseModel]) -> str:
        common = [
            "You are running inside a local, manual-copy IC Copilot product path.",
            "Do not execute tools, call web search, call file search, post to Slack, page anyone, or remediate systems.",
            "Commands are human-approved text suggestions only.",
            f"Your output must validate as {response_model.__name__}.",
        ]
        if prompt_name == "slack_turn_reconstruction":
            common.extend(
                [
                    "Reconstruct speaker turns only; do not infer incident facts.",
                    "Preserve source event IDs and mark uncertainty.",
                    "Do not invent speakers, customers, tenants, teams, commands, or impact.",
                ]
            )
        if prompt_name in {
            "clean_turn_ledger",
            "actor_workstream_ledger",
            "incident_fact_ledger",
            "question_intent_ledger",
        }:
            common.extend(
                [
                    "This is a typed semantic read inside the product pipeline, not a tool call or action.",
                    "Use only current event evidence and preserve event IDs.",
                    "Unknown is allowed and safer than guessing.",
                    "Do not infer customers from URL domains or tenants from URL path numbers.",
                    "Do not turn bot/system placeholders, logs, tables, ticket IDs, or URL fragments into targetable entities.",
                ]
            )
        if prompt_name in {"clean_incident_context_extractor", "state_delta_extractor"}:
            common.extend(
                [
                    "Extract facts only from current incident evidence and CurrentIncidentState.",
                    "Every fact must cite event IDs when evidence exists.",
                    "Unknown is allowed and safer than guessing.",
                    "Do not infer customers from URLs.",
                    "Do not infer tenants from URL path numbers.",
                    "Do not create people from pasted display-name fragments.",
                    "Do not treat bot/system lifecycle messages as human commands.",
                ]
            )
        if prompt_name == "incident_brief_extractor":
            common.extend(
                [
                    "Produce one IncidentBrief, not final user-facing output.",
                    "Use only normalized events, latest high-signal events, and allowed target IDs.",
                    "Do not invent target names; role candidates and preferred targets must reference allowed_targets.",
                    "Latest human or technical evidence supersedes earlier bot/system summaries when they conflict.",
                    "Do not infer customers from URL domains or tenants from URL path numbers.",
                ]
            )
        if prompt_name == "incident_read_and_whisper":
            common.extend(
                [
                    "Output exactly one IncidentReadAndWhisper.",
                    "AI is responsible for semantic IC judgment; deterministic code will verify safety and grounding.",
                    "Use latest human/operator evidence before older bot summaries and preview cards.",
                    "selected_target_id must be null or from candidate_targets.",
                    "candidate_targets is canonicalized; use the shown canonical target ID for a chosen target.",
                    "Use current_work_items as explicit owner/action evidence; ask the listed owner for that work item.",
                    "current_work_items may come from Owner rows or rows like 'Label: @person is checking...' / 'Label: team will monitor...'.",
                    "For permission-blocked command attempts, ask for owner/path/scope/topic validation; do not ask anyone to run, execute, perform, or move a tenant/topic.",
                    "Do not target a person whose latest relevant evidence only says they lack permission for that action.",
                    "Do not expose raw tenant/account IDs or redacted tenant placeholders in visible output.",
                    "Do not reopen an older generic status/Zoom recap ask after a later human incident update provides Current Status, Findings, or Next Steps.",
                    "Do not ask one owner for another work item's action unless current evidence says they coordinate it.",
                    "Separate need-by/deadline clarification from implementation ETA/status/feasibility; do not mix owners.",
                    "already_answered contains only questions answered by later current evidence; it must not repeat latest_open_loop.",
                    "do_not_target IDs may be grounded facts but are not selectable targets.",
                    "Use concise Slack-copyable direct address; @handle is fine for handle-like one-token targets.",
                    "Copy evidence quotes exactly from latest_window_events text; do not paraphrase evidence quotes.",
                    "A useful SAY THIS may stand alone; NEXT LINE is optional.",
                    "Do not put command-like text in SAY THIS or NEXT LINE.",
                    "Preserve safe grounded terms like DataConnectSalesforceSync, DACO, dedicated topic, shard, topic, bottleneck, and permission-blocked when relevant.",
                    "Do not infer customers from URL domains or tenants/accounts from URL path numbers or ticket IDs.",
                    "Do not suggest posting, paging, execution, or remediation.",
                ]
            )
        if prompt_name == "incident_read_and_whisper_v2":
            common.extend(
                [
                    "Output exactly one IncidentReadAndWhisperV2.",
                    "This is the normal state-first product path: incident_state, then next_blocker, then whisper.",
                    "AI is responsible for semantic IC judgment; deterministic code verifies safety, grounding, and usefulness.",
                    "Use current evidence as authoritative; behavior hints are secondary patterns only.",
                    "Do not ask the asker to answer their own question unless the evidence clearly makes them the answer source.",
                    "Do not target pseudo-authors, bot/system actors, preview-card labels, file labels, URLs, IDs, logs, or headings.",
                    "Do not use broad catalog targets unless the service/team is directly present in current evidence.",
                    "Do not output command text; command must be null.",
                    "Do not suggest posting, paging, execution, or remediation.",
                    "Evidence quotes must be copied exactly from event text.",
                    "For next_blocker.blocker_type, use canonical schema values such as missing_owner, awaiting_service_owner_status, awaiting_validation_signal, missing_impact_scope, or no_safe_next_move.",
                    "If evidence shows owner/routing/engagement uncertainty, use missing_owner or awaiting_service_owner_status, not a new blocker type.",
                    "If accepted behavior hints plus current evidence support a safe direct ask, do not choose no_safe_recommendation.",
                    "For early deployment/version-mismatch routing, ask the current coordinator, Support path, or visible owner/support team to confirm ownership or engagement; do not wait for late-stage remediation/rerun evidence.",
                ]
            )
        if prompt_name == "sharp_blocker_assessment":
            common.extend(
                [
                    "Identify the sharpest IC blocker, not root cause.",
                    "Use CleanIncidentContext and CurrentIncidentState only.",
                    "Prefer mitigation, rollback, disablement, cleanup, status, ETA, and validation blockers when visible.",
                    "Classify role candidates so reporters/validators are not asked for technical fix status.",
                    "Do not turn shell snippets or rollback/disable discussions into command suggestions.",
                    "Unknown is safer than inventing owners, customers, tenants, impact, or completion.",
                ]
            )
        if prompt_name == "semantic_intent_assessment":
            common.extend(
                [
                    "Classify candidate output intent semantically.",
                    "Stale paraphrase findings can only add blocks or repair directions.",
                    "Never bypass deterministic safety checks.",
                    "Do not treat owner, exposure scope, containment, mitigation, status, or validation asks as stale raw-details asks.",
                ]
            )
        if prompt_name == "ic_planner":
            common.extend(
                [
                    "Output exactly one ICDecision.",
                    "Current facts may only come from current_state or current evidence.",
                    "Catalog/tool facts may only come from catalog matches and command registry facts.",
                    "Historical incidents provide behavior patterns, not current facts.",
                    "Do not leak historical customer, tenant, Jira, account, or environment facts.",
                    "Do not ask stale questions.",
                    "If current_state says a target is suggested_but_not_engaged, do not ask whether that target is looped in or already engaged; ask the target directly to confirm ownership or next validation.",
                    "If current_state says a target is already engaged or actively working, do not ask to engage or page that target again.",
                    "Do not prefix team/person targets with @ in SAY THIS or NEXT LINE; use plain names unless an exact approved registry command is in the command field.",
                    "Do not put command-like text in SAY THIS or NEXT LINE.",
                    "Keep the IC whisper short.",
                ]
            )
        return "\n".join(f"- {line}" for line in common)

    def _loads_json(self, value: Any) -> Any:
        if isinstance(value, dict):
            return value
        if isinstance(value, BaseModel):
            return value.model_dump()
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError as exc:
                raise ProviderJSONError(f"Provider returned invalid JSON: {exc}") from exc
        raise ProviderJSONError(f"Provider returned unsupported JSON container: {type(value).__name__}")

    def _extract_object(self, raw: Any) -> dict[str, Any]:
        data = self._loads_json(raw)
        if not isinstance(data, dict):
            raise ProviderJSONError("Provider JSON response is not an object")
        for key in ("output", "json", "data"):
            if isinstance(data.get(key), dict):
                return data[key]
        return data

    def _validate(self, raw: Any, response_model: type[ModelT]) -> ModelT:
        return validate_with_repair(self._extract_object(raw), response_model, context="provider_json")

    def _latency_ms(self, started: float) -> int:
        return int((time.perf_counter() - started) * 1000)

    def _extract_usage(self, response: Any) -> dict[str, Any]:
        usage = getattr(response, "usage", None)
        if usage is None and isinstance(response, dict):
            usage = response.get("usage") or response.get("raw_usage")
        if usage is None:
            return {}
        if isinstance(usage, dict):
            return dict(usage)
        if isinstance(usage, BaseModel):
            return usage.model_dump(mode="json")
        if hasattr(usage, "model_dump"):
            return usage.model_dump()
        if hasattr(usage, "__dict__"):
            return {key: value for key, value in vars(usage).items() if not key.startswith("_")}
        return {}

    def _extract_model_response_id(self, response: Any) -> str | None:
        response_id = getattr(response, "id", None)
        if response_id is None and isinstance(response, dict):
            response_id = response.get("id") or response.get("provider_response_id")
        return str(response_id) if response_id else None

    def _extract_model_used(self, response: Any) -> str | None:
        model = getattr(response, "model", None)
        if model is None and isinstance(response, dict):
            model = response.get("model") or response.get("model_used")
        return str(model) if model else None

    def _record_response_metadata(self, response: Any) -> None:
        usage = self._extract_usage(response)
        self.last_response_metadata = {
            "provider_response_id": self._extract_model_response_id(response),
            "model_used": self._extract_model_used(response),
            "raw_usage": usage,
            "input_tokens": usage.get("input_tokens")
            or usage.get("prompt_tokens")
            or usage.get("input_token_count"),
            "output_tokens": usage.get("output_tokens")
            or usage.get("completion_tokens")
            or usage.get("output_token_count"),
            "total_tokens": usage.get("total_tokens") or usage.get("total_token_count"),
        }
