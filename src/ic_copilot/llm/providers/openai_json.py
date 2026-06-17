from __future__ import annotations

import importlib
import json
import os
import urllib.error
import urllib.request
from typing import Any
from typing import TypeVar

from pydantic import BaseModel, ConfigDict, Field

from ic_copilot.env import maybe_load_local_env
from ic_copilot.error_sanitizer import classify_provider_error, extract_safe_request_id, sanitize_provider_error
from ic_copilot.llm.config import LLMConfig
from ic_copilot.llm.providers.base_json import BaseJSONProviderClient, ProviderJSONError
from ic_copilot.schema_repair import (
    repair_ic_decision_payload,
    repair_state_delta_payload,
    validate_with_repair,
)
from ic_copilot.schemas import (
    ActionRecord,
    CommandCandidate,
    EntityRef,
    EvidenceBackedFact,
    ICDecision,
    ImpactState,
    IncidentBrief,
    IncidentBriefBlocker,
    IncidentBriefDoNotAsk,
    IncidentBriefFocus,
    IncidentBriefRoleCandidate,
    IncidentBriefValue,
    IncidentBriefWorkstream,
    IncidentPhase,
    LinkRef,
    QuestionRecord,
    StateDelta,
)


ModelT = TypeVar("ModelT", bound=BaseModel)
DEFAULT_OPENAI_SHADOW_MODEL = "gpt-4.1-mini"


class OpenAIEvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    quote: str
    source: str
    confidence: float = Field(ge=0.0, le=1.0)


class OpenAIEntityRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: str
    display_name: str
    canonical_id: str = ""
    status: str = "mentioned"
    evidence: list[OpenAIEvidenceRef] = Field(default_factory=list)
    confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    source: str = "current_evidence"


class OpenAIStateDeltaOutput(BaseModel):
    """Provider-facing StateDelta wrapper.

    Some live models include CurrentIncidentState bookkeeping fields such as
    updated_at/state_version. Those fields are not current facts and are
    intentionally ignored here before validating against the strict runtime
    StateDelta schema.
    """

    model_config = ConfigDict(extra="ignore")

    incident_id: str
    source_progress: dict[str, Any] = Field(default_factory=dict)
    severity: EvidenceBackedFact | None = None
    phase: IncidentPhase | None = None
    impact: ImpactState | None = None
    candidate_services: list[EntityRef] = Field(default_factory=list)
    engaged_entities: list[EntityRef] = Field(default_factory=list)
    suggested_but_not_engaged: list[EntityRef] = Field(default_factory=list)
    actions_completed: list[ActionRecord] = Field(default_factory=list)
    open_questions: list[QuestionRecord] = Field(default_factory=list)
    answered_questions: list[QuestionRecord] = Field(default_factory=list)
    stale_question_intents: list[str] = Field(default_factory=list)
    current_blocker: str | None = None
    monitoring_signals: list[EvidenceBackedFact] = Field(default_factory=list)
    commands_seen: list[CommandCandidate] = Field(default_factory=list)
    links_seen: list[LinkRef] = Field(default_factory=list)
    rejected_entities: list[EntityRef] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    safety_flags: list[str] = Field(default_factory=list)
    compact_summary: str = ""


class OpenAIICDecisionOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    decision_id: str
    incident_id: str
    move: str
    phase: str
    domain_intent: str | None = None
    model_metadata: dict[str, Any] = Field(default_factory=dict)
    say_this: str
    next_line: str = ""
    command: str = ""
    target_ids: list[str] = Field(default_factory=list)
    targets: list[OpenAIEntityRef] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
    grounding: list[OpenAIEvidenceRef] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    expiration: str = "PT15M"


class OpenAIIncidentBriefOutput(BaseModel):
    """Provider-facing IncidentBrief shape.

    The product still validates into the strict IncidentBrief schema. This smaller
    shape avoids asking the live provider to populate every debug-oriented list
    when the planner only needs the current summary, blocker, roles, and focus.
    """

    model_config = ConfigDict(extra="ignore")

    schema_version: str = "1.0"
    incident_id: str
    based_on_event_ids: list[str] = Field(default_factory=list)
    latest_window_event_ids: list[str] = Field(default_factory=list)
    full_context_used: bool = True
    latest_window_used: bool = False
    partial_context: bool = False
    current_summary: str = ""
    phase: IncidentBriefValue = Field(default_factory=IncidentBriefValue)
    latest_blocker: IncidentBriefBlocker = Field(default_factory=IncidentBriefBlocker)
    active_workstreams: list[IncidentBriefWorkstream] = Field(default_factory=list)
    role_candidates: list[IncidentBriefRoleCandidate] = Field(default_factory=list)
    do_not_ask: list[IncidentBriefDoNotAsk] = Field(default_factory=list)
    recommended_ic_focus: IncidentBriefFocus = Field(default_factory=IncidentBriefFocus)
    warnings: list[str] = Field(default_factory=list)


class OpenAIJSONClient(BaseJSONProviderClient):
    def __init__(self, config: LLMConfig, transport=None) -> None:
        super().__init__(config, transport)
        maybe_load_local_env()
        self.api_key_env = config.api_key_env or "OPENAI_API_KEY"
        if transport is None and not os.environ.get(self.api_key_env):
            raise RuntimeError(f"Missing API key environment variable: {self.api_key_env}")

    def _model(self) -> str:
        return self.config.model or DEFAULT_OPENAI_SHADOW_MODEL

    def _provider_response_model(self, response_model: type[ModelT]) -> type[BaseModel]:
        if response_model is StateDelta:
            return OpenAIStateDeltaOutput
        if response_model is ICDecision:
            return OpenAIICDecisionOutput
        if response_model is IncidentBrief:
            return OpenAIIncidentBriefOutput
        return response_model

    def _request(
        self,
        prompt_name: str,
        input_payload: dict,
        response_model: type[BaseModel],
        *,
        strict: bool = True,
    ) -> dict[str, Any]:
        schema_model = self._provider_response_model(response_model)
        return {
            "model": self._model(),
            "input": self._messages_for_prompt(prompt_name, input_payload, schema_model),
            "temperature": self.config.temperature,
            "text": {"format": self._schema_format(schema_model, strict=strict)},
        }

    def _validate_transport_response(self, raw: Any, response_model: type[ModelT]) -> ModelT:
        self._record_response_metadata(raw)
        return self._validate_openai_output(raw, response_model)

    def _convert_provider_model(self, value: BaseModel, response_model: type[ModelT]) -> ModelT:
        if response_model is StateDelta and isinstance(value, OpenAIStateDeltaOutput):
            return validate_with_repair(
                value.model_dump(mode="json"),
                response_model,
                context="openai_state_delta",
            )
        if response_model is ICDecision and isinstance(value, OpenAIICDecisionOutput):
            output = {"say_this": value.say_this}
            if value.next_line.strip():
                output["next_line"] = value.next_line
            if value.command.strip():
                output["command"] = value.command
            payload = {
                "decision_id": value.decision_id,
                "incident_id": value.incident_id,
                "move": value.move,
                "phase": value.phase,
                "domain_intent": value.domain_intent,
                "model_metadata": value.model_metadata,
                "output": output,
                "target_ids": value.target_ids,
                "targets": [target.model_dump() for target in value.targets],
                "rationale": value.rationale,
                "grounding": [item.model_dump() for item in value.grounding],
                "confidence": value.confidence,
                "expiration": value.expiration,
            }
            return validate_with_repair(payload, response_model, context="openai_ic_decision")
        if response_model is IncidentBrief and isinstance(value, OpenAIIncidentBriefOutput):
            return validate_with_repair(
                value.model_dump(mode="json"),
                response_model,
                context="openai_incident_brief",
            )
        return validate_with_repair(value, response_model, context="openai_provider_model")

    def _decision_from_normalized_obj(self, obj: dict[str, Any]) -> ICDecision:
        shim = OpenAIICDecisionOutput.model_construct(
            decision_id=str(obj.get("decision_id")),
            incident_id=str(obj.get("incident_id")),
            move=str(obj.get("move")),
            phase=str(obj.get("phase")),
            domain_intent=obj.get("domain_intent"),
            model_metadata=dict(obj.get("model_metadata") or {}),
            say_this=str(obj.get("say_this")),
            next_line=str(obj.get("next_line") or ""),
            command=str(obj.get("command") or ""),
            target_ids=[str(item) for item in obj.get("target_ids", []) if item],
            targets=[
                OpenAIEntityRef.model_validate(target)
                for target in obj.get("targets", [])
                if isinstance(target, dict)
            ],
            rationale=[str(item) for item in obj.get("rationale", [])],
            grounding=[
                OpenAIEvidenceRef.model_validate(item)
                for item in obj.get("grounding", [])
                if isinstance(item, dict)
            ],
            confidence=float(obj.get("confidence") or 0.5),
            expiration=str(obj.get("expiration") or "PT15M"),
        )
        return self._convert_provider_model(shim, ICDecision)

    def _normalize_openai_decision_obj(self, obj: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(obj)
        output = normalized.get("output")
        if isinstance(output, dict):
            normalized.setdefault("say_this", output.get("say_this") or output.get("message") or "")
            normalized.setdefault("next_line", output.get("next_line") or "")
            normalized.setdefault("command", output.get("command") or "")
        if "message" in normalized and "say_this" not in normalized:
            normalized["say_this"] = normalized["message"]
        normalized.setdefault("decision_id", f"openai-{normalized.get('incident_id', 'unknown')}")
        normalized.setdefault("incident_id", "unknown")
        normalized.setdefault("move", "no_safe_recommendation")
        normalized.setdefault("phase", "unknown")
        normalized.setdefault("domain_intent", None)
        normalized.setdefault("model_metadata", {})
        normalized.setdefault("say_this", "I do not have a safe, grounded next move yet.")
        normalized.setdefault("next_line", "")
        normalized.setdefault("command", "")
        targets = normalized.get("targets")
        if isinstance(targets, list):
            normalized["targets"] = [
                {
                    "entity_type": "team",
                    "display_name": str(
                        item.get("display_name")
                        or item.get("name")
                        or item.get("target")
                        or item.get("canonical_name")
                        or item
                    ),
                    "canonical_id": str(item.get("canonical_id") or item.get("id") or ""),
                    "status": str(item.get("status") or "mentioned"),
                    "evidence": [
                        ev
                        for ev in item.get("evidence", [])
                        if isinstance(ev, dict) and ev.get("event_id")
                    ],
                    "confidence": float(item.get("confidence") or 0.5),
                    "source": str(item.get("source") or "current_evidence"),
                }
                if isinstance(item, dict)
                else {
                    "entity_type": "team",
                    "display_name": str(item),
                    "canonical_id": "",
                    "status": "mentioned",
                    "evidence": [],
                    "confidence": 0.5,
                    "source": "current_evidence",
                }
                for item in targets
            ]
        else:
            normalized["targets"] = []
        target_ids = normalized.get("target_ids")
        if isinstance(target_ids, list):
            normalized["target_ids"] = [str(item) for item in target_ids if item]
        else:
            normalized["target_ids"] = []
        rationale = normalized.get("rationale")
        if isinstance(rationale, str):
            normalized["rationale"] = [rationale]
        elif not isinstance(rationale, list):
            normalized["rationale"] = []
        grounding = normalized.get("grounding")
        if isinstance(grounding, list):
            normalized["grounding"] = [
                {
                    "event_id": str(item.get("event_id")),
                    "quote": str(item.get("quote") or ""),
                    "source": str(item.get("source") or "slack"),
                    "confidence": float(item.get("confidence") or 0.5),
                }
                for item in grounding
                if isinstance(item, dict) and item.get("event_id")
            ]
        else:
            normalized["grounding"] = []
        normalized["confidence"] = float(normalized.get("confidence") or 0.5)
        normalized.setdefault("expiration", "PT15M")
        return normalized

    def _validate_openai_output(self, raw: Any, response_model: type[ModelT]) -> ModelT:
        provider_model = self._provider_response_model(response_model)
        obj = self._extract_object(raw)
        if response_model is StateDelta:
            obj = repair_state_delta_payload(obj)
        if provider_model is OpenAIICDecisionOutput:
            obj = self._normalize_openai_decision_obj(obj)
            obj = repair_ic_decision_payload(obj)
        try:
            validated = provider_model.model_validate(obj)
            return self._convert_provider_model(validated, response_model)
        except Exception:
            if provider_model is response_model:
                raise
            if response_model is ICDecision:
                return validate_with_repair(
                    self._decision_from_normalized_obj(obj),
                    response_model,
                    context="openai_ic_decision_fallback",
                )
            return validate_with_repair(obj, response_model, context="openai_provider_fallback")

    def _output_text_from_response_dict(self, data: dict[str, Any]) -> str:
        if isinstance(data.get("output_text"), str):
            return data["output_text"]
        chunks: list[str] = []
        for item in data.get("output", []):
            if not isinstance(item, dict):
                continue
            for content in item.get("content", []):
                if not isinstance(content, dict):
                    continue
                if isinstance(content.get("text"), str):
                    chunks.append(content["text"])
                elif isinstance(content.get("json"), dict):
                    return json.dumps(content["json"])
        if chunks:
            return "".join(chunks)
        raise ProviderJSONError("OpenAI response did not include structured output text")

    def _http_responses_create(self, request: dict[str, Any]) -> dict[str, Any]:
        api_key = os.environ.get(self.api_key_env)
        if not api_key:
            raise RuntimeError(f"Missing API key environment variable: {self.api_key_env}")
        http_request = urllib.request.Request(
            "https://api.openai.com/v1/responses",
            data=json.dumps(request, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(http_request, timeout=self.config.timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))

    def _generate_with_http(self, request: dict[str, Any], response_model: type[ModelT]) -> ModelT:
        try:
            data = self._http_responses_create(request)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            if exc.code == 400 and "invalid_json_schema" in detail and request["text"]["format"].get("strict"):
                relaxed = dict(request)
                relaxed["text"] = {"format": dict(request["text"]["format"], strict=False)}
                try:
                    data = self._http_responses_create(relaxed)
                except urllib.error.HTTPError as retry_exc:
                    retry_detail = retry_exc.read().decode("utf-8", errors="replace")
                    raise ProviderJSONError(
                        f"OpenAI HTTP error {retry_exc.code}: {retry_detail}",
                        provider="openai",
                        model=self._model(),
                        error_type=classify_provider_error(retry_detail),
                        request_id=extract_safe_request_id(retry_detail),
                        raw_error_redacted=sanitize_provider_error(retry_detail),
                    ) from retry_exc
            else:
                raise ProviderJSONError(
                    f"OpenAI HTTP error {exc.code}: {detail}",
                    provider="openai",
                    model=self._model(),
                    error_type=classify_provider_error(detail),
                    request_id=extract_safe_request_id(detail),
                    raw_error_redacted=sanitize_provider_error(detail),
                ) from exc
        except urllib.error.URLError as exc:
            raise ProviderJSONError(
                f"OpenAI network error: {exc.reason}",
                provider="openai",
                model=self._model(),
                error_type="network_error",
            ) from exc
        self._record_response_metadata(data)
        return self._validate_openai_output(self._output_text_from_response_dict(data), response_model)

    def _generate_with_sdk(
        self,
        openai: Any,
        request: dict[str, Any],
        response_model: type[ModelT],
    ) -> ModelT:
        client = openai.OpenAI(
            api_key=os.environ.get(self.api_key_env),
            timeout=self.config.timeout_seconds,
            max_retries=self.config.max_retries,
        )
        try:
            if hasattr(client.responses, "parse"):
                response = client.responses.parse(
                    model=request["model"],
                    input=request["input"],
                    text_format=self._provider_response_model(response_model),
                    temperature=self.config.temperature,
                )
                self._record_response_metadata(response)
                parsed = getattr(response, "output_parsed", None)
                if parsed is None:
                    raise ProviderJSONError(
                        "OpenAI parsed response did not include output_parsed",
                        provider="openai",
                        model=self._model(),
                        error_type="schema_error",
                    )
                if isinstance(parsed, BaseModel):
                    return self._convert_provider_model(parsed, response_model)
                return self._validate_openai_output(parsed, response_model)

            response = client.responses.create(**request)
            self._record_response_metadata(response)
            output_text = getattr(response, "output_text", None)
            if output_text is None:
                raise ProviderJSONError(
                    "OpenAI response did not include output_text",
                    provider="openai",
                    model=self._model(),
                    error_type="schema_error",
                )
            return self._validate_openai_output(output_text, response_model)
        except ProviderJSONError:
            raise
        except Exception as exc:
            request_id = extract_safe_request_id(exc)
            raise ProviderJSONError(
                f"OpenAI provider error: {exc}",
                provider="openai",
                model=self._model(),
                error_type=classify_provider_error(exc),
                request_id=request_id,
                raw_error_redacted=sanitize_provider_error(exc),
            ) from exc

    def generate_json(self, prompt_name: str, input_payload: dict, response_model: type[ModelT]) -> ModelT:
        request = self._request(prompt_name, input_payload, response_model)
        if self.transport is not None:
            return self._validate_transport_response(self.transport(request), response_model)
        try:
            openai = importlib.import_module("openai")
        except ImportError:
            return self._generate_with_http(request, response_model)
        return self._generate_with_sdk(openai, request, response_model)
