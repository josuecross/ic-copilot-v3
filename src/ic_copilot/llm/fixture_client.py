from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel

from ic_copilot.clean_context import _deterministic_clean_context
from ic_copilot.incident_brief import incident_brief_from_state
from ic_copilot.incident_read_v2 import incident_read_v2_from_v1_fixture
from ic_copilot.semantic_read import (
    build_deterministic_actor_workstream_ledger,
    build_deterministic_clean_turn_ledger,
    build_deterministic_incident_fact_ledger,
    build_deterministic_question_intent_ledger,
)
from ic_copilot.semantic_intent import _deterministic_assessment
from ic_copilot.sharp_blocker import _deterministic_assessment as _deterministic_sharp_blocker_assessment
from ic_copilot.schemas import (
    ActionRecord,
    AllowedTarget,
    ActorWorkstreamLedger,
    CleanIncidentContext,
    CleanTurnLedger,
    CommandCandidate,
    CurrentIncidentState,
    EntityRef,
    EntityType,
    EvidenceBackedFact,
    EvidenceRef,
    ICDecision,
    ICMove,
    ImpactState,
    IncidentReadAndWhisper,
    IncidentReadAndWhisperV2,
    WhisperCommandSuggestion,
    WhisperEvidenceRef,
    IncidentPhase,
    IncidentBrief,
    IncidentFactLedger,
    LinkRef,
    QuestionIntentLedger,
    QuestionRecord,
    SemanticIntentAssessment,
    SharpBlockerAssessment,
    Severity,
    StateDelta,
    IncidentEvent,
)

ModelT = TypeVar("ModelT", bound=BaseModel)


def _e(event: dict, quote: str | None = None, confidence: float = 0.85) -> EvidenceRef:
    return EvidenceRef(
        event_id=event.get("event_id", "m000"),
        quote=quote if quote is not None else event.get("message", ""),
        confidence=confidence,
    )


def _first(events: list[dict], *needles: str) -> dict:
    for event in events:
        text = f"{event.get('author', '')} {event.get('message', '')}".lower()
        if all(needle.lower() in text for needle in needles):
            return event
    return events[0] if events else {"event_id": "m000", "message": ""}


def _entity(
    name: str,
    entity_type: EntityType,
    evidence: EvidenceRef,
    status: str = "mentioned",
    canonical_id: str | None = None,
    source: str = "current_evidence",
) -> EntityRef:
    return EntityRef(
        entity_type=entity_type,
        display_name=name,
        canonical_id=canonical_id,
        status=status,
        evidence=[evidence],
        source=source,  # type: ignore[arg-type]
    )


def _links_from_events(events: list[dict]) -> list[LinkRef]:
    links: list[LinkRef] = []
    for event in events:
        for url in event.get("extracted_tokens", {}).get("urls", []):
            links.append(LinkRef(url=url, evidence=[_e(event)]))
    return links


def _commands_from_events(events: list[dict]) -> list[CommandCandidate]:
    commands: list[CommandCandidate] = []
    for event in events:
        for command in event.get("extracted_tokens", {}).get("command_candidates", []):
            commands.append(CommandCandidate(command=command, evidence=[_e(event)]))
    return commands


def _event_text(events: list[dict]) -> str:
    return "\n".join(f"{event.get('author', '')} {event.get('message', '')}" for event in events).lower()


def _compact_fixture_text(value: str, limit: int = 240) -> str:
    compacted = " ".join((value or "").split())
    return compacted if len(compacted) <= limit else compacted[:limit].rstrip()


def _event_from_payload(event: dict) -> IncidentEvent:
    data = dict(event)
    data.pop("author_type", None)
    data.pop("compact_text", None)
    return IncidentEvent.model_validate(data)


def _fact(
    value: str,
    event: dict | EvidenceRef,
    confidence: float = 0.75,
    metadata: dict | None = None,
) -> EvidenceBackedFact:
    evidence = event if isinstance(event, EvidenceRef) else _e(event)
    return EvidenceBackedFact(value=value, evidence=[evidence], confidence=confidence, metadata=metadata or {})


class FixtureLLMClient:
    """Deterministic fixtures for the sample incidents.

    The client is intentionally small. It does not try to solve arbitrary incidents; it only
    returns known structured objects for local MVP replay and tests.
    """

    def generate_json(
        self,
        prompt_name: str,
        input_payload: dict,
        response_model: type[ModelT],
    ) -> ModelT:
        if response_model is StateDelta or response_model.__name__ == "StateDelta":
            return self._state_delta(input_payload)  # type: ignore[return-value]
        if response_model is ICDecision or response_model.__name__ == "ICDecision":
            return self._decision(input_payload)  # type: ignore[return-value]
        if response_model is IncidentReadAndWhisper or response_model.__name__ == "IncidentReadAndWhisper":
            return self._incident_read_and_whisper(input_payload)  # type: ignore[return-value]
        if response_model is IncidentReadAndWhisperV2 or response_model.__name__ == "IncidentReadAndWhisperV2":
            read = self._incident_read_and_whisper(input_payload)
            return incident_read_v2_from_v1_fixture(read=read, context_pack=input_payload)  # type: ignore[return-value]
        if response_model is CleanIncidentContext or response_model.__name__ == "CleanIncidentContext":
            return self._clean_context(input_payload)  # type: ignore[return-value]
        if response_model is IncidentBrief or response_model.__name__ == "IncidentBrief":
            return self._incident_brief(input_payload)  # type: ignore[return-value]
        if response_model is CleanTurnLedger or response_model.__name__ == "CleanTurnLedger":
            events = [_event_from_payload(event) for event in input_payload.get("events", [])]
            return build_deterministic_clean_turn_ledger(
                input_payload.get("incident_id", "incident-local"),
                events,
            )  # type: ignore[return-value]
        if response_model is ActorWorkstreamLedger or response_model.__name__ == "ActorWorkstreamLedger":
            events = [_event_from_payload(event) for event in input_payload.get("events", [])]
            allowed_targets = [
                AllowedTarget.model_validate(target)
                for target in input_payload.get("allowed_targets", [])
            ]
            return build_deterministic_actor_workstream_ledger(
                input_payload.get("incident_id", "incident-local"),
                events,
                allowed_targets,
            )  # type: ignore[return-value]
        if response_model is IncidentFactLedger or response_model.__name__ == "IncidentFactLedger":
            events = [_event_from_payload(event) for event in input_payload.get("events", [])]
            return build_deterministic_incident_fact_ledger(
                input_payload.get("incident_id", "incident-local"),
                events,
            )  # type: ignore[return-value]
        if response_model is QuestionIntentLedger or response_model.__name__ == "QuestionIntentLedger":
            events = [_event_from_payload(event) for event in input_payload.get("events", [])]
            return build_deterministic_question_intent_ledger(
                input_payload.get("incident_id", "incident-local"),
                events,
            )  # type: ignore[return-value]
        if response_model is SemanticIntentAssessment or response_model.__name__ == "SemanticIntentAssessment":
            return self._semantic_intent(input_payload)  # type: ignore[return-value]
        if response_model is SharpBlockerAssessment or response_model.__name__ == "SharpBlockerAssessment":
            return self._sharp_blocker(input_payload)  # type: ignore[return-value]
        raise NotImplementedError(f"No fixture for prompt={prompt_name} model={response_model}")

    def _incident_read_and_whisper(self, payload: dict) -> IncidentReadAndWhisper:
        events: list[dict] = payload.get("latest_window_events") or payload.get("events", [])
        incident_id = payload.get("incident_id") or (events[0].get("incident_id") if events else "incident-local")
        candidate_targets = payload.get("candidate_targets", [])
        all_text = " ".join(str(event.get("text") or event.get("message") or "") for event in events).lower()
        if "no confirmed customer name or tenant id" in all_text:
            source_event = events[-1] if events else {"event_id": "m000", "text": ""}
            return IncidentReadAndWhisper(
                incident_id=incident_id,
                current_read="No confirmed customer name or tenant ID yet.",
                latest_open_loop="insufficient current customer/tenant grounding",
                already_answered=[],
                selected_move=ICMove.NO_SAFE_RECOMMENDATION,
                say_this="I do not have a safe, grounded next move yet.",
                next_line="No confirmed customer name or tenant ID yet.",
                evidence=[
                    WhisperEvidenceRef(
                        event_id=source_event.get("event_id", "m000"),
                        quote=_compact_fixture_text(source_event.get("text") or source_event.get("message") or ""),
                        confidence=0.8,
                    )
                ],
                uncertainty="The paste contains URL/doc/ticket numbers but no explicit customer or tenant evidence.",
                confidence=0.3,
            )
        if "revpro support" in all_text and ("not engaged" in all_text or "no revpro support acknowledgement" in all_text):
            target = next(
                (candidate for candidate in candidate_targets if candidate.get("display_name") == "RevPro Support"),
                None,
            )
            source_event = events[-1] if events else {"event_id": "m000", "text": ""}
            return IncidentReadAndWhisper(
                incident_id=incident_id,
                current_read="RevPro Support is suggested but not visibly engaged.",
                latest_open_loop="engage RevPro Support without re-asking whether they are looped in",
                already_answered=["ask whether RevPro Support is looped in"],
                selected_move=ICMove.ENGAGE_OWNER,
                selected_target_id=target.get("target_id") if target else None,
                selected_target_display_name="RevPro Support",
                say_this="RevPro Support has no visible acknowledgement yet; engage RevPro Support for ownership.",
                next_line="RevPro Support, can you confirm ownership and the next validation step?",
                command=WhisperCommandSuggestion(command_text="@zsrebot oncall RevPro support"),
                evidence=[
                    WhisperEvidenceRef(
                        event_id=source_event.get("event_id", "m000"),
                        quote=_compact_fixture_text(source_event.get("text") or source_event.get("message") or ""),
                        confidence=0.8,
                    )
                ],
                confidence=0.72,
            )
        state_events = [
            {
                "event_id": event.get("event_id", f"m{index:03d}"),
                "incident_id": incident_id,
                "sequence": event.get("sequence", index),
                "author": event.get("author"),
                "message": event.get("text") or event.get("message") or "",
                "extracted_tokens": {
                    "urls": event.get("urls", []),
                    "slack_mentions": event.get("slack_mentions", []),
                    "command_candidates": event.get("command_candidates", []),
                },
            }
            for index, event in enumerate(events, start=1)
        ]
        current_state: CurrentIncidentState | None = None
        try:
            state = self._state_delta({"incident_id": incident_id, "events": state_events})
            current_state = CurrentIncidentState(
                incident_id=state.incident_id,
                severity=state.severity,
                phase=state.phase or IncidentPhase.UNKNOWN,
                impact=state.impact or ImpactState(),
                candidate_services=state.candidate_services,
                engaged_entities=state.engaged_entities,
                suggested_but_not_engaged=state.suggested_but_not_engaged,
                actions_completed=state.actions_completed,
                open_questions=state.open_questions,
                answered_questions=state.answered_questions,
                stale_question_intents=state.stale_question_intents,
                current_blocker=state.current_blocker,
                monitoring_signals=state.monitoring_signals,
                commands_seen=state.commands_seen,
                links_seen=state.links_seen,
                rejected_entities=state.rejected_entities,
                unknowns=state.unknowns,
                safety_flags=state.safety_flags,
                compact_summary=state.compact_summary,
            )
            decision = self._decision(
                {
                    "current_state": current_state.model_dump(mode="json"),
                    "allowed_targets": candidate_targets,
                }
            )
            say_this = str(decision.output.get("say_this") or "")
            next_line = decision.output.get("next_line")
            command = decision.output.get("command")
            evidence = [
                WhisperEvidenceRef(event_id=ref.event_id, quote=ref.quote or "", confidence=ref.confidence)
                for ref in decision.grounding
                if ref.event_id
            ]
            if not evidence and state_events:
                evidence = [
                    WhisperEvidenceRef(
                        event_id=state_events[-1]["event_id"],
                        quote=_compact_fixture_text(state_events[-1]["message"]),
                        confidence=0.7,
                    )
                ]
            return IncidentReadAndWhisper(
                incident_id=incident_id,
                current_read=current_state.compact_summary or say_this or "Latest incident evidence read.",
                latest_open_loop=decision.domain_intent or current_state.current_blocker or "current IC next move",
                already_answered=current_state.stale_question_intents,
                selected_move=decision.move,
                selected_target_id=decision.target_ids[0] if decision.target_ids else None,
                selected_target_display_name=decision.targets[0].display_name if decision.targets else None,
                say_this=say_this,
                next_line=str(next_line) if next_line else None,
                command=WhisperCommandSuggestion(command_text=command) if isinstance(command, str) else None,
                evidence=evidence,
                uncertainty=None,
                confidence=decision.confidence,
            )
        except Exception:
            if current_state is not None and current_state.current_blocker:
                target = (
                    current_state.engaged_entities[0]
                    if current_state.engaged_entities
                    else current_state.suggested_but_not_engaged[0]
                    if current_state.suggested_but_not_engaged
                    else current_state.candidate_services[0]
                    if current_state.candidate_services
                    else None
                )
                target_name = target.display_name if target else None
                selected_target_id = None
                if target_name:
                    target_norm = _event_text([{"message": target_name}]).strip()
                    for candidate in candidate_targets:
                        if _event_text([{"message": candidate.get("display_name", "")}]).strip() == target_norm:
                            selected_target_id = candidate.get("target_id")
                            break
                blocker = current_state.current_blocker
                move = ICMove.REQUEST_STATUS_OR_ETA
                say_this = f"{target_name or 'Active owner'}, can you share the latest status and blocker?"
                next_line = None
                if blocker == "missing_owner":
                    move = ICMove.ENGAGE_OWNER
                    say_this = f"{target_name or 'Owner team'}, can you confirm ownership and the next validation step?"
                elif blocker == "waiting_on_code_fix":
                    move = ICMove.REQUEST_STATUS_OR_ETA
                    people = ", ".join(entity.display_name for entity in current_state.engaged_entities[:2])
                    if any(entity.display_name == "Guo Qing" for entity in current_state.engaged_entities):
                        trisha_target = next(
                            (
                                candidate
                                for candidate in candidate_targets
                                if _event_text([{"message": candidate.get("display_name", "")}]).strip().startswith("trisha")
                            ),
                            None,
                        )
                        if trisha_target is not None:
                            selected_target_id = trisha_target.get("target_id")
                            target_name = trisha_target.get("display_name")
                        people = target_name or "Trisha"
                        say_this = f"{people}, can you sync with Guo Qing on code fix status and hotfix ETA?"
                    else:
                        say_this = (
                            f"{people or target_name or 'Code owner'}, can you share code fix status, "
                            "hotfix ETA, and any release blocker?"
                        )
                elif blocker == "missing_validation":
                    move = ICMove.ASK_NEXT_VALIDATION
                    say_this = f"{target_name or 'Active owner'}, can you confirm the next validation signal?"
                    if "revenueorgmapping" in current_state.compact_summary.lower():
                        say_this = f"{target_name or 'Active owner'}, can you validate RevenueOrgMapping=0 and tenant 10005051 behavior?"
                    elif "cpu" in current_state.compact_summary.lower():
                        say_this = f"{target_name or 'Active owner'}, can you confirm whether CPU did not decrease because tenant/workload bulk operation is still driving load?"
                    elif "deployment" in current_state.compact_summary.lower():
                        say_this = f"{target_name or 'Active owner'}, can you confirm deployment relation and the validation signal?"
                elif blocker == "waiting_on_monitoring":
                    move = ICMove.REQUEST_MONITORING_SIGNAL
                    signals = ", ".join(signal.value for signal in current_state.monitoring_signals[:2])
                    say_this = f"{target_name or 'Active owner'}, can you confirm the current monitoring signal{f' for {signals}' if signals else ''}?"
                elif blocker == "mitigation_status_or_validation":
                    move = ICMove.REQUEST_STATUS_OR_ETA
                    if "queue" in current_state.compact_summary.lower():
                        say_this = (
                            f"{target_name or 'Active owner'}, can you confirm queue isolation mitigation status "
                            "and the next validation signal?"
                        )
                    else:
                        say_this = f"{target_name or 'Active owner'}, can you share mitigation status and validation signal?"
                elif blocker == "missing_impact":
                    move = ICMove.NO_SAFE_RECOMMENDATION
                    selected_target_id = None
                    target_name = None
                    say_this = "I do not have a safe, grounded next move yet."
                    next_line = "No confirmed customer name or tenant ID yet."
                if blocker == "rollback_or_disable_status" or (
                    "rpcapd" in current_state.compact_summary.lower()
                    and ("rollback" in current_state.compact_summary.lower() or "disable" in current_state.compact_summary.lower())
                ):
                    move = ICMove.REQUEST_MITIGATION_OPTION
                    say_this = (
                        f"{target_name or 'Active owner'}, can you share rpcapd mitigation status, "
                        "affected scope, and what validation signal confirms recovery?"
                    )
                if blocker == "waiting_on_owner_status" and "ocs lag" in current_state.compact_summary.lower():
                    move = ICMove.REQUEST_MONITORING_SIGNAL
                    say_this = (
                        f"{target_name or 'Active owner'}, can you share the current OCS lag recovery "
                        "metric or validation signal?"
                    )
                evidence = []
                for group in (
                    current_state.engaged_entities,
                    current_state.suggested_but_not_engaged,
                    current_state.candidate_services,
                ):
                    for entity in group:
                        evidence.extend(
                            WhisperEvidenceRef(event_id=ref.event_id, quote=ref.quote or "", confidence=ref.confidence)
                            for ref in entity.evidence
                        )
                if not evidence and state_events:
                    evidence = [
                        WhisperEvidenceRef(
                            event_id=state_events[-1]["event_id"],
                            quote=_compact_fixture_text(state_events[-1]["message"]),
                            confidence=0.7,
                        )
                    ]
                return IncidentReadAndWhisper(
                    incident_id=incident_id,
                    current_read=current_state.compact_summary or say_this,
                    latest_open_loop=blocker,
                    already_answered=current_state.stale_question_intents,
                    selected_move=move,
                    selected_target_id=selected_target_id,
                    selected_target_display_name=target_name,
                    say_this=say_this,
                    next_line=next_line,
                    evidence=evidence,
                    uncertainty=None,
                    confidence=0.7,
                )
        def _candidate_named(*needles: str) -> dict | None:
            for needle in needles:
                needle_norm = _event_text([{"message": needle}]).strip()
                for candidate in candidate_targets:
                    candidate_norm = _event_text([{"message": candidate.get("display_name", "")}]).strip()
                    if needle_norm and (needle_norm == candidate_norm or needle_norm in candidate_norm):
                        return candidate
            return candidate_targets[0] if candidate_targets else None

        if "rpcapd" in all_text and ("rollback" in all_text or "disable" in all_text):
            selected_target = _candidate_named("Kenneth Cambronero", "SRE", "rpcapd service")
            source_event = _first(events, "rpcapd")
            target_name = selected_target.get("display_name") if selected_target else "Active owner"
            return IncidentReadAndWhisper(
                incident_id=incident_id,
                current_read="rpcapd disable or rollback is discussed, but completion and validation are still open.",
                latest_open_loop="confirm mitigation status and affected scope validation",
                selected_move=ICMove.REQUEST_MITIGATION_OPTION,
                selected_target_id=selected_target.get("target_id") if selected_target else None,
                selected_target_display_name=target_name,
                say_this=(
                    f"{target_name}, can you share rpcapd mitigation status, affected scope, "
                    "and what validation signal confirms recovery?"
                ),
                evidence=[
                    WhisperEvidenceRef(
                        event_id=source_event.get("event_id", "m000"),
                        quote=_compact_fixture_text(source_event.get("text") or source_event.get("message") or ""),
                        confidence=0.8,
                    )
                ],
                confidence=0.76,
            )

        if "ocs lag" in all_text:
            selected_target = _candidate_named("SRE", "OCS", "Kafka team", "henryzhu")
            source_event = _first(events, "ocs lag")
            target_name = selected_target.get("display_name") if selected_target else "Active owner"
            return IncidentReadAndWhisper(
                incident_id=incident_id,
                current_read="OCS lag is under investigation and needs a recovery signal.",
                latest_open_loop="confirm OCS lag recovery validation",
                selected_move=ICMove.REQUEST_MONITORING_SIGNAL,
                selected_target_id=selected_target.get("target_id") if selected_target else None,
                selected_target_display_name=target_name,
                say_this=f"{target_name}, can you share the current OCS lag recovery metric or validation signal?",
                evidence=[
                    WhisperEvidenceRef(
                        event_id=source_event.get("event_id", "m000"),
                        quote=_compact_fixture_text(source_event.get("text") or source_event.get("message") or ""),
                        confidence=0.8,
                    )
                ],
                confidence=0.76,
            )
        human_events = [
            event for event in events
            if str(event.get("author_type") or "").lower() == "human"
            or str(event.get("event_kind") or "").startswith("human_")
        ]
        source_event = human_events[-1] if human_events else (events[-1] if events else {"event_id": "m000", "text": ""})
        text = source_event.get("text") or source_event.get("message") or ""
        event_id = source_event.get("event_id", "m000")
        author = source_event.get("author")
        selected_target = None
        if author:
            author_norm = _event_text([{"message": author}]).strip()
            for target in candidate_targets:
                if _event_text([{"message": target.get("display_name", "")}]).strip() == author_norm:
                    selected_target = target
                    break
        if selected_target is None and candidate_targets:
            selected_target = candidate_targets[0]
        lowered = text.lower()
        if any(term in lowered for term in ("pause", "stop", "mitigation", "rollback", "disable")):
            move = ICMove.REQUEST_MITIGATION_OPTION
            loop = "confirm the mitigation or pause decision"
        elif any(term in lowered for term in ("monitor", "signal", "lag", "latency", "metric", "pod", "db load")):
            move = ICMove.REQUEST_MONITORING_SIGNAL
            loop = "confirm the current recovery or monitoring signal"
        elif any(term in lowered for term in ("confirm", "validate", "whether", "still", "same activity")):
            move = ICMove.ASK_NEXT_VALIDATION
            loop = "confirm the latest validation result"
        elif not text:
            move = ICMove.NO_SAFE_RECOMMENDATION
            loop = "no current human/operator evidence is clear enough"
        else:
            move = ICMove.REQUEST_STATUS_OR_ETA
            loop = "share the latest status and blocker"
        target_name = selected_target.get("display_name") if selected_target else None
        if move == ICMove.NO_SAFE_RECOMMENDATION:
            say_this = "I do not have a safe, grounded next move yet."
        elif target_name:
            say_this = f"{target_name}, can you {loop}?"
        else:
            say_this = f"Can the active owner {loop}?"
        return IncidentReadAndWhisper(
            incident_id=incident_id,
            current_read=_compact_fixture_text(text) or "Latest evidence is limited.",
            latest_open_loop=loop,
            already_answered=[],
            selected_move=move,
            selected_target_id=selected_target.get("target_id") if selected_target else None,
            selected_target_display_name=target_name,
            say_this=say_this,
            evidence=[WhisperEvidenceRef(event_id=event_id, quote=_compact_fixture_text(text), confidence=0.8)] if text else [],
            uncertainty=None if text else "No clear current human/operator evidence.",
            confidence=0.72 if text else 0.25,
        )

    def _clean_context(self, payload: dict) -> CleanIncidentContext:
        events = [_event_from_payload(event) for event in payload.get("events", [])]
        state = CurrentIncidentState.model_validate(
            payload.get("current_state") or {"incident_id": payload.get("incident_id", "incident-local")}
        )
        return _deterministic_clean_context(payload.get("raw_text", ""), events, state)

    def _incident_brief(self, payload: dict) -> IncidentBrief:
        events = [_event_from_payload(event) for event in payload.get("events", [])]
        allowed_targets = [AllowedTarget.model_validate(target) for target in payload.get("allowed_targets", [])]
        state = self._state_delta(
            {
                "incident_id": payload.get("incident_id", "incident-local"),
                "events": [event.model_dump(mode="json") for event in events],
            }
        )
        current_state = CurrentIncidentState(
            incident_id=state.incident_id,
            severity=state.severity,
            phase=state.phase or IncidentPhase.UNKNOWN,
            impact=state.impact or ImpactState(),
            candidate_services=state.candidate_services,
            engaged_entities=state.engaged_entities,
            suggested_but_not_engaged=state.suggested_but_not_engaged,
            actions_completed=state.actions_completed,
            open_questions=state.open_questions,
            answered_questions=state.answered_questions,
            stale_question_intents=state.stale_question_intents,
            current_blocker=state.current_blocker,
            monitoring_signals=state.monitoring_signals,
            commands_seen=state.commands_seen,
            links_seen=state.links_seen,
            rejected_entities=state.rejected_entities,
            unknowns=state.unknowns,
            safety_flags=state.safety_flags,
            compact_summary=state.compact_summary,
        )
        return incident_brief_from_state(current_state, allowed_targets, events=events)

    def _semantic_intent(self, payload: dict) -> SemanticIntentAssessment:
        decision = ICDecision.model_validate(payload["decision"])
        state = CurrentIncidentState.model_validate(payload["current_state"])
        context = CleanIncidentContext.model_validate(payload["clean_context"])
        return _deterministic_assessment(decision, state, context)

    def _sharp_blocker(self, payload: dict) -> SharpBlockerAssessment:
        context = CleanIncidentContext.model_validate(payload["clean_context"])
        state = CurrentIncidentState.model_validate(payload["current_state"])
        return _deterministic_sharp_blocker_assessment(context, state, [])

    def _state_delta(self, payload: dict) -> StateDelta:
        events: list[dict] = payload.get("events", [])
        incident_id = payload.get("incident_id") or (events[0].get("incident_id") if events else "incident-local")
        text = _event_text(events)
        progress = {
            "last_event_id": events[-1]["event_id"] if events else None,
            "last_sequence": events[-1]["sequence"] if events else 0,
        }

        if "revpro" in text and "27 customers" in text:
            sev_e = _e(_first(events, "p3"))
            support_e = _e(_first(events, "revpro support"))
            impact_e = _e(_first(events, "27 customers"))
            phase = IncidentPhase.ENGAGEMENT if "incident.io" in text else IncidentPhase.TRIAGE
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P3, evidence=[sev_e], confidence=0.95),
                phase=phase,
                impact=ImpactState(
                    description="27 customers affected by RevPro deployment/version mismatch",
                    affected_count=27,
                    evidence=[impact_e],
                    confidence=0.9,
                ),
                candidate_services=[
                    _entity("RevPro", EntityType.SERVICE, _e(_first(events, "revpro")), canonical_id="revpro")
                ],
                engaged_entities=[
                    _entity("Support", EntityType.TEAM, _e(_first(events, "support")), "engaged", "support")
                ],
                suggested_but_not_engaged=[
                    _entity(
                        "RevPro Support",
                        EntityType.TEAM,
                        support_e,
                        "suggested_not_engaged",
                        "revpro-support",
                    )
                ],
                open_questions=[
                    QuestionRecord(
                        question_id="q-revpro-owner",
                        intent="confirm_owner",
                        text="RevPro Support should be engaged",
                        target="RevPro Support",
                        evidence=[support_e],
                    )
                ],
                stale_question_intents=[
                    "ask whether RevPro Support is already engaged",
                    "ask whether RevPro Support is looped in",
                    "already_looped_in",
                ],
                current_blocker="missing_owner",
                compact_summary="P3 RevPro deployment/version mismatch affecting 27 customers; Support points to RevPro Support, not visibly engaged.",
            )

        if "central sandbox" in text and ("zb-zr" in text or "zb/zr" in text or "uno" in text):
            tenant_e = _e(_first(events, "10005051"))
            customer_e = _e(_first(events, "google fiber"))
            dune_e = _e(_first(events, "dune"))
            uno_e = _e(_first(events, "uno"))
            revenue_e = _e(_first(events, "revenue"))
            impact = ImpactState(
                description="Central Sandbox ZB-ZR/UNO data-flow issue",
                evidence=[_e(_first(events, "central sandbox"))],
                confidence=0.85,
            )
            if "10005051" in text:
                impact.affected_tenants.append(
                    EvidenceBackedFact(value="10005051", evidence=[tenant_e], confidence=0.95)
                )
                impact.evidence.append(tenant_e)
            if "google fiber" in text:
                impact.affected_customers.append(
                    EvidenceBackedFact(value="Google Fiber", evidence=[customer_e], confidence=0.95)
                )
                impact.evidence.append(customer_e)
            if "revenueorgmapping=0" in text:
                impact.description = (
                    "Central Sandbox ZB-ZR/UNO data-flow issue for tenant 10005051 / "
                    "Google Fiber with RevenueOrgMapping=0"
                    if "10005051" in text and "google fiber" in text
                    else "Central Sandbox ZB-ZR/UNO data-flow issue with RevenueOrgMapping=0"
                )
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P2 if "p2" in text else Severity.P3, evidence=[_e(_first(events, "p"))], confidence=0.75),
                phase=IncidentPhase.INVESTIGATION,
                impact=impact,
                candidate_services=[
                    _entity("UNO", EntityType.SERVICE, uno_e, canonical_id="uno"),
                    _entity(
                        "Universal Sandbox",
                        EntityType.SERVICE,
                        _e(_first(events, "central sandbox")),
                        canonical_id="universal-sandbox",
                    ),
                    _entity("DUNE", EntityType.TEAM, dune_e, canonical_id="dune"),
                    _entity("Revenue", EntityType.TEAM, revenue_e, canonical_id="revenue"),
                ],
                engaged_entities=[
                    _entity("DUNE", EntityType.TEAM, dune_e, "responded", "dune"),
                    _entity("UNO", EntityType.TEAM, uno_e, "responded", "uno"),
                    _entity("Revenue", EntityType.TEAM, revenue_e, "responded", "revenue"),
                ],
                current_blocker="missing_validation",
                compact_summary=impact.description + "; DUNE/UNO/Revenue are engaged.",
            )

        previous_delta = self._previous_incident_delta(incident_id, progress, events, text)
        if previous_delta is not None:
            return previous_delta

        if "stripe" in text and ("psg-1843" in text or "bank transfer" in text):
            trisha_e = _e(_first(events, "trisha"))
            guo_e = _e(_first(events, "guo qing"))
            psg_e = _e(_first(events, "psg-1843"))
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P2, evidence=[_e(_first(events, "p2"))], confidence=0.95),
                phase=IncidentPhase.INVESTIGATION,
                impact=ImpactState(
                    description="P2 Bank Transfer failures on Stripe integration; customer estimates GBP 1M loss",
                    evidence=[_e(_first(events, "£1m"))],
                    confidence=0.9,
                ),
                candidate_services=[
                    _entity("Stripe Integration", EntityType.SERVICE, _e(_first(events, "stripe")), canonical_id="stripe"),
                    _entity("PSG", EntityType.TEAM, psg_e, canonical_id="psg"),
                ],
                engaged_entities=[
                    _entity("PSG", EntityType.TEAM, psg_e, "actively_working", "psg"),
                    _entity("Trisha", EntityType.PERSON, trisha_e, "working"),
                    _entity("Guo Qing", EntityType.PERSON, guo_e, "coordinating"),
                ],
                actions_completed=[
                    ActionRecord(
                        action_id="a-psg-1843",
                        action_type="code_fix_identified",
                        summary="PSG-1843 requires code fix",
                        actor="Trisha",
                        target="PSG-1843",
                        evidence=[psg_e],
                    )
                ],
                current_blocker="waiting_on_code_fix",
                compact_summary="P2 Bank Transfer failures in Stripe integration; PSG-1843 code fix is in progress with Trisha and Guo Qing coordinating hotfix release.",
            )

        if "cpu busy percent" in text and ("dba" in text or "dbs36p1" in text):
            dba_e = _e(_first(events, "dba"))
            sai_e = _e(_first(events, "sai"))
            queue_e = _e(_first(events, "queue"))
            cpu_e = _e(_first(events, "cpu"))
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P3, evidence=[cpu_e], confidence=0.6),
                phase=IncidentPhase.INVESTIGATION,
                impact=ImpactState(
                    description="DB CPU Busy Percent above 90% on dbs36p1 in PROD NA2; queue pending messages high.",
                    evidence=[cpu_e, queue_e],
                    confidence=0.75,
                ),
                candidate_services=[
                    _entity("DBA", EntityType.TEAM, dba_e, canonical_id="dba"),
                    _entity("ActiveMQ", EntityType.SERVICE, queue_e, canonical_id="activemq"),
                ],
                engaged_entities=[
                    _entity("DBA", EntityType.TEAM, sai_e, "actively_working", "dba"),
                    _entity("Sai", EntityType.PERSON, sai_e, "working"),
                    _entity("Platform Messaging", EntityType.TEAM, queue_e, "responded", "platform-messaging"),
                ],
                actions_completed=[
                    ActionRecord(
                        action_id="a-oncall-dba",
                        action_type="command_run",
                        summary="@zsrebot oncall dba",
                        target="DBA",
                        evidence=[_e(_first(events, "@zsrebot oncall dba"))],
                    ),
                    ActionRecord(
                        action_id="a-queue-isolation",
                        action_type="queue_isolation_attempted",
                        summary="Dedicated queue created but CPU did not decrease yet",
                        target="SubscriptionOrderProcessed",
                        evidence=[_e(_first(events, "cpu did not decrease"))],
                    ),
                ],
                commands_seen=_commands_from_events(events),
                current_blocker="missing_validation",
                compact_summary="DBA is engaged; CPU did not decrease after dedicated queue action; need tenant/workload validation for bulk operation.",
            )

        if "reverted" in text and "monitor" in text and "order api error rate" in text:
            ocm_e = _e(_first(events, "ocm"))
            signal_e = _e(_first(events, "order api error rate"))
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P2, evidence=[_e(_first(events, "p2"))], confidence=0.9),
                phase=IncidentPhase.MONITORING,
                impact=ImpactState(
                    description="OCM order creation failures; revert completed and early customer validation successful.",
                    evidence=[ocm_e, _e(_first(events, "succeeding"))],
                    confidence=0.85,
                ),
                candidate_services=[
                    _entity("OCM", EntityType.SERVICE, ocm_e, canonical_id="ocm"),
                    _entity("commerce-catalog", EntityType.SERVICE, signal_e, canonical_id="commerce-catalog"),
                ],
                engaged_entities=[_entity("OCM", EntityType.TEAM, ocm_e, "actively_working", "ocm")],
                actions_completed=[
                    ActionRecord(
                        action_id="a-revert-flag",
                        action_type="mitigation_completed",
                        summary="Bad deployment flag reverted",
                        actor="OCM",
                        target="bad deployment flag",
                        evidence=[ocm_e],
                    )
                ],
                monitoring_signals=[
                    EvidenceBackedFact(value="order API error rate", evidence=[signal_e], confidence=0.95),
                    EvidenceBackedFact(value="catalog lookup latency", evidence=[signal_e], confidence=0.95),
                ],
                current_blocker="waiting_on_monitoring",
                compact_summary="Mitigation/revert completed; order API error rate and catalog lookup latency are current monitoring signals.",
            )

        if "data augmentation step completed" in text and "timeout increase" in text:
            signal_e = _e(_first(events, "data augmentation step completed"))
            deploy_e = _e(_first(events, "deployment complete"))
            revenue_e = _e(_first(events, "revenue engineering"))
            if revenue_e.event_id == "m000" or not revenue_e.quote:
                revenue_e = _e(_first(events, "paged robert"))
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P2, evidence=[_e(_first(events, "incident summary"))], confidence=0.7),
                phase=IncidentPhase.MONITORING,
                impact=ImpactState(
                    description="RevPro Data Collection socket timeout; visible snippet does not confirm customer/tenant impact.",
                    evidence=[_e(_first(events, "socket timeout"))],
                    confidence=0.45,
                ),
                candidate_services=[
                    _entity("RevPro Data Collection", EntityType.SERVICE, _e(_first(events, "data collection")), canonical_id="revpro-data-collection"),
                    _entity("Oracle DB socket timeout", EntityType.SERVICE, _e(_first(events, "socket timeout")), canonical_id="oracle-db-socket-timeout"),
                    _entity("nova-infra", EntityType.SERVICE, _e(_first(events, "nova-infra")), canonical_id="nova-infra"),
                ],
                engaged_entities=[
                    _entity("Revenue Engineering", EntityType.TEAM, revenue_e, "actively_working", "revenue-engineering"),
                    _entity("Incident Management", EntityType.TEAM, _e(_first(events, "incident update")), "engaged"),
                    _entity("Duty Manager", EntityType.TEAM, _e(_first(events, "approved")), "engaged"),
                ],
                actions_completed=[
                    ActionRecord(
                        action_id="a-timeout-increase-deployed",
                        action_type="mitigation_completed",
                        summary="ECM deployed to increase timeout; pods running and job restarted",
                        target="timeout increase",
                        evidence=[deploy_e],
                    ),
                    ActionRecord(
                        action_id="a-data-augmentation-complete",
                        action_type="validation_progress",
                        summary="Data augmentation step completed after timeout increase; job processing further",
                        target="RevPro data collection job",
                        evidence=[signal_e],
                    ),
                ],
                stale_question_intents=["ask_if_cm_approved", "ask_if_deployed"],
                current_blocker="waiting_on_monitoring",
                monitoring_signals=[
                    EvidenceBackedFact(
                        value="data augmentation step/job completion",
                        evidence=[signal_e],
                        confidence=0.9,
                        metadata={
                            "Tool": "RevPro job status/logs",
                            "What it means": "Validation after socket timeout change",
                        },
                    )
                ],
                rejected_entities=[
                    _entity("numbers_in_urls", EntityType.TENANT, _e(_first(events, "CM-30678")), "rejected:url_path_number")
                ],
                compact_summary="ECM deployed to increase timeout; data augmentation completed and job is processing further; monitor job completion.",
            )

        if "order creation" in text and ("ocm" in text or "commerce-catalog" in text):
            sev_e = _e(_first(events, "p3"))
            praneeth_e = _e(_first(events, "praneeth"))
            deploy_e = _e(_first(events, "deployment"))
            impact_description = (
                "3 customers blocked on order creation"
                if "3 customers" in text
                else "P3 order creation failures in NA2 sandbox; deployment correlation suspected"
            )
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P3, evidence=[sev_e], confidence=0.9),
                phase=IncidentPhase.INVESTIGATION,
                impact=ImpactState(
                    description=impact_description,
                    affected_count=3 if "3 customers" in text else None,
                    evidence=[_e(_first(events, "3 customers"))],
                    confidence=0.9,
                ),
                candidate_services=[
                    _entity("OCM", EntityType.SERVICE, _e(_first(events, "ocm")), canonical_id="ocm"),
                    _entity("commerce-catalog", EntityType.SERVICE, _e(_first(events, "commerce-catalog")), canonical_id="commerce-catalog"),
                ],
                engaged_entities=[
                    _entity("OCM", EntityType.TEAM, _e(_first(events, "ocm")), "actively_working", "ocm"),
                    _entity("commerce-catalog", EntityType.TEAM, _e(_first(events, "commerce-catalog")), "responded", "commerce-catalog"),
                    _entity("Praneeth", EntityType.PERSON, praneeth_e, "working"),
                ],
                open_questions=[
                    QuestionRecord(
                        question_id="q-ocm-deploy",
                        intent="confirm_deployment_related",
                        text="Need to confirm whether today's NA2 CSBX/sandbox deployment is related",
                        target="OCM",
                        evidence=[deploy_e],
                    )
                ],
                current_blocker="missing_validation",
                compact_summary=impact_description + "; OCM/commerce-catalog engaged; need deployment relationship confirmation.",
            )

        if "ocs lag" in text and "zapps" in text:
            lag_e = _e(_first(events, "ocs lag"))
            dashboard_e = _e(_first(events, "dashboards"))
            tenant_e = _e(_first(events, "tenant id"))
            trust_e = _e(_first(events, "trust post no need"))
            jose_e = _e(_first(events, "jose"))
            ticket_e = _e(_first(events, "zendesk"))
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P2, evidence=[_e(_first(events, "p2"))], confidence=0.7),
                phase=IncidentPhase.INVESTIGATION,
                impact=ImpactState(
                    description=(
                        "High OCS lag is visible on AP PROD zapps2 and AP CSBX zapps1; Zendesk/L3 tickets "
                        "and affected shard/tenant evidence are already visible."
                    ),
                    affected_tenants=[
                        _fact("30000091", _first(events, "tenant id 30000091"), 0.92),
                    ],
                    evidence=[lag_e, ticket_e, tenant_e],
                    confidence=0.82,
                ),
                candidate_services=[
                    _entity("OCS", EntityType.SERVICE, lag_e, canonical_id="ocs"),
                    _entity("AP PROD zapps2", EntityType.SERVICE, lag_e, canonical_id="ap-prod-zapps2"),
                    _entity("AP CSBX zapps1", EntityType.SERVICE, lag_e, canonical_id="ap-csbx-zapps1"),
                ],
                engaged_entities=[
                    _entity("SRE", EntityType.TEAM, dashboard_e, "actively_working"),
                    _entity("Jose", EntityType.PERSON, jose_e, "actively_working"),
                    _entity("Support", EntityType.TEAM, trust_e, "responded"),
                ],
                actions_completed=[
                    ActionRecord(
                        action_id="a-ocs-tickets-visible",
                        action_type="tickets_shared",
                        summary="Zendesk and L3 tickets are already visible.",
                        evidence=[ticket_e],
                    ),
                    ActionRecord(
                        action_id="a-ocs-trust-post-no-need",
                        action_type="customer_comms_answered",
                        summary="Trust Post was answered as not needed.",
                        actor="Support",
                        evidence=[trust_e],
                    ),
                ],
                answered_questions=[
                    QuestionRecord(
                        question_id="q-trust-post-no-need",
                        intent="ask_trust_post_needed",
                        text="Is Trust Post needed?",
                        answer="Trust Post No Need.",
                        status="answered",
                        evidence=[trust_e],
                    )
                ],
                stale_question_intents=[
                    "ask_trust_post_needed",
                    "confirm_trust_post_needed",
                    "trust_post_confirmation",
                    "ask_for_ticket_sharing",
                ],
                current_blocker="waiting_on_owner_status",
                monitoring_signals=[
                    _fact(
                        "OCS lag recovery on AP PROD zapps2 and AP CSBX zapps1 after shard/tenant lookup",
                        tenant_e,
                        0.86,
                        {"Tool": "DBZ/Kubernetes dashboards and shard tenant lookup", "What it means": "Lag recovery or growth"},
                    )
                ],
                commands_seen=_commands_from_events(events),
                links_seen=_links_from_events(events),
                rejected_entities=[
                    _entity("9863631", EntityType.TENANT, _e(_first(events, "9863631")), "rejected:url_path_number"),
                    _entity("Default_Agent", EntityType.TEAM, _e(_first(events, "Default_Agent")), "rejected:bot_system_message"),
                ],
                compact_summary=(
                    "P2/P3 proactive OCS lag investigation is active for AP PROD zapps2 and AP CSBX zapps1; "
                    "tickets, dashboards, impacted shards, and tenant lookup evidence are visible; need owner status "
                    "and lag recovery validation."
                ),
            )

        if ("default_agent" in text or "gaurav trisha" in text) and "rpcapd" not in text and "trimble sandbox 5" not in text:
            fake_e = _e(_first(events, "atlassian"))
            default_e = _e(_first(events, "default_agent"))
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                phase=IncidentPhase.TRIAGE,
                impact=ImpactState(
                    description="No confirmed customer name or tenant ID yet.",
                    evidence=[_e(_first(events, "no confirmed customer"))],
                    confidence=0.7,
                ),
                links_seen=_links_from_events(events),
                rejected_entities=[
                    _entity("Atlassian", EntityType.CUSTOMER, fake_e, "rejected:url_domain"),
                    _entity("9863631", EntityType.TENANT, fake_e, "rejected:url_path_number"),
                    _entity("@zsrebot created this channel", EntityType.COMMAND, _e(_first(events, "created this channel")), "rejected:bot_system_message"),
                    _entity("Gaurav Could", EntityType.PERSON, _e(_first(events, "Gaurav")), "rejected:display_name_fragment"),
                    _entity("Gaurav Trisha", EntityType.PERSON, _e(_first(events, "Gaurav Trisha")), "rejected:display_name_fragment"),
                    _entity("MD. Please", EntityType.PERSON, _e(_first(events, "MD. Please")), "rejected:display_name_fragment"),
                    _entity("Default_Agent", EntityType.TEAM, default_e, "rejected:not_supported_by_evidence"),
                ],
                current_blocker="missing_impact",
                compact_summary="No confirmed customer name or tenant ID yet; URL-domain, URL-path, bot command, person-fragment, and Default_Agent candidates are rejected.",
            )

        if "rpcapd" in text and ("rollback" in text or "disable" in text):
            sev_e = _e(_first(events, "p3"))
            kenneth_e = _e(_first(events, "kenneth"))
            yong_e = _e(_first(events, "yong"))
            rollback_e = _e(_first(events, "rollback"))
            disable_e = _e(_first(events, "disable rpcapd"))
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P3, evidence=[sev_e], confidence=0.9),
                phase=IncidentPhase.INVESTIGATION,
                impact=ImpactState(
                    description="Billing tomcat EC2 disk-full alerts on FET/BET CSBX nodes; customer impact not confirmed.",
                    evidence=[_e(_first(events, "disk full")), _e(_first(events, "billing tomcat"))],
                    confidence=0.72,
                ),
                candidate_services=[
                    _entity("Billing tomcat", EntityType.SERVICE, _e(_first(events, "billing tomcat")), canonical_id="billing-tomcat"),
                    _entity("rpcapd service", EntityType.SERVICE, _e(_first(events, "rpcapd")), canonical_id="rpcapd-service"),
                    _entity("Extrahop rollout", EntityType.SERVICE, _e(_first(events, "extrahop")), canonical_id="extrahop-rollout"),
                ],
                engaged_entities=[
                    _entity("Kenneth Cambronero", EntityType.PERSON, kenneth_e, "actively_working"),
                    _entity("Yong Chang", EntityType.PERSON, yong_e, "responded"),
                    _entity("Balaji", EntityType.PERSON, _e(_first(events, "balaji")), "asked"),
                    _entity("Vinod", EntityType.PERSON, _e(_first(events, "vinod")), "mentioned"),
                ],
                actions_completed=[
                    ActionRecord(
                        action_id="a-rpcapd-disable-requested",
                        action_type="mitigation_requested",
                        summary="SRE was asked to disable rpcapd across environments.",
                        actor="Yong Chang",
                        target="rpcapd service",
                        evidence=[disable_e],
                    ),
                    ActionRecord(
                        action_id="a-rollback-requested",
                        action_type="rollback_requested",
                        summary="Balaji was asked to rollback the related change.",
                        actor="Yong Chang",
                        target="related change",
                        evidence=[rollback_e],
                    ),
                ],
                monitoring_signals=[
                    _fact(
                        "disk full alerts on FET/BET CSBX nodes",
                        _first(events, "disk full"),
                        0.83,
                        {"Tool": "alert examples/screenshots", "What it means": "Validation after rollback/disable"},
                    )
                ],
                commands_seen=_commands_from_events(events),
                links_seen=_links_from_events(events),
                rejected_entities=[
                    _entity("9863631", EntityType.TENANT, _e(_first(events, "9863631")), "rejected:url_path_number"),
                    _entity("Default_Agent", EntityType.TEAM, _e(_first(events, "Default_Agent")), "rejected:bot_system_message"),
                ],
                current_blocker="rollback_or_disable_status",
                compact_summary="P3 Billing tomcat disk-full alerts; rpcapd disablement and rollback are requested but mitigation completion and validation are not confirmed.",
            )

        if "hotfix" in text and ("eta" in text or "in progress" in text or "release blocker" in text):
            owner_e = _e(_first(events, "engineer"))
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P3, evidence=[_e(_first(events, "p3"))], confidence=0.75),
                phase=IncidentPhase.INVESTIGATION,
                impact=ImpactState(description="Service issue with hotfix in progress.", evidence=[owner_e], confidence=0.5),
                candidate_services=[_entity("Affected service", EntityType.SERVICE, _e(_first(events, "service issue")))],
                engaged_entities=[_entity("Engineer", EntityType.PERSON, owner_e, "actively_working")],
                current_blocker="waiting_on_code_fix",
                compact_summary="Engineer says code fix/hotfix is in progress; ETA and release blockers are the sharp blocker.",
            )

        if "queue isolation" in text and ("not improved" in text or "no improvement" in text or "metrics still" in text):
            owner_e = _e(_first(events, "owner"))
            signal_e = _e(_first(events, "metrics"))
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P3, evidence=[_e(_first(events, "p3"))], confidence=0.7),
                phase=IncidentPhase.INVESTIGATION,
                impact=ImpactState(description="Queue isolation was attempted but metrics did not improve.", evidence=[signal_e], confidence=0.65),
                candidate_services=[_entity("Queue processing", EntityType.SERVICE, _e(_first(events, "queue")))],
                engaged_entities=[_entity("Active owner", EntityType.PERSON, owner_e, "actively_working")],
                actions_completed=[
                    ActionRecord(
                        action_id="a-queue-isolation-attempted",
                        action_type="queue_isolation_attempted",
                        summary="Queue isolation attempted but metrics did not improve.",
                        evidence=[signal_e],
                    )
                ],
                current_blocker="mitigation_status_or_validation",
                monitoring_signals=[_fact("post-isolation queue depth/error rate", signal_e, 0.8)],
                compact_summary="Queue isolation was attempted and metrics did not improve; active owner needs next mitigation or validation signal.",
            )

        if "trust post no need" in text and ("investigating" in text or "technical" in text):
            owner_e = _e(_first(events, "technical owner"))
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P3, evidence=[_e(_first(events, "p3"))], confidence=0.7),
                phase=IncidentPhase.INVESTIGATION,
                impact=ImpactState(description="Technical investigation continues after Trust Post was answered as not needed.", evidence=[owner_e], confidence=0.55),
                candidate_services=[_entity("Affected service", EntityType.SERVICE, _e(_first(events, "technical")))],
                engaged_entities=[_entity("Technical owner", EntityType.PERSON, owner_e, "actively_working")],
                current_blocker="missing_validation",
                compact_summary="Trust Post was answered as no need; technical investigation still needs mitigation/validation status.",
            )

        if "trimble sandbox 5" in text and "open connection" in text:
            sriram_e = _e(_first(events, "sriram"))
            aditya_e = _e(_first(events, "aditya"))
            signal_e = _e(_first(events, "trimble sandbox 5"))
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P3, evidence=[_e(_first(events, "p3"))], confidence=0.85),
                phase=IncidentPhase.MONITORING,
                impact=ImpactState(
                    description="TRIMBLE and SEMRUSH reported API 504 gateway timeouts; Trimble sandbox impact is visible.",
                    evidence=[_e(_first(events, "504 gateway timeout")), _e(_first(events, "trimble"))],
                    confidence=0.72,
                ),
                candidate_services=[
                    _entity(
                        "Revenue Engineering",
                        EntityType.TEAM,
                        _e(_first(events, "Revenue Engineering")),
                        canonical_id="revenue-engineering",
                    ),
                    _entity(
                        "RevPro Support",
                        EntityType.TEAM,
                        _e(_first(events, "Revpro Support")),
                        canonical_id="revpro-support",
                    ),
                    _entity(
                        "rpro-oracle-integrations",
                        EntityType.SERVICE,
                        _e(_first(events, "rpro-oracle-integrations")),
                        canonical_id="rpro-oracle-integrations",
                    ),
                ],
                engaged_entities=[
                    _entity("Sriram", EntityType.PERSON, sriram_e, "actively_working"),
                    _entity("Aditya", EntityType.PERSON, aditya_e, "asked"),
                    _entity(
                        "Revenue Engineering",
                        EntityType.TEAM,
                        _e(_first(events, "page team revenue")),
                        "engaged_or_requested",
                        "revenue-engineering",
                    ),
                ],
                actions_completed=[
                    ActionRecord(
                        action_id="a-revenue-paged",
                        action_type="owner_engaged",
                        summary="Revenue was looked up and paged; Sriram is checking.",
                        actor="IC",
                        target="Revenue Engineering",
                        evidence=[_e(_first(events, "page team revenue")), sriram_e],
                    ),
                    ActionRecord(
                        action_id="a-task-restarted",
                        action_type="mitigation_or_recovery_seen",
                        summary="Task restart and ELB health-check failure are visible; validation is still pending.",
                        target="API task",
                        evidence=[_e(_first(events, "task restarted")), _e(_first(events, "ELB health"))],
                    ),
                ],
                stale_question_intents=["ask_if_revenue_engaged"],
                current_blocker="waiting_on_monitoring",
                monitoring_signals=[
                    _fact(
                        "Trimble sandbox 5 completion and 504/open-connection-limit condition cleared",
                        signal_e,
                        0.86,
                        {"Tool": "application/API health/logs", "What it means": "Validation after task restart"},
                    )
                ],
                commands_seen=_commands_from_events(events),
                links_seen=_links_from_events(events),
                rejected_entities=[
                    _entity("9863631", EntityType.TENANT, _e(_first(events, "9863631")), "rejected:url_path_number"),
                    _entity("Default_Agent", EntityType.TEAM, _e(_first(events, "Default_Agent")), "rejected:bot_system_message"),
                ],
                compact_summary=(
                    "Revenue is already paged and Sriram is checking API 504/open connection limit recovery; "
                    "Aditya is validating Trimble sandbox 5."
                ),
            )

        # Negative and generic cases. Preserve links as evidence, but do not promote URL
        # domains or path numbers into customer/tenant facts.
        impact = ImpactState(confidence=0.1)
        if "revpro support" in text:
            support_e = _e(_first(events, "revpro support"))
            phase = IncidentPhase.ENGAGEMENT if "incident.io" in text or "rookie ic draft" in text else IncidentPhase.TRIAGE
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                phase=phase,
                candidate_services=[
                    _entity("RevPro", EntityType.SERVICE, _e(_first(events, "revpro")), canonical_id="revpro")
                ],
                suggested_but_not_engaged=[
                    _entity("RevPro Support", EntityType.TEAM, support_e, "suggested_not_engaged", "revpro-support")
                ],
                engaged_entities=[
                    _entity("Support", EntityType.TEAM, _e(_first(events, "support")), "responded", "support")
                ],
                stale_question_intents=[
                    "ask whether RevPro Support is looped in",
                    "ask whether RevPro Support is already engaged",
                    "already_looped_in",
                ],
                current_blocker="missing_owner",
                compact_summary="RevPro Support is suggested but not visibly engaged.",
            )
        return StateDelta(
            incident_id=incident_id,
            source_progress=progress,
            phase=IncidentPhase.TRIAGE,
            impact=impact,
            current_blocker="missing_impact",
            compact_summary="Insufficient current evidence for a sharper recommendation.",
        )

    def _previous_incident_delta(
        self,
        incident_id: str,
        progress: dict,
        events: list[dict],
        text: str,
    ) -> StateDelta | None:
        """Reusable JSONL fixture extraction patterns from previous sanitized incidents."""
        if not events or not any(event.get("source") == "incident_jsonl" for event in events):
            return None

        if "stripe integration" in text and ("hotfix canceled" in text or "incident is now mitigated" in text):
            mitigation_event = _first(events, "incident is now mitigated")
            if mitigation_event.get("event_id") == "m000":
                mitigation_event = _first(events, "hotfix canceled")
            support_event = _first(events, "support ops")
            payment_event = _first(events, "payment team")
            followup_event = _first(events, "psg-1876")
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P2, evidence=[_e(_first(events, "p2"))], confidence=0.9),
                phase=IncidentPhase.MITIGATION,
                impact=ImpactState(
                    description="Payment failure on Stripe/BACS path mitigated; current blocker is customer/internal acknowledgement.",
                    affected_count=1,
                    evidence=[_e(_first(events, "high financial impact")), _e(_first(events, "TENANT_001"))],
                    confidence=0.7,
                ),
                candidate_services=[
                    _entity("Stripe Bank Transfer integration", EntityType.SERVICE, _e(_first(events, "stripe integration")), canonical_id="stripe-bank-transfer"),
                    _entity("Payments Strategic Gateway", EntityType.TEAM, _e(_first(events, "payments-strategic-gateway")), canonical_id="payments-strategic-gateway"),
                ],
                engaged_entities=[
                    _entity("Payments team", EntityType.TEAM, _e(payment_event), "engaged", "payments"),
                    _entity("Guo Qing", EntityType.PERSON, _e(_first(events, "Guo Qing")), "engaged"),
                    _entity("Support", EntityType.TEAM, _e(support_event), "engaged", "support"),
                ],
                actions_completed=[
                    ActionRecord(
                        action_id="a-payment-hotfix-canceled",
                        action_type="mitigation_completed",
                        summary="Engineering corrected diagnosis; hotfix canceled and incident mitigated.",
                        evidence=[_e(mitigation_event)],
                    )
                ],
                answered_questions=[
                    QuestionRecord(
                        question_id="q-payment-hotfix-needed",
                        intent="ask_if_hotfix_needed",
                        text="Is hotfix still needed?",
                        status="answered",
                        answer="No; hotfix was canceled after corrected diagnosis.",
                        evidence=[_e(_first(events, "hotfix canceled"))],
                    )
                ],
                stale_question_intents=[
                    "ask_if_support_engaged",
                    "ask_if_hotfix_needed",
                    "ask_to_start_bridge",
                ],
                current_blocker="waiting_on_customer_confirmation",
                monitoring_signals=[
                    _fact(
                        "customer/internal acknowledgement and PSG-1876 follow-up",
                        followup_event,
                        0.78,
                        {"Tool": "Support update / PSG ticket", "What it means": "Closeout validation after mitigation"},
                    )
                ],
                commands_seen=_commands_from_events(events),
                compact_summary="Payment incident is mitigated after corrected Stripe/BACS diagnosis; track customer/internal acknowledgement and PSG-1876 follow-up.",
            )

        if "revenue events" in text and "queue congestion" in text and "customer confirmation" in text:
            revenue_event = _first(events, "revenue")
            provisioning_event = _first(events, "provisioning")
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P3, evidence=[_e(_first(events, "root cause"))], confidence=0.65),
                phase=IncidentPhase.INVESTIGATION,
                impact=ImpactState(
                    description="Revenue Kafka queue congestion from unmapped CSBX tenant events; scope expanded to 6 customers.",
                    affected_count=6,
                    evidence=[_e(_first(events, "6 customers")), _e(_first(events, "queue congestion"))],
                    confidence=0.72,
                ),
                candidate_services=[
                    _entity("Revenue Kafka queue", EntityType.SERVICE, _e(_first(events, "queue congestion")), canonical_id="revenue-kafka-queue"),
                    _entity("CSBX refresh", EntityType.SERVICE, _e(_first(events, "csbx")), canonical_id="csbx-refresh"),
                    _entity("RevenueOrgMapping", EntityType.SERVICE, _e(_first(events, "revenue org mapping")), canonical_id="revenue-org-mapping"),
                    _entity("UNO events", EntityType.SERVICE, _e(_first(events, "revenue events")), canonical_id="uno-events"),
                ],
                suggested_but_not_engaged=[
                    _entity("Revenue", EntityType.TEAM, _e(revenue_event), "suggested_not_engaged", "revenue"),
                    _entity("Provisioning", EntityType.TEAM, _e(provisioning_event), "suggested_not_engaged", "provisioning"),
                ],
                engaged_entities=[
                    _entity("CSBX", EntityType.TEAM, _e(_first(events, "csbx")), "engaged_or_requested", "csbx"),
                    _entity("UNO", EntityType.TEAM, _e(_first(events, "revenue events")), "engaged_or_requested", "uno"),
                ],
                stale_question_intents=["ask_if_provisioning_can_link_without_customer_confirmation"],
                current_blocker="missing_owner",
                monitoring_signals=[
                    _fact(
                        "Revenue Kafka queue congestion",
                        _first(events, "queue congestion"),
                        0.78,
                        {"Tool": "queue metrics", "What it means": "Backlog should reduce after mitigation"},
                    )
                ],
                commands_seen=_commands_from_events(events),
                compact_summary="Revenue Kafka queue congestion from unmapped CSBX tenant events; need Revenue guidance while Provisioning is blocked on customer approval.",
            )

        if (
            "data loss" in text
            and ("sqr" in text or "prob-5318" in text or "problem ticket" in text)
            and any(phrase in text for phrase in ("possible data loss", "potential data loss", "chance of data loss", "data loss review"))
        ):
            impact_event = _first(events, "data loss")
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P2, evidence=[_e(impact_event)], confidence=0.7),
                phase=IncidentPhase.INVESTIGATION,
                impact=ImpactState(
                    description="Customer impact and possible data loss are confirmed; SQR/PROB review is tracking validation.",
                    evidence=[_e(impact_event)],
                    confidence=0.76,
                ),
                candidate_services=[
                    _entity("SQR", EntityType.TEAM, _e(impact_event), canonical_id="sqr"),
                    _entity("tenant/shard mapping", EntityType.SERVICE, _e(_first(events, "shard")), canonical_id="tenant-shard-mapping"),
                    _entity("Jira incident", EntityType.JIRA, _e(_first(events, "jira")), canonical_id="jira-incident"),
                ],
                engaged_entities=[
                    _entity("SQR team", EntityType.TEAM, _e(impact_event), "engaged_or_requested", "sqr"),
                    _entity("Incident Management", EntityType.TEAM, _e(_first(events, "incident")), "engaged_or_requested"),
                ],
                stale_question_intents=["ask_if_customer_impact_exists"],
                current_blocker="missing_impact",
                monitoring_signals=[
                    _fact(
                        "SQR data loss review",
                        impact_event,
                        0.76,
                        {"Tool": "Problem ticket/Jira", "What it means": "Validation of customer impact"},
                    )
                ],
                links_seen=_links_from_events(events),
                compact_summary="Impact is clarified as possible data loss; SQR/PROB review should validate affected tenant/shard entries.",
            )

        if "ebs volume" in text and ("deployed" in text or "looks ok" in text):
            deployed_event = _first(events, "deployed")
            ok_event = _first(events, "looks ok")
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                phase=IncidentPhase.VERIFICATION,
                impact=ImpactState(
                    description="EBS volume increase for busy database shard; implementer says DB looks OK.",
                    evidence=[_e(_first(events, "ebs volume")), _e(ok_event)],
                    confidence=0.58,
                ),
                candidate_services=[
                    _entity("EBS volume", EntityType.SERVICE, _e(_first(events, "ebs volume")), canonical_id="ebs-volume"),
                    _entity("database shard", EntityType.SERVICE, _e(_first(events, "shard")), canonical_id="database-shard"),
                ],
                engaged_entities=[
                    _entity("DBA/SRE", EntityType.TEAM, _e(_first(events, "ebs volume")), "engaged_or_requested", "dba-sre"),
                    _entity("Incident Management", EntityType.TEAM, _e(_first(events, "cm details")), "engaged_or_requested"),
                ],
                actions_completed=[
                    ActionRecord(
                        action_id="a-ebs-deployed",
                        action_type="deployment_completed",
                        summary="EBS increase deployed; DB health looked OK",
                        evidence=[_e(deployed_event), _e(ok_event)],
                    )
                ],
                stale_question_intents=["ask_for_cm_details", "ask_if_deployed"],
                current_blocker="missing_validation",
                monitoring_signals=[
                    _fact(
                        "DB health after EBS increase",
                        ok_event,
                        0.78,
                        {"Tool": "DB/Grafana metrics", "What it means": "Validation of storage change"},
                    )
                ],
                links_seen=_links_from_events(events),
                compact_summary="EBS increase is deployed and DB looks OK; capture final DB health validation and duplicate CM cleanup.",
            )

        if "edition update" in text and ("zdt job" in text or "partner tenants" in text):
            pending_event = _first(events, "still pending")
            if pending_event.get("event_id") == "m000":
                pending_event = _first(events, "partner tenants")
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                phase=IncidentPhase.MITIGATION,
                impact=ImpactState(
                    description="RevPro edition update mostly mitigated, with named customer/partner tenant validation still pending.",
                    evidence=[_e(_first(events, "edition update")), _e(pending_event)],
                    confidence=0.62,
                ),
                candidate_services=[
                    _entity("RevPro", EntityType.SERVICE, _e(_first(events, "revpro")), canonical_id="revpro"),
                    _entity("ZDT test jobs", EntityType.SERVICE, _e(_first(events, "zdt job")), canonical_id="zdt-test-jobs"),
                    _entity("tenant edition update", EntityType.SERVICE, _e(_first(events, "edition update")), canonical_id="tenant-edition-update"),
                ],
                engaged_entities=[
                    _entity("RevPro", EntityType.TEAM, _e(_first(events, "aaditya")), "engaged_or_requested", "revpro"),
                    _entity("Support", EntityType.TEAM, _e(_first(events, "support")), "engaged_or_requested", "support"),
                ],
                stale_question_intents=["ask_if_all_tenants_done", "ask_to_mitigate_now"],
                current_blocker="waiting_on_monitoring",
                monitoring_signals=[
                    _fact(
                        "ZDT job completion per tenant",
                        _first(events, "zdt job"),
                        0.78,
                        {"Tool": "Arena/Jenkins job links", "What it means": "Tenant validation status"},
                    )
                ],
                links_seen=_links_from_events(events),
                compact_summary="RevPro edition update has pending partner/customer tenant validation and credential blocker; do not mitigate until remaining status is confirmed.",
            )

        if "slack approval" in text and ("jira" in text or "ecm" in text) and "build" in text:
            approval_event = _first(events, "slack approval")
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                phase=IncidentPhase.ENGAGEMENT,
                impact=ImpactState(
                    description="Build/deployment approval is blocked by Jira ECM availability; interim Slack approval documentation requested.",
                    evidence=[_e(approval_event)],
                    confidence=0.55,
                ),
                candidate_services=[
                    _entity("Build/deployment pipeline", EntityType.SERVICE, _e(_first(events, "build")), canonical_id="build-deployment-pipeline"),
                    _entity("Jira ECM", EntityType.SERVICE, _e(_first(events, "ecm")), canonical_id="jira-ecm"),
                ],
                engaged_entities=[
                    _entity("Change Management", EntityType.TEAM, _e(approval_event), "engaged_or_requested", "change-management"),
                    _entity("Engineering", EntityType.TEAM, _e(_first(events, "code change")), "engaged_or_requested", "engineering"),
                ],
                stale_question_intents=["ask_if_zoom_needed", "ask_if_testing_done"],
                current_blocker="waiting_on_deploy",
                monitoring_signals=[
                    _fact(
                        "build/deployment status",
                        _first(events, "build"),
                        0.75,
                        {"Tool": "pipeline", "What it means": "Deployment readiness after approval"},
                    )
                ],
                compact_summary="Jira ECM unavailable; Change Management requested interim Slack approval docs before build/deploy.",
            )

        if "param_total_connection" in text and "data sync job completed" in text:
            signal_event = _first(events, "revenue sync")
            data_sync_event = _first(events, "data sync job completed")
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(value=Severity.P3, evidence=[_e(_first(events, "phase 3"))], confidence=0.7),
                phase=IncidentPhase.VERIFICATION,
                impact=ImpactState(
                    description="Revenue sync/Data Sync validation after param_total_connection change",
                    evidence=[_e(_first(events, "param_total_connection"))],
                    confidence=0.55,
                ),
                candidate_services=[
                    _entity("Data-sync", EntityType.SERVICE, _e(_first(events, "data-sync")), canonical_id="data-sync"),
                    _entity("Sphere", EntityType.SERVICE, _e(_first(events, "sphere")), canonical_id="sphere"),
                    _entity("Zuora Revenue sync", EntityType.SERVICE, _e(_first(events, "revenue sync")), canonical_id="zuora-revenue-sync"),
                ],
                engaged_entities=[
                    _entity("SRE", EntityType.TEAM, _e(_first(events, "sre")), "engaged_or_requested", "sre"),
                    _entity("UNO team", EntityType.TEAM, _e(_first(events, "ccv")), "engaged_or_requested", "uno"),
                    _entity("Revenue", EntityType.TEAM, _e(_first(events, "revenue sync")), "engaged_or_requested", "revenue"),
                ],
                actions_completed=[
                    ActionRecord(
                        action_id="a-data-sync-completed",
                        action_type="validation_progress",
                        summary="Data Sync job completed successfully after parameter change",
                        target="Data Sync",
                        evidence=[_e(data_sync_event)],
                    )
                ],
                stale_question_intents=["ask_if_parameter_needed"],
                current_blocker="missing_validation",
                monitoring_signals=[
                    _fact(
                        "new revenue sync ID completion",
                        signal_event,
                        0.8,
                        {
                            "Tool": "Revenue sync monitoring",
                            "What it means": "Validation after pool increase",
                        },
                    )
                ],
                commands_seen=_commands_from_events(events),
                compact_summary="Data Sync completed after param_total_connection change; verify Data Transformation and revenue sync object completion.",
            )

        if "transfer accounting" in text and (
            "completed successfully" in text or "incident is now mitigated" in text or "can mitigate incident" in text
        ):
            completed_event = _first(events, "completed successfully")
            if completed_event.get("event_id") == "m000":
                completed_event = _first(events, "incident is now mitigated")
            signal = "Transfer Accounting batch completion"
            if "batch 10112" in text:
                signal = "Transfer Accounting batch 10112 completion"
            elif "batch 10058" in text:
                signal = "TA Batch 10058 completion"
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                severity=EvidenceBackedFact(
                    value=Severity.P2 if "p2" in text else Severity.P3,
                    evidence=[_e(_first(events, "p2" if "p2" in text else "p3"))],
                    confidence=0.75,
                ),
                phase=IncidentPhase.MITIGATION,
                impact=ImpactState(
                    description="Transfer Accounting workflow issue; current evidence says TA completed after mitigation work.",
                    evidence=[_e(_first(events, "transfer accounting"))],
                    confidence=0.6,
                ),
                candidate_services=[
                    _entity("Transfer Accounting", EntityType.SERVICE, _e(_first(events, "transfer accounting")), canonical_id="transfer-accounting"),
                    _entity("Zuora Revenue", EntityType.SERVICE, _e(_first(events, "revenue")), canonical_id="zuora-revenue"),
                    _entity("Temporal Workflow Service", EntityType.SERVICE, _e(_first(events, "temporal")), canonical_id="temporal-workflow"),
                ],
                engaged_entities=[
                    _entity("Revenue Engineering", EntityType.TEAM, _e(_first(events, "revenue")), "engaged_or_requested", "revenue-engineering"),
                    _entity("Support", EntityType.TEAM, _e(_first(events, "support")), "engaged_or_requested", "support"),
                    _entity("Database Engineering", EntityType.TEAM, _e(_first(events, "db")), "engaged_or_requested", "database-engineering")
                    if "db" in text
                    else _entity("Mayank", EntityType.PERSON, _e(_first(events, "mayank")), "engaged_or_requested"),
                ],
                actions_completed=[
                    ActionRecord(
                        action_id="a-transfer-accounting-complete",
                        action_type="mitigation_completed",
                        summary="Transfer Accounting batch completed after mitigation work",
                        target="Transfer Accounting",
                        evidence=[_e(completed_event)],
                    )
                ],
                stale_question_intents=["ask_if_revenue_engaged", "ask_impact_scope_generic", "ask_if_zoom_started"],
                current_blocker="waiting_on_monitoring",
                monitoring_signals=[
                    _fact(
                        signal,
                        completed_event,
                        0.82,
                        {
                            "Tool": "Transfer Accounting job status",
                            "What it means": "Mitigation validation",
                        },
                    )
                ],
                commands_seen=_commands_from_events(events),
                compact_summary="Transfer Accounting batch completed after mitigation work; confirm no remaining failures and track RCA separately.",
            )

        if "daco" in text and "long-running quer" in text:
            page_event = _first(events, "daco")
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                phase=IncidentPhase.ENGAGEMENT,
                impact=ImpactState(
                    description="Long-running query pressure under DACO/database query ownership",
                    evidence=[_e(_first(events, "long-running queries"))],
                    confidence=0.45,
                ),
                candidate_services=[
                    _entity("DACO", EntityType.TEAM, _e(page_event), canonical_id="daco"),
                    _entity("database queries", EntityType.SERVICE, _e(_first(events, "long-running queries")), canonical_id="database-queries"),
                ],
                engaged_entities=[
                    _entity("DACO", EntityType.TEAM, _e(page_event), "engaged_or_requested", "daco"),
                    _entity("DBA/SME", EntityType.TEAM, _e(_first(events, "steven")), "engaged_or_requested"),
                ],
                stale_question_intents=["ask_who_to_page", "ask_if_daco_paged"],
                current_blocker="missing_owner",
                monitoring_signals=[
                    _fact(
                        "long-running query status",
                        _first(events, "long-running queries"),
                        0.75,
                        {
                            "Tool": "DB monitoring/logs",
                            "What it means": "Determines whether query pressure is reducing",
                        },
                    )
                ],
                commands_seen=_commands_from_events(events),
                compact_summary="DACO was paged and a specific SME was asked to help with long-running queries.",
            )

        if "zdp" in text and ("pending job exceeds" in text or "restart our pods" in text):
            zdp_event = _first(events, "zdp")
            restart_event = _first(events, "restart our pods")
            return StateDelta(
                incident_id=incident_id,
                source_progress=progress,
                phase=IncidentPhase.ENGAGEMENT,
                impact=ImpactState(
                    description="ZDP latency with OMNI pending job alert in SBX01",
                    evidence=[_e(_first(events, "latency")), _e(_first(events, "pending job"))],
                    confidence=0.55,
                ),
                candidate_services=[
                    _entity("ZDP", EntityType.SERVICE, _e(zdp_event), canonical_id="zdp"),
                    _entity("OMNI pending job", EntityType.SERVICE, _e(_first(events, "pending job")), canonical_id="omni-pending-job"),
                    _entity("SBX01", EntityType.ENVIRONMENT, _e(_first(events, "sbx01")), canonical_id="sbx01"),
                ],
                engaged_entities=[
                    _entity("platform-zdp-service-ep", EntityType.TEAM, _e(_first(events, "platform-zdp-service-ep")), "engaged_or_requested", "platform-zdp-service-ep"),
                    _entity("ZDP", EntityType.TEAM, _e(zdp_event), "engaged_or_requested", "zdp"),
                ],
                stale_question_intents=["ask_who_owns_zdp"],
                current_blocker="waiting_on_mitigation",
                monitoring_signals=[
                    _fact(
                        "OMNI Pending Job Exceeds 15 Minutes",
                        _first(events, "pending job exceeds"),
                        0.8,
                        {"Tool": "PagerDuty/alert", "What it means": "Latency/backlog signal"},
                    )
                ],
                commands_seen=_commands_from_events(events),
                compact_summary="ZDP owner engaged; next step depends on node fix then pod restart per runbook.",
                actions_completed=[
                    ActionRecord(
                        action_id="a-zdp-runbook-next-step",
                        action_type="mitigation_plan_identified",
                        summary="ZDP asked for pod restart after node fix per runbook",
                        actor="Kunal Patange",
                        evidence=[_e(restart_event)],
                    )
                ],
            )

        return None

    def _decision(self, payload: dict) -> ICDecision:
        state = CurrentIncidentState.model_validate(payload["current_state"])
        allowed_targets = payload.get("allowed_targets") or []

        def target_ids_for_name(display_name: str) -> list[str]:
            name = " ".join(display_name.lower().split())
            return [
                str(item.get("target_id"))
                for item in allowed_targets
                if item.get("targetable")
                and " ".join(str(item.get("display_name") or "").lower().split()) == name
                and item.get("target_id")
            ][:1]

        if state.current_blocker == "missing_owner" and state.suggested_but_not_engaged:
            target = state.suggested_but_not_engaged[0]
            if target.display_name == "RevPro Support" and state.impact.affected_count == 27:
                return ICDecision(
                    decision_id="fixture-revpro-engage-owner",
                    incident_id=state.incident_id,
                    move=ICMove.ENGAGE_OWNER,
                    phase=state.phase,
                    output={
                        "say_this": "Looks like Support is pointing this toward RevPro Support, and I do not see RevPro Support engaged yet.",
                        "next_line": "RevPro Support, we have a P3 RevPro deployment/version mismatch affecting 27 customers. Can you help confirm ownership and the next validation step?",
                        "command": "@zsrebot oncall RevPro support",
                    },
                    target_ids=target_ids_for_name(target.display_name),
                    targets=[target],
                    rationale=["Support suggested RevPro Support, with no visible acknowledgement."],
                    grounding=target.evidence + (state.impact.evidence or []),
                    confidence=0.9,
                )
        if (
            state.current_blocker == "waiting_on_monitoring"
            and "data augmentation" in state.compact_summary.lower()
            and state.monitoring_signals
        ):
            target = next(
                (entity for entity in state.engaged_entities if entity.display_name == "Revenue Engineering"),
                state.engaged_entities[0] if state.engaged_entities else None,
            )
            grounding = []
            if target:
                grounding.extend(target.evidence)
            for action in state.actions_completed:
                grounding.extend(action.evidence)
            for signal in state.monitoring_signals:
                grounding.extend(signal.evidence)
            return ICDecision(
                decision_id="fixture-in10984-monitoring",
                incident_id=state.incident_id,
                move=ICMove.REQUEST_MONITORING_SIGNAL,
                phase=state.phase,
                output={
                    "say_this": "The timeout increase is deployed and the data augmentation step completed; let's monitor the remaining job stages before calling this fully resolved.",
                    "next_line": "Revenue Engineering, please confirm final job completion and whether any customer data collection jobs are still failing.",
                    "monitor_next": {
                        "Signal": "data augmentation step/job completion",
                        "Tool": "RevPro job status/logs",
                        "What it means": "Validation after socket timeout change",
                    },
                },
                target_ids=target_ids_for_name(target.display_name) if target else [],
                targets=[target] if target else [],
                rationale=["Latest visible blocker is monitoring job completion after the timeout change."],
                grounding=grounding,
                confidence=0.72,
            )
        raise NotImplementedError("No fixture ICDecision for this state")
