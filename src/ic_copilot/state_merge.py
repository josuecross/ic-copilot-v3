from __future__ import annotations

import re

from ic_copilot.schemas import (
    ActionRecord,
    CommandCandidate,
    CurrentIncidentState,
    EntityRef,
    EvidenceBackedFact,
    LinkRef,
    QuestionRecord,
    StateDelta,
    utc_now,
)


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _entity_key(entity: EntityRef) -> str:
    return _norm(entity.canonical_id or entity.display_name)


def _fact_key(fact: EvidenceBackedFact) -> str:
    return _norm(fact.value)


def _question_key(question: QuestionRecord) -> str:
    return f"{_norm(question.intent)}::{_norm(question.target or question.text)}"


def _merge_entities(existing: list[EntityRef], incoming: list[EntityRef]) -> list[EntityRef]:
    by_key = {_entity_key(entity): entity for entity in existing}
    for entity in incoming:
        key = _entity_key(entity)
        if key in by_key:
            current = by_key[key]
            evidence = current.evidence + [
                ref for ref in entity.evidence if ref.event_id not in {e.event_id for e in current.evidence}
            ]
            if entity.confidence >= current.confidence or entity.status not in {"mentioned", "suggested_not_engaged"}:
                by_key[key] = entity.model_copy(update={"evidence": evidence})
            else:
                by_key[key] = current.model_copy(update={"evidence": evidence})
        else:
            by_key[key] = entity
    return list(by_key.values())


def _merge_facts(existing: list[EvidenceBackedFact], incoming: list[EvidenceBackedFact]) -> list[EvidenceBackedFact]:
    by_key = {_fact_key(fact): fact for fact in existing}
    for fact in incoming:
        key = _fact_key(fact)
        if key in by_key:
            current = by_key[key]
            evidence = current.evidence + [
                ref for ref in fact.evidence if ref.event_id not in {e.event_id for e in current.evidence}
            ]
            by_key[key] = (fact if fact.confidence >= current.confidence else current).model_copy(
                update={"evidence": evidence}
            )
        else:
            by_key[key] = fact
    return list(by_key.values())


def _merge_actions(existing: list[ActionRecord], incoming: list[ActionRecord]) -> list[ActionRecord]:
    by_key = {action.action_id: action for action in existing}
    for action in incoming:
        by_key[action.action_id] = action
    return list(by_key.values())


def _merge_commands(existing: list[CommandCandidate], incoming: list[CommandCandidate]) -> list[CommandCandidate]:
    by_key = {_norm(command.command): command for command in existing}
    for command in incoming:
        by_key[_norm(command.command)] = command
    return list(by_key.values())


def _merge_links(existing: list[LinkRef], incoming: list[LinkRef]) -> list[LinkRef]:
    by_key = {link.url: link for link in existing}
    for link in incoming:
        by_key[link.url] = link
    return list(by_key.values())


def _is_stale_question(question: QuestionRecord, state: CurrentIncidentState) -> bool:
    intent = _norm(question.intent)
    target = _norm(question.target)
    if intent in {_norm(value) for value in state.stale_question_intents}:
        return True
    if any(_question_key(question) == _question_key(answered) for answered in state.answered_questions):
        return True
    if intent in {"already_looped_in", "is_engaged", "engagement_status"} and target:
        suggested = {
            value
            for entity in state.suggested_but_not_engaged
            for value in {_entity_key(entity), _norm(entity.display_name), _norm(entity.canonical_id)}
            if value
        }
        engaged = {
            value
            for entity in state.engaged_entities
            for value in {_entity_key(entity), _norm(entity.display_name), _norm(entity.canonical_id)}
            if value
        }
        if target in suggested or target in engaged:
            return True
    return False


def _promote_rejected(
    rejected_entities: list[EntityRef],
    candidate_services: list[EntityRef],
    engaged_entities: list[EntityRef],
    suggested_entities: list[EntityRef],
) -> list[EntityRef]:
    promoted = {_entity_key(entity) for entity in candidate_services + engaged_entities + suggested_entities if entity.confidence >= 0.85}
    protected_reasons = ("url_domain", "url_path_number", "bot_system_message", "display_name_fragment")
    kept = []
    for entity in rejected_entities:
        if any(reason in entity.status for reason in protected_reasons):
            kept.append(entity)
        elif _entity_key(entity) not in promoted:
            kept.append(entity)
    return kept


def merge_state_delta(current_state: CurrentIncidentState | dict | None, delta: StateDelta | dict) -> CurrentIncidentState:
    delta = StateDelta.model_validate(delta)
    if current_state is None:
        current_state = CurrentIncidentState(incident_id=delta.incident_id)
    elif isinstance(current_state, dict):
        current_state = CurrentIncidentState.model_validate(current_state)
    state = current_state.model_copy(deep=True)
    state.state_version += 1
    state.updated_at = utc_now()
    state.source_progress.update(delta.source_progress)

    if delta.severity and (
        state.severity is None
        or delta.severity.confidence >= state.severity.confidence
        or delta.severity.evidence
    ):
        state.severity = delta.severity

    if delta.phase is not None:
        state.phase = delta.phase

    if delta.impact is not None:
        if not state.impact.has_useful_info() or delta.impact.confidence >= state.impact.confidence:
            state.impact = delta.impact
        else:
            state.impact.affected_customers = _merge_facts(
                state.impact.affected_customers, delta.impact.affected_customers
            )
            state.impact.affected_tenants = _merge_facts(
                state.impact.affected_tenants, delta.impact.affected_tenants
            )
            state.impact.evidence.extend(
                ref for ref in delta.impact.evidence if ref.event_id not in {e.event_id for e in state.impact.evidence}
            )
            if state.impact.affected_count is None:
                state.impact.affected_count = delta.impact.affected_count

    state.candidate_services = _merge_entities(state.candidate_services, delta.candidate_services)
    state.engaged_entities = _merge_entities(state.engaged_entities, delta.engaged_entities)
    state.suggested_but_not_engaged = _merge_entities(
        state.suggested_but_not_engaged, delta.suggested_but_not_engaged
    )

    engaged_keys = {
        value
        for entity in state.engaged_entities
        for value in {_entity_key(entity), _norm(entity.display_name), _norm(entity.canonical_id)}
        if value
    }
    updated_engaged = []
    for engaged in state.engaged_entities:
        engaged_values = {
            value
            for value in {_entity_key(engaged), _norm(engaged.display_name), _norm(engaged.canonical_id)}
            if value
        }
        extra_evidence = []
        existing_ids = {ref.event_id for ref in engaged.evidence}
        for suggested in state.suggested_but_not_engaged:
            suggested_values = {
                value
                for value in {_entity_key(suggested), _norm(suggested.display_name), _norm(suggested.canonical_id)}
                if value
            }
            if engaged_values.intersection(suggested_values):
                extra_evidence.extend(ref for ref in suggested.evidence if ref.event_id not in existing_ids)
        updated_engaged.append(engaged.model_copy(update={"evidence": engaged.evidence + extra_evidence}))
    state.engaged_entities = updated_engaged
    state.suggested_but_not_engaged = [
        entity
        for entity in state.suggested_but_not_engaged
        if not {
            value
            for value in {_entity_key(entity), _norm(entity.display_name), _norm(entity.canonical_id)}
            if value
        }.intersection(engaged_keys)
    ]

    state.actions_completed = _merge_actions(state.actions_completed, delta.actions_completed)
    state.monitoring_signals = _merge_facts(state.monitoring_signals, delta.monitoring_signals)
    state.commands_seen = _merge_commands(state.commands_seen, delta.commands_seen)
    state.links_seen = _merge_links(state.links_seen, delta.links_seen)

    answered_by_intent = {_question_key(question): question for question in state.answered_questions}
    for answered in delta.answered_questions:
        answered_by_intent[_question_key(answered)] = answered.model_copy(update={"status": "answered"})
    state.answered_questions = list(answered_by_intent.values())

    answered_keys = set(answered_by_intent)
    open_by_key = {
        _question_key(question): question
        for question in state.open_questions
        if _question_key(question) not in answered_keys and question.status == "open"
    }
    stale_intents = {_norm(intent) for intent in state.stale_question_intents}
    for question in delta.open_questions:
        if _is_stale_question(question, state):
            stale_intents.add(_norm(question.intent))
            continue
        key = _question_key(question)
        if key not in answered_keys:
            open_by_key[key] = question
    state.open_questions = list(open_by_key.values())
    state.stale_question_intents = sorted(stale_intents.union(_norm(intent) for intent in delta.stale_question_intents))

    state.rejected_entities = _merge_entities(state.rejected_entities, delta.rejected_entities)
    state.rejected_entities = _promote_rejected(
        state.rejected_entities,
        state.candidate_services,
        state.engaged_entities,
        state.suggested_but_not_engaged,
    )

    state.unknowns = sorted(set(state.unknowns).union(delta.unknowns))
    state.safety_flags = sorted(set(state.safety_flags).union(delta.safety_flags))
    if delta.current_blocker:
        state.current_blocker = delta.current_blocker
    if delta.compact_summary:
        state.compact_summary = delta.compact_summary
    elif not state.compact_summary:
        state.compact_summary = "Current incident state updated from evidence."

    return state
