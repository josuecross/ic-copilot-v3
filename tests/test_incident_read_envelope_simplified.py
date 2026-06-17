from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from ic_copilot.incident_brief import build_allowed_targets
from ic_copilot.incident_read_v2 import incident_read_v2_from_v1_fixture
from ic_copilot.catalog import load_command_registry, load_service_catalog
from ic_copilot.evidence_quality import classify_events_quality
from ic_copilot.memory import judge_applicability, load_decision_moments
from ic_copilot.normalizers.slack_paste import normalize_slack_paste
from ic_copilot.pipeline import run_pipeline
from ic_copilot.read_and_whisper import (
    build_incident_read_context_pack,
    build_ultra_compact_incident_read_context_pack,
    normalize_incident_read_envelope,
)
from ic_copilot.schemas import (
    AllowedTarget,
    CurrentIncidentState,
    ICMove,
    IncidentReadAndWhisper,
    IncidentReadAndWhisperV2,
    InputSizeAssessment,
    LatestWindowSelection,
    WhisperEvidenceRef,
)
from ic_copilot.verifier import detect_unregistered_commands
from ic_copilot.work_items import extract_current_work_items


class _ReadClient:
    def __init__(self, read_factory):
        self.read_factory = read_factory
        self.payloads: list[dict[str, Any]] = []

    def generate_json(self, prompt_name: str, input_payload: dict, response_model: type[BaseModel]):
        self.payloads.append(input_payload)
        if response_model is IncidentReadAndWhisper or response_model.__name__ == "IncidentReadAndWhisper":
            return self.read_factory(input_payload)
        if response_model is IncidentReadAndWhisperV2 or response_model.__name__ == "IncidentReadAndWhisperV2":
            read = self.read_factory(input_payload)
            if isinstance(read, dict):
                return read
            return incident_read_v2_from_v1_fixture(
                read=read,
                context_pack=input_payload,
            )
        raise AssertionError(f"unexpected prompt/model in simplified product path: {prompt_name} {response_model}")


def _selection(events) -> LatestWindowSelection:
    return LatestWindowSelection(
        event_ids=[event.event_id for event in events],
        reason="test latest window",
        dropped_event_count=0,
        kept_event_count=len(events),
        contains_latest_human_evidence=True,
    )


def _assessment(events) -> InputSizeAssessment:
    text = "\n".join(event.message for event in events)
    return InputSizeAssessment(
        event_count=len(events),
        character_count=len(text),
        estimated_token_count=max(1, len(text) // 4),
    )


def _context_pack(events, allowed_targets):
    return build_incident_read_context_pack(
        incident_id="envelope",
        latest_window_events=events,
        input_size_assessment=_assessment(events),
        latest_window_selection=_selection(events),
        allowed_targets=allowed_targets,
        command_registry=[],
        catalog=[],
        accepted_memories=[],
        event_quality=[],
    )


class _TimeoutThenReadClient:
    def __init__(self, read_factory, *, timeout_count: int = 1):
        self.read_factory = read_factory
        self.timeout_count = timeout_count
        self.payloads: list[dict[str, Any]] = []

    def generate_json(self, prompt_name: str, input_payload: dict, response_model: type[BaseModel]):
        self.payloads.append(input_payload)
        if response_model not in {IncidentReadAndWhisper, IncidentReadAndWhisperV2} and response_model.__name__ not in {
            "IncidentReadAndWhisper",
            "IncidentReadAndWhisperV2",
        }:
            raise AssertionError(f"unexpected prompt/model in simplified product path: {prompt_name} {response_model}")
        if len(self.payloads) <= self.timeout_count:
            raise TimeoutError("provider timed out while reading latest incident context")
        read = self.read_factory(input_payload)
        if response_model is IncidentReadAndWhisper or response_model.__name__ == "IncidentReadAndWhisper":
            return read
        return incident_read_v2_from_v1_fixture(read=read, context_pack=input_payload)


COMPACT_AUDIT_EVENT_LATENCY_PASTE = """zsrebot  [10:05 AM]
joined #p2_in-11032_260502.zsrebot  [10:05 AM]
set the channel topic: audit event latencyAnanthadev  [10:05 AM]
joined #p2_in-11032_260502
Vignesh S S  [10:06 AM]
ESG team confirmed the pod can connect to Kafka broker.
curl -v http://speed-racer-kafka:9092
* Connected to speed-racer-kafka port 9092
jinhui.zhao  [10:07 AM]
https://teamzuora.slack.com/archives/C123/p456
Please kafka oncall help...
we got
[Producer clientId=notary-message-producer] Connection to node -1 could not be established. Broker may not be available.
pod info,
kubectl -n genesis get pods
Notary event worker pods are Running.
And ESG team already confirmed
I can see pod can connect
you might want to check on may cert/runtime config.
"""


INITIAL_DB_CPU_ALERT_PASTE = """p3_in-11037_260503
@zsrebot created this channel on May 3rd. This is the very beginning of the p3_in-11037_260503 channel.
zsrebot
APP  5:43 PM
joined #p3_in-11037_260503.
zsrebot
APP  5:43 PM
set the channel topic: [FIRING] [Critical] dbc7i1.0001.sbx.auw2.zuora CPU / Memory CPUBusyPercent 98.91168376181848 Threshold > 90
zsrebot
APP  5:43 PM
:fire: An incident has been created!
Summary
[FIRING] [Critical] dbc7i1.0001.sbx.auw2.zuora CPU / Memory CPUBusyPercent 98.91168376181848 Threshold > 90
P3 incident - No auto engage.
zsrebot
APP  5:44 PM
:correct: Engaging Self-Checking Workflow
5:44
:check-img: checking shard Replication Lag...
5:44
| instance:port [role]                      | sbm | pthb | io | sql | workers | conn | ins_type   |
| dbc7i1.0001.sbx.auw2.zuora:3306 [ACW]     | 0s  | 0s   | N  | N   | 32      | 925  | r7g.xlarge |
| dbc7i2.0001.sbx.auw2.zuora:3306 [ACR,SBW] | 1s  | 0s   | Y  | Y   | 32      | 2    | r7g.xlarge |
5:44
:check-img: checking dbc7i1.0001.sbx.auw2.zuora CPU & Memory Snapshot...
5:44
:check-img: checking dbc7i1.0001.sbx.auw2.zuora Shard Dune Jobs...
Anantha
APP  5:44 PM
:robot: [IM-Agent] Hey @Fang Zheng Could you please help to check this incident.
5:44
Phase Update: Phase 1 - Acknowledge
Incident created, teams are engaging, initial investigation is in progress.
5:44
:robot: [IM-Agent] I will involve Database_Agent for incident analysis...
"""


REVPRO_EARLY_OWNER_ROUTING_PASTE = """Support Coordinator  [8:45 AM]
After the RevPro deployment, 27 customers have a version mismatch. Raghunandan, could you please confirm if this is RevPro and whether we should engage RevPro Support?
Raghunandan  [8:48 AM]
This looks like a Zuora Revenue / RevPro deployment version mismatch. Please engage RevPro Support to own the mismatch check.
"""


def _audit_context_pack(events, targets, event_quality):
    text = "\n".join(event.message for event in events)
    catalog = load_service_catalog("local_knowledge/service_catalog.yaml")
    command_registry = load_command_registry("local_knowledge/command_registry.yaml", catalog)
    return build_incident_read_context_pack(
        incident_id="audit-latency",
        latest_window_events=events,
        input_size_assessment=InputSizeAssessment(
            event_count=len(events),
            character_count=len(text),
            estimated_token_count=max(1, len(text) // 4),
        ),
        latest_window_selection=LatestWindowSelection(
            event_ids=[event.event_id for event in events],
            reason="compact audit latency test",
            dropped_event_count=0,
            kept_event_count=len(events),
            contains_latest_human_evidence=True,
        ),
        allowed_targets=targets,
        command_registry=command_registry,
        catalog=catalog,
        accepted_memories=[],
        event_quality=event_quality,
    )


def test_compact_audit_latency_paste_recovers_human_diagnostic_events() -> None:
    events = normalize_slack_paste(COMPACT_AUDIT_EVENT_LATENCY_PASTE, incident_id="audit-latency")
    quality = classify_events_quality(events)

    by_author = {event.author: event for event in events}
    assert "jinhui.zhao" in by_author
    assert "Vignesh S S" in by_author
    assert "Connection to node -1 could not be established" in by_author["jinhui.zhao"].message
    assert "pod can connect" in by_author["jinhui.zhao"].message
    assert "cert/runtime config" in by_author["jinhui.zhao"].message
    assert "pod can connect to Kafka broker" in by_author["Vignesh S S"].message

    quality_by_id = {item.event_id: item for item in quality}
    assert quality_by_id[by_author["jinhui.zhao"].event_id].event_kind == "human_diagnostic_evidence"
    assert quality_by_id[by_author["jinhui.zhao"].event_id].is_planner_grounding_allowed
    assert quality_by_id[by_author["Vignesh S S"].event_id].event_kind == "human_diagnostic_evidence"
    assert quality_by_id[by_author["Vignesh S S"].event_id].is_planner_grounding_allowed
    assert quality_by_id[by_author["jinhui.zhao"].event_id].is_blocker_evidence_allowed
    assert quality_by_id[by_author["Vignesh S S"].event_id].is_blocker_evidence_allowed


def test_compact_audit_latency_context_retains_diagnostic_evidence_and_filters_noise_targets() -> None:
    events = normalize_slack_paste(COMPACT_AUDIT_EVENT_LATENCY_PASTE, incident_id="audit-latency")
    quality = classify_events_quality(events)
    targets = build_allowed_targets(
        events,
        load_service_catalog("local_knowledge/service_catalog.yaml"),
        load_command_registry("local_knowledge/command_registry.yaml", load_service_catalog("local_knowledge/service_catalog.yaml")),
    )
    context_pack = _audit_context_pack(events, targets, quality)
    model_text = "\n".join(event["text"] for event in context_pack["latest_window_events"])
    candidate_names = {target["display_name"] for target in context_pack["candidate_targets"]}

    assert "Connection to node -1" in model_text
    assert "Broker may n" in model_text
    assert "pod can connect" in model_text
    assert "cert/runtime config" in model_text
    assert "teamzuora.slack.com/archives" not in model_text
    assert context_pack["retained_high_signal_diagnostic_event_ids"] == ["m003", "m004"]
    assert context_pack["dropped_high_signal_diagnostic_event_ids"] == []
    for noisy_name in {
        "zsrebot",
        "APP",
        "set the channel topic",
        "kubectl",
        "curl",
        "Running",
        "Connected",
        "speed-racer-kafka",
        "9092",
    }:
        assert noisy_name not in candidate_names
    assert {"Developer Success / ESG", "Notary Event Worker", "ESG Deployment / Config Support"}.intersection(
        candidate_names
    )


def test_compact_audit_latency_memory_applicability_accepts_config_drift_shape() -> None:
    events = normalize_slack_paste(COMPACT_AUDIT_EVENT_LATENCY_PASTE, incident_id="audit-latency")
    evidence_text = "\n".join(event.message for event in events)
    moment = next(
        item
        for item in load_decision_moments("local_knowledge/decision_moments.jsonl")
        if item.decision_id == "DM_kafka_connection_error_check_service_config_drift"
    )

    result = judge_applicability(
        CurrentIncidentState(incident_id="audit-latency"),
        [moment],
        current_evidence_text=evidence_text,
    )[0]

    assert result.accepted
    assert result.required_current_evidence_missing == []


def test_compact_audit_latency_useful_one_call_output_passes(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(COMPACT_AUDIT_EVENT_LATENCY_PASTE)

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        model_text = "\n".join(event["text"] for event in payload["latest_window_events"])
        assert "Connection to node -1" in model_text
        assert "pod can connect" in model_text
        assert "cert/runtime config" in model_text
        assert "DM_kafka_connection_error_check_service_config_drift" in {
            item["decision_id"] for item in payload["decision_moment_behavior_hints"]
        }
        target = next(
            item
            for item in payload["candidate_targets"]
            if item["display_name"] in {"Developer Success / ESG", "ESG Deployment / Config Support", "Notary Event Worker"}
        )
        event = next(event for event in payload["latest_window_events"] if "Connection to node -1" in event["text"])
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read=(
                "Notary producer reports a Kafka broker connection error while current evidence says the pod can reach Kafka."
            ),
            latest_open_loop="Need Kafka health versus service cert/runtime config validation and recovery signal.",
            selected_move=ICMove.ENGAGE_OWNER,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this=(
                f"@{target['display_name']}, since the pod can reach Kafka but the producer still reports node -1 "
                "unavailable, can you confirm Kafka health versus client cert/config drift and what signal shows "
                "audit-event latency is recovering?"
            ),
            evidence=[
                WhisperEvidenceRef(
                    event_id=event["event_id"],
                    quote="Connection to node -1 could not be established. Broker may not be available.",
                )
            ],
            confidence=0.86,
        )

    result = run_pipeline(
        incident,
        catalog_path="local_knowledge/service_catalog.yaml",
        command_registry_path="local_knowledge/command_registry.yaml",
        memory_path="local_knowledge/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["verifier_result"].passed
    assert result["decision"].move == ICMove.ENGAGE_OWNER
    assert "I do not have a safe" not in result["final_output"]
    lowered = result["final_output"].lower()
    assert "kafka" in lowered
    assert "cert/config" in lowered or "config drift" in lowered
    assert "audit-event latency" in lowered
    for forbidden in ("page kafka", "run kubectl", "curl ", "restart", "rotate", "execute"):
        assert forbidden not in lowered
    safety = result["trace"].safety_summary
    assert safety["recovered_compact_author_count"] >= 3
    assert safety["human_diagnostic_grounding_count"] >= 2
    assert safety["retained_high_signal_diagnostic_event_ids"] == ["m003", "m004"]
    assert safety["dropped_high_signal_diagnostic_event_ids"] == []


def test_revpro_early_routing_memory_is_accepted_and_injected_into_v2(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(REVPRO_EARLY_OWNER_ROUTING_PASTE)

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        memory_ids = {item["decision_id"] for item in payload["decision_moment_behavior_hints"]}
        contract_ids = {item["decision_id"] for item in payload["accepted_memory_behavior_contracts"]}
        assert "DM_revpro_early_deployment_mismatch_owner_routing" in memory_ids
        assert "DM_revpro_early_deployment_mismatch_owner_routing" in contract_ids
        assert "DM_multitenant_postdeploy_owner_split" not in contract_ids
        model_text = "\n".join(event["text"] for event in payload["latest_window_events"])
        assert "27 customers" in model_text
        assert "version mismatch" in model_text
        assert "engage RevPro Support" in model_text
        target = next(
            item
            for preferred in ("RevPro Support", "Raghunandan", "Zuora Revenue / RevPro", "RevPro")
            for item in payload["candidate_targets"]
            if item["display_name"] == preferred
        )
        event = next(event for event in payload["latest_window_events"] if "mismatch check" in event["text"])
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="RevPro deployment version mismatch affects multiple customers.",
            latest_open_loop="Need RevPro Support ownership and mismatch-check engagement confirmed.",
            selected_move=ICMove.ENGAGE_OWNER,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this=(
                f"@{target['display_name']}, can you confirm ownership for the RevPro deployment version mismatch "
                "and who is starting the mismatch check?"
            ),
            evidence=[
                WhisperEvidenceRef(
                    event_id=event["event_id"],
                    quote="Please engage RevPro Support to own the mismatch check.",
                )
            ],
            confidence=0.87,
        )

    result = run_pipeline(
        incident,
        catalog_path="local_knowledge/service_catalog.yaml",
        command_registry_path="local_knowledge/command_registry.yaml",
        memory_path="local_knowledge/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    trace = result["trace"]
    assert "DM_revpro_early_deployment_mismatch_owner_routing" in trace.accepted_memory_ids
    assert "DM_multitenant_postdeploy_owner_split" not in trace.accepted_memory_ids
    assert result["decision"].move == ICMove.ENGAGE_OWNER
    assert result["verifier_result"].passed
    assert not trace.safety_summary["fallback_used"]
    assert trace.safety_summary["runtime_knowledge_counts"]["decision_moments"] >= 101
    assert "I do not have a safe" not in result["final_output"]
    assert "version mismatch" in result["final_output"]


def test_initial_db_cpu_alert_bot_diagnostics_ground_without_becoming_targets() -> None:
    events = normalize_slack_paste(INITIAL_DB_CPU_ALERT_PASTE, incident_id="db-cpu-initial")
    quality = classify_events_quality(events)
    quality_by_id = {item.event_id: item for item in quality}
    assert any(item.event_kind == "bot_diagnostic_evidence" for item in quality)
    assert any(
        item.event_kind == "bot_diagnostic_evidence" and item.is_planner_grounding_allowed and not item.is_target_source_allowed
        for item in quality
    )

    catalog = load_service_catalog("local_knowledge/service_catalog.yaml")
    targets = build_allowed_targets(
        events,
        catalog,
        load_command_registry("local_knowledge/command_registry.yaml", catalog),
    )
    context_pack = build_incident_read_context_pack(
        incident_id="db-cpu-initial",
        latest_window_events=events,
        input_size_assessment=_assessment(events),
        latest_window_selection=_selection(events),
        allowed_targets=targets,
        command_registry=load_command_registry("local_knowledge/command_registry.yaml", catalog),
        catalog=catalog,
        accepted_memories=[],
        event_quality=quality,
    )
    retained_fact_ids = {fact["fact_id"] for fact in context_pack["retained_diagnostic_facts"]}
    candidate_names = {target["display_name"] for target in context_pack["candidate_targets"]}
    candidate_classes = {target["target_class"] for target in context_pack["candidate_targets"]}
    classifications = {
        item["fact_id"]: item
        for item in context_pack["diagnostic_fact_classifications"]
    }

    assert {"db_cpu_threshold", "db_instance_or_host", "replication_lag_status", "dune_or_jobs_check", "database_agent_involvement"}.issubset(retained_fact_ids)
    assert "sync_latency_topic_permission" not in retained_fact_ids
    assert "temporal_transfer_accounting" not in retained_fact_ids
    assert "DBA" in candidate_names
    assert "database_owner" in candidate_classes
    assert "DACO / Sync" not in candidate_names
    assert "Transfer Accounting" not in candidate_names
    assert "Workflow Service" not in candidate_names
    assert "Fang" not in candidate_names
    assert classifications["db_cpu_threshold"]["allowed_for"]["model_grounding"]
    assert not classifications["db_cpu_threshold"]["allowed_for"]["target_selection"]
    assert quality_by_id["m003"].event_kind == "bot_diagnostic_evidence"


def test_initial_db_cpu_no_safe_fails_original_verifier(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(INITIAL_DB_CPU_ALERT_PASTE)

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        assert "DIAG_db_cpu_initial_database_owner_status" in {
            item["decision_id"] for item in payload["diagnostic_behavior_contracts"]
        }
        assert any(target["display_name"] == "DBA" for target in payload["candidate_targets"])
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="No safe move.",
            latest_open_loop="No safe move.",
            selected_move=ICMove.NO_SAFE_RECOMMENDATION,
            say_this="I do not have a safe, grounded next move yet.",
            confidence=0.2,
        )

    result = run_pipeline(
        incident,
        catalog_path="local_knowledge/service_catalog.yaml",
        command_registry_path="local_knowledge/command_registry.yaml",
        memory_path="local_knowledge/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    checks = result["trace"].safety_summary["simplified_verifier_checks"]
    assert checks["no_safe_despite_diagnostic_signal"] is False
    assert any("DB CPU alert" in claim for claim in result["trace"].safety_summary["original_blocked_claims"])


def test_initial_db_cpu_wrong_daco_target_fails_without_failed_records(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(INITIAL_DB_CPU_ALERT_PASTE)
    parsed_events = normalize_slack_paste(INITIAL_DB_CPU_ALERT_PASTE, incident_id="db-cpu-initial")
    catalog = load_service_catalog("local_knowledge/service_catalog.yaml")
    allowed = build_allowed_targets(
        parsed_events,
        catalog,
        load_command_registry("local_knowledge/command_registry.yaml", catalog),
    )
    daco_target_id = next(
        target.target_id
        for target in allowed
        if target.display_name == "DACO / Sync" and target.targetable
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        event = next(event for event in payload["latest_window_events"] if "CPUBusyPercent" in event["text"])
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="DB CPU is above threshold.",
            latest_open_loop="Need status.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=daco_target_id,
            selected_target_display_name="DACO / Sync",
            say_this="@DACO / Sync, can you share the failed_records DB CPU status?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote="CPUBusyPercent 98.91168376181848 Threshold > 90")],
            confidence=0.8,
        )

    result = run_pipeline(
        incident,
        catalog_path="local_knowledge/service_catalog.yaml",
        command_registry_path="local_knowledge/command_registry.yaml",
        memory_path="local_knowledge/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    checks = result["trace"].safety_summary["simplified_verifier_checks"]
    assert checks["accepted_memory_target_class_satisfied"] is False or checks["selected_target_allowed"] is False


def test_quote_canonicalization_repairs_safe_paraphrase() -> None:
    events = normalize_slack_paste(
        "[10:01] henryzhu: Kafka team is reviewing cluster performance and event latency. ETA will follow after investigation.",
        incident_id="envelope",
    )
    targets = build_allowed_targets(events, [], [])
    context_pack = _context_pack(events, targets)
    target = context_pack["candidate_targets"][0]
    read = IncidentReadAndWhisper(
        incident_id="envelope",
        current_read="Kafka performance and event latency investigation is active.",
        latest_open_loop="Need investigation status and ETA.",
        selected_move=ICMove.REQUEST_STATUS_OR_ETA,
        selected_target_id=target["target_id"],
        selected_target_display_name=target["display_name"],
        say_this="henryzhu, can you share the Kafka investigation status and ETA for event latency?",
        evidence=[
            WhisperEvidenceRef(
                event_id=events[0].event_id,
                quote="Henry is coordinating Kafka performance and event latency.",
            )
        ],
        confidence=0.8,
    )

    normalized, metadata = normalize_incident_read_envelope(
        read,
        context_pack=context_pack,
        latest_window_events=events,
    )

    assert metadata["evidence_quote_canonicalized"] is True
    assert normalized.evidence[0].quote in events[0].message
    assert normalized.selected_move == read.selected_move
    assert normalized.selected_target_id == read.selected_target_id
    assert normalized.say_this == read.say_this


def test_duplicate_target_id_remaps_to_canonical_human_author() -> None:
    events = normalize_slack_paste(
        "[10:00] zsrebot: Hi @henryzhu please acknowledge.\n"
        "[10:01] henryzhu: Kafka team is reviewing event latency now.",
        incident_id="envelope",
    )
    targets = build_allowed_targets(events, [], [])
    context_pack = _context_pack(events, targets)
    alias = next(item for item in context_pack["target_aliases"] if item["canonical_display_name"] == "henryzhu")
    read = IncidentReadAndWhisper(
        incident_id="envelope",
        current_read="Event latency review is active.",
        latest_open_loop="Need status from the current reviewer.",
        selected_move=ICMove.REQUEST_STATUS_OR_ETA,
        selected_target_id=alias["alias_target_ids"][0],
        selected_target_display_name="henryzhu",
        say_this="henryzhu, can you share the current event-latency review status?",
        evidence=[WhisperEvidenceRef(event_id=events[-1].event_id, quote=events[-1].message)],
    )

    normalized, metadata = normalize_incident_read_envelope(
        read,
        context_pack=context_pack,
        latest_window_events=events,
    )

    assert metadata["target_id_canonicalized"] is True
    assert normalized.selected_target_id == alias["canonical_target_id"]
    assert normalized.selected_target_display_name == "henryzhu"


def test_noisy_targets_filtered_from_model_facing_candidates() -> None:
    events = normalize_slack_paste(
        "Coordinator\n"
        "10:00 AM\n"
        "Investigating now.\n"
        "Kafka Investigation:\n"
        "Trust Post:\n"
        "Monitor Workers:\n"
        "Incident Commander:\n"
        "Current Status:\n"
        "Heavy Database Load:\n"
        "1. Severity Downgrade & Tenant Impact:\n"
        "screenshot.png:\n"
        "ticket created to bigglobe:\n",
        incident_id="noise-targets",
    )
    targets = build_allowed_targets(events, [], [])
    context_pack = _context_pack(events, targets)
    candidate_names = {target["display_name"] for target in context_pack["candidate_targets"]}
    rejected_names = {target["display_name"] for target in context_pack["do_not_target"]}

    assert "Coordinator" in candidate_names
    for name in {
        "Kafka Investigation",
        "Trust Post",
        "Monitor Workers",
        "Incident Commander",
        "Current Status",
        "Heavy Database Load",
        "1. Severity Downgrade & Tenant Impact",
        "screenshot.png",
        "ticket created to bigglobe",
    }:
        assert name not in candidate_names
        if name in {target.display_name for target in targets}:
            assert name in rejected_names


def test_bot_summary_headings_are_not_model_facing_targets() -> None:
    events = normalize_slack_paste(
        "[10:00] APP: Incident Summary:\n"
        "Issue:\n"
        "Issue Status:\n"
        "Roles:\n"
        "Teams Involved:\n"
        "Services Impacted:\n"
        "Tenants Impacted:\n"
        "Next Action:\n"
        "Owners:\n"
        "Checkpoint:\n"
        "[10:05] Priya N: Security owner is reviewing the exposure and validation path.",
        incident_id="summary-labels",
    )
    targets = build_allowed_targets(events, [], [])
    context_pack = _context_pack(events, targets)
    candidate_names = {target["display_name"] for target in context_pack["candidate_targets"]}

    assert "Priya N" in candidate_names
    for name in {
        "Issue",
        "Issue Status",
        "Roles",
        "Teams Involved",
        "Services Impacted",
        "Tenants Impacted",
        "Next Action",
        "Owners",
    }:
        assert name not in candidate_names


def test_preview_and_meeting_labels_are_not_model_facing_targets() -> None:
    events = normalize_slack_paste(
        "[10:00] Zoom APP: Call\n"
        "Meeting ID: 12345678901\n"
        "Status: started\n"
        "Priority: High\n"
        "Assignee: Security team\n"
        "Refresh\n"
        "[10:03] Coordinator: Security team is checking exposure status.",
        incident_id="preview-labels",
    )
    targets = build_allowed_targets(events, [], [])
    context_pack = _context_pack(events, targets)
    candidate_names = {target["display_name"] for target in context_pack["candidate_targets"]}

    for name in {"Meeting ID", "Status", "Priority", "Assignee", "Refresh", "Call", "Zoom APP"}:
        assert name not in candidate_names


def test_context_pack_is_hard_bounded_and_omits_unmatched_catalog_command_memory() -> None:
    lines = ["[09:00] APP: Incident Summary: older bot summary"]
    for index in range(1, 70):
        if index % 3 == 0:
            lines.append(f"[09:{index:02d}] APP: Checkpoint: generated update {index}")
        else:
            lines.append(f"[09:{index:02d}] Engineer {index}: Please confirm current validation status for item {index}.")
    events = normalize_slack_paste("\n".join(lines), incident_id="bounded-pack")
    catalog = load_service_catalog("data/contract/service_catalog.yaml")
    command_registry = load_command_registry("data/contract/command_registry.yaml", catalog)
    targets = build_allowed_targets(events, catalog, command_registry)
    context_pack = build_incident_read_context_pack(
        incident_id="bounded-pack",
        latest_window_events=events,
        input_size_assessment=_assessment(events),
        latest_window_selection=_selection(events),
        allowed_targets=targets,
        command_registry=command_registry,
        catalog=catalog,
        accepted_memories=[],
        event_quality=[],
    )

    assert len(context_pack["latest_window_events"]) <= 22
    assert len(context_pack["candidate_targets"]) <= 20
    assert len(context_pack["do_not_target"]) <= 15
    assert len(context_pack["catalog_hints"]) < len(catalog)
    assert context_pack["command_registry"] == []
    assert context_pack["decision_moment_behavior_hints"] == []
    assert context_pack["context_pack_variant"] == "compact"
    assert len(json.dumps(context_pack, default=str)) <= 18_000


def test_ultra_compact_pack_keeps_latest_human_evidence_over_bot_summary() -> None:
    events = normalize_slack_paste(
        "\n".join(
            [
                "[10:00] APP: Incident Summary: older bot summary says generic monitoring is ongoing.",
                *[
                    f"[10:{index:02d}] APP: Checkpoint: generated update {index}"
                    for index in range(1, 14)
                ],
                "[10:20] Maya P: Customer validation came back; please confirm whether exposure is contained.",
                "[10:21] Arun S: I am checking audit logs and will provide validation status.",
            ]
        ),
        incident_id="ultra-human",
    )
    targets = build_allowed_targets(events, [], [])
    context_pack = build_ultra_compact_incident_read_context_pack(
        incident_id="ultra-human",
        latest_window_events=events,
        input_size_assessment=_assessment(events),
        latest_window_selection=_selection(events),
        allowed_targets=targets,
        command_registry=[],
        catalog=[],
        accepted_memories=[],
        event_quality=[],
    )
    packed_text = "\n".join(event["text"] for event in context_pack["latest_window_events"])

    assert len(context_pack["latest_window_events"]) <= 12
    assert "Customer validation came back" in packed_text
    assert "checking audit logs" in packed_text
    assert "older bot summary" not in packed_text


def test_pipeline_preserves_useful_output_after_quote_and_target_envelope_repair(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "[10:00] zsrebot: Hi @henryzhu please acknowledge.\n"
        "[10:01] henryzhu: Kafka team is reviewing cluster performance and event latency. ETA will follow after investigation."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        alias = next(item for item in payload["target_aliases"] if item["canonical_display_name"] == "henryzhu")
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Kafka performance and event latency investigation is active.",
            latest_open_loop="Need status and ETA from the current reviewer.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=alias["alias_target_ids"][0],
            selected_target_display_name="henryzhu",
            say_this="henryzhu, can you share the Kafka investigation status and ETA for event latency?",
            evidence=[
                WhisperEvidenceRef(
                    event_id=payload["latest_window_events"][-1]["event_id"],
                    quote="Henry is coordinating Kafka performance and event latency.",
                )
            ],
            confidence=0.82,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["verifier_result"].passed
    assert result["decision"].move == ICMove.REQUEST_STATUS_OR_ETA
    assert "I do not have a safe" not in result["final_output"]
    safety = result["trace"].safety_summary
    assert safety["target_id_canonicalized"] is True
    assert safety["evidence_quote_canonicalized"] is True


def test_timeout_retries_with_ultra_compact_context_and_succeeds(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "\n".join(
            [
                "[10:00] APP: Incident Summary: older generated context",
                *[
                    f"[10:{index:02d}] Engineer {index}: Please confirm validation status and owner update for security workflow {index}."
                    for index in range(1, 28)
                ],
            ]
        )
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        assert payload["context_pack_variant"] == "ultra_compact"
        assert len(payload["latest_window_events"]) <= 12
        target = payload["candidate_targets"][0]
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Validation status is needed from the current owner.",
            latest_open_loop="Need the latest validation status.",
            selected_move=ICMove.ASK_NEXT_VALIDATION,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this=f"{target['display_name']}, can you share the latest validation status?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote=event["text"])],
            confidence=0.8,
        )

    client = _TimeoutThenReadClient(read_factory, timeout_count=1)
    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=client,
    )

    assert len(client.payloads) == 2
    assert client.payloads[0]["context_pack_variant"] == "compact"
    assert client.payloads[1]["context_pack_variant"] == "ultra_compact"
    assert result["verifier_result"].passed
    assert "I do not have a safe" not in result["final_output"]
    safety = result["trace"].safety_summary
    assert safety["provider_timeout_stage"] == "incident_read_and_whisper_v2"
    assert safety["retry_attempted"] is True
    assert safety["retry_strategy"] == "ultra_compact_incident_read_and_whisper"
    assert safety["ultra_compact_payload_event_count"] <= 12


def test_double_timeout_preserves_context_pack_debug(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text("[10:01] Alex Rivera: Please confirm current validation status.")
    client = _TimeoutThenReadClient(lambda payload: None, timeout_count=2)

    try:
        run_pipeline(
            incident,
            catalog_path="data/contract/service_catalog.yaml",
            command_registry_path="data/contract/command_registry.yaml",
            memory_path="data/contract/decision_moments.jsonl",
            save_trace=False,
            llm_client=client,
        )
    except TimeoutError as exc:
        debug = exc.debug_payload
    else:  # pragma: no cover - this would mean timeout handling regressed
        raise AssertionError("expected terminal timeout failure")

    assert len(client.payloads) == 2
    assert debug["provider_timeout_stage"] == "incident_read_and_whisper_v2"
    assert debug["retry_attempted"] is True
    assert debug["retry_strategy"] == "ultra_compact_incident_read_and_whisper"
    assert debug["context_pack_summary"]["event_count"] >= 1
    assert debug["candidate_targets"]
    assert debug["latest_window_event_ids"]
    assert "raw" not in debug["terminal_failure_reason"].lower()


def test_secret_like_values_are_redacted_from_model_and_debug_payloads(tmp_path: Path) -> None:
    raw_secret = "AKIA1234567890ABCDEF"
    incident = tmp_path / "incident.txt"
    incident.write_text(
        f"[10:01] Security Owner: AWS credential mentioned {raw_secret}; checking exposure and validation status."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        payload_json = json.dumps(payload, default=str)
        assert raw_secret not in payload_json
        assert "[REDACTED]" in payload_json
        target = payload["candidate_targets"][0]
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="A credential exposure is being checked.",
            latest_open_loop="Need exposure validation status.",
            selected_move=ICMove.ASK_NEXT_VALIDATION,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this=f"{target['display_name']}, can you share the exposure validation status?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote=event["text"])],
            confidence=0.84,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    trace_json = json.dumps(result["trace"].model_dump(mode="json"), default=str)
    assert raw_secret not in trace_json
    assert raw_secret not in result["final_output"]
    assert result["verifier_result"].passed


def test_grounded_non_target_fact_and_secondary_human_address_do_not_force_fallback(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "Hajime Watanabe\n"
        "8:00 PM\n"
        "I can help validate with the customer contact.\n"
        "Salim Thakkar\n"
        "8:01 PM\n"
        "I am available to confirm whether the activity can stop.\n"
        "Utsav\n"
        "8:02 PM\n"
        "@Hajime Watanabe and @Salim Thakkar, customer activity is confirmed in tenant 30000080 sandbox; "
        "please confirm if the deletion process can be stopped to reduce load.\n"
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        names = {target["display_name"]: target for target in payload["candidate_targets"]}
        event = payload["latest_window_events"][-1]
        assert any(item["display_name"] == "30000080" for item in payload["non_targetable_but_mentionable_facts"])
        assert any(
            alias.get("alias_reason") == "short mention maps to full visible Slack author"
            for alias in payload["target_aliases"]
        )
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Customer deletion activity is confirmed for a sandbox tenant.",
            latest_open_loop="Confirm whether the deletion activity can stop to reduce load.",
            already_answered=["customer activity is confirmed"],
            selected_move=ICMove.ASK_NEXT_VALIDATION,
            selected_target_id=names["Hajime Watanabe"]["target_id"],
            selected_target_display_name="Hajime Watanabe",
            say_this=(
                "@Hajime Watanabe and @Salim Thakkar, can you confirm if the affected sandbox "
                "deletion activity can be stopped to reduce load?"
            ),
            evidence=[
                WhisperEvidenceRef(
                    event_id=event["event_id"],
                    quote="tenant 30000080 sandbox; please confirm if the deletion process can be stopped",
                )
            ],
            confidence=0.86,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["verifier_result"].passed
    assert result["decision"].move == ICMove.ASK_NEXT_VALIDATION
    assert "I do not have a safe" not in result["final_output"]
    assert len(result["decision"].target_ids) == 2
    assert not any("unregistered command-like output" in claim for claim in result["trace"].safety_summary["original_blocked_claims"])
    assert "30000080" not in result["final_output"]


def test_pipeline_falls_back_for_invented_claim_after_canonicalization_attempt(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text("[10:01] Engineer: Checking service health now.")

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Acme customer tenant 12345 was mitigated.",
            latest_open_loop="Need confirmation.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            say_this="Acme customer tenant 12345 was mitigated; can the owner confirm status?",
            evidence=[
                WhisperEvidenceRef(
                    event_id=payload["latest_window_events"][-1]["event_id"],
                    quote="Acme customer tenant 12345 was mitigated.",
                )
            ],
            confidence=0.8,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert any("tenant/account" in claim or "customer" in claim for claim in result["trace"].safety_summary["original_blocked_claims"])


def test_true_unsafe_output_still_falls_back(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text("[10:01] Engineer: Current status is under investigation.")

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Investigation is active.",
            latest_open_loop="Unsafe action requested.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            say_this="Please page the owner and execute the restart now.",
            evidence=[
                WhisperEvidenceRef(
                    event_id=payload["latest_window_events"][-1]["event_id"],
                    quote=payload["latest_window_events"][-1]["text"],
                )
            ],
            confidence=0.7,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert any("unsafe executable action wording" in claim for claim in result["trace"].safety_summary["original_blocked_claims"])


def test_human_address_does_not_hide_command_like_action(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text("[10:01] Alex Rivera: Current status is under investigation.")

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = payload["candidate_targets"][0]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Investigation is active.",
            latest_open_loop="Need an update from the investigator.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@Alex Rivera please restart the worker now.",
            evidence=[
                WhisperEvidenceRef(
                    event_id=payload["latest_window_events"][-1]["event_id"],
                    quote=payload["latest_window_events"][-1]["text"],
                )
            ],
            confidence=0.7,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert any("unsafe executable action wording" in claim for claim in result["trace"].safety_summary["original_blocked_claims"])


def test_action_labels_are_work_items_not_candidate_targets() -> None:
    events = normalize_slack_paste(
        "Leo\n"
        "10:00 AM\n"
        "Security Incident Update\n"
        "Current Status: investigating\n"
        "Next Actions:\n"
        "Fix Vulnerability: (Owner: Workflow @wenxuan) - Implement input validation.\n"
        "Rotate Credentials: (Owner: Security @Bimodh@Emanuel Ch. S.) - Cycle leaked keys.\n"
        "Audit Logs: (Owner: Security/SRE @garyyang@Bimodh) - Check unauthorized access attempts.",
        incident_id="work-items",
    )
    targets = build_allowed_targets(events, [], [])
    context_pack = _context_pack(events, targets)
    candidate_names = {target["display_name"] for target in context_pack["candidate_targets"]}
    work_items = context_pack["current_work_items"]

    assert {"Fix Vulnerability", "Rotate Credentials", "Audit Logs"}.isdisjoint(candidate_names)
    assert {"wenxuan", "Bimodh", "Emanuel Ch. S.", "garyyang"}.issubset(candidate_names)
    assert [item["work_item_label"] for item in work_items] == [
        "Fix Vulnerability",
        "Rotate Credentials",
        "Audit Logs",
    ]


def test_label_mention_action_rows_are_current_work_items_not_authors() -> None:
    events = normalize_slack_paste(
        "Jose Amey\n"
        "10:05 AM\n"
        "Incident Update\n"
        "Current Status: severity downgrade completed\n"
        "Next Steps:\n"
        "Kafka Investigation: @henryzhu is contacting the Kafka team to check cluster performance "
        "regarding slow event produce latency.",
        incident_id="ocs-work-item",
    )
    targets = build_allowed_targets(events, [], [])
    context_pack = _context_pack(events, targets)
    candidate_names = {target["display_name"] for target in context_pack["candidate_targets"]}
    work_items = context_pack["current_work_items"]

    assert len(events) == 1
    assert events[0].author == "Jose Amey"
    assert "Kafka Investigation" not in {event.author for event in events}
    assert [item["work_item_label"] for item in work_items] == ["Kafka Investigation"]
    assert work_items[0]["owner_names"] == ["henryzhu"]
    assert work_items[0]["owner_group"] == "Kafka team"
    assert "check cluster performance" in work_items[0]["status_or_action"]
    assert "slow event produce latency" in work_items[0]["status_or_action"]
    assert "Kafka Investigation" not in candidate_names
    assert {"henryzhu", "Kafka team"}.issubset(candidate_names)


def test_explicit_next_action_memory_applicability_accepts_label_mention_work_item(tmp_path: Path) -> None:
    memory = tmp_path / "decision_moments.jsonl"
    memory.write_text(
        json.dumps(
            {
                "decision_id": "DM_explicit_next_action_owner_alignment",
                "source_incident_id": "test",
                "review_status": "approved",
                "quality_score": 0.93,
                "phase_before": "unknown",
                "phase_after": "unknown",
                "move": "request_status_or_eta",
                "situation_before": "Current update lists action rows with explicit owners.",
                "trigger": "Use next action text and owner markers.",
                "ic_action": "@{owner}, can you share status and ETA for {next_action}?",
                "why_it_worked": "Owner/action alignment prevents wrong-owner status asks.",
                "labels": ["explicit", "next", "owner", "request_status_or_eta"],
                "applicability": {
                    "required_current_evidence": [
                        "next action text",
                        "explicit owner marker",
                        "current incident phase or summary indicating the action is still active",
                    ]
                },
            }
        )
        + "\n"
    )
    moments = load_decision_moments(memory)
    evidence_text = (
        "Incident Update\n"
        "Current Status: investigation continues\n"
        "Kafka Investigation: @henryzhu is contacting the Kafka team to check cluster performance "
        "regarding slow event produce latency."
    )

    result = judge_applicability(
        CurrentIncidentState(incident_id="ocs-memory"),
        moments,
        current_evidence_text=evidence_text,
    )[0]

    assert result.accepted
    assert result.required_current_evidence_missing == []
    assert set(result.required_current_evidence_satisfied) == {
        "next action text",
        "explicit owner marker",
        "current incident phase or summary indicating the action is still active",
    }


def test_compiled_audit_latency_evidence_phrases_accept_current_config_drift_shape(tmp_path: Path) -> None:
    memory = tmp_path / "decision_moments.jsonl"
    memory.write_text(
        json.dumps(
            {
                "decision_id": "DM_kafka_connection_error_check_service_config_drift",
                "source_incident_id": "test",
                "review_status": "approved",
                "quality_score": 0.91,
                "phase_before": "unknown",
                "phase_after": "unknown",
                "move": "engage_owner",
                "situation_before": "Route producer failures to config owner when Kafka is healthy.",
                "trigger": "Use current producer, health, and runtime config evidence.",
                "ic_action": "@{owner}, can you confirm runtime config and next validation?",
                "why_it_worked": "Prevents wrong-owner looping on Kafka.",
                "labels": ["codex_compiled", "config", "kafka"],
                "applicability": {
                    "required_current_evidence": [
                        "producer connection error",
                        "Kafka/network health check",
                        "runtime configuration or feature-flag evidence",
                    ]
                },
            }
        )
        + "\n"
    )

    result = judge_applicability(
        CurrentIncidentState(incident_id="audit-latency-memory"),
        load_decision_moments(memory),
        current_evidence_text=(
            "Producer logs show Connection to node -1 could not be established. "
            "Pod network connectivity succeeds and the Kafka health dashboard is green. "
            "The runtime flag is enabled without the expected broker addresses, indicating config drift."
        ),
    )[0]

    assert result.accepted
    assert result.required_current_evidence_missing == []


def test_compiled_daco_cpu_evidence_phrases_accept_query_cleanup_shape(tmp_path: Path) -> None:
    memory = tmp_path / "decision_moments.jsonl"
    memory.write_text(
        json.dumps(
            {
                "decision_id": "DM_db_cpu_bad_query_route_to_app_owner",
                "source_incident_id": "test",
                "review_status": "approved",
                "quality_score": 0.91,
                "phase_before": "unknown",
                "phase_after": "unknown",
                "move": "engage_owner",
                "situation_before": "Route DB CPU caused by a bad query to app owner.",
                "trigger": "Use current CPU, query, and owner evidence.",
                "ic_action": "@{owner}, can you confirm cleanup status?",
                "why_it_worked": "Keeps DBA from owning app query cleanup.",
                "labels": ["codex_compiled", "cpu", "query"],
                "applicability": {
                    "required_current_evidence": [
                        "database CPU or resource saturation",
                        "DBA-identified problematic query",
                        "service/table or owner hint",
                    ]
                },
            }
        )
        + "\n"
    )

    result = judge_applicability(
        CurrentIncidentState(incident_id="daco-cpu-memory"),
        load_decision_moments(memory),
        current_evidence_text=(
            "DB CPU is high and the DBA identified a problematic query. "
            "The service/table owner hint points to the application owner for query cleanup."
        ),
    )[0]

    assert result.accepted
    assert result.required_current_evidence_missing == []


def test_compiled_manual_retry_source_clarification_phrases_accept_current_shape(tmp_path: Path) -> None:
    memory = tmp_path / "decision_moments.jsonl"
    memory.write_text(
        json.dumps(
            {
                "decision_id": "DM_correct_source_when_app_owner_clarifies_manual_retry",
                "source_incident_id": "test",
                "review_status": "approved",
                "quality_score": 0.91,
                "phase_before": "unknown",
                "phase_after": "unknown",
                "move": "ask_next_validation",
                "situation_before": "Use owner clarification when the source hypothesis changes.",
                "trigger": "Use current source clarification evidence.",
                "ic_action": "@{owner}, can you confirm the next validation step?",
                "why_it_worked": "Prevents stale source assumptions.",
                "labels": ["codex_compiled", "source", "manual_retry"],
                "applicability": {
                    "required_current_evidence": [
                        "owner clarification of source",
                        "prior ambiguous or incorrect source hypothesis",
                    ]
                },
            }
        )
        + "\n"
    )

    result = judge_applicability(
        CurrentIncidentState(incident_id="daco-source-memory"),
        load_decision_moments(memory),
        current_evidence_text=(
            "Earlier message hypothesized automation. The owner later says the queries came from "
            "tenant manual retry, not automation."
        ),
    )[0]

    assert result.accepted
    assert result.required_current_evidence_missing == []


def test_compiled_pipeline_data_integrity_phrases_accept_recovery_shape(tmp_path: Path) -> None:
    memory = tmp_path / "decision_moments.jsonl"
    memory.write_text(
        json.dumps(
            {
                "decision_id": "DM_after_pipeline_latency_mitigation_request_data_integrity_scope",
                "source_incident_id": "test",
                "review_status": "approved",
                "quality_score": 0.91,
                "phase_before": "unknown",
                "phase_after": "unknown",
                "move": "ask_next_validation",
                "situation_before": "After event flow recovers, ask for data integrity scope.",
                "trigger": "Use latency, mitigation, and data-loss evidence.",
                "ic_action": "@{owner}, can you confirm data integrity and scope?",
                "why_it_worked": "Recovery does not prove all delayed events are accounted for.",
                "labels": ["codex_compiled", "pipeline", "data_integrity"],
                "applicability": {
                    "required_current_evidence": [
                        "event pipeline latency",
                        "mitigation or error cessation",
                        "pending data integrity or loss assessment",
                    ]
                },
            }
        )
        + "\n"
    )

    result = judge_applicability(
        CurrentIncidentState(incident_id="audit-integrity-memory"),
        load_decision_moments(memory),
        current_evidence_text=(
            "Audit event latency was mitigated and messages are flowing. "
            "Updates still list potential message loss and recovery feasibility as pending."
        ),
    )[0]

    assert result.accepted
    assert result.required_current_evidence_missing == []


def test_compiled_temporal_evidence_phrases_accept_owner_status_shape(tmp_path: Path) -> None:
    memory = tmp_path / "decision_moments.jsonl"
    memory.write_text(
        json.dumps(
            {
                "decision_id": "DM_temporal_workflow_failure_owner_status",
                "source_incident_id": "test",
                "review_status": "approved",
                "quality_score": 0.91,
                "phase_before": "unknown",
                "phase_after": "unknown",
                "move": "request_status_or_eta",
                "situation_before": "Ask owning engineering team for Temporal workflow status.",
                "trigger": "Use current workflow, error, and owner evidence.",
                "ic_action": "@{owner}, can you share workflow status and ETA?",
                "why_it_worked": "Targets the active owner for workflow failure status.",
                "labels": ["codex_compiled", "temporal", "workflow"],
                "applicability": {
                    "required_current_evidence": [
                        "Temporal workflow status or execution-history reference",
                        "specific error text",
                        "owning engineering team or SME evidence",
                    ]
                },
            }
        )
        + "\n"
    )

    result = judge_applicability(
        CurrentIncidentState(incident_id="temporal-memory"),
        load_decision_moments(memory),
        current_evidence_text=(
            "Temporal workflow execution history shows the job failed with a specific error. "
            "The owning engineering team and SME are engaged for current status."
        ),
    )[0]

    assert result.accepted
    assert result.required_current_evidence_missing == []


def test_stale_status_zoom_recap_is_blocked_after_later_human_update(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "Mario\n"
        "9:58 AM\n"
        "@Jose Amey @dcruz can you provide current status and include what we discussed on Zoom?\n"
        "Jose Amey\n"
        "10:05 AM\n"
        "Incident Update\n"
        "Current Status: OCS lag is elevated but production impact is downgraded.\n"
        "Findings: impacted shards are identified and trust post is no need.\n"
        "Next Steps:\n"
        "Kafka Investigation: @henryzhu is contacting the Kafka team to check cluster performance "
        "regarding slow event produce latency.\n"
        "Monitoring Plan: watch OCS lag recovery and worker pod status."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Jose Amey")
        update_event = next(event for event in payload["latest_window_events"] if "Kafka Investigation" in event["text"])
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="A status update exists, but the model repeated an older recap ask.",
            latest_open_loop="Need Jose to provide current status and Zoom discussion details.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@Jose Amey could you please provide the current status of the case including the Zoom discussion details?",
            evidence=[WhisperEvidenceRef(event_id=update_event["event_id"], quote="Current Status")],
            confidence=0.8,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    safety = result["trace"].safety_summary
    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert safety["stale_status_recap_check"] is False
    assert any("stale visible status/Zoom recap ask" in claim for claim in safety["original_blocked_claims"])


def test_current_next_action_owner_output_passes_after_status_update(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "Mario\n"
        "9:58 AM\n"
        "@Jose Amey @dcruz can you provide current status and include what we discussed on Zoom?\n"
        "Jose Amey\n"
        "10:05 AM\n"
        "Incident Update\n"
        "Current Status: OCS lag is elevated but production impact is downgraded.\n"
        "Findings: impacted shards are identified and trust post is no need.\n"
        "Next Steps:\n"
        "Kafka Investigation: @henryzhu is contacting the Kafka team to check cluster performance "
        "regarding slow event produce latency.\n"
        "Monitoring Plan: watch OCS lag recovery and worker pod status."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        assert payload["current_work_items"]
        assert payload["current_work_items"][0]["work_item_label"] == "Kafka Investigation"
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "henryzhu")
        update_event = next(event for event in payload["latest_window_events"] if "Kafka Investigation" in event["text"])
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Jose posted a status update; Kafka investigation is the explicit next action.",
            latest_open_loop="Need Kafka cluster performance and event latency status from the explicit owner.",
            already_answered=["Jose provided current status and next steps."],
            selected_move=ICMove.REQUEST_MONITORING_SIGNAL,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this=(
                "@henryzhu, can you share the Kafka cluster performance check for the slow event produce "
                "latency and what signal we should watch next for OCS lag recovery?"
            ),
            evidence=[
                WhisperEvidenceRef(
                    event_id=update_event["event_id"],
                    quote="Kafka Investigation: @henryzhu is contacting the Kafka team",
                )
            ],
            confidence=0.86,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["verifier_result"].passed
    assert result["decision"].move == ICMove.REQUEST_MONITORING_SIGNAL
    assert "I do not have a safe" not in result["final_output"]
    assert "Zoom discussion" not in result["final_output"]
    assert result["trace"].safety_summary["stale_status_recap_check"] is True


def test_wrong_action_owner_is_blocked_by_verifier(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "[10:00] Leo: Security Incident Update\n"
        "Next Actions:\n"
        "Fix Vulnerability: (Owner: Workflow @wenxuan) - Implement input validation.\n"
        "Rotate Credentials: (Owner: Security @Bimodh) - Cycle leaked keys."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Bimodh")
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="The vulnerability fix and credential rotation are assigned.",
            latest_open_loop="Need the vulnerability fix ETA.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@Bimodh, can you provide the ETA for fixing the vulnerability?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote="Fix Vulnerability")],
            confidence=0.82,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert result["trace"].safety_summary["action_owner_alignment_check"] is False
    assert any("action owner mismatch" in claim for claim in result["trace"].safety_summary["original_blocked_claims"])


def test_correct_fix_owner_passes_action_owner_check(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "[10:00] Leo: Security Incident Update\n"
        "Next Actions:\n"
        "Fix Vulnerability: (Owner: Workflow @wenxuan) - Implement input validation."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "wenxuan")
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="The fix owner is explicit.",
            latest_open_loop="Need current fix status and ETA.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@wenxuan, can you share the current fix status and ETA?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote="Fix Vulnerability")],
            confidence=0.85,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["verifier_result"].passed
    assert result["trace"].safety_summary["action_owner_alignment_check"] is True
    assert "I do not have a safe" not in result["final_output"]


def test_credential_rotation_owner_passes_action_owner_check(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "[10:00] Leo: Security Incident Update\n"
        "Next Actions:\n"
        "Rotate Credentials: (Owner: Security @Bimodh@Emanuel Ch. S.) - Cycle leaked keys."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Bimodh")
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Credential rotation is assigned.",
            latest_open_loop="Need credential rotation status.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@Bimodh, can you share credential rotation status and any blocker?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote="Rotate Credentials")],
            confidence=0.84,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["verifier_result"].passed
    assert result["trace"].safety_summary["action_owner_alignment_check"] is True


def test_bad_input_validation_fix_feasibility_to_rotation_owner_blocks(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "[10:00] Leo: @Bimodh when do we need this fixed?\n"
        "[10:05] Leo: Security Incident Update\n"
        "Next Actions:\n"
        "Fix Vulnerability: (Owner: Workflow @wenxuan) - Implement input validation for the action_type parameter.\n"
        "Rotate Credentials: (Owner: Security @Bimodh@Emanuel Ch. S.) - Cycle leaked credentials."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Bimodh")
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="The fix and rotation owners are explicit.",
            latest_open_loop=(
                "wenxuan asked Bimodh when the fix is needed and if it can be done in the next 24 hours, "
                "but no answer yet."
            ),
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@Bimodh, when do we need the input validation fix completed, and can it be done within the next 24 hours?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote="Fix Vulnerability")],
            confidence=0.86,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert result["trace"].safety_summary["action_owner_alignment_check"] is False
    detail = result["trace"].safety_summary["action_owner_alignment_check_detail"]
    assert detail["matched_work_item_label"] == "Fix Vulnerability"
    assert detail["output_action_type"] == "mixed_deadline_and_implementation"


def test_owner_aligned_output_survives_stale_metadata_contradiction(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "[10:00] Leo: @Bimodh when do we need this fixed? Can we get this done in the next 24 hours?\n"
        "[10:05] Leo: Security Incident Update\n"
        "Next Actions:\n"
        "Fix Vulnerability: (Owner: Workflow @wenxuan) - Implement input validation for the action_type parameter.\n"
        "Rotate Credentials: (Owner: Security @Bimodh@Emanuel Ch. S.) - Cycle leaked credentials."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "wenxuan")
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="The Workflow fix owner is explicit.",
            latest_open_loop=(
                "wenxuan has been asked about the deadline for the fix and feasibility of completing it "
                "in 24 hours but has not yet responded."
            ),
            already_answered=[
                "When do we need this fixed?",
                "Can we get this done in the next 24 hours?",
            ],
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@wenxuan, can you share the input validation fix status and ETA?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote="Fix Vulnerability")],
            confidence=0.86,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    safety = result["trace"].safety_summary
    assert result["verifier_result"].passed
    assert result["decision"].move != ICMove.NO_SAFE_RECOMMENDATION
    assert result["decision"].output["say_this"] == "@wenxuan, can you share the input validation fix status and ETA?"
    assert safety["fallback_used"] is False
    assert safety["metadata_repair_used"] is True
    assert safety["metadata_repair_reason"] == "stale_open_loop_metadata_only"
    assert safety["metadata_only_stale_open_loop_repaired"] is True
    assert safety["original_blocked_claims"] == []
    assert safety["action_owner_alignment_check"] is True


def test_deadline_only_to_security_requester_passes(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "[10:00] Leo: @Bimodh when do we need this fixed?\n"
        "[10:05] Leo: Next Actions:\n"
        "Fix Vulnerability: (Owner: Workflow @wenxuan) - Implement input validation for the action_type parameter."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Bimodh")
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="The requester deadline is still useful to clarify.",
            latest_open_loop="Need required security deadline for the Workflow fix.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@Bimodh, can you confirm the required security deadline for the Workflow fix?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote="Fix Vulnerability")],
            confidence=0.82,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["verifier_result"].passed
    assert result["trace"].safety_summary["action_owner_alignment_check"] is True


def test_mixed_deadline_and_feasibility_to_non_owner_blocks(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "[10:00] Leo: @Bimodh when do we need this fixed?\n"
        "[10:05] Leo: Next Actions:\n"
        "Fix Vulnerability: (Owner: Workflow @wenxuan) - Implement input validation for the action_type parameter."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Bimodh")
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="A deadline question exists, but fix feasibility belongs to the fix owner.",
            latest_open_loop="Need deadline and feasibility.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@Bimodh, when is this required and can the input validation fix be done in 24 hours?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote="Fix Vulnerability")],
            confidence=0.82,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert result["trace"].safety_summary["action_owner_alignment_check"] is False


def test_workflow_team_fix_eta_passes(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "[10:05] Leo: Next Actions:\n"
        "Fix Vulnerability: (Owner: Workflow @wenxuan) - Implement input validation for the action_type parameter."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Workflow")
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="The Workflow team owns the input validation fix.",
            latest_open_loop="Need fix status and ETA.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@Workflow, can you share the input validation fix status and ETA?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote="Fix Vulnerability")],
            confidence=0.83,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["verifier_result"].passed


def test_audit_owner_passes_action_owner_check(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "[10:05] Leo: Next Actions:\n"
        "Audit Logs: (Owner: Security/SRE @garyyang@Bimodh) - Check for unauthorized access attempts."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "garyyang")
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="The log audit owner is explicit.",
            latest_open_loop="Need audit status and signs of unauthorized use.",
            selected_move=ICMove.ASK_NEXT_VALIDATION,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@garyyang, can you share the key-usage/log audit status and whether there is any sign of unauthorized use?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote="Audit Logs")],
            confidence=0.83,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["verifier_result"].passed


def test_bad_owner_with_stale_metadata_still_blocks(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "[10:00] Leo: @Bimodh when do we need this fixed?\n"
        "[10:05] Leo: Next Actions:\n"
        "Fix Vulnerability: (Owner: Workflow @wenxuan) - Implement input validation."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Bimodh")
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="A fix owner is now explicit.",
            latest_open_loop="@Bimodh when do we need this fixed?",
            already_answered=["When do we need this fixed?"],
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@Bimodh, can you provide ETA for fixing the vulnerability?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote="Fix Vulnerability")],
            confidence=0.8,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert result["trace"].safety_summary["action_owner_alignment_check"] is False
    assert any(
        "action owner mismatch" in claim
        for claim in result["trace"].safety_summary["original_blocked_claims"]
    )


def test_visible_stale_say_this_still_blocks(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "[10:00] Leo: @wenxuan can you share input validation fix status and ETA?\n"
        "[10:05] Leo: Next Actions:\n"
        "Fix Vulnerability: (Owner: Workflow @wenxuan) - ETA is 2 PM and the implementation is already in progress."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "wenxuan")
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="The fix owner is explicit.",
            latest_open_loop="Input validation fix ETA is open with wenxuan.",
            already_answered=["Input validation fix ETA is 2 PM."],
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@wenxuan, can you share the input validation fix ETA?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote="Fix Vulnerability")],
            confidence=0.8,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert result["trace"].safety_summary["stale_open_loop_contradiction_check"] is False
    assert any(
        "already_answered repeats SAY THIS" in claim
        for claim in result["trace"].safety_summary["original_blocked_claims"]
    )


def test_truncated_work_item_quote_is_canonicalized() -> None:
    events = normalize_slack_paste(
        "[10:05] Leo: Security Incident Update\n"
        "Current Status: Awaiting SRE to confirm key usage/logs and the Workflow team to provide a production-ready resolution.\n"
        "Next Actions:\n"
        "Fix Vulnerability: (Owner: Workflow @wenxuan) - Implement input validation for the action_type parameter.",
        incident_id="quote-truncation",
    )
    targets = build_allowed_targets(events, [], [])
    context_pack = _context_pack(events, targets)
    target = next(item for item in context_pack["candidate_targets"] if item["display_name"] == "wenxuan")
    read = IncidentReadAndWhisper(
        incident_id="quote-truncation",
        current_read="The Workflow fix is assigned.",
        latest_open_loop="Need input validation fix status and ETA.",
        selected_move=ICMove.REQUEST_STATUS_OR_ETA,
        selected_target_id=target["target_id"],
        selected_target_display_name=target["display_name"],
        say_this="@wenxuan, can you share the input validation fix status and ETA?",
        evidence=[
            WhisperEvidenceRef(
                event_id=events[0].event_id,
                quote="Security Incident Update Current Status: Awaiting SRE to confirm key usage/logs and the Workflow team to provide a production-ready resoluti",
            )
        ],
        confidence=0.84,
    )

    normalized, metadata = normalize_incident_read_envelope(
        read,
        context_pack=context_pack,
        latest_window_events=events,
    )

    assert metadata["evidence_quote_canonicalized"] is True
    assert normalized.evidence[0].quote in events[0].message
    assert not normalized.evidence[0].quote.endswith("resoluti")


def test_human_mentions_are_not_command_candidates_but_bot_commands_are() -> None:
    human_events = normalize_slack_paste(
        "[10:00] Leo: @Bimodh when do we need this fixed?\n"
        "[10:01] Leo: @wenxuan not sure if you can join the bridge\n"
        "[10:02] Leo: @Zhenqiang Cao, could you join?",
        incident_id="human-mentions",
    )
    assert all(not (event.extracted_tokens or {}).get("command_candidates") for event in human_events)

    bot_events = normalize_slack_paste(
        "[10:00] Leo: @zsrebot oncall workflow\n"
        "[10:01] Leo: @zsrebot page team sre\n"
        "[10:02] Leo: @zsrebot incident priority p2",
        incident_id="bot-commands",
    )
    commands = [
        command
        for event in bot_events
        for command in (event.extracted_tokens or {}).get("command_candidates", [])
    ]
    assert "@zsrebot oncall workflow" in commands
    assert "@zsrebot page team sre" in commands
    assert "@zsrebot incident priority p2" in commands


def test_url_slash_false_positive_is_not_command_candidate() -> None:
    events = normalize_slack_paste(
        "[10:00] Leo: @Zhenqiang Cao, could you join: https://teamzuora.slack.com/archives/C123/p456",
        incident_id="url-command-false-positive",
    )
    assert events[0].extracted_tokens["command_candidates"] == []


def test_command_debug_counts_distinguish_mentions_bot_commands_and_model_exposure() -> None:
    events = normalize_slack_paste(
        "[10:00] Leo: @Bimodh when do we need this fixed?\n"
        "[10:01] Leo: @zsrebot oncall workflow\n"
        "[10:02] Leo: https://teamzuora.slack.com/archives/C123/p456",
        incident_id="command-counts",
    )
    targets = build_allowed_targets(events, [], [])
    context_pack = _context_pack(events, targets)
    summary = context_pack["excluded_human_mention_count"], context_pack["observed_bot_command_candidate_count"]

    assert summary[0] >= 1
    assert summary[1] >= 1
    assert context_pack["url_slash_false_positive_count"] == 0
    assert context_pack["model_exposed_command_count"] == 0


def test_exact_provider_payload_respects_hard_cap_and_keeps_work_items(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    lines = [
        "[10:00] Leo: Security Incident Update\n"
        "Next Actions:\n"
        "Fix Vulnerability: (Owner: Workflow @wenxuan) - Implement input validation for the action_type parameter.\n"
        "Rotate Credentials: (Owner: Security @Bimodh@Emanuel Ch. S.) - Cycle leaked credentials.\n"
        "Audit Logs: (Owner: Security/SRE @garyyang@Bimodh) - Check for unauthorized access attempts."
    ]
    for index in range(1, 80):
        lines.append(
            f"[10:{index:02d}] APP: Generated summary field {index}: "
            + "preview metadata and repeated low value text " * 16
        )
    lines.append("[11:20] wenxuan: I am checking the input validation fix status now.")
    incident.write_text("\n".join(lines))

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        serialized = json.dumps(payload, default=str)
        assert len(serialized) <= 18_000
        assert payload["current_work_items"]
        assert any("input validation fix status" in event["text"] for event in payload["latest_window_events"])
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "wenxuan")
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Fix owner is checking status.",
            latest_open_loop="Need current fix status.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@wenxuan, can you share the input validation fix status?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote=event["text"])],
            confidence=0.82,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    summary = result["trace"].safety_summary
    assert summary["model_payload_char_count"] <= 18_000
    assert summary["provider_payload_char_count"] <= 18_000
    assert summary["model_payload_over_cap"] is False
    assert result["verifier_result"].passed


def test_work_item_secret_values_are_redacted_from_context_pack() -> None:
    raw_secret = "AKIA1234567890ABCDEF"
    events = normalize_slack_paste(
        "[10:00] Leo: Security Incident Update\n"
        "Next Actions:\n"
        f"Rotate Credentials: (Owner: Security @Bimodh) - Cycle leaked key {raw_secret}.",
        incident_id="work-item-secret",
    )
    targets = build_allowed_targets(events, [], [])
    context_pack = _context_pack(events, targets)
    packed = json.dumps(context_pack, default=str)

    assert raw_secret not in packed
    assert "[REDACTED]" in packed


def test_json_diagnostic_blocks_are_continuations_not_targets() -> None:
    events = normalize_slack_paste(
        "Dharani\n"
        "7:13 AM\n"
        "@incident-managers can someone help validate the dedicated topic path.\n"
        "{\n"
        '  "recordFromDB" : {\n'
        '    "topicName" : "DataConnectSalesforceSync",\n'
        '    "topicNumber" : 3,\n'
        '    "tenantId" : "[REDACTED_TENANT_ID]",\n'
        '    "active" : true,\n'
        '    "expiry" : 2366,\n'
        '    "comment" : "latency threshold evidence"\n'
        "  }\n"
        "}",
        incident_id="sync-json",
    )
    targets = build_allowed_targets(events, [], [])
    context_pack = _context_pack(events, targets)
    authors = {event.author for event in events}
    candidate_names = {target["display_name"] for target in context_pack["candidate_targets"]}
    rejected_names = {target["display_name"] for target in context_pack["do_not_target"]}

    assert authors == {"Dharani"}
    for name in {"recordFromDB", "topicName", "topicNumber", "tenantId", "active", "expiry", "comment"}:
        assert name not in candidate_names
        assert name not in authors
    assert any(name in rejected_names for name in {"recordFromDB", "topicName", "tenantId", "active", "comment"})


def test_permission_blocked_attempt_becomes_safe_work_item_not_failed_users_as_owners() -> None:
    events = normalize_slack_paste(
        "Dharani\n"
        "7:13 AM\n"
        "@incident-managers can someone help move this tenant to an dedicated topic. I don't have access to execute a move\n"
        "Faisal Hasan\n"
        "7:23 AM\n"
        "do-not-thread @daco-bot topics for [REDACTED_TENANT_ID] move DataConnectSalesforceSync to 14 true false\n"
        "daco-bot\n"
        "APP  7:23 AM\n"
        "Hello @Faisal Hasan, You don't have required permission to execute this command! Command requires DEDICATED_TOPIC permission.\n"
        "Irfan\n"
        "7:24 AM\n"
        "look like i also don't have the permission",
        incident_id="sync-permission",
    )
    context_pack = _context_pack(events, build_allowed_targets(events, [], []))
    permission_item = next(
        item for item in context_pack["current_work_items"] if item["work_item_label"] == "Dedicated topic permission path"
    )
    candidate_names = {target["display_name"] for target in context_pack["candidate_targets"]}

    assert permission_item["work_item_type"] == "permission_blocked_operational_attempt"
    assert permission_item["owner_group"] == "DACO"
    assert permission_item["owner_names"] == []
    assert "permission-blocked" in permission_item["status_or_action"]
    assert {"Dharani", "incident-managers", "DACO"}.issubset(candidate_names)
    assert "daco-bot" not in candidate_names


def test_permission_loop_preserves_reporter_scope_symptom_work_item() -> None:
    events = normalize_slack_paste(
        "Dharani\n"
        "11:10 AM\n"
        "@incident-managers can someone move the sync workload to a dedicated queue? I don't have access to execute it.\n"
        "Alex\n"
        "11:13 AM\n"
        "do-not-thread @daco-bot sync move [REDACTED_TENANT_ID] InvoiceSyncTopic dedicated\n"
        "daco-bot\n"
        "APP 11:13 AM\n"
        "Hello @Alex, You don't have required permission to execute this command.\n"
        "Nina\n"
        "11:15 AM\n"
        "Before grouping this with the other report, can we get exact symptoms and affected scope for InvoiceSyncTopic?",
        incident_id="sync-permission-scope",
    )
    work_items = extract_current_work_items(events)

    assert work_items[0]["work_item_type"] == "scope_symptom_validation"
    assert work_items[0]["owner_names"] == ["Nina"]
    assert "exact symptoms and affected scope" in work_items[0]["status_or_action"]
    assert any(item["work_item_type"] == "permission_blocked_operational_attempt" for item in work_items)


def test_permission_loop_scope_symptom_work_item_uses_addressed_validator() -> None:
    events = normalize_slack_paste(
        "Dharani\n"
        "11:10 AM\n"
        "@incident-managers can someone move the sync workload to a dedicated queue? I don't have access to execute it.\n"
        "Alex\n"
        "11:13 AM\n"
        "do-not-thread @daco-bot sync move [REDACTED_TENANT_ID] InvoiceSyncTopic dedicated\n"
        "daco-bot\n"
        "APP 11:13 AM\n"
        "Hello @Alex, You don't have required permission to execute this command.\n"
        "Dharani\n"
        "11:15 AM\n"
        "@Anmol can you share exact symptoms and affected scope before grouping this as the same issue?",
        incident_id="sync-permission-addressed-scope",
    )
    work_items = extract_current_work_items(events)

    scope_item = next(item for item in work_items if item["work_item_type"] == "scope_symptom_validation")
    assert scope_item["owner_names"] == ["Anmol"]
    assert scope_item["evidence_id"] == "m004"


def test_sync_latency_memory_applicability_accepts_current_shape(tmp_path: Path) -> None:
    memory = tmp_path / "decision_moments.jsonl"
    records = [
        {
            "decision_id": "DM_do_not_merge_tenants_without_shared_scope_evidence",
            "phase_before": "unknown",
            "move": "ask_impact",
            "applicability": {
                "required_current_evidence": [
                    "additional impacted tenants/customers reported",
                    "different shard/topic/service evidence",
                    "missing symptom details",
                ]
            },
        },
        {
            "decision_id": "DM_verify_actual_bottleneck_topic_before_mitigation",
            "phase_before": "unknown",
            "move": "request_monitoring_signal",
            "applicability": {
                "required_current_evidence": [
                    "attempted tenant/topic isolation",
                    "continued latency evidence",
                    "explicit statement identifying the actual bottleneck topic or queue",
                ]
            },
        },
        {
            "decision_id": "DM_target_service_owner_for_correct_topic_root_cause",
            "phase_before": "unknown",
            "move": "engage_owner",
            "applicability": {
                "required_current_evidence": [
                    "named topic/queue/consumer group",
                    "owning engineer or team",
                    "technical ask needed",
                ]
            },
        },
    ]
    memory.write_text(
        "\n".join(
            json.dumps(
                {
                    "source_incident_id": "test",
                    "review_status": "approved",
                    "quality_score": 0.9,
                    "phase_after": "unknown",
                    "situation_before": "sync latency",
                    "trigger": "sync latency",
                    "ic_action": "ask current owner for validation",
                    "why_it_worked": "keeps routing grounded",
                    "labels": [],
                    **record,
                }
            )
            for record in records
        )
        + "\n"
    )
    moments = load_decision_moments(memory)
    evidence_text = (
        "another tenant reported same issue and they have not been able to send any data. "
        "Both tenants are in different shard zapps19 and zapps3; can you elaborate the issue they are facing. "
        "The reported issue was latency on DataConnectSalesforceSync topic with latency 33 > threshold 30. "
        "A dedicated topic move was attempted, but daco-bot says required permission and the path is permission-blocked."
    )

    results = judge_applicability(
        CurrentIncidentState(incident_id="sync-memory"),
        moments,
        current_evidence_text=evidence_text,
    )

    accepted_ids = {result.decision_id for result in results if result.accepted}
    assert accepted_ids == {
        "DM_do_not_merge_tenants_without_shared_scope_evidence",
        "DM_target_service_owner_for_correct_topic_root_cause",
    }
    bottleneck = next(result for result in results if result.decision_id == "DM_verify_actual_bottleneck_topic_before_mitigation")
    assert not bottleneck.accepted
    assert "suppressed_until_permission_loop_scope_is_resolved" in bottleneck.reasons


def test_sync_latency_bad_permission_loop_output_is_blocked(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "Dharani\n"
        "7:13 AM\n"
        "@incident-managers can someone help move this tenant to an dedicated topic. I don't have access to execute a move\n"
        '{ "topicName": "DataConnectSalesforceSync", "tenantId": "[REDACTED_TENANT_ID]" }\n'
        "Irfan\n"
        "7:24 AM\n"
        "do-not-thread @daco-bot topics for [REDACTED_TENANT_ID] move DataConnectSalesforceSync to 14 true false\n"
        "daco-bot\n"
        "APP  7:24 AM\n"
        "Hello @Irfan, You don't have required permission to execute this command! Command requires DEDICATED_TOPIC permission."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Irfan")
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Dedicated topic movement is permission blocked.",
            latest_open_loop="Need to know who has access to perform the move.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@Irfan, since you mentioned lacking permission to move tenant [TENANT_ID], can you confirm who has the access to perform this move?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote=event["text"])],
            confidence=0.82,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    safety = result["trace"].safety_summary
    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert safety["no_private_identifier_in_visible_output"] is False
    assert safety["permission_denied_wrong_owner_check"] is False
    assert any("unsafe executable action wording" in claim for claim in safety["original_blocked_claims"])
    assert any("permission-denied wrong-owner loop" in claim for claim in safety["original_blocked_claims"])


def test_sync_latency_safe_scope_validation_output_passes(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "Dharani\n"
        "7:17 AM\n"
        "@Anmol I don't think both the issues are related. For the reported tenant the issue was latency on DataConnectSalesforceSync topic.\n"
        "Are you seeing the similar issue for the other tenant?\n"
        "Anmol\n"
        "7:19 AM\n"
        "another tenant reported same issue\n"
        "Dharani\n"
        "7:20 AM\n"
        "Both tenants are in different shard zapps19 and zapps3, I don't think it's related. Can you elaborate the issue they are facing\n"
        "daco-bot\n"
        "APP  7:24 AM\n"
        "Hello @Irfan, You don't have required permission to execute this command! Command requires DEDICATED_TOPIC permission."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Anmol")
        event = next(event for event in payload["latest_window_events"] if "Can you elaborate" in event["text"])
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Multiple tenant reports may not share the same shard/topic scope.",
            latest_open_loop="Need exact symptoms and affected scope before merging the reports.",
            selected_move=ICMove.ASK_IMPACT,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@Anmol, can you share the exact symptoms and affected scope for the other reported tenants before we treat them as the same DataConnectSalesforceSync latency issue?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote="Can you elaborate the issue they are facing")],
            confidence=0.86,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["verifier_result"].passed
    assert "perform this move" not in result["final_output"]
    assert "[TENANT_ID]" not in result["final_output"]
    assert result["trace"].safety_summary["permission_denied_wrong_owner_check"] is True


def test_allowed_team_mention_is_not_command_like_output() -> None:
    allowed_targets = [
        AllowedTarget(
            target_id="t-daco",
            display_name="DACO",
            target_type="team",
            targetable=True,
            target_quality="medium",
            source="current_evidence",
        )
    ]

    assert (
        detect_unregistered_commands(
            "@DACO The dedicated-topic move attempt is permission-blocked. "
            "Please validate the correct owner and confirm scope/topic evidence.",
            [],
            allowed_targets,
        )
        == []
    )
    assert detect_unregistered_commands("@zsrebot page team sre", [], allowed_targets)


def test_slash_separated_allowed_team_address_is_not_command_like_output() -> None:
    allowed_targets = [
        AllowedTarget(
            target_id="t-esg",
            display_name="Developer Success / ESG",
            target_type="team",
            targetable=True,
            target_quality="medium",
            source="catalog",
        )
    ]

    assert (
        detect_unregistered_commands(
            "@Developer Success / ESG, can you confirm cert/config validation status?",
            [],
            allowed_targets,
        )
        == []
    )
    assert detect_unregistered_commands("@Developer Success / ESG, please /deploy now", [], allowed_targets)


def test_daco_bot_and_json_key_targets_are_blocked_even_if_model_selects_them(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "Dharani\n"
        "7:13 AM\n"
        '{ "recordFromDB": { "topicName": "DataConnectSalesforceSync" } }\n'
        "daco-bot\n"
        "APP  7:24 AM\n"
        "Hello @Irfan, You don't have required permission to execute this command! Command requires DEDICATED_TOPIC permission."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="The model selected a bot target.",
            latest_open_loop="Need bot status.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=None,
            selected_target_display_name="daco-bot",
            say_this="daco-bot, can you confirm the topic status?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote=event["text"])],
            confidence=0.6,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert result["trace"].safety_summary["no_json_log_target"] is False


def test_normal_product_path_does_not_call_legacy_semantic_truth_stages(tmp_path: Path, monkeypatch) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text("[10:01] Alex: Need status from the owner.")

    def boom(*args, **kwargs):  # pragma: no cover - assertion is that this is never reached
        raise AssertionError("legacy semantic stage should not run in simplified product path")

    monkeypatch.setattr("ic_copilot.pipeline.run_parallel_semantic_read", boom)
    monkeypatch.setattr("ic_copilot.pipeline.select_authoritative_blocker", boom)
    monkeypatch.setattr("ic_copilot.pipeline.assess_output_intent", boom)
    monkeypatch.setattr("ic_copilot.pipeline.build_target_shortlist", boom)
    monkeypatch.setattr("ic_copilot.pipeline.repair_blocked_decision", boom)

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = payload["candidate_targets"][0]
        event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Owner status is needed.",
            latest_open_loop="Need owner status.",
            selected_move=ICMove.REQUEST_STATUS_OR_ETA,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this=f"{target['display_name']}, can you share current status and ETA?",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote=event["text"])],
            confidence=0.8,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["trace"].processing_strategy == "incident_read_and_whisper_v2"
    assert result["verifier_result"].passed


def test_latest_human_open_loop_fixture_passes_through_one_call_read(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "[10:00] Default_Agent: Next Actions: Data Pipeline team continues monitoring cluster latency.\n"
        "[10:05] Utsav: Got reply from the customer contact; sandbox tenant scope is confirmed and they are deleting account data.\n"
        "[10:06] Hajime Watanabe: Can we confirm whether they can pause or stop the deletion process, and whether the same activity is happening elsewhere?"
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        names = {target["display_name"]: target for target in payload["candidate_targets"]}
        assert "Data Pipeline team" not in names or names["Data Pipeline team"]["source"] != "catalog"
        target = names["Hajime Watanabe"]
        latest_event = payload["latest_window_events"][-1]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Customer activity is confirmed and the latest open loop is whether it can pause or stop.",
            latest_open_loop="Confirm pause/stop decision and whether the same activity exists elsewhere.",
            already_answered=["customer confirmation of activity"],
            selected_move=ICMove.REQUEST_MITIGATION_OPTION,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this=(
                "Hajime Watanabe, can we confirm whether the customer can pause or stop the deletion process "
                "and whether the same activity is happening elsewhere?"
            ),
            evidence=[
                WhisperEvidenceRef(
                    event_id=latest_event["event_id"],
                    quote="Can we confirm whether they can pause or stop the deletion process",
                )
            ],
            confidence=0.84,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["verifier_result"].passed
    assert result["decision"].move == ICMove.REQUEST_MITIGATION_OPTION
    assert result["decision"].target_ids
    assert "pause or stop" in result["final_output"].lower()
    assert "I do not have a safe" not in result["final_output"]


def _megastore_scope_escalation_paste() -> str:
    filler = "\n".join(
        f"[09:{index:02d}] Coordinator {index}: Current investigation note {index}; status and validation still pending."
        for index in range(1, 22)
    )
    return (
        filler
        + "\n[09:30] Navneeth: This should be P1 since the customer is blocked from running Megastore enabled reports."
        + "\n[09:31] Kenneth: What does P1 mean here? Are multiple customers impacted or only Toast?"
        + "\n[09:32] Zeenie Louis: Only Toast has reported impact. The only live customers on the pipeline are Toast and Okta, and Okta has not reported impact."
        + "\n[09:33] Zeenie Louis: Current findings show report failure with row-count mismatch on the Iceberg side. We want Rajesh or the Megastore pipeline owner engaged to decide next steps and validation."
    )


def test_megastore_context_keeps_later_scope_and_row_count_evidence(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(_megastore_scope_escalation_paste())

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        model_text = "\n".join(event["text"] for event in payload["latest_window_events"])
        assert "What does P1 mean here" in model_text
        assert "Only Toast has reported impact" in model_text
        assert "row-count mismatch" in model_text
        assert payload["trailing_high_signal_human_event_ids_kept"]
        assert not payload["trailing_high_signal_human_event_ids_dropped"]
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Zeenie Louis")
        event = next(event for event in payload["latest_window_events"] if "row-count mismatch" in event["text"])
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="The P1 claim needs scope validation and pipeline row-count validation.",
            latest_open_loop="Scope is answered; need Megastore pipeline row-count validation.",
            selected_move=ICMove.ASK_NEXT_VALIDATION,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this=(
                "@Zeenie Louis, since current evidence says only Toast has reported impact, can you confirm what "
                "validation the Megastore pipeline owner needs next for the Iceberg row-count mismatch?"
            ),
            evidence=[
                WhisperEvidenceRef(
                    event_id=event["event_id"],
                    quote="Current findings show report failure with row-count mismatch on the Iceberg side.",
                )
            ],
            confidence=0.86,
        )

    result = run_pipeline(
        incident,
        catalog_path="local_knowledge/service_catalog.yaml",
        command_registry_path="local_knowledge/command_registry.yaml",
        memory_path="local_knowledge/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["verifier_result"].passed
    diagnosis = result["trace"].run_diagnosis
    assert any(
        item["question_intent"] == "impact_scope"
        for item in diagnosis["open_loop_diagnosis"]["answered_open_loops"]
    )
    assert any(
        item["question_intent"] == "technical_validation"
        for item in diagnosis["open_loop_diagnosis"]["unresolved_open_loops"]
    )
    assert not diagnosis["open_loop_diagnosis"]["stale_output_risks"]
    accepted = set(result["trace"].accepted_memory_ids)
    assert "DM_pipeline_health_signals_for_report_failures" in accepted
    scope_result = next(
        (
            item
            for item in result["trace"].applicability_results
            if item.decision_id == "DM_scope_before_priority_escalation"
        ),
        None,
    )
    if scope_result is not None:
        assert not scope_result.accepted
        assert "suppressed_scope_question_answered_by_later_current_evidence" in scope_result.reasons
    summary = result["trace"].context_pack_summary
    assert summary["trailing_high_signal_human_event_ids_kept"]
    assert not summary["trailing_high_signal_human_event_ids_dropped"]
    assert "Trust" not in result["final_output"]
    assert "page Rajesh" not in result["final_output"]
    assert "execute" not in result["final_output"].lower()


def test_megastore_scope_answer_supersedes_repeated_broad_scope_ask(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(_megastore_scope_escalation_paste())

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Navneeth")
        event = next(event for event in payload["latest_window_events"] if "should be P1" in event["text"])
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="The reporter proposed P1 and impact scope is being checked.",
            latest_open_loop="Need impacted customer scope.",
            selected_move=ICMove.ASK_IMPACT,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this=(
                "@Navneeth, can you confirm whether this is isolated to one customer or if more production "
                "customers are affected before we change severity?"
            ),
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote=event["text"])],
            confidence=0.7,
        )

    result = run_pipeline(
        incident,
        catalog_path="local_knowledge/service_catalog.yaml",
        command_registry_path="local_knowledge/command_registry.yaml",
        memory_path="local_knowledge/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert "more production customers" not in result["final_output"].lower()
    safety = result["trace"].safety_summary
    assert safety["simplified_verifier_checks"]["stale_answered_open_loop"] is False
    assert any("answered by later human evidence" in claim for claim in safety["original_blocked_claims"])
    diagnosis = result["trace"].run_diagnosis
    assert any(
        item["question_intent"] == "impact_scope"
        for item in diagnosis["open_loop_diagnosis"]["answered_open_loops"]
    )
    assert diagnosis["open_loop_diagnosis"]["model_candidate_stale_output_risks"]
    assert diagnosis["final_output_quality"]["safe_but_weak"] is True
    assert diagnosis["final_output_quality"]["likely_failure_category"] == "open_loop_supersedence"


def test_megastore_schema_invalid_no_safe_exposes_planning_failure(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(_megastore_scope_escalation_paste())

    def read_factory(payload: dict[str, Any]) -> dict[str, Any]:
        event = next(event for event in payload["latest_window_events"] if "row-count mismatch" in event["text"])
        return {
            "incident_id": payload["incident_id"],
            "current_read": "Report failure has row-count mismatch.",
            "latest_open_loop": "Need pipeline validation.",
            "selected_move": "request_customer_impact",
            "selected_target_id": "not-a-candidate",
            "selected_target_display_name": "Rajesh",
            "say_this": "We need Rajesh or the Megastore pipeline owner to decide next steps.",
            "evidence": [{"event_id": event["event_id"], "quote": event["text"]}],
        }

    result = run_pipeline(
        incident,
        catalog_path="local_knowledge/service_catalog.yaml",
        command_registry_path="local_knowledge/command_registry.yaml",
        memory_path="local_knowledge/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    safety = result["trace"].safety_summary
    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert safety["provider_output_was_invalid"] is True
    assert safety["provider_schema_error"] is True
    assert safety["planning_failure_category"] == "planning_model_schema_invalid"
    assert safety["simplified_verifier_checks"]["no_safe_despite_accepted_memory"] is False
    assert any("planning/model schema failure" in claim for claim in safety["original_blocked_claims"])
    diagnosis = result["trace"].run_diagnosis
    quality = diagnosis["final_output_quality"]
    assert quality["likely_failure_category"] == "planning_model_schema_invalid"
    assert quality["provider_output_was_invalid"] is True
    assert "one-call IncidentReadAndWhisper output did not validate cleanly" in quality["weakness_reasons"]
    assert quality["likely_failure_category"] != "none"


def test_megastore_passive_owner_statement_is_blocked_without_content_repair(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(_megastore_scope_escalation_paste())

    weak_say_this = (
        "Current findings show report failure with row-count mismatch on Iceberg. "
        "We need Rajesh or the Megastore pipeline owner to decide next steps and validation."
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        event = next(event for event in payload["latest_window_events"] if "row-count mismatch" in event["text"])
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Report failure has a row-count mismatch on Iceberg.",
            latest_open_loop="Need pipeline owner validation.",
            selected_move=ICMove.ESCALATE_SEVERITY_OR_OWNER,
            selected_target_id=None,
            selected_target_display_name=None,
            say_this=weak_say_this,
            evidence=[
                WhisperEvidenceRef(
                    event_id=event["event_id"],
                    quote="Current findings show report failure with row-count mismatch on the Iceberg side.",
                )
            ],
            confidence=0.7,
        )

    result = run_pipeline(
        incident,
        catalog_path="local_knowledge/service_catalog.yaml",
        command_registry_path="local_knowledge/command_registry.yaml",
        memory_path="local_knowledge/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert weak_say_this not in result["final_output"]
    assert "can you confirm what validation" not in result["final_output"]
    safety_checks = result["trace"].safety_summary["simplified_verifier_checks"]
    assert safety_checks["no_passive_we_need_owner_statement"] is False
    assert safety_checks["no_low_quality_named_person_as_owner"] is False
    diagnosis = result["trace"].run_diagnosis
    quality = diagnosis["final_output_quality"]
    assert quality["safe_but_weak"] is True
    assert quality["passive_owner_statement"] is True
    assert "Rajesh" in quality["low_quality_named_owner_terms"]
    assert quality["actionability_failure_category"] == "low_quality_named_owner"


def test_megastore_direct_validation_ask_passes_actionability(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(_megastore_scope_escalation_paste())

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Zeenie Louis")
        event = next(event for event in payload["latest_window_events"] if "row-count mismatch" in event["text"])
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Scope is answered and row-count validation remains open.",
            latest_open_loop="Need Megastore pipeline validation.",
            selected_move=ICMove.ASK_NEXT_VALIDATION,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this=(
                "@Zeenie Louis, can you confirm what validation the Megastore pipeline owner needs next "
                "for the Iceberg row-count mismatch?"
            ),
            evidence=[
                WhisperEvidenceRef(
                    event_id=event["event_id"],
                    quote="Current findings show report failure with row-count mismatch on the Iceberg side.",
                )
            ],
            confidence=0.86,
        )

    result = run_pipeline(
        incident,
        catalog_path="local_knowledge/service_catalog.yaml",
        command_registry_path="local_knowledge/command_registry.yaml",
        memory_path="local_knowledge/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["verifier_result"].passed
    quality = result["trace"].run_diagnosis["final_output_quality"]
    assert quality["direct_ask"] is True
    assert quality["passive_owner_statement"] is False
    assert quality["low_quality_named_owner_terms"] == []
    assert quality["actionability_failure_category"] == "none"


def test_megastore_good_direct_ask_move_is_metadata_normalized_only(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(_megastore_scope_escalation_paste())
    say_this = (
        "@Zeenie Louis, can you confirm the next validation for the Iceberg row-count mismatch?"
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Zeenie Louis")
        event = next(event for event in payload["latest_window_events"] if "row-count mismatch" in event["text"])
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Scope is answered and row-count validation remains open.",
            latest_open_loop="Need Megastore pipeline validation.",
            selected_move=ICMove.ESCALATE_SEVERITY_OR_OWNER,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this=say_this,
            evidence=[
                WhisperEvidenceRef(
                    event_id=event["event_id"],
                    quote="Current findings show report failure with row-count mismatch on the Iceberg side.",
                )
            ],
            confidence=0.82,
        )

    result = run_pipeline(
        incident,
        catalog_path="local_knowledge/service_catalog.yaml",
        command_registry_path="local_knowledge/command_registry.yaml",
        memory_path="local_knowledge/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["verifier_result"].passed
    assert result["decision"].move == ICMove.ASK_NEXT_VALIDATION
    assert say_this in result["final_output"]
    assert result["trace"].safety_summary["actionability_move_normalized"] is True
    assert result["decision"].output["say_this"] == say_this


def test_megastore_p1_self_summary_output_is_blocked(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(_megastore_scope_escalation_paste())

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Navneeth")
        event = next(event for event in payload["latest_window_events"] if "should be P1" in event["text"])
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="The reporter proposed P1.",
            latest_open_loop="No open loops detected.",
            selected_move=ICMove.ASK_IMPACT,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@Navneeth noted this is a P1 since the customer is blocked from running Megastore enabled reports.",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote=event["text"])],
            confidence=0.7,
        )

    result = run_pipeline(
        incident,
        catalog_path="local_knowledge/service_catalog.yaml",
        command_registry_path="local_knowledge/command_registry.yaml",
        memory_path="local_knowledge/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    safety = result["trace"].safety_summary
    assert safety["simplified_verifier_checks"]["severity_claim_confirmed"] is False
    assert safety["simplified_verifier_checks"]["no_useless_self_summary"] is False
    assert any("proposed severity" in claim for claim in safety["original_blocked_claims"])


def test_unconfirmed_priority_update_claim_blocks_without_bot_or_ic_confirmation(tmp_path: Path) -> None:
    incident = tmp_path / "incident.txt"
    incident.write_text(
        "[09:30] Navneeth: This should be P1 since the customer is blocked from running reports.\n"
        "[09:31] Kenneth: Are multiple customers impacted?"
    )

    def read_factory(payload: dict[str, Any]) -> IncidentReadAndWhisper:
        target = next(item for item in payload["candidate_targets"] if item["display_name"] == "Navneeth")
        event = payload["latest_window_events"][0]
        return IncidentReadAndWhisper(
            incident_id=payload["incident_id"],
            current_read="Priority update was inferred incorrectly.",
            latest_open_loop="No open loops detected.",
            selected_move=ICMove.ASK_IMPACT,
            selected_target_id=target["target_id"],
            selected_target_display_name=target["display_name"],
            say_this="@Navneeth, severity has been updated to P1 because the customer is blocked.",
            evidence=[WhisperEvidenceRef(event_id=event["event_id"], quote=event["text"])],
            confidence=0.7,
        )

    result = run_pipeline(
        incident,
        catalog_path="data/contract/service_catalog.yaml",
        command_registry_path="data/contract/command_registry.yaml",
        memory_path="data/contract/decision_moments.jsonl",
        save_trace=False,
        llm_client=_ReadClient(read_factory),
    )

    assert result["decision"].move == ICMove.NO_SAFE_RECOMMENDATION
    assert result["trace"].safety_summary["simplified_verifier_checks"]["severity_claim_confirmed"] is False
