from __future__ import annotations

import re
from typing import Any

from ic_copilot.llm.redaction import redact_for_llm
from ic_copilot.schemas import AllowedTarget, IncidentEvent


DIAGNOSTIC_FACT_PATTERNS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "producer_connection_error",
        "Kafka producer/broker connection error",
        ("connection to node -1", "broker may not be available", "producer clientid", "producer clientid="),
    ),
    (
        "kafka_network_connectivity",
        "Kafka network or pod connectivity check",
        ("pod can connect", "can connect to kafka", "curl connected", "connected to speed-racer-kafka", "connected to kafka"),
    ),
    (
        "cert_runtime_config_clue",
        "certificate/runtime/service configuration clue",
        ("runtime config", "service config", "feature flag", "cert", "certificate"),
    ),
    (
        "notary_event_worker_context",
        "Notary Event Worker context",
        ("notary event worker", "notary-message-producer"),
    ),
    (
        "db_cpu_threshold",
        "database CPU saturation threshold",
        ("cpubusypercent", "threshold > 90", "cpu busy", "db cpu", "database cpu", "cpu threshold", "cpu usage"),
    ),
    (
        "db_instance_or_host",
        "database instance or host evidence",
        ("db instance", "database host", "host:", "instance:", "rds", "aurora", ".zuora:3306"),
    ),
    (
        "db_connection_count",
        "database connection count",
        ("connection count", "connections", "total connections", "session count"),
    ),
    (
        "replication_lag_status",
        "database replication lag status",
        ("replication lag", "replica lag", "lag status", "lag is normal", "no replication lag"),
    ),
    (
        "dune_or_jobs_check",
        "DUNE/shard/jobs check",
        ("shard dune jobs", "dune jobs", "jobs check", "dune", "shard", "scheduler", "job queue"),
    ),
    (
        "database_agent_involvement",
        "Database_Agent involvement",
        ("database_agent", "database-agent", "database agent", "dba"),
    ),
    (
        "db_workload_validation_next_action",
        "database workload validation next action",
        (
            "cpu did not decrease",
            "tenant is still driving bulk operation",
            "workload bulk operation",
            "driving bulk operation",
            "dedicated queue",
        ),
    ),
    (
        "failed_records_workload",
        "failed_records / DACO workload clue",
        ("failed_records", "daco", "failed records", "query cleanup"),
    ),
    (
        "current_owner_request",
        "current owner request",
        ("owner", "oncall", "on call", "can you help", "please help", "need help"),
    ),
    (
        "bot_suggested_owner_request",
        "bot-suggested owner request",
        ("can you help", "please help", "need help"),
    ),
    (
        "temporal_transfer_accounting",
        "Temporal Transfer Accounting workflow evidence",
        ("temporal", "transfer accounting", "execution history", "ta batch", "activity error"),
    ),
    (
        "megastore_scope_or_pipeline",
        "Megastore scope/pipeline validation evidence",
        ("megastore", "iceberg", "row-count", "row count", "pipeline", "reports"),
    ),
    (
        "sync_latency_topic_permission",
        "sync-latency topic/permission evidence",
        (
            "dataconnectsalesforcesync",
            "dedicated topic",
            "dedicated_topic",
            "permission denied",
            "required permission",
            "topic move",
            "move dataconnectsalesforcesync",
        ),
    ),
    (
        "ocs_lag_owner_action",
        "OCS lag owner/action evidence",
        ("event produce latency", "slow event", "ocs lag", "worker pod", "kafka investigation"),
    ),
)

MEMORY_INTENT_CONTRACTS: dict[str, dict[str, Any]] = {
    "DIAG_db_cpu_initial_database_owner_status": {
        "expected_target_classes": ["database_owner", "service_owner", "investigating_human"],
        "expected_visible_term_groups": [
            ["cpu", "cpubusypercent", "threshold", "load"],
            ["status", "still", "current", "confirm"],
            ["recover", "recovery", "signal", "replication", "dune", "connection"],
        ],
        "diagnostic_fact_ids": [
            "db_cpu_threshold",
            "db_instance_or_host",
            "replication_lag_status",
            "dune_or_jobs_check",
            "database_agent_involvement",
        ],
    },
    "DM_kafka_connection_error_check_service_config_drift": {
        "expected_target_classes": ["config_owner", "service_owner", "investigating_human"],
        "expected_visible_term_groups": [
            ["kafka", "broker", "producer"],
            ["config", "cert", "certificate", "runtime", "feature"],
            ["confirm", "validate", "validation", "signal", "recover", "recovery", "check"],
        ],
        "diagnostic_fact_ids": [
            "producer_connection_error",
            "kafka_network_connectivity",
            "cert_runtime_config_clue",
        ],
    },
    "DM_db_cpu_bad_query_route_to_app_owner": {
        "expected_target_classes": ["service_owner", "explicit_action_owner", "investigating_human"],
        "expected_visible_term_groups": [
            ["cpu", "load", "cpubusypercent"],
            ["failed_records", "daco", "query", "workload"],
            ["confirm", "validate", "source", "owner", "signal"],
        ],
        "diagnostic_fact_ids": ["db_cpu_threshold", "failed_records_workload"],
    },
    "DM_verify_cpu_recovery_before_mitigation": {
        "expected_target_classes": ["service_owner", "investigating_human", "explicit_action_owner"],
        "expected_visible_term_groups": [
            ["cpu", "load", "cpubusypercent"],
            ["recover", "recovery", "stable", "validation", "confirm", "signal"],
        ],
        "diagnostic_fact_ids": ["db_cpu_threshold"],
    },
    "DM_temporal_workflow_failure_owner_status": {
        "expected_target_classes": ["service_owner", "explicit_action_owner", "investigating_human"],
        "expected_visible_term_groups": [
            ["temporal", "workflow", "execution"],
            ["status", "eta", "history", "logs", "scope", "workaround"],
        ],
        "diagnostic_fact_ids": ["temporal_transfer_accounting"],
    },
    "DM_scope_before_priority_escalation": {
        "expected_target_classes": ["reporter", "coordinator", "investigating_human"],
        "expected_visible_term_groups": [
            ["scope", "impact", "customer", "affected", "blocked"],
        ],
        "diagnostic_fact_ids": ["megastore_scope_or_pipeline"],
    },
    "DM_pipeline_health_signals_for_report_failures": {
        "expected_target_classes": ["service_owner", "explicit_action_owner", "investigating_human"],
        "expected_visible_term_groups": [
            ["pipeline", "iceberg", "row-count", "row count", "report"],
            ["validation", "validate", "signal", "status", "confirm"],
        ],
        "diagnostic_fact_ids": ["megastore_scope_or_pipeline"],
    },
    "DM_verify_actual_bottleneck_topic_before_mitigation": {
        "expected_target_classes": ["service_owner", "explicit_action_owner", "investigating_human"],
        "expected_visible_term_groups": [
            ["topic", "queue", "bottleneck", "dataconnectsalesforcesync"],
            ["validate", "confirm", "latency", "signal", "scope"],
        ],
        "diagnostic_fact_ids": ["sync_latency_topic_permission"],
    },
    "DM_target_service_owner_for_correct_topic_root_cause": {
        "expected_target_classes": ["service_owner", "config_owner", "explicit_action_owner", "investigating_human"],
        "expected_visible_term_groups": [
            ["topic", "queue", "dataconnectsalesforcesync", "daco", "kafka", "broker", "producer"],
            ["owner", "root cause", "validation", "confirm", "scope", "config", "signal"],
        ],
        "diagnostic_fact_ids": ["sync_latency_topic_permission"],
    },
    "DM_explicit_next_action_owner_alignment": {
        "expected_target_classes": ["explicit_action_owner", "service_owner", "investigating_human"],
        "expected_visible_term_groups": [
            ["status", "eta", "signal", "validation", "confirm", "share"],
        ],
        "diagnostic_fact_ids": ["ocs_lag_owner_action"],
    },
}


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _name_key(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", " ", _norm(value)).strip()


def _excerpt_for_term(text: str, term: str, *, limit: int = 220) -> str:
    compact = " ".join((text or "").split())
    lowered = compact.lower()
    index = lowered.find(term.lower())
    if index < 0:
        excerpt = compact[:limit]
    else:
        start = max(0, index - 70)
        end = min(len(compact), index + len(term) + 120)
        excerpt = compact[start:end].strip()
    if len(excerpt) > limit:
        excerpt = excerpt[:limit].rsplit(" ", 1)[0]
    return str(redact_for_llm(excerpt))


def extract_diagnostic_facts(
    events: list[IncidentEvent],
    event_quality_by_id: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    event_quality_by_id = event_quality_by_id or {}
    facts: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for event in events:
        text = event.message or ""
        text_norm = _norm(text)
        if not text_norm:
            continue
        quality = event_quality_by_id.get(event.event_id)
        event_kind = str(getattr(quality, "event_kind", "") or "unknown")
        planner_allowed = bool(getattr(quality, "is_planner_grounding_allowed", True))
        author_type = str(getattr(quality, "author_type", "") or "")
        for fact_id, fact_label, terms in DIAGNOSTIC_FACT_PATTERNS:
            if fact_id == "current_owner_request" and author_type in {"bot", "system"}:
                continue
            if fact_id == "bot_suggested_owner_request" and author_type not in {"bot", "system"}:
                continue
            term = next(
                (
                    candidate
                    for candidate in terms
                    if candidate in text_norm and (candidate != "rds" or re.search(r"\brds\b", text_norm))
                ),
                None,
            )
            if term is None:
                continue
            present_terms = [
                candidate
                for candidate in terms
                if candidate in text_norm and (candidate != "rds" or re.search(r"\brds\b", text_norm))
            ]
            key = (fact_id, event.event_id)
            if key in seen:
                continue
            seen.add(key)
            facts.append(
                {
                    "fact_id": fact_id,
                    "fact_label": fact_label,
                    "event_id": event.event_id,
                    "author": event.author,
                    "source_event_kind": event_kind,
                    "author_type": author_type,
                    "planner_grounding_allowed": planner_allowed,
                    "matched_term": term,
                    "present_terms": present_terms[:6],
                    "diagnostic_allowed_for": _diagnostic_allowed_for(fact_id, author_type),
                    "excerpt": _excerpt_for_term(text, term),
                }
            )
    return facts


def _diagnostic_allowed_for(fact_id: str, author_type: str) -> dict[str, bool]:
    target_selection = fact_id not in {
        "bot_suggested_owner_request",
        "current_owner_request",
    } and author_type not in {"bot", "system"}
    if fact_id in {
        "db_cpu_threshold",
        "db_instance_or_host",
        "db_connection_count",
        "replication_lag_status",
        "dune_or_jobs_check",
        "database_agent_involvement",
        "db_workload_validation_next_action",
    }:
        target_selection = False
    return {
        "target_selection": target_selection,
        "memory_applicability": fact_id != "bot_suggested_owner_request",
        "model_grounding": True,
        "verifier_no_safe_blocking": fact_id
        in {
            "db_cpu_threshold",
            "db_instance_or_host",
            "db_connection_count",
            "replication_lag_status",
            "dune_or_jobs_check",
            "database_agent_involvement",
            "db_workload_validation_next_action",
            "failed_records_workload",
            "producer_connection_error",
            "kafka_network_connectivity",
            "cert_runtime_config_clue",
            "sync_latency_topic_permission",
            "ocs_lag_owner_action",
            "megastore_scope_or_pipeline",
            "temporal_transfer_accounting",
        },
    }


def diagnostic_fact_classifications(
    detected_facts: list[dict[str, Any]],
    retained_facts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    detected_ids = {str(fact.get("fact_id") or "") for fact in detected_facts}
    retained_ids = {str(fact.get("fact_id") or "") for fact in retained_facts}
    rows: list[dict[str, Any]] = []
    for fact in retained_facts:
        fact_id = str(fact.get("fact_id") or "")
        category = "harmless_extra_fact"
        if fact_id in {
            "db_cpu_threshold",
            "db_instance_or_host",
            "replication_lag_status",
            "dune_or_jobs_check",
            "database_agent_involvement",
            "db_connection_count",
            "db_workload_validation_next_action",
            "failed_records_workload",
            "producer_connection_error",
            "kafka_network_connectivity",
            "cert_runtime_config_clue",
            "sync_latency_topic_permission",
            "temporal_transfer_accounting",
            "ocs_lag_owner_action",
            "megastore_scope_or_pipeline",
        }:
            category = "expected_fact"
        if fact_id in {"bot_suggested_owner_request"}:
            category = "harmless_extra_fact"
        rows.append(
            {
                "fact_id": fact_id,
                "category": category,
                "event_id": fact.get("event_id"),
                "allowed_for": fact.get("diagnostic_allowed_for") or _diagnostic_allowed_for(
                    fact_id,
                    str(fact.get("author_type") or ""),
                ),
            }
        )
    for fact_id in sorted(detected_ids - retained_ids):
        rows.append(
            {
                "fact_id": fact_id,
                "category": "missing_fact",
                "event_id": None,
                "allowed_for": _diagnostic_allowed_for(fact_id, ""),
            }
        )
    harmful_false_positive_ids = {
        "sync_latency_topic_permission",
        "temporal_transfer_accounting",
    }
    for row in rows:
        if row["fact_id"] in harmful_false_positive_ids and row["category"] == "harmless_extra_fact":
            row["category"] = "harmful_extra_fact"
    return rows[:24]


def db_cpu_initial_contract(facts: list[dict[str, Any]]) -> dict[str, Any] | None:
    fact_ids = {str(fact.get("fact_id") or "") for fact in facts}
    if "db_cpu_threshold" not in fact_ids:
        return None
    if "failed_records_workload" in fact_ids or "db_workload_validation_next_action" in fact_ids:
        return None
    supporting = fact_ids.intersection(
        {
            "db_instance_or_host",
            "db_connection_count",
            "replication_lag_status",
            "dune_or_jobs_check",
            "database_agent_involvement",
        }
    )
    if not supporting:
        return None
    return {"decision_id": "DIAG_db_cpu_initial_database_owner_status", **MEMORY_INTENT_CONTRACTS["DIAG_db_cpu_initial_database_owner_status"]}


def target_class_for_allowed_target(
    target: AllowedTarget,
    *,
    work_item_owner: bool = False,
    accepted_memory_ids: list[str] | None = None,
) -> str:
    if not target.targetable or target.target_type in {"bot_system", "non_targetable_noise"}:
        return "bot_or_noise"
    target_name = _name_key(target.display_name)
    canonical_id = _name_key(target.canonical_id)
    if target_name in {"dba", "database", "database dbe", "database engineering"} or canonical_id in {
        "dba",
        "database_engineering",
        "database dbe",
    }:
        return "database_owner"
    if work_item_owner:
        return "explicit_action_owner"
    source_kind = str(target.source_event_kind or "")
    if source_kind.startswith(("human_diagnostic", "human_validation", "human_status")):
        return "investigating_human"
    role = target.role_hint or "unknown"
    if role == "ic_or_coordinator":
        return "coordinator"
    if role == "reporter_or_validator":
        return "reporter"
    if role == "support_team":
        return "customer_support"
    if target.target_type in {"service", "team"}:
        memory_text = " ".join(accepted_memory_ids or []).lower()
        if "config" in memory_text or "kafka_connection_error" in memory_text:
            return "config_owner"
        return "service_owner"
    if role in {"owner_team", "technical_investigator"}:
        return "investigating_human"
    if target.source in {"slack_author", "explicit_mention"} and target.target_type == "person":
        return "investigating_human"
    return "service_owner" if target.target_type in {"service", "team"} else "reporter"


def target_class_for_candidate_row(row: dict[str, Any]) -> str:
    value = str(row.get("target_class") or "")
    if value:
        return value
    target_type = str(row.get("target_type") or "")
    role = str(row.get("role_hint") or "")
    source = str(row.get("source") or "")
    source_kind = str(row.get("source_event_kind") or "")
    why = _norm(str(row.get("why_visible") or ""))
    if target_type in {"bot_system", "non_targetable_noise"}:
        return "bot_or_noise"
    if "work-item owner" in why:
        return "explicit_action_owner"
    if source_kind.startswith(("human_diagnostic", "human_validation", "human_status")):
        return "investigating_human"
    if role == "ic_or_coordinator":
        return "coordinator"
    if role == "reporter_or_validator":
        return "reporter"
    if role == "support_team":
        return "customer_support"
    if target_type in {"service", "team"}:
        return "service_owner"
    if role in {"owner_team", "technical_investigator"} or source_kind.startswith("human_diagnostic"):
        return "investigating_human"
    if source in {"slack_author", "explicit_mention"}:
        return "investigating_human"
    return "bot_or_noise" if target_type == "bot_system" else "reporter"


def memory_contract_for_id(decision_id: str) -> dict[str, Any]:
    if decision_id in MEMORY_INTENT_CONTRACTS:
        return {"decision_id": decision_id, **MEMORY_INTENT_CONTRACTS[decision_id]}
    lowered = decision_id.lower()
    if "kafka" in lowered and "config" in lowered:
        base = MEMORY_INTENT_CONTRACTS["DM_kafka_connection_error_check_service_config_drift"]
    elif "cpu" in lowered:
        base = MEMORY_INTENT_CONTRACTS["DM_verify_cpu_recovery_before_mitigation"]
    elif "temporal" in lowered:
        base = MEMORY_INTENT_CONTRACTS["DM_temporal_workflow_failure_owner_status"]
    elif "pipeline" in lowered:
        base = MEMORY_INTENT_CONTRACTS["DM_pipeline_health_signals_for_report_failures"]
    elif "topic" in lowered or "bottleneck" in lowered:
        base = MEMORY_INTENT_CONTRACTS["DM_verify_actual_bottleneck_topic_before_mitigation"]
    else:
        base = {}
    return {"decision_id": decision_id, **base}


def visible_terms_satisfied(text: str, term_groups: list[list[str]]) -> tuple[bool, list[str]]:
    text_norm = _norm(text)
    missing: list[str] = []
    for group in term_groups:
        if not any(_norm(term) and _norm(term) in text_norm for term in group):
            missing.append("/".join(group))
    return not missing, missing


def expected_memory_contracts(decision_ids: list[str]) -> list[dict[str, Any]]:
    return [memory_contract_for_id(decision_id) for decision_id in decision_ids if memory_contract_for_id(decision_id)]
