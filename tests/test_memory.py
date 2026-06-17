from pathlib import Path
import json

from ic_copilot.memory import (
    build_memory_query,
    hydrate_decision_moments,
    judge_applicability,
    load_decision_moments,
    retrieve_decision_moment_ids,
)
from ic_copilot.schemas import CurrentIncidentState, DecisionMoment, EntityRef, EntityType, EvidenceRef, IncidentPhase


MEMORY_DIR = Path("data/sample/decision_moments")


def state():
    evidence = EvidenceRef(event_id="m001", quote="RevPro Support should be engaged")
    return CurrentIncidentState(
        incident_id="i1",
        phase=IncidentPhase.TRIAGE,
        current_blocker="missing_owner",
        suggested_but_not_engaged=[
            EntityRef(
                entity_type=EntityType.TEAM,
                display_name="RevPro Support",
                canonical_id="revpro-support",
                status="suggested_not_engaged",
                evidence=[evidence],
            )
        ],
        compact_summary="RevPro Support should be engaged.",
    )


def test_retrieval_returns_ids_only():
    moments = load_decision_moments(MEMORY_DIR)
    ids = retrieve_decision_moment_ids(build_memory_query(state()), moments)
    assert ids
    assert all(isinstance(item, str) for item in ids)


def test_hydration_returns_full_decision_moment():
    moments = load_decision_moments(MEMORY_DIR)
    hydrated = hydrate_decision_moments(["dm_missing_owner_after_support_signal"], moments)
    assert hydrated[0].decision_id == "dm_missing_owner_after_support_signal"
    assert hydrated[0].ic_action


def test_wrong_phase_memory_is_rejected():
    moments = load_decision_moments(MEMORY_DIR)
    code_fix = hydrate_decision_moments(["dm_code_fix_eta_blocker"], moments)
    result = judge_applicability(state(), code_fix)
    assert not result[0].accepted
    assert "wrong_phase" in result[0].reasons


def test_missing_required_current_evidence_is_rejected():
    moments = load_decision_moments(MEMORY_DIR)
    current = CurrentIncidentState(
        incident_id="i1",
        phase=IncidentPhase.TRIAGE,
        current_blocker="missing_owner",
        compact_summary="No owner yet.",
    )
    moment = hydrate_decision_moments(["dm_missing_owner_after_support_signal"], moments)
    result = judge_applicability(current, moment)
    assert not result[0].accepted
    assert any(reason.startswith("missing_hard_current_evidence") for reason in result[0].reasons)


def test_revenue_api_memory_accepts_connection_limit_without_api_only_soft_signal():
    moment = DecisionMoment(
        decision_id="DM_revenue_api_timeout_route_to_ria_and_revenue_engineering",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.9,
        phase_before=IncidentPhase.TRIAGE,
        phase_after=IncidentPhase.ENGAGEMENT,
        move="engage_owner",
        situation_before="Revenue API/RIA timeout needs owner routing.",
        trigger="Use when API/RIA timeout evidence appears.",
        ic_action="Ask Revenue/RIA owner to validate API health and connection-limit signal.",
        why_it_worked="Routes early diagnostics to the owning service path.",
        applicability={
            "required_current_evidence": [
                "API timeout/error symptom",
                "service name such as RIA, Revenue API, Kong, or load balancer",
                "API-only or UI-not-impacted statement",
            ],
        },
    )

    result = judge_applicability(
        CurrentIncidentState(incident_id="i", phase=IncidentPhase.TRIAGE),
        [moment],
        current_evidence_text=(
            "Sriram asks Vignesh to page engineering. Irfan says let me page, "
            "@zsrebot page team revenue, and zsrebot says Done. "
            "Sriram then posts RIA connection limit warning from the current logs."
        ),
    )[0]

    assert result.accepted
    assert "API timeout/error symptom" in result.hard_requirements_satisfied
    assert "service name such as RIA, Revenue API, Kong, or load balancer" in result.hard_requirements_satisfied
    assert "API-only or UI-not-impacted statement" in result.soft_signals_missing
    assert any(reason.startswith("missing_soft_signal") for reason in result.reasons)


def test_permission_scope_ambiguity_suppresses_late_bottleneck_memory() -> None:
    moment = DecisionMoment(
        decision_id="DM_verify_actual_bottleneck_topic_before_mitigation",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.93,
        phase_before=IncidentPhase.UNKNOWN,
        phase_after=IncidentPhase.MONITORING,
        move="request_monitoring_signal",
        situation_before="Latency persists after a tenant/topic isolation step.",
        trigger="Verify the actual bottleneck topic before treating mitigation as complete.",
        ic_action="Ask the owner to confirm the actual bottleneck topic and remaining affected tenants.",
        why_it_worked="Avoids anchoring on the first attempted mitigation.",
        applicability={
            "required_current_evidence": [
                "attempted tenant/topic isolation",
                "continued latency evidence",
                "explicit statement identifying the actual bottleneck topic or queue",
            ],
        },
    )
    evidence = (
        "Dharani says DataConnectSalesforceSync latency is above threshold. "
        "Faisal tried do-not-thread @daco-bot topics for [REDACTED_TENANT_ID] move "
        "DataConnectSalesforceSync and got required permission denied. "
        "Dharani says both tenants are in different shards and asks Anmol to elaborate the exact symptoms "
        "and affected scope before treating this as the same issue."
    )

    result = judge_applicability(
        CurrentIncidentState(incident_id="i", phase=IncidentPhase.UNKNOWN),
        [moment],
        current_evidence_text=evidence,
    )[0]

    assert not result.accepted
    assert "suppressed_until_permission_loop_scope_is_resolved" in result.reasons


def test_latest_window_evidence_can_satisfy_simplified_memory_gate():
    moment = DecisionMoment(
        decision_id="DM_app_owner_after_infra_ruled_out",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.94,
        phase_before=IncidentPhase.TRIAGE,
        phase_after=IncidentPhase.ENGAGEMENT,
        move="engage_owner",
        situation_before="Infra resource pressure ruled out while app jobs remain stuck.",
        trigger="Pods healthy and application-level queue/job bottleneck remains.",
        ic_action="Ask the service owner for app-layer findings and safe mitigation path.",
        why_it_worked="Keeps ownership aligned after infra is ruled out.",
        applicability={
            "current_blocker": "missing_owner",
            "required_current_evidence": [
                "infra/resource health statement",
                "application-level bottleneck statement",
            ],
        },
    )
    evidence = (
        "ESG says pods healthy, CPU below threshold, memory stable, and HPA did not trigger. "
        "Data Loader import jobs are stuck in the application layer queue."
    )

    ids = retrieve_decision_moment_ids(
        build_memory_query(CurrentIncidentState(incident_id="i"), current_evidence_text=evidence),
        [moment],
    )
    result = judge_applicability(
        CurrentIncidentState(incident_id="i"),
        [moment],
        current_evidence_text=evidence,
    )[0]

    assert ids == ["DM_app_owner_after_infra_ruled_out"]
    assert result.accepted
    assert result.required_current_evidence_satisfied == [
        "infra/resource health statement",
        "application-level bottleneck statement",
    ]


def test_compiled_security_workstream_evidence_can_be_accepted():
    moment = DecisionMoment(
        decision_id="DM_security_workstream_owner_alignment",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.94,
        phase_before=IncidentPhase.INVESTIGATION,
        phase_after=IncidentPhase.INVESTIGATION,
        move="request_status_or_eta",
        situation_before="Security workstreams list owners for fix, rotation, and audit.",
        trigger="Use explicit workstream owner labels.",
        ic_action="Ask the owner for their assigned workstream status.",
        why_it_worked="Prevents wrong-owner asks.",
        applicability={
            "required_current_evidence": [
                "explicit workstream label",
                "explicit owner or owning team",
                "action/status text",
            ],
        },
    )
    evidence = (
        "Next Actions: Fix Vulnerability (Owner: Workflow @wenxuan): implement input validation and ETA. "
        "Rotate Credentials (Owner: Security): confirm rotation. Audit Logs (Owner: Security/SRE): validate usage."
    )

    result = judge_applicability(CurrentIncidentState(incident_id="i"), [moment], current_evidence_text=evidence)[0]

    assert result.accepted
    assert result.required_current_evidence_satisfied == [
        "explicit workstream label",
        "explicit owner or owning team",
        "action/status text",
    ]


def test_compiled_security_old_credential_usage_evidence_can_be_accepted():
    moment = DecisionMoment(
        decision_id="DM_old_secret_last_used_blocks_closure",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.92,
        phase_before=IncidentPhase.INVESTIGATION,
        phase_after=IncidentPhase.VERIFICATION,
        move="ask_next_validation",
        situation_before="Old credential usage blocks closure after rotation work.",
        trigger="Old credential still shows recent usage.",
        ic_action="Ask credential owner to confirm usage source and decommission readiness.",
        why_it_worked="Avoids premature closure.",
        applicability={
            "required_current_evidence": [
                "old credential recent usage",
                "new credential deployed or rotation attempted",
                "owner needed for validation",
            ],
        },
    )
    evidence = (
        "The input validation patch is deployed. Credential rotation/decommission validation is the blocker. "
        "The old credential still shows recent usage and Security/SRE owner validation is needed."
    )

    result = judge_applicability(CurrentIncidentState(incident_id="i"), [moment], current_evidence_text=evidence)[0]

    assert result.accepted
    assert result.required_current_evidence_satisfied == [
        "old credential recent usage",
        "new credential deployed or rotation attempted",
        "owner needed for validation",
    ]


def test_scope_before_priority_memory_is_suppressed_after_later_scope_answer() -> None:
    moment = DecisionMoment(
        decision_id="DM_scope_before_priority_escalation",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.9,
        phase_before=IncidentPhase.INVESTIGATION,
        phase_after=IncidentPhase.INVESTIGATION,
        move="ask_impact",
        situation_before="A participant requests higher priority because a customer is blocked.",
        trigger="Ask for current customer scope before supporting escalation.",
        ic_action="@{reporter}, can you confirm whether more production customers are affected?",
        why_it_worked="Prevents over-escalation before scope is known.",
        applicability={
            "current_blocker": "missing_impact",
            "required_current_evidence": [
                "customer blocked statement",
                "uncertain or limited impact scope",
                "severity discussion",
            ],
        },
    )
    evidence = (
        "Navneeth: This should be P1 since the customer is blocked from running Megastore enabled reports. "
        "Kenneth: Are multiple customers impacted or only Toast? "
        "Zeenie Louis: Only Toast has reported impact. No other customer has reported it."
    )

    result = judge_applicability(
        CurrentIncidentState(
            incident_id="i",
            phase=IncidentPhase.INVESTIGATION,
            current_blocker="missing_impact",
        ),
        [moment],
        current_evidence_text=evidence,
    )[0]

    assert not result.accepted
    assert result.required_current_evidence_satisfied == [
        "customer blocked statement",
        "uncertain or limited impact scope",
        "severity discussion",
    ]
    assert "suppressed_scope_question_answered_by_later_current_evidence" in result.reasons
    assert "stale_after_scope_answer" in result.restrictions


def test_pipeline_health_memory_accepts_report_failure_row_count_and_scope_answer() -> None:
    moment = DecisionMoment(
        decision_id="DM_pipeline_health_signals_for_report_failures",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.9,
        phase_before=IncidentPhase.MITIGATION,
        phase_after=IncidentPhase.MONITORING,
        move="request_monitoring_signal",
        situation_before="Reports fail after data pipeline consistency issues.",
        trigger="Ask for pipeline health and data consistency signals.",
        ic_action="@{owner}, can you share row-count validation status and whether the latest run passed?",
        why_it_worked="Grounds recovery in report re-run and row-count evidence.",
        applicability={
            "current_blocker": "waiting_on_monitoring",
            "required_current_evidence": [
                "report failure",
                "pipeline health signal",
                "data consistency concern",
            ],
        },
    )
    evidence = (
        "Navneeth: customer is blocked and not able to run any Megastore enabled reports. "
        "Kenneth: how many customers are impacted? "
        "Zeenie Louis: The issue reported is only for Toast. No other customer has reported it. "
        "Zeenie Louis: row count mismatch exists; one DEL table is less on Iceberg side."
    )

    result = judge_applicability(
        CurrentIncidentState(
            incident_id="i",
            phase=IncidentPhase.MITIGATION,
            current_blocker="waiting_on_monitoring",
        ),
        [moment],
        current_evidence_text=evidence,
    )[0]

    assert result.accepted
    assert result.required_current_evidence_satisfied == [
        "report failure",
        "pipeline health signal",
        "data consistency concern",
    ]


def test_compiled_sync_bottleneck_evidence_can_be_accepted():
    moment = DecisionMoment(
        decision_id="DM_verify_actual_bottleneck_topic_before_mitigation",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.93,
        phase_before=IncidentPhase.MITIGATION,
        phase_after=IncidentPhase.MONITORING,
        move="request_monitoring_signal",
        situation_before="Latency persists after first topic isolation.",
        trigger="Validate actual bottleneck topic.",
        ic_action="Ask owner to confirm actual topic and isolation need.",
        why_it_worked="Avoids anchoring on the first mitigation.",
        applicability={
            "required_current_evidence": [
                "attempted tenant/topic isolation",
                "continued latency evidence",
                "explicit statement identifying the actual bottleneck topic or queue",
            ],
        },
    )
    evidence = (
        "We moved the workload to a dedicated topic, but latency did not improve. "
        "The mapper topic appears to be the actual bottleneck and consumer lag is still rising."
    )

    result = judge_applicability(CurrentIncidentState(incident_id="i"), [moment], current_evidence_text=evidence)[0]

    assert result.accepted
    assert result.required_current_evidence_satisfied == [
        "attempted tenant/topic isolation",
        "continued latency evidence",
        "explicit statement identifying the actual bottleneck topic or queue",
    ]


def test_compiled_topic_owner_evidence_accepts_current_sync_permission_shape() -> None:
    moment = DecisionMoment(
        decision_id="DM_target_service_owner_for_correct_topic_root_cause",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.93,
        phase_before=IncidentPhase.TRIAGE,
        phase_after=IncidentPhase.ENGAGEMENT,
        move="engage_owner",
        situation_before="A named topic needs service owner validation.",
        trigger="Named topic plus owner/team evidence.",
        ic_action="Ask the owning team for topic validation.",
        why_it_worked="Routes topic/root-cause asks away from bots and reporters.",
        applicability={
            "required_current_evidence": [
                "named topic/queue/consumer group",
                "owning engineer or team",
                "technical ask needed",
            ],
        },
    )
    evidence = (
        "The DataConnectSalesforceSync topic has latency above threshold. "
        "@incident-managers and DACO are present, and the current ask is to validate exact symptoms, "
        "affected scope, and whether this is the same issue."
    )

    result = judge_applicability(CurrentIncidentState(incident_id="i"), [moment], current_evidence_text=evidence)[0]

    assert result.accepted
    assert result.required_current_evidence_satisfied == [
        "named topic/queue/consumer group",
        "owning engineer or team",
        "technical ask needed",
    ]


def test_compiled_daco_cpu_evidence_accepts_raw_cpubusy_failed_records_shape() -> None:
    moment = DecisionMoment(
        decision_id="DM_db_cpu_bad_query_route_to_app_owner",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.93,
        phase_before=IncidentPhase.TRIAGE,
        phase_after=IncidentPhase.ENGAGEMENT,
        move="engage_owner",
        situation_before="DB CPU is tied to app-owned failed_records workload.",
        trigger="CPUBusy and explain-plan evidence.",
        ic_action="Ask the app owner for source and recovery signal.",
        why_it_worked="Keeps DBA from owning app workload cleanup.",
        applicability={
            "required_current_evidence": [
                "database CPU or resource saturation",
                "DBA-identified problematic query",
                "service/table or owner hint",
            ],
        },
    )
    evidence = (
        "CPUBusyPercent crossed 92 percent. The explain plan points to failed_records cleanup queries. "
        "DACO failed_records source workload is repeatedly scanning rows."
    )

    result = judge_applicability(CurrentIncidentState(incident_id="i"), [moment], current_evidence_text=evidence)[0]

    assert result.accepted
    assert result.required_current_evidence_satisfied == [
        "database CPU or resource saturation",
        "DBA-identified problematic query",
        "service/table or owner hint",
    ]


def test_compiled_temporal_evidence_accepts_raw_activity_error_owner_shape() -> None:
    moment = DecisionMoment(
        decision_id="DM_temporal_workflow_failure_owner_status",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.93,
        phase_before=IncidentPhase.INVESTIGATION,
        phase_after=IncidentPhase.INVESTIGATION,
        move="request_status_or_eta",
        situation_before="Temporal workflow failure needs owning engineering status.",
        trigger="Execution history, error, and owning team evidence.",
        ic_action="Ask the owning engineering team for workflow status.",
        why_it_worked="Targets the team that can interpret Temporal history.",
        applicability={
            "required_current_evidence": [
                "Temporal workflow status or execution-history reference",
                "specific error text",
                "owning engineering team or SME evidence",
            ],
        },
    )
    evidence = (
        "Temporal workflow execution history shows an activity error during Transfer Accounting posting. "
        "Zuora Revenue Engineering is reviewing the workflow logs."
    )

    result = judge_applicability(CurrentIncidentState(incident_id="i"), [moment], current_evidence_text=evidence)[0]

    assert result.accepted
    assert result.required_current_evidence_satisfied == [
        "Temporal workflow status or execution-history reference",
        "specific error text",
        "owning engineering team or SME evidence",
    ]


def test_revpro_early_routing_memory_accepts_deployment_mismatch_support_engagement() -> None:
    moment = DecisionMoment(
        decision_id="DM_revpro_early_deployment_mismatch_owner_routing",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.91,
        phase_before=IncidentPhase.TRIAGE,
        phase_after=IncidentPhase.ENGAGEMENT,
        move="engage_owner",
        situation_before="RevPro deployment mismatch needs owner routing.",
        trigger="RevPro deployment/version mismatch with multiple customers and engagement uncertainty.",
        ic_action="Ask coordinator or RevPro Support to confirm ownership and start mismatch check.",
        why_it_worked="Uses early routing evidence before remediation workstreams exist.",
        applicability={
            "current_blocker": "missing_owner",
            "required_current_evidence": [
                "RevPro service evidence",
                "deployment mismatch evidence",
                "multi-customer impact evidence",
                "owner routing uncertainty or engagement request",
            ],
        },
    )
    evidence = (
        "After the RevPro deployment 27 customers have mismatch with the version. "
        "Could you please engage RevPro Support and confirm whether this is RevPro?"
    )

    result = judge_applicability(
        CurrentIncidentState(
            incident_id="i",
            phase=IncidentPhase.TRIAGE,
            current_blocker="missing_owner",
        ),
        [moment],
        current_evidence_text=evidence,
    )[0]

    assert result.accepted
    assert result.required_current_evidence_satisfied == [
        "RevPro service evidence",
        "deployment mismatch evidence",
        "multi-customer impact evidence",
        "owner routing uncertainty or engagement request",
    ]


def test_revpro_late_stage_owner_split_remains_gated_for_early_routing_evidence() -> None:
    moment = next(
        item
        for item in load_decision_moments("local_knowledge/decision_moments.jsonl")
        if item.decision_id == "DM_multitenant_postdeploy_owner_split"
    )
    evidence = (
        "After the RevPro deployment 27 customers have mismatch with the version. "
        "Could you please engage RevPro Support and confirm whether this is RevPro?"
    )

    result = judge_applicability(
        CurrentIncidentState(
            incident_id="i",
            phase=IncidentPhase.INVESTIGATION,
            current_blocker="waiting_on_status",
        ),
        [moment],
        current_evidence_text=evidence,
    )[0]

    assert not result.accepted
    assert set(result.required_current_evidence_missing) == {
        "database remediation owner",
        "deployment or post-deploy rerun owner",
        "remaining tenant validation status",
    }


def test_compiled_revenue_api_timeout_evidence_can_be_accepted():
    moment = DecisionMoment(
        decision_id="DM_revenue_api_timeout_route_to_ria_and_revenue_engineering",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.9,
        phase_before=IncidentPhase.TRIAGE,
        phase_after=IncidentPhase.ENGAGEMENT,
        move="engage_owner",
        situation_before="Revenue API timeouts need RIA/API owner routing.",
        trigger="Use when current evidence says API-only Revenue timeout.",
        ic_action="Ask Revenue/RIA owner for API health validation.",
        why_it_worked="Keeps the ask away from UI owners.",
        applicability={
            "current_blocker": "missing_owner",
            "required_current_evidence": [
                "API timeout/error symptom",
                "service name such as RIA, Revenue API, Kong, or load balancer",
                "API-only or UI-not-impacted statement",
            ],
        },
    )
    evidence = (
        "Support reports Revenue API 504 and 503 gateway timeout errors. "
        "RIA REST and Kong gateway are in scope. UI access works, only API calls fail."
    )

    result = judge_applicability(
        CurrentIncidentState(incident_id="i", phase=IncidentPhase.TRIAGE, current_blocker="missing_owner"),
        [moment],
        current_evidence_text=evidence,
    )[0]

    assert result.accepted
    assert result.required_current_evidence_satisfied == [
        "API timeout/error symptom",
        "service name such as RIA, Revenue API, Kong, or load balancer",
        "API-only or UI-not-impacted statement",
    ]


def test_compiled_revenue_temporary_traffic_control_evidence_can_be_accepted():
    moment = DecisionMoment(
        decision_id="DM_temporary_traffic_controls_need_owner_status_and_reversibility",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.86,
        phase_before=IncidentPhase.INVESTIGATION,
        phase_after=IncidentPhase.INVESTIGATION,
        move="request_status_or_eta",
        situation_before="Temporary traffic controls need owner status.",
        trigger="Use when WAF/rate-limit controls are active.",
        ic_action="Ask owner for status and monitoring signal.",
        why_it_worked="Keeps guidance as a coordination ask.",
        applicability={
            "current_blocker": "waiting_on_status",
            "required_current_evidence": [
                "temporary traffic control or scaling mitigation",
                "named owner or owner team",
                "current mitigation status or pending approval",
            ],
        },
    )
    evidence = (
        "Network owner says a temporary WAF rule and service scaling are being evaluated. "
        "Current status is pending while the SRE owner watches effectiveness in monitoring."
    )

    result = judge_applicability(
        CurrentIncidentState(incident_id="i", phase=IncidentPhase.INVESTIGATION, current_blocker="waiting_on_status"),
        [moment],
        current_evidence_text=evidence,
    )[0]

    assert result.accepted
    assert result.required_current_evidence_satisfied == [
        "temporary traffic control or scaling mitigation",
        "named owner or owner team",
        "current mitigation status or pending approval",
    ]


def test_compiled_revenue_changed_root_cause_evidence_can_be_accepted():
    moment = DecisionMoment(
        decision_id="DM_oracle_lock_retry_storm_changes_mitigation_path",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.9,
        phase_before=IncidentPhase.INVESTIGATION,
        phase_after=IncidentPhase.VERIFICATION,
        move="ask_next_validation",
        situation_before="Updated backend root cause supersedes earlier gateway hypothesis.",
        trigger="Use when service owner gives newer cause.",
        ic_action="Ask owner for validation signal for the updated cause.",
        why_it_worked="Prevents stale mitigation-path asks.",
        applicability={
            "current_blocker": "missing_validation",
            "required_current_evidence": [
                "old hypothesis or mitigation path",
                "new owner-provided root-cause evidence",
                "explicit recommendation or uncertainty from owner",
            ],
        },
    )
    evidence = (
        "Earlier hypothesis was gateway noisy neighbor and prior mitigation was WAF. "
        "Revenue Engineering says the updated root cause is Oracle package lock errors, "
        "and they do not think more WAF work is needed."
    )

    result = judge_applicability(
        CurrentIncidentState(incident_id="i", phase=IncidentPhase.INVESTIGATION, current_blocker="missing_validation"),
        [moment],
        current_evidence_text=evidence,
    )[0]

    assert result.accepted
    assert result.required_current_evidence_satisfied == [
        "old hypothesis or mitigation path",
        "new owner-provided root-cause evidence",
        "explicit recommendation or uncertainty from owner",
    ]


def test_compiled_revenue_trust_and_stability_evidence_can_be_accepted():
    trust_moment = DecisionMoment(
        decision_id="DM_trust_state_should_follow_current_published_status",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.9,
        phase_before=IncidentPhase.INVESTIGATION,
        phase_after=IncidentPhase.INVESTIGATION,
        move="ask_next_validation",
        situation_before="Trust status is already published.",
        trigger="Use when current Trust state exists.",
        ic_action="Ask owner to confirm current Trust state and update need.",
        why_it_worked="Avoids stale Trust-needed asks.",
        applicability={
            "current_blocker": "missing_validation",
            "required_current_evidence": [
                "current Trust/status state",
                "owner or support communication context",
            ],
        },
    )
    stability_moment = DecisionMoment(
        decision_id="DM_stability_window_before_mitigation_after_unblock",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.9,
        phase_before=IncidentPhase.MITIGATION,
        phase_after=IncidentPhase.MONITORING,
        move="request_monitoring_signal",
        situation_before="Temporary control removed; stability window needed.",
        trigger="Use when traffic control removal has happened.",
        ic_action="Ask owner for monitoring window and error metrics.",
        why_it_worked="Requires monitoring evidence before mitigation readiness.",
        applicability={
            "current_blocker": "waiting_on_monitoring",
            "required_current_evidence": [
                "reversal action completed",
                "monitoring period or stability evidence needed",
                "engineering owner available",
            ],
        },
    )

    trust_result = judge_applicability(
        CurrentIncidentState(incident_id="i", phase=IncidentPhase.INVESTIGATION, current_blocker="missing_validation"),
        [trust_moment],
        current_evidence_text="Support owner says the Trust/status post is published and changed to Monitoring.",
    )[0]
    stability_result = judge_applicability(
        CurrentIncidentState(incident_id="i", phase=IncidentPhase.MITIGATION, current_blocker="waiting_on_monitoring"),
        [stability_moment],
        current_evidence_text=(
            "Revenue Engineering owner says the temporary WAF control was removed. "
            "Need the monitoring window, error rates, and API health stability for the next update."
        ),
    )[0]

    assert trust_result.accepted
    assert stability_result.accepted


def test_compiled_ocs_db_healthy_streaming_evidence_can_be_accepted():
    moment = DecisionMoment(
        decision_id="DM_db_healthy_route_to_streaming_owner",
        source_incident_id="fixture",
        review_status="externally_reviewed",
        quality_score=0.91,
        phase_before=IncidentPhase.TRIAGE,
        phase_after=IncidentPhase.ENGAGEMENT,
        move="engage_owner",
        situation_before="DB is healthy but downstream lag continues.",
        trigger="Route to streaming owner.",
        ic_action="Ask streaming owner for CDC/Kafka/OCS bottleneck.",
        why_it_worked="Keeps owner targeting aligned after DB is ruled out.",
        applicability={
            "required_current_evidence": [
                "DBE health confirmation",
                "ongoing lag/backlog",
                "candidate non-DB processing layers",
            ],
        },
    )
    evidence = (
        "DBE says database and shard health are normal. Downstream lag is still elevated, "
        "likely CDC/Kafka/OCS worker throughput."
    )

    result = judge_applicability(CurrentIncidentState(incident_id="i"), [moment], current_evidence_text=evidence)[0]

    assert result.accepted
    assert result.required_current_evidence_satisfied == [
        "DBE health confirmation",
        "ongoing lag/backlog",
        "candidate non-DB processing layers",
    ]


def test_jsonl_loader_normalizes_richer_memory_shapes(tmp_path):
    path = tmp_path / "moments.jsonl"
    path.write_text(
        json.dumps(
            {
                "decision_id": "dm-rich",
                "review_status": "approved",
                "quality_score": 92,
                "phase_before": "triage",
                "move": "engage_owner",
                "situation_before": {"summary": "Support suggested owner"},
                "trigger": {"text": "Owner not observed"},
                "ic_action": {"text": "Ask owner to acknowledge"},
                "why_it_worked": {"reason": "Clear DRI"},
                "labels": [{"name": "missing_owner"}],
                "forbidden_fact_leakage": [{"value": "Tenant-Old"}],
            }
        )
        + "\n"
    )
    moment = load_decision_moments(path)[0]
    assert moment.quality_score == 0.92
    assert moment.labels == ["missing_owner"]
    assert moment.forbidden_fact_leakage == ["Tenant-Old"]
