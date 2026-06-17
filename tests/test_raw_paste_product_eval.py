from __future__ import annotations

from ic_copilot.raw_paste_product_eval import (
    RawPasteProductEvalFixture,
    load_raw_paste_product_eval_fixtures,
    run_raw_paste_product_eval,
)


def test_raw_paste_product_eval_core_cases_pass() -> None:
    report = run_raw_paste_product_eval(load_raw_paste_product_eval_fixtures())

    assert report["passed"]
    assert report["total_cases"] == 7
    assert report["useful_pass_count"] == 7
    assert report["fallback_count"] == 0
    assert report["wrong_target_class_count"] == 0
    assert report["diagnostic_evidence_dropped_count"] == 0


def test_raw_paste_product_eval_catches_unexpected_no_safe() -> None:
    fixture = RawPasteProductEvalFixture(
        fixture_id="raw_eval_no_safe_regression",
        raw_paste_input=(
            "Jules\n"
            "9:00 AM\n"
            "Producer shows Connection to node -1 could not be established. "
            "The pod can connect to Kafka, so cert/runtime config validation is needed."
        ),
        expected_normalized_evidence_anchors=["Connection to node -1", "pod can connect", "cert/runtime config"],
        expected_retained_diagnostic_terms=["Connection to node -1", "pod can connect", "cert/runtime config"],
        expected_retained_diagnostic_fact_ids=[
            "producer_connection_error",
            "kafka_network_connectivity",
            "cert_runtime_config_clue",
        ],
        expected_accepted_memory_ids=["DM_kafka_connection_error_check_service_config_drift"],
        expected_target_classes=["service_owner", "config_owner", "investigating_human"],
        acceptable_target_names=["Kafka Escalation", "Developer Success / ESG", "Jules"],
        unacceptable_target_names=["APP", "zsrebot"],
        expected_move_families=["ask_next_validation", "engage_owner"],
        required_visible_ask_terms=["Kafka", "config"],
        forbidden_visible_ask_terms=["page", "restart", "execute"],
        allow_no_safe=False,
        notes="No-safe should fail when retained diagnostic facts and accepted memory exist.",
        expected_read={
            "selected_move": "no_safe_recommendation",
            "selected_target_display_name": None,
            "say_this": "I do not have a safe, grounded next move yet.",
            "current_read": "The model failed to use available diagnostic evidence.",
            "latest_open_loop": "No safe move.",
            "evidence_quote": "Connection to node -1 could not be established.",
        },
    )

    report = run_raw_paste_product_eval([fixture])
    case = report["cases"][0]

    assert not report["passed"]
    assert not case["passed"]
    assert "unexpected_no_safe" in case["reasons"]


def test_raw_paste_product_eval_allows_no_safe_without_diagnostic_signal() -> None:
    fixture = RawPasteProductEvalFixture(
        fixture_id="raw_eval_generic_no_signal",
        raw_paste_input="zsrebot\nAPP  9:00 AM\n:fire: An incident has been created!\nNo details yet.",
        expected_normalized_evidence_anchors=[],
        expected_retained_diagnostic_terms=[],
        expected_retained_diagnostic_fact_ids=[],
        expected_accepted_memory_ids=[],
        expected_target_classes=[],
        acceptable_target_names=[],
        unacceptable_target_names=["zsrebot", "APP"],
        expected_move_families=["no_safe_recommendation"],
        required_visible_ask_terms=[],
        forbidden_visible_ask_terms=["execute", "page", "restart"],
        allow_no_safe=True,
        notes="Generic incident-created noise without diagnostic signal may safely render no_safe.",
        expected_read={
            "selected_move": "no_safe_recommendation",
            "selected_target_display_name": None,
            "say_this": "I do not have a safe, grounded next move yet.",
            "current_read": "No actionable diagnostic signal is available yet.",
            "latest_open_loop": "No safe current ask.",
        },
    )

    report = run_raw_paste_product_eval([fixture])

    assert report["passed"]
    assert report["cases"][0]["fallback_used"] is False
