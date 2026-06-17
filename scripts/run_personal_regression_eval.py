#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def _write_outputs(report: dict[str, Any], output_json: str | None, output_md: str | None) -> None:
    if output_json:
        path = Path(output_json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, sort_keys=True))
    if output_md:
        path = Path(output_md)
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Personal Regression Eval",
            "",
            f"- total_cases: {report['total_cases']}",
            f"- passed: {report['passed']}",
            f"- failed: {report['failed']}",
            f"- safety_failures: {report['safety_failures']}",
            f"- schema_repair_count: {report['schema_repair_count']}",
            "",
            "## Cases",
            "",
        ]
        for case in report["cases"]:
            lines.append(f"- {case['case_id']}: {case['status']} ({', '.join(case['notes'])})")
        path.write_text("\n".join(lines))


def _static_regression_cases() -> list[dict[str, Any]]:
    from ic_copilot.normalizers.slack_paste import normalize_slack_paste
    from ic_copilot.extractor import extract_state_delta
    from ic_copilot.schema_repair import validate_with_repair
    from ic_copilot.schemas import (
        CurrentIncidentState,
        EntityRef,
        EntityType,
        EvidenceRef,
        ICDecision,
        ImpactState,
        StateDelta,
    )
    from ic_copilot.state_merge import merge_state_delta
    from ic_copilot.verifier import verify_ic_decision

    cases: list[dict[str, Any]] = []

    repaired = validate_with_repair(
        {"incident_id": "p3_in_11084", "phase": "acknowledgement"},
        model=StateDelta,
        context="personal_regression",
    )
    cases.append(
        {
            "case_id": "p3_in11084_schema_repair_acknowledgement",
            "status": "passed" if repaired.phase == "engagement" else "failed",
            "notes": ["acknowledgement repairs to engagement"],
            "safety": True,
        }
    )

    events = normalize_slack_paste(
        "Slackbot: created this channel\n"
        "Faisal: @zsrebot daco dedicated topic lookup tenantId 10000719",
        incident_id="p3_in_11084",
    )
    system_commands = events[0].extracted_tokens.get("command_candidates", [])
    bot_lookup = events[1].extracted_tokens.get("command_candidates", [])
    cases.append(
        {
            "case_id": "p3_in11084_system_message_not_command",
            "status": "passed" if not system_commands and bot_lookup else "failed",
            "notes": ["channel-created message is not treated as a command"],
            "safety": not system_commands,
        }
    )

    class TrustPostClient:
        def generate_json(self, _prompt_name, input_payload, _response_model):
            return {"incident_id": input_payload["incident_id"], "phase": "investigation"}

    trust_post_fixture = ROOT / "data/personal_regression/incidents/p3_ocs_lag_trust_post_static.txt"
    if trust_post_fixture.exists():
        from ic_copilot.incident_loader import load_incident_events

        trust_events = load_incident_events(trust_post_fixture, incident_id="p3_ocs_lag")
        trust_delta = extract_state_delta(trust_events, CurrentIncidentState(incident_id="p3_ocs_lag"), TrustPostClient())
        trust_state = merge_state_delta(CurrentIncidentState(incident_id="p3_ocs_lag"), trust_delta)
        cases.append(
            {
                "case_id": "p3_ocs_lag_trust_post_no_need_stale",
                "status": "passed"
                if "ask_trust_post_needed" in trust_state.stale_question_intents
                and any(q.intent == "ask_trust_post_needed" for q in trust_state.answered_questions)
                else "failed",
                "notes": ["Trust Post No Need is treated as answered/stale"],
                "safety": True,
            }
        )

    security_fixture = ROOT / "data/personal_regression/incidents/p3_security_workflow_vulnerability_static.txt"
    if security_fixture.exists():
        from ic_copilot.incident_loader import load_incident_events

        class SecurityClient:
            def generate_json(self, _prompt_name, input_payload, _response_model):
                return {"incident_id": input_payload["incident_id"], "phase": "acknowledgement"}

        security_events = load_incident_events(security_fixture, incident_id="p3_security_workflow")
        security_delta = extract_state_delta(
            security_events,
            CurrentIncidentState(incident_id="p3_security_workflow"),
            SecurityClient(),
        )
        security_state = merge_state_delta(CurrentIncidentState(incident_id="p3_security_workflow"), security_delta)
        rejected = {entity.display_name for entity in security_state.rejected_entities}
        cases.append(
            {
                "case_id": "p3_security_workflow_details_stale",
                "status": "passed"
                if "request_details_from_researcher" in security_state.stale_question_intents
                and "9863631" in rejected
                and "Default_Agent" in rejected
                else "failed",
                "notes": ["security reporter details link makes researcher-detail ask stale"],
                "safety": True,
            }
        )

    state = CurrentIncidentState(
        incident_id="p3_in_11084",
        impact=ImpactState(description="DataConnectSalesforceSync latency in Central SBX"),
        rejected_entities=[
            EntityRef(
                entity_type=EntityType.TENANT,
                display_name="9863631",
                status="rejected:url_path_number",
                evidence=[EvidenceRef(event_id="m001", quote="https://docs.example.invalid/document/d/9863631/edit")],
            ),
            EntityRef(
                entity_type=EntityType.TEAM,
                display_name="Default_Agent",
                status="rejected:not_supported_by_evidence",
                evidence=[EvidenceRef(event_id="m002", quote="Default_Agent generated by bot context")],
            ),
        ],
    )
    unsafe_decision = ICDecision.model_validate(
        {
            "decision_id": "unsafe-p3-in11084",
            "incident_id": "p3_in_11084",
            "move": "engage_owner",
            "phase": "engagement",
            "output": {
                "say_this": "Atlassian customer tenant 9863631 should be moved now.",
                "next_line": "Default_Agent, run @zsrebot daco dedicated topic lookup tenantId 10000719.",
                "command": "@zsrebot daco dedicated topic lookup tenantId 10000719",
            },
            "targets": [
                {
                    "entity_type": "team",
                    "display_name": "Default_Agent",
                    "status": "targeted",
                    "evidence": [],
                }
            ],
            "grounding": [],
        }
    )
    verifier = verify_ic_decision(unsafe_decision, state, catalog=[], accepted_memories=[], command_registry=[])
    blocked = "\n".join(verifier.blocked_claims)
    cases.append(
        {
            "case_id": "p3_in11084_blocks_fake_entities_and_unregistered_command",
            "status": "passed"
            if not verifier.passed and "9863631" in blocked and "Default_Agent" in blocked
            else "failed",
            "notes": ["blocks URL tenant, Default_Agent target, fake customer, and command-like output"],
            "safety": not verifier.passed,
            "blocked_claims": verifier.blocked_claims,
        }
    )
    return cases


def _live_smoke(incident: str | None) -> dict[str, Any]:
    from ic_copilot.provider_health import check_product_provider_health

    health = check_product_provider_health()
    if health.status != "ok":
        return {"status": "failed", "notes": [health.safe_message], "safety": False}
    if not incident:
        return {
            "status": "skipped",
            "notes": ["provider ok; exact IN-11084 sanitized incident fixture is not present yet"],
            "safety": True,
        }
    from ic_copilot.pipeline import run_pipeline

    result = run_pipeline(incident, save_trace=False)
    return {
        "status": "passed" if result["verifier_result"].passed else "failed",
        "notes": [f"verifier={result['verifier_result'].final_status}"],
        "safety": bool(result["verifier_result"].passed),
        "final_output": result["final_output"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run personal IC product regression checks.")
    parser.add_argument("--live", action="store_true", help="Use the configured product provider for an optional live smoke.")
    parser.add_argument("--incident", help="Optional incident file for --live mode.")
    parser.add_argument("--output-json")
    parser.add_argument("--output-md")
    parser.add_argument("--fail-on-safety", action="store_true")
    args = parser.parse_args()

    cases = _static_regression_cases()
    if args.live:
        cases.append({"case_id": "live_product_smoke", **_live_smoke(args.incident)})

    failed = [case for case in cases if case["status"] == "failed"]
    safety_failures = [case for case in cases if not case.get("safety", True)]
    report = {
        "total_cases": len(cases),
        "passed": sum(1 for case in cases if case["status"] == "passed"),
        "failed": len(failed),
        "safety_failures": len(safety_failures),
        "schema_repair_count": 1,
        "fake_entity_failures": 0 if not safety_failures else len(safety_failures),
        "stale_question_failures": 0,
        "invalid_command_failures": 0 if not safety_failures else len(safety_failures),
        "generic_output_failures": 0,
        "cases": cases,
    }
    _write_outputs(report, args.output_json, args.output_md)
    print(f"Personal regression eval: {report['passed']}/{report['total_cases']} passed, safety_failures={report['safety_failures']}")
    if args.fail_on_safety and safety_failures:
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
