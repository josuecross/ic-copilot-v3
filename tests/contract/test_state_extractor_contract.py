from pathlib import Path

from ic_copilot.extractor import extract_state_delta
from ic_copilot.llm.fixture_client import FixtureLLMClient
from ic_copilot.normalizers.slack_paste import normalize_slack_text
from ic_copilot.schemas import CurrentIncidentState


CONTRACT = Path("data/contract")


def _delta(file_name: str, incident_id: str):
    raw = (CONTRACT / "incidents" / file_name).read_text()
    events = normalize_slack_text(raw, incident_id=incident_id)
    return extract_state_delta(events, CurrentIncidentState(incident_id=incident_id), FixtureLLMClient())


def test_revpro_missing_owner_state_delta():
    delta = _delta("01_revpro_early_engage.txt", "INC-9001")
    assert delta.phase == "engagement"
    assert delta.current_blocker == "missing_owner"
    assert any(entity.display_name == "RevPro Support" for entity in delta.suggested_but_not_engaged)
    assert delta.severity and delta.severity.value == "P3"


def test_payment_codefix_state_delta():
    delta = _delta("02_payment_stripe_codefix.txt", "INC-9002")
    assert delta.phase == "investigation"
    assert delta.current_blocker == "waiting_on_code_fix"
    assert any(entity.display_name == "Trisha" for entity in delta.engaged_entities)
    assert any(action.action_type == "code_fix_identified" for action in delta.actions_completed)


def test_ocm_uno_db_monitoring_and_negative_contract_states():
    ocm = _delta("03_ocm_order_creation.txt", "INC-9003")
    assert ocm.current_blocker == "missing_validation"
    assert any(entity.display_name == "OCM" for entity in ocm.engaged_entities)

    uno = _delta("04_uno_revenue_mapping.txt", "INC-9004")
    assert any(fact.value == "10005051" for fact in uno.impact.affected_tenants)
    assert any(fact.value == "Google Fiber" for fact in uno.impact.affected_customers)
    assert "RevenueOrgMapping=0" in uno.impact.description

    db = _delta("05_db_high_cpu_queue.txt", "INC-9005")
    assert any(entity.display_name == "DBA" for entity in db.engaged_entities)
    assert not db.suggested_but_not_engaged

    negative = _delta("06_negative_fake_entities.txt", "INC-9006")
    rejected = {entity.display_name for entity in negative.rejected_entities}
    assert {"Atlassian", "9863631", "Default_Agent", "Gaurav Trisha"}.issubset(rejected)

    monitoring = _delta("08_monitoring_after_mitigation.txt", "INC-9008")
    assert monitoring.phase == "monitoring"
    assert monitoring.current_blocker == "waiting_on_monitoring"
    assert {signal.value for signal in monitoring.monitoring_signals} >= {
        "order API error rate",
        "catalog lookup latency",
    }

