from ic_copilot.normalizers.slack_paste import normalize_slack_paste
from ic_copilot.schemas import CurrentIncidentState
from ic_copilot.trigger import decide_trigger


def test_low_value_ack_does_not_trigger_planning():
    events = normalize_slack_paste("Alex: ack")
    decision = decide_trigger(events, CurrentIncidentState(incident_id="i1"))
    assert decision.level == "ingest_only"
    assert not decision.should_plan


def test_new_owner_signal_triggers_state_extraction_and_planning():
    events = normalize_slack_paste("Support: RevPro Support should be engaged for ownership")
    decision = decide_trigger(events, CurrentIncidentState(incident_id="i1"))
    assert decision.should_extract
    assert decision.should_plan


def test_new_mitigation_signal_triggers_planning():
    events = normalize_slack_paste("Ops: mitigation started with hotfix rollout")
    decision = decide_trigger(events, CurrentIncidentState(incident_id="i1"))
    assert decision.level == "full_planning"

