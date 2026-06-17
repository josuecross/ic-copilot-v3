# Memory applicability gate contract

Before the planner can use a DecisionMoment, judge whether the historical behavior pattern applies to the current incident.

Output:
- accepted: boolean
- score
- reason
- allowed_behavior_patterns
- facts_allowed_in_output
- facts_forbidden_in_output
- rejection_reason

Rules:
- Historical incidents teach behavior patterns, not current facts.
- Reject memory if phase/blocker is wrong.
- Reject memory if required current evidence is missing.
- Reject memory if it risks leaking historical customer/tenant/Jira/service-specific facts.
