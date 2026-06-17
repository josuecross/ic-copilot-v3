# Verifier contract

Verifier inputs:
- ICDecision
- CurrentIncidentState
- ServiceCatalog matches
- accepted DecisionMoments
- CommandRegistry
- RejectedEntity ledger

Hard-block:
- stale questions
- fake customers
- fake tenants
- fake people
- fake teams/services
- invalid commands
- historical fact leakage
- unsupported monitoring signals
- generic output when a sharper blocker exists

Verifier outcomes:
- pass
- rewrite_required
- blocked
- fallback_required
