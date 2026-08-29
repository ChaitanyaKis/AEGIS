"""Policy engine outcomes: the ALLOW, DENY and REQUIRE_APPROVAL paths.

The engine is the first authoritative security boundary in AEGIS, so most of this file
is negative testing. Each case names the rule reference it expects, because a decision
that lands on the right outcome via the wrong rule is a latent bug.
"""

from __future__ import annotations

import pytest

from aegis.core.domain import (
    AgentLifecycleState,
    PolicyDecisionType,
    RiskLevel,
    to_json,
)
from aegis.core.policy import PolicyEngine, PolicyRule
from tests.fleet import (
    CUSTOMER_DATABASE,
    DIAGNOSTIC,
    FIXED_EVALUATION_TIME,
    ORDER_SERVICE,
    PAYMENT_API,
    QUARANTINED_REMEDIATION,
    REGISTERED_REMEDIATION,
    REMEDIATION,
    RESTRICTED_DIAGNOSTIC,
    RESTRICTED_REMEDIATION,
    RETIRED_REMEDIATION,
    UNREGISTERED,
    build_action,
    fixed_clock,
)

# --- ALLOW --------------------------------------------------------------------------


def test_allow_for_a_fully_satisfied_request(engine: PolicyEngine) -> None:
    """Valid agent, known capability, held, in scope, no approval needed."""
    action = build_action(
        requesting_agent="diagnostic",
        capability="telemetry.read",
        target_resource=PAYMENT_API,
    )
    decision = engine.evaluate(action, DIAGNOSTIC)
    assert decision.decision is PolicyDecisionType.ALLOW
    assert decision.policy_reference == PolicyRule.ALLOWED.value
    assert decision.reason


def test_allow_with_an_assessed_risk(engine: PolicyEngine) -> None:
    action = build_action(
        requesting_agent="diagnostic",
        capability="telemetry.read",
        risk=RiskLevel.LOW,
    )
    assert engine.evaluate(action, DIAGNOSTIC).decision is PolicyDecisionType.ALLOW


def test_allow_across_every_resource_in_scope(engine: PolicyEngine) -> None:
    for resource in (PAYMENT_API, ORDER_SERVICE):
        action = build_action(
            requesting_agent="diagnostic",
            capability="telemetry.read",
            target_resource=resource,
        )
        assert engine.evaluate(action, DIAGNOSTIC).decision is PolicyDecisionType.ALLOW


def test_allow_records_every_check_as_satisfied(engine: PolicyEngine) -> None:
    action = build_action(requesting_agent="diagnostic", capability="telemetry.read")
    checks = engine.evaluate_detailed(action, DIAGNOSTIC).checks
    assert checks.agent_known is True
    assert checks.agent_lifecycle_permitted is True
    assert checks.capability_exists is True
    assert checks.capability_held is True
    assert checks.resource_in_scope is True
    assert checks.approval_required is False


def test_restricted_agent_may_still_use_an_unprivileged_capability(
    engine: PolicyEngine,
) -> None:
    """RESTRICTED is reduced authority, not revoked authority."""
    action = build_action(requesting_agent="diagnostic", capability="telemetry.read")
    decision = engine.evaluate(action, RESTRICTED_DIAGNOSTIC)
    assert decision.decision is PolicyDecisionType.ALLOW


# --- DENY: agent --------------------------------------------------------------------


def test_unknown_agent_is_denied(engine: PolicyEngine) -> None:
    action = build_action(requesting_agent="ghost", capability="telemetry.read")
    decision = engine.evaluate(action, None)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == PolicyRule.AGENT_UNKNOWN.value
    assert "unknown agent" in decision.reason


def test_unknown_agent_is_never_allowed_or_deferred_to_approval(
    engine: PolicyEngine,
) -> None:
    for capability in ("telemetry.read", "production.rollback", "nope.nope"):
        action = build_action(requesting_agent="ghost", capability=capability)
        decision = engine.evaluate(action, None)
        assert decision.decision is PolicyDecisionType.DENY, capability


def test_agent_identity_mismatch_is_denied(engine: PolicyEngine) -> None:
    """The supplied record must be the agent the action claims to come from."""
    action = build_action(requesting_agent="remediation", capability="telemetry.read")
    decision = engine.evaluate(action, DIAGNOSTIC)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == PolicyRule.AGENT_IDENTITY_MISMATCH.value


def test_unknown_agent_stops_evaluation_before_any_other_check(
    engine: PolicyEngine,
) -> None:
    action = build_action(requesting_agent="ghost", capability="telemetry.read")
    checks = engine.evaluate_detailed(action, None).checks
    assert checks.agent_known is False
    assert checks.capability_exists is None
    assert checks.capability_held is None
    assert checks.resource_in_scope is None


# --- DENY: lifecycle ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("agent", "rule"),
    [
        (QUARANTINED_REMEDIATION, PolicyRule.AGENT_LIFECYCLE_NOT_OPERATIONAL),
        (RETIRED_REMEDIATION, PolicyRule.AGENT_LIFECYCLE_NOT_OPERATIONAL),
        (REGISTERED_REMEDIATION, PolicyRule.AGENT_LIFECYCLE_NOT_OPERATIONAL),
        (RESTRICTED_REMEDIATION, PolicyRule.AGENT_LIFECYCLE_FORBIDS_CAPABILITY),
    ],
    ids=["quarantined", "retired", "registered", "restricted"],
)
def test_privileged_capability_denied_by_lifecycle(
    engine: PolicyEngine, agent, rule: PolicyRule
) -> None:
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    decision = engine.evaluate(action, agent)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == rule.value


def test_quarantined_agent_denied_even_for_an_unprivileged_capability(
    engine: PolicyEngine,
) -> None:
    """QUARANTINED withdraws all authority, not just privileged authority."""
    quarantined = DIAGNOSTIC.model_copy(update={"status": AgentLifecycleState.QUARANTINED})
    action = build_action(requesting_agent="diagnostic", capability="telemetry.read")
    decision = engine.evaluate(action, quarantined)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == PolicyRule.AGENT_LIFECYCLE_NOT_OPERATIONAL.value


@pytest.mark.parametrize(
    "state",
    [
        AgentLifecycleState.REGISTERED,
        AgentLifecycleState.EVALUATING,
        AgentLifecycleState.SANDBOXED,
        AgentLifecycleState.APPROVED,
        AgentLifecycleState.QUARANTINED,
        AgentLifecycleState.RETIRED,
    ],
)
def test_no_non_operational_state_can_act(engine: PolicyEngine, state: AgentLifecycleState) -> None:
    """A newly registered agent never holds production authority."""
    agent = REMEDIATION.model_copy(update={"status": state})
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    assert engine.evaluate(action, agent).decision is PolicyDecisionType.DENY


# --- DENY: capability ---------------------------------------------------------------


def test_unknown_capability_is_denied(engine: PolicyEngine) -> None:
    action = build_action(requesting_agent="remediation", capability="production.delete-everything")
    decision = engine.evaluate(action, REMEDIATION)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == PolicyRule.CAPABILITY_UNKNOWN.value


def test_agent_lacking_the_capability_is_denied(engine: PolicyEngine) -> None:
    """Diagnostic cannot roll back, even though production.rollback exists."""
    action = build_action(
        requesting_agent="diagnostic",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    decision = engine.evaluate(action, DIAGNOSTIC)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == PolicyRule.CAPABILITY_NOT_HELD.value


def test_self_declared_capability_is_not_enough(engine: PolicyEngine) -> None:
    """An agent record claiming a grant the capability does not permit is denied."""
    action = build_action(
        requesting_agent="rogue", capability="production.rollback", risk=RiskLevel.HIGH
    )
    decision = engine.evaluate(action, UNREGISTERED)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == PolicyRule.CAPABILITY_NOT_HELD.value


def test_diagnostic_cannot_scale_production(engine: PolicyEngine) -> None:
    action = build_action(
        requesting_agent="diagnostic",
        capability="production.scale",
        risk=RiskLevel.MEDIUM,
    )
    assert engine.evaluate(action, DIAGNOSTIC).decision is PolicyDecisionType.DENY


# --- DENY: resource scope -----------------------------------------------------------


def test_out_of_scope_resource_is_denied(engine: PolicyEngine) -> None:
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=CUSTOMER_DATABASE,
        risk=RiskLevel.HIGH,
    )
    decision = engine.evaluate(action, REMEDIATION)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == PolicyRule.RESOURCE_OUT_OF_SCOPE.value
    assert CUSTOMER_DATABASE in decision.reason


def test_scope_is_per_capability_not_per_agent(engine: PolicyEngine) -> None:
    """Remediation may roll back order-service but may not scale it."""
    rollback = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=ORDER_SERVICE,
        risk=RiskLevel.HIGH,
    )
    scale = build_action(
        requesting_agent="remediation",
        capability="production.scale",
        target_resource=ORDER_SERVICE,
        risk=RiskLevel.LOW,
    )
    assert engine.evaluate(rollback, REMEDIATION).decision is (PolicyDecisionType.REQUIRE_APPROVAL)
    scale_decision = engine.evaluate(scale, REMEDIATION)
    assert scale_decision.decision is PolicyDecisionType.DENY
    assert scale_decision.policy_reference == PolicyRule.RESOURCE_OUT_OF_SCOPE.value


def test_near_miss_resource_names_are_denied(engine: PolicyEngine) -> None:
    """No prefix or fuzzy matching: a near miss is a miss."""
    for resource in ("service:payment-api/replica-1", "payment-api", "service:payment"):
        action = build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=resource,
            risk=RiskLevel.HIGH,
        )
        decision = engine.evaluate(action, REMEDIATION)
        assert decision.decision is PolicyDecisionType.DENY, resource
        assert decision.policy_reference == PolicyRule.RESOURCE_OUT_OF_SCOPE.value


# --- DENY: unassessed risk ----------------------------------------------------------


def test_unassessed_production_mutation_is_denied(engine: PolicyEngine) -> None:
    """Missing risk means UNASSESSED, never LOW."""
    action = build_action(
        requesting_agent="remediation", capability="production.rollback", risk=None
    )
    decision = engine.evaluate(action, REMEDIATION)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == PolicyRule.RISK_UNASSESSED.value


def test_every_privileged_capability_requires_an_assessed_risk(
    engine: PolicyEngine,
) -> None:
    for agent, capability in (
        (REMEDIATION, "production.rollback"),
        (REMEDIATION, "production.scale"),
        (REMEDIATION, "customer.notify"),
    ):
        action = build_action(requesting_agent=agent.agent_id, capability=capability, risk=None)
        decision = engine.evaluate(action, agent)
        assert decision.decision is PolicyDecisionType.DENY, capability
        assert decision.policy_reference == PolicyRule.RISK_UNASSESSED.value


def test_an_agent_cannot_bypass_governance_by_declaring_low_risk(
    engine: PolicyEngine,
) -> None:
    """A self-declared LOW does not become an ALLOW for an always-approve capability."""
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        risk=RiskLevel.LOW,
    )
    decision = engine.evaluate(action, REMEDIATION)
    assert decision.decision is PolicyDecisionType.REQUIRE_APPROVAL


def test_unprivileged_capability_does_not_require_risk_assessment(
    engine: PolicyEngine,
) -> None:
    action = build_action(requesting_agent="diagnostic", capability="telemetry.read", risk=None)
    evaluation = engine.evaluate_detailed(action, DIAGNOSTIC)
    assert evaluation.decision.decision is PolicyDecisionType.ALLOW
    assert evaluation.checks.risk_assessed is False


# --- REQUIRE_APPROVAL ---------------------------------------------------------------


def test_approval_required_for_an_always_approve_capability(
    engine: PolicyEngine,
) -> None:
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    decision = engine.evaluate(action, REMEDIATION)
    assert decision.decision is PolicyDecisionType.REQUIRE_APPROVAL
    assert decision.policy_reference == PolicyRule.APPROVAL_REQUIRED.value


def test_approval_required_records_its_checks(engine: PolicyEngine) -> None:
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    checks = engine.evaluate_detailed(action, REMEDIATION).checks
    assert checks.agent_known is True
    assert checks.capability_held is True
    assert checks.resource_in_scope is True
    assert checks.risk_assessed is True
    assert checks.approval_required is True


@pytest.mark.parametrize(
    ("risk", "expected"),
    [
        (RiskLevel.LOW, PolicyDecisionType.ALLOW),
        (RiskLevel.MEDIUM, PolicyDecisionType.ALLOW),
        (RiskLevel.HIGH, PolicyDecisionType.REQUIRE_APPROVAL),
        (RiskLevel.CRITICAL, PolicyDecisionType.REQUIRE_APPROVAL),
    ],
)
def test_risk_based_approval_uses_the_assessed_risk(
    engine: PolicyEngine, risk: RiskLevel, expected: PolicyDecisionType
) -> None:
    action = build_action(requesting_agent="remediation", capability="production.scale", risk=risk)
    assert engine.evaluate(action, REMEDIATION).decision is expected


# --- decision quality ---------------------------------------------------------------


def test_every_decision_carries_a_reason_and_a_rule_reference(
    engine: PolicyEngine,
) -> None:
    """A decision that cannot be explained or traced to a rule is not auditable."""
    cases = [
        (build_action(requesting_agent="ghost", capability="telemetry.read"), None),
        (build_action(requesting_agent="diagnostic", capability="telemetry.read"), DIAGNOSTIC),
        (
            build_action(
                requesting_agent="remediation",
                capability="production.rollback",
                risk=RiskLevel.HIGH,
            ),
            REMEDIATION,
        ),
        (
            build_action(requesting_agent="remediation", capability="production.rollback"),
            QUARANTINED_REMEDIATION,
        ),
    ]
    known_rules = {rule.value for rule in PolicyRule}
    for action, agent in cases:
        decision = engine.evaluate(action, agent)
        assert decision.reason.strip()
        assert decision.policy_reference in known_rules


def test_decisions_cite_no_incident_evidence(engine: PolicyEngine) -> None:
    """The engine decides from registry state and declared metadata, not from evidence.

    Leaving ``evidence`` empty is honest: citing the action's evidence would imply the
    decision rested on it.
    """
    action = build_action(requesting_agent="diagnostic", capability="telemetry.read")
    assert engine.evaluate(action, DIAGNOSTIC).evidence == ()


def test_decision_timestamp_comes_from_the_injected_clock(engine: PolicyEngine) -> None:
    action = build_action(requesting_agent="diagnostic", capability="telemetry.read")
    assert engine.evaluate(action, DIAGNOSTIC).evaluated_at == FIXED_EVALUATION_TIME


def test_evaluation_serializes_for_audit_transport(engine: PolicyEngine) -> None:
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    evaluation = engine.evaluate_detailed(action, REMEDIATION)
    payload = to_json(evaluation)
    assert '"decision":"REQUIRE_APPROVAL"' in payload
    assert '"capability_held":true' in payload


def test_evaluate_returns_the_same_decision_as_evaluate_detailed(
    engine: PolicyEngine,
) -> None:
    action = build_action(requesting_agent="diagnostic", capability="telemetry.read")
    assert engine.evaluate(action, DIAGNOSTIC) == (
        engine.evaluate_detailed(action, DIAGNOSTIC).decision
    )


def test_engine_exposes_its_registry(engine: PolicyEngine) -> None:
    assert engine.registry.exists("production.rollback")


def test_engine_defaults_to_the_real_clock(registry) -> None:
    """The default clock is the domain helper, not a test stub."""
    engine = PolicyEngine(registry)
    action = build_action(requesting_agent="diagnostic", capability="telemetry.read")
    decision = engine.evaluate(action, DIAGNOSTIC)
    assert decision.evaluated_at != FIXED_EVALUATION_TIME
    assert decision.evaluated_at.tzinfo is not None


def test_an_empty_registry_denies_everything(engine: PolicyEngine) -> None:
    from aegis.core.capabilities import CapabilityRegistry

    empty = PolicyEngine(CapabilityRegistry(), clock=fixed_clock)
    for agent, capability in (
        (DIAGNOSTIC, "telemetry.read"),
        (REMEDIATION, "production.rollback"),
    ):
        action = build_action(
            requesting_agent=agent.agent_id, capability=capability, risk=RiskLevel.LOW
        )
        decision = empty.evaluate(action, agent)
        assert decision.decision is PolicyDecisionType.DENY
        assert decision.policy_reference == PolicyRule.CAPABILITY_UNKNOWN.value
