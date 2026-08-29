"""DENY precedence and engine purity.

``DENY > REQUIRE_APPROVAL > ALLOW`` has to be structural, not a preference applied at
the end. These tests stack an approval requirement on top of each hard-deny condition
and assert the denial survives: approval can never repair an authorization failure.
"""

from __future__ import annotations

import pytest

from aegis.core.capabilities import CapabilityRegistry
from aegis.core.domain import (
    AgentLifecycleState,
    ApprovalRequirement,
    PolicyDecisionType,
    RiskLevel,
    to_json,
)
from aegis.core.policy import PolicyChecks, PolicyEngine, PolicyEvaluation, PolicyRule
from aegis.core.policy.engine import CHECK_FIELDS
from tests.fleet import (
    ALL_CAPABILITIES,
    CUSTOMER_DATABASE,
    DIAGNOSTIC,
    ORDER_SERVICE,
    PAYMENT_API,
    QUARANTINED_REMEDIATION,
    REMEDIATION,
    RESTRICTED_REMEDIATION,
    RETIRED_REMEDIATION,
    build_action,
    build_registry,
    fixed_clock,
)

# Every capability below is ALWAYS-approve, so any of these reaching REQUIRE_APPROVAL
# instead of DENY would mean approval had overridden a hard denial.


def test_missing_capability_beats_approval_requirement(engine: PolicyEngine) -> None:
    action = build_action(
        requesting_agent="diagnostic",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    decision = engine.evaluate(action, DIAGNOSTIC)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == PolicyRule.CAPABILITY_NOT_HELD.value


def test_out_of_scope_resource_beats_approval_requirement(engine: PolicyEngine) -> None:
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=CUSTOMER_DATABASE,
        risk=RiskLevel.HIGH,
    )
    decision = engine.evaluate(action, REMEDIATION)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == PolicyRule.RESOURCE_OUT_OF_SCOPE.value


def test_quarantined_agent_beats_approval_requirement(engine: PolicyEngine) -> None:
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    decision = engine.evaluate(action, QUARANTINED_REMEDIATION)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == PolicyRule.AGENT_LIFECYCLE_NOT_OPERATIONAL.value


def test_restricted_agent_beats_approval_requirement(engine: PolicyEngine) -> None:
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    decision = engine.evaluate(action, RESTRICTED_REMEDIATION)
    assert decision.decision is PolicyDecisionType.DENY


def test_unknown_agent_beats_approval_requirement(engine: PolicyEngine) -> None:
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    assert engine.evaluate(action, None).decision is PolicyDecisionType.DENY


def test_unassessed_risk_beats_approval_requirement(engine: PolicyEngine) -> None:
    """An always-approve capability still denies before it can ask for approval."""
    action = build_action(
        requesting_agent="remediation", capability="production.rollback", risk=None
    )
    decision = engine.evaluate(action, REMEDIATION)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == PolicyRule.RISK_UNASSESSED.value


def test_unknown_capability_beats_approval_requirement(engine: PolicyEngine) -> None:
    """A capability that requires approval but is not registered still denies."""
    action = build_action(
        requesting_agent="remediation",
        capability="production.disable-route",
        risk=RiskLevel.HIGH,
    )
    assert engine.evaluate(action, None).decision is PolicyDecisionType.DENY


def test_no_hard_deny_condition_ever_yields_approval_or_allow(
    engine: PolicyEngine,
) -> None:
    """The full hard-deny matrix, each with approval-requiring capabilities."""
    cases = [
        (
            "unknown agent",
            build_action(
                requesting_agent="remediation",
                capability="production.rollback",
                risk=RiskLevel.HIGH,
            ),
            None,
        ),
        (
            "identity mismatch",
            build_action(requesting_agent="remediation", capability="telemetry.read"),
            DIAGNOSTIC,
        ),
        (
            "quarantined",
            build_action(
                requesting_agent="remediation",
                capability="production.rollback",
                risk=RiskLevel.HIGH,
            ),
            QUARANTINED_REMEDIATION,
        ),
        (
            "retired",
            build_action(
                requesting_agent="remediation",
                capability="production.rollback",
                risk=RiskLevel.HIGH,
            ),
            RETIRED_REMEDIATION,
        ),
        (
            "restricted",
            build_action(
                requesting_agent="remediation",
                capability="production.rollback",
                risk=RiskLevel.HIGH,
            ),
            RESTRICTED_REMEDIATION,
        ),
        (
            "unknown capability",
            build_action(
                requesting_agent="remediation", capability="production.nuke", risk=RiskLevel.HIGH
            ),
            REMEDIATION,
        ),
        (
            "not held",
            build_action(
                requesting_agent="diagnostic", capability="production.rollback", risk=RiskLevel.HIGH
            ),
            DIAGNOSTIC,
        ),
        (
            "out of scope",
            build_action(
                requesting_agent="remediation",
                capability="production.rollback",
                target_resource=CUSTOMER_DATABASE,
                risk=RiskLevel.HIGH,
            ),
            REMEDIATION,
        ),
        (
            "unassessed",
            build_action(requesting_agent="remediation", capability="production.rollback"),
            REMEDIATION,
        ),
    ]
    for label, action, agent in cases:
        decision = engine.evaluate(action, agent)
        assert decision.decision is PolicyDecisionType.DENY, label


def test_approval_is_only_reachable_once_every_hard_gate_passes(
    engine: PolicyEngine,
) -> None:
    """The one configuration that legitimately reaches REQUIRE_APPROVAL."""
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=ORDER_SERVICE,
        risk=RiskLevel.CRITICAL,
    )
    evaluation = engine.evaluate_detailed(action, REMEDIATION)
    assert evaluation.decision.decision is PolicyDecisionType.REQUIRE_APPROVAL
    assert evaluation.checks.agent_known is True
    assert evaluation.checks.agent_lifecycle_permitted is True
    assert evaluation.checks.capability_exists is True
    assert evaluation.checks.capability_held is True
    assert evaluation.checks.resource_in_scope is True
    assert evaluation.checks.risk_assessed is True


# --- checks record ------------------------------------------------------------------


def test_check_fields_match_the_checks_model() -> None:
    """Guards the string keys the engine writes against silent drift."""
    expected = (
        "agent_known",
        "agent_lifecycle_permitted",
        "capability_exists",
        "capability_held",
        "resource_in_scope",
        "risk_assessed",
        "approval_required",
    )
    assert tuple(PolicyChecks.model_fields) == expected
    assert tuple(CHECK_FIELDS) == expected


def test_unreached_checks_stay_none_rather_than_false(engine: PolicyEngine) -> None:
    """ "Not checked" and "checked and failed" must stay distinguishable in audit."""
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    checks = engine.evaluate_detailed(action, QUARANTINED_REMEDIATION).checks
    assert checks.agent_known is True
    assert checks.agent_lifecycle_permitted is False
    assert checks.capability_exists is None
    assert checks.capability_held is None
    assert checks.resource_in_scope is None
    assert checks.risk_assessed is None
    assert checks.approval_required is None


def test_checks_and_evaluation_are_frozen_and_closed() -> None:
    for model in (PolicyChecks, PolicyEvaluation):
        assert model.model_config["frozen"] is True
        assert model.model_config["extra"] == "forbid"


# --- purity -------------------------------------------------------------------------


def test_repeated_evaluation_is_byte_identical(engine: PolicyEngine) -> None:
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    first = engine.evaluate_detailed(action, REMEDIATION)
    second = engine.evaluate_detailed(action, REMEDIATION)
    assert to_json(first) == to_json(second)


def test_two_engines_over_equal_registries_agree(engine: PolicyEngine) -> None:
    """Same inputs plus same registry contents equals same decision."""
    other = PolicyEngine(CapabilityRegistry(tuple(reversed(ALL_CAPABILITIES))), clock=fixed_clock)
    action = build_action(
        requesting_agent="remediation",
        capability="production.scale",
        risk=RiskLevel.HIGH,
    )
    assert to_json(engine.evaluate_detailed(action, REMEDIATION)) == to_json(
        other.evaluate_detailed(action, REMEDIATION)
    )


def test_only_the_timestamp_varies_under_a_real_clock() -> None:
    """Time stamps the decision; it never influences it."""
    engine = PolicyEngine(build_registry())
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    first = engine.evaluate_detailed(action, REMEDIATION)
    second = engine.evaluate_detailed(action, REMEDIATION)
    assert first.checks == second.checks
    assert first.decision.decision is second.decision.decision
    assert first.decision.policy_reference == second.decision.policy_reference
    assert first.decision.reason == second.decision.reason


def test_evaluation_does_not_mutate_its_inputs(engine: PolicyEngine) -> None:
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    action_before = to_json(action)
    agent_before = to_json(REMEDIATION)
    registry_before = [to_json(c) for c in engine.registry.list()]

    engine.evaluate_detailed(action, REMEDIATION)

    assert to_json(action) == action_before
    assert to_json(REMEDIATION) == agent_before
    assert [to_json(c) for c in engine.registry.list()] == registry_before


@pytest.mark.parametrize("state", list(AgentLifecycleState))
def test_every_lifecycle_state_produces_an_authoritative_decision(
    engine: PolicyEngine, state: AgentLifecycleState
) -> None:
    """No input combination falls through without a decision."""
    agent = REMEDIATION.model_copy(update={"status": state})
    action = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        risk=RiskLevel.HIGH,
    )
    assert engine.evaluate(action, agent).decision in set(PolicyDecisionType)


@pytest.mark.parametrize("approval", list(ApprovalRequirement))
@pytest.mark.parametrize("risk", [None, *list(RiskLevel)])
def test_the_full_approval_and_risk_grid_is_decided(
    approval: ApprovalRequirement, risk: RiskLevel | None
) -> None:
    """Every approval/risk combination yields exactly one authoritative decision."""
    capability = next(c for c in ALL_CAPABILITIES if c.capability_id == "production.scale")
    registry = CapabilityRegistry(
        [capability.model_copy(update={"approval_requirement": approval})]
    )
    engine = PolicyEngine(registry, clock=fixed_clock)
    action = build_action(
        requesting_agent="remediation",
        capability="production.scale",
        target_resource=PAYMENT_API,
        risk=risk,
    )
    decision = engine.evaluate(action, REMEDIATION)
    assert decision.decision in set(PolicyDecisionType)
    if risk is None and approval is not ApprovalRequirement.NONE:
        assert decision.decision is PolicyDecisionType.DENY
