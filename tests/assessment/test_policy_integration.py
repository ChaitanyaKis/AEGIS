"""End-to-end: proposal → assessment → policy decision.

No mocks and no hand-set risk values. These tests run the real capability registry, the
real dependency graph, the real blast-radius and risk engines and the real policy engine,
in that order, exactly as the control plane will.
"""

from __future__ import annotations

import pytest

from aegis.core.assessment import AssessmentPipeline
from aegis.core.domain import Action, PolicyDecision, PolicyDecisionType, RiskLevel
from aegis.core.policy import PolicyEngine, PolicyRule
from tests.fleet import (
    DIAGNOSTIC,
    ORDER_SERVICE,
    PAYMENT_API,
    QUARANTINED_REMEDIATION,
    REMEDIATION,
    RESTRICTED_REMEDIATION,
    UNKNOWN_RESOURCE,
    build_action,
)


def _propose_assess_authorize(
    pipeline: AssessmentPipeline,
    policy_engine: PolicyEngine,
    proposal: Action,
    agent,
) -> PolicyDecision:
    """The real flow: assess, then authorize whatever the assessment produced.

    On a failed assessment the *unassessed proposal* goes to policy, which is the whole
    point of failing closed — there is nothing authoritative to submit, and the policy
    engine denies any privileged capability on an unassessed action.
    """
    assessment = pipeline.assess(proposal)
    submitted = assessment.assessed_action if assessment.ok else assessment.proposal
    return policy_engine.evaluate(submitted, agent)


# --- the three named examples -------------------------------------------------------


def test_diagnostic_attempting_rollback_is_denied(
    pipeline: AssessmentPipeline, policy_engine: PolicyEngine
) -> None:
    """Example A: assessment succeeds and reports real risk; policy denies anyway."""
    proposal = build_action(
        requesting_agent="diagnostic",
        capability="production.rollback",
        target_resource=PAYMENT_API,
    )
    assessment = pipeline.assess(proposal)
    assert assessment.require_assessed_action().risk is RiskLevel.HIGH

    decision = _propose_assess_authorize(pipeline, policy_engine, proposal, DIAGNOSTIC)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == PolicyRule.CAPABILITY_NOT_HELD.value


def test_remediation_rollback_requires_approval(
    pipeline: AssessmentPipeline, policy_engine: PolicyEngine
) -> None:
    """Example B: assessed HIGH on real dependencies, and the capability needs sign-off."""
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_API,
    )
    assessment = pipeline.assess(proposal)
    assessed = assessment.require_assessed_action()
    assert assessed.risk is RiskLevel.HIGH
    assert assessed.blast_radius is not None
    assert assessed.blast_radius.impact is RiskLevel.HIGH

    decision = _propose_assess_authorize(pipeline, policy_engine, proposal, REMEDIATION)
    assert decision.decision is PolicyDecisionType.REQUIRE_APPROVAL
    assert decision.policy_reference == PolicyRule.APPROVAL_REQUIRED.value


def test_low_risk_read_is_allowed(
    pipeline: AssessmentPipeline, policy_engine: PolicyEngine
) -> None:
    """Example C: a telemetry read assesses LOW and is permitted."""
    proposal = build_action(
        requesting_agent="diagnostic",
        capability="telemetry.read",
        target_resource=PAYMENT_API,
    )
    assessed = pipeline.assess(proposal).require_assessed_action()
    assert assessed.risk is RiskLevel.LOW

    decision = _propose_assess_authorize(pipeline, policy_engine, proposal, DIAGNOSTIC)
    assert decision.decision is PolicyDecisionType.ALLOW


# --- the pipeline cannot be talked into an ALLOW ------------------------------------


def test_a_self_declared_low_risk_cannot_buy_an_allow(
    pipeline: AssessmentPipeline, policy_engine: PolicyEngine
) -> None:
    """The mandatory security case, carried all the way to a decision."""
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_API,
        risk=RiskLevel.LOW,
    )
    decision = _propose_assess_authorize(pipeline, policy_engine, proposal, REMEDIATION)
    assert decision.decision is not PolicyDecisionType.ALLOW
    assert decision.decision is PolicyDecisionType.REQUIRE_APPROVAL


def test_risk_based_approval_triggers_on_the_computed_risk(
    pipeline: AssessmentPipeline, policy_engine: PolicyEngine
) -> None:
    """production.scale defers to risk; the computed HIGH is what escalates it."""
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.scale",
        target_resource=PAYMENT_API,
        risk=RiskLevel.LOW,
    )
    assessed = pipeline.assess(proposal).require_assessed_action()
    assert assessed.risk is RiskLevel.HIGH

    decision = _propose_assess_authorize(pipeline, policy_engine, proposal, REMEDIATION)
    assert decision.decision is PolicyDecisionType.REQUIRE_APPROVAL


def test_unknown_resource_cannot_reach_an_allow(
    pipeline: AssessmentPipeline, policy_engine: PolicyEngine
) -> None:
    """No assessment, so nothing authoritative to submit, so policy denies."""
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=UNKNOWN_RESOURCE,
        risk=RiskLevel.LOW,
    )
    assert not pipeline.assess(proposal).ok
    decision = _propose_assess_authorize(pipeline, policy_engine, proposal, REMEDIATION)
    assert decision.decision is PolicyDecisionType.DENY


def test_assessment_does_not_soften_any_hard_denial(
    pipeline: AssessmentPipeline, policy_engine: PolicyEngine
) -> None:
    """Assessment adds information; it never widens authority."""
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_API,
    )
    for agent in (None, QUARANTINED_REMEDIATION, RESTRICTED_REMEDIATION):
        decision = _propose_assess_authorize(pipeline, policy_engine, proposal, agent)
        assert decision.decision is PolicyDecisionType.DENY


def test_out_of_scope_resource_still_denies_after_assessment(
    pipeline: AssessmentPipeline, policy_engine: PolicyEngine
) -> None:
    """production.scale is scoped to payment-api only, whatever its assessed risk."""
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.scale",
        target_resource=ORDER_SERVICE,
    )
    assert pipeline.assess(proposal).ok
    decision = _propose_assess_authorize(pipeline, policy_engine, proposal, REMEDIATION)
    assert decision.decision is PolicyDecisionType.DENY
    assert decision.policy_reference == PolicyRule.RESOURCE_OUT_OF_SCOPE.value


# --- documented behaviour worth knowing about ---------------------------------------


def test_approval_follows_declared_metadata_not_assessed_risk(
    pipeline: AssessmentPipeline, policy_engine: PolicyEngine
) -> None:
    """customer.notify assesses HIGH yet is ALLOWed, because it declares no approval.

    Not an engine defect: the policy engine decides approval from
    ``Capability.approval_requirement``, and this fixture declares NONE. It is recorded
    here because it shows that a HIGH assessed risk does not by itself gate an action —
    a capability that should escalate must declare RISK_BASED or ALWAYS.
    """
    proposal = build_action(
        requesting_agent="remediation",
        capability="customer.notify",
        target_resource=PAYMENT_API,
    )
    assessed = pipeline.assess(proposal).require_assessed_action()
    assert assessed.risk is RiskLevel.HIGH

    decision = _propose_assess_authorize(pipeline, policy_engine, proposal, REMEDIATION)
    assert decision.decision is PolicyDecisionType.ALLOW


@pytest.mark.parametrize(
    ("agent", "capability", "expected"),
    [
        (DIAGNOSTIC, "telemetry.read", PolicyDecisionType.ALLOW),
        (DIAGNOSTIC, "logs.read", PolicyDecisionType.ALLOW),
        (DIAGNOSTIC, "production.rollback", PolicyDecisionType.DENY),
        (REMEDIATION, "production.rollback", PolicyDecisionType.REQUIRE_APPROVAL),
        (REMEDIATION, "production.scale", PolicyDecisionType.REQUIRE_APPROVAL),
        # Remediation now holds telemetry.read: it must observe before proposing a fix.
        (REMEDIATION, "telemetry.read", PolicyDecisionType.ALLOW),
    ],
    ids=[
        "diagnostic-telemetry",
        "diagnostic-logs",
        "diagnostic-rollback",
        "remediation-rollback",
        "remediation-scale",
        "remediation-telemetry",
    ],
)
def test_full_flow_matrix(
    pipeline: AssessmentPipeline,
    policy_engine: PolicyEngine,
    agent,
    capability: str,
    expected: PolicyDecisionType,
) -> None:
    proposal = build_action(
        requesting_agent=agent.agent_id,
        capability=capability,
        target_resource=PAYMENT_API,
    )
    decision = _propose_assess_authorize(pipeline, policy_engine, proposal, agent)
    assert decision.decision is expected


def test_the_whole_flow_is_reproducible(
    pipeline: AssessmentPipeline, policy_engine: PolicyEngine
) -> None:
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_API,
    )
    first = _propose_assess_authorize(pipeline, policy_engine, proposal, REMEDIATION)
    second = _propose_assess_authorize(pipeline, policy_engine, proposal, REMEDIATION)
    assert first == second
