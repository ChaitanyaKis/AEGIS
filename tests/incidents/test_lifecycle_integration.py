"""The governed lifecycle, end to end.

Real registry, real dependency graph, real assessment pipeline, real policy engine, real
approval engine, real state machine. Nothing is mocked and no decision is hand-written:
each transition is justified by an artifact the previous stage actually produced.
"""

from __future__ import annotations

import pytest

from aegis.core.approval import (
    ApprovalConsumptionRefused,
    ApprovalCreationRefused,
    ApprovalEngine,
    ApprovalStatus,
)
from aegis.core.assessment import AssessmentPipeline
from aegis.core.domain import (
    AgentLifecycleState,
    IncidentState,
    PolicyDecisionType,
    RiskLevel,
)
from aegis.core.incidents import (
    IncidentStateMachine,
    InvalidIncidentTransition,
    TransitionGuard,
)
from aegis.core.policy import PolicyEngine
from aegis.core.verification import VerificationEngine, VerificationStatus
from tests.fleet import (
    CUSTOMER_DATABASE,
    DIAGNOSTIC,
    FIXED_EVALUATION_TIME,
    PAYMENT_API,
    PAYMENT_API_RECOVERED,
    REMEDIATION,
    build_action,
    build_incident,
    healthy_observations,
)
from tests.incidents.conftest import MovableClock


def _advance_to_policy_check(machine: IncidentStateMachine, actor: str = "agent:commander"):
    """Walk the intake path RECEIVED -> POLICY_CHECK, one legal edge at a time."""
    incident = build_incident(state=IncidentState.RECEIVED)
    for to_state, reason in (
        (IncidentState.CLASSIFIED, "payment error rate 37%"),
        (IncidentState.INVESTIGATING, "diagnostic dispatched"),
        (IncidentState.IMPACT_ASSESSED, "customer impact assessed"),
        (IncidentState.PLAN_PROPOSED, "rollback to v4.7 proposed"),
        (IncidentState.POLICY_CHECK, "submitting plan for authorization"),
    ):
        incident = machine.transition(incident, to_state, reason=reason, actor=actor)
    return incident


# --- the approval path --------------------------------------------------------------


def test_full_governed_lifecycle_through_human_approval(
    machine: IncidentStateMachine,
    pipeline: AssessmentPipeline,
    policy_engine: PolicyEngine,
    approval_engine: ApprovalEngine,
) -> None:
    """PLAN_PROPOSED -> POLICY_CHECK -> AWAITING_APPROVAL -> EXECUTING -> VERIFYING -> RESOLVED."""
    incident = _advance_to_policy_check(machine)
    assert incident.state is IncidentState.POLICY_CHECK

    # Assess, then authorize. Both engines are real.
    action = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    ).require_assessed_action()
    assert action.risk is RiskLevel.HIGH

    decision = policy_engine.evaluate(action, REMEDIATION)
    assert decision.decision is PolicyDecisionType.REQUIRE_APPROVAL

    incident = machine.transition(
        incident,
        IncidentState.AWAITING_APPROVAL,
        reason=decision.reason,
        actor="system:policy-engine",
        policy_decision=decision,
    )
    assert incident.state is IncidentState.AWAITING_APPROVAL

    # A human signs off, and the approval is spent to authorize exactly this action.
    approval = approval_engine.approve(
        approval_engine.request(
            approval_id="apr-001",
            action=action,
            agent=REMEDIATION,
            decision=decision,
        ),
        by="human:oncall",
    )
    authorization = approval_engine.consume_for_execution(approval, action, REMEDIATION)
    assert authorization.approval.status is ApprovalStatus.CONSUMED

    incident = machine.transition(
        incident,
        IncidentState.EXECUTING,
        reason="human approval consumed",
        actor="agent:remediation",
        authorization=authorization,
    )
    incident = machine.transition(
        incident,
        IncidentState.VERIFYING,
        reason="rollback issued, verifying actual state",
        actor="agent:remediation",
    )
    # Resolution requires independent observations, not the fact that a tool returned.
    verification = VerificationEngine(clock=lambda: FIXED_EVALUATION_TIME).verify(
        action,
        PAYMENT_API_RECOVERED,
        healthy_observations(),
        verification_id="ver-001",
    )
    assert verification.status is VerificationStatus.VERIFIED

    incident = machine.transition(
        incident,
        IncidentState.RESOLVED,
        reason=verification.reason,
        actor="system:verification",
        verification=verification,
        action=action,
    )
    assert incident.state is IncidentState.RESOLVED


def test_the_execution_transition_records_its_authorization(
    machine: IncidentStateMachine,
    pipeline: AssessmentPipeline,
    policy_engine: PolicyEngine,
    approval_engine: ApprovalEngine,
) -> None:
    """Everything a future audit store needs about the most sensitive transition."""
    action = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    ).require_assessed_action()
    decision = policy_engine.evaluate(action, REMEDIATION)
    authorization = approval_engine.consume_for_execution(
        approval_engine.approve(
            approval_engine.request(
                approval_id="apr-001",
                action=action,
                agent=REMEDIATION,
                decision=decision,
            ),
            by="human:oncall",
        ),
        action,
        REMEDIATION,
    )

    result = machine.transition_detailed(
        build_incident(state=IncidentState.AWAITING_APPROVAL),
        IncidentState.EXECUTING,
        reason="approval consumed",
        actor="agent:remediation",
        authorization=authorization,
    )
    record = result.transition
    assert record.guard is TransitionGuard.EXECUTION_AUTHORIZATION
    assert record.approval_id == "apr-001"
    assert record.action_fingerprint == authorization.action_fingerprint
    assert record.from_state is IncidentState.AWAITING_APPROVAL
    assert record.to_state is IncidentState.EXECUTING


def test_an_authorization_for_another_incident_is_refused(
    machine: IncidentStateMachine,
    pipeline: AssessmentPipeline,
    policy_engine: PolicyEngine,
    approval_engine: ApprovalEngine,
) -> None:
    action = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    ).require_assessed_action()
    decision = policy_engine.evaluate(action, REMEDIATION)
    authorization = approval_engine.consume_for_execution(
        approval_engine.approve(
            approval_engine.request(
                approval_id="apr-001",
                action=action,
                agent=REMEDIATION,
                decision=decision,
            ),
            by="human:oncall",
        ),
        action,
        REMEDIATION,
    )

    other_incident = build_incident(
        state=IncidentState.AWAITING_APPROVAL, incident_id="INC-2026-0002"
    )
    with pytest.raises(InvalidIncidentTransition, match="belongs to incident"):
        machine.transition(
            other_incident,
            IncidentState.EXECUTING,
            reason="borrowed approval",
            actor="agent:remediation",
            authorization=authorization,
        )


# --- the allow path -----------------------------------------------------------------


def test_an_allowed_read_executes_without_an_approval_artifact(
    machine: IncidentStateMachine,
    pipeline: AssessmentPipeline,
    policy_engine: PolicyEngine,
) -> None:
    incident = _advance_to_policy_check(machine)
    action = pipeline.assess(
        build_action(
            requesting_agent="diagnostic",
            capability="telemetry.read",
            target_resource=PAYMENT_API,
        )
    ).require_assessed_action()
    decision = policy_engine.evaluate(action, DIAGNOSTIC)
    assert decision.decision is PolicyDecisionType.ALLOW

    incident = machine.transition(
        incident,
        IncidentState.EXECUTING,
        reason=decision.reason,
        actor="system:policy-engine",
        policy_decision=decision,
    )
    assert incident.state is IncidentState.EXECUTING


# --- the deny path ------------------------------------------------------------------


def test_a_denied_plan_enters_neither_approval_nor_execution(
    machine: IncidentStateMachine,
    pipeline: AssessmentPipeline,
    policy_engine: PolicyEngine,
) -> None:
    """Diagnostic cannot roll back. The incident escalates instead of proceeding."""
    incident = _advance_to_policy_check(machine)
    action = pipeline.assess(
        build_action(
            requesting_agent="diagnostic",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    ).require_assessed_action()
    decision = policy_engine.evaluate(action, DIAGNOSTIC)
    assert decision.decision is PolicyDecisionType.DENY

    for to_state in (IncidentState.AWAITING_APPROVAL, IncidentState.EXECUTING):
        with pytest.raises(InvalidIncidentTransition):
            machine.transition(
                incident,
                to_state,
                reason="trying anyway",
                actor="agent:diagnostic",
                policy_decision=decision,
            )

    escalated = machine.transition(
        incident,
        IncidentState.ESCALATED,
        reason=decision.reason,
        actor="system:policy-engine",
    )
    assert escalated.state is IncidentState.ESCALATED


def test_a_denied_action_cannot_even_raise_an_approval(
    pipeline: AssessmentPipeline,
    policy_engine: PolicyEngine,
    approval_engine: ApprovalEngine,
) -> None:
    action = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=CUSTOMER_DATABASE,
        )
    ).require_assessed_action()
    decision = policy_engine.evaluate(action, REMEDIATION)
    assert decision.decision is PolicyDecisionType.DENY
    with pytest.raises(ApprovalCreationRefused):
        approval_engine.request(
            approval_id="apr-001",
            action=action,
            agent=REMEDIATION,
            decision=decision,
        )


# --- the rejection path -------------------------------------------------------------


def test_a_rejected_approval_sends_the_plan_back_and_never_executes(
    machine: IncidentStateMachine,
    pipeline: AssessmentPipeline,
    policy_engine: PolicyEngine,
    approval_engine: ApprovalEngine,
) -> None:
    incident = build_incident(state=IncidentState.AWAITING_APPROVAL)
    action = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    ).require_assessed_action()
    decision = policy_engine.evaluate(action, REMEDIATION)
    rejected = approval_engine.reject(
        approval_engine.request(
            approval_id="apr-001",
            action=action,
            agent=REMEDIATION,
            decision=decision,
        ),
        by="human:oncall",
    )
    assert rejected.status is ApprovalStatus.REJECTED

    with pytest.raises(ApprovalConsumptionRefused):
        approval_engine.consume_for_execution(rejected, action, REMEDIATION)
    with pytest.raises(InvalidIncidentTransition):
        machine.transition(
            incident,
            IncidentState.EXECUTING,
            reason="rejected anyway",
            actor="agent:remediation",
        )

    replanned = machine.transition(
        incident,
        IncidentState.PLAN_PROPOSED,
        reason="human rejected the rollback; proposing an alternative",
        actor="agent:commander",
    )
    assert replanned.state is IncidentState.PLAN_PROPOSED


# --- quarantine mid-flight ----------------------------------------------------------


def test_quarantine_between_approval_and_execution_stops_the_lifecycle(
    machine: IncidentStateMachine,
    pipeline: AssessmentPipeline,
    policy_engine: PolicyEngine,
    approval_engine: ApprovalEngine,
) -> None:
    """The golden-incident ending: an agent is quarantined and its approval dies with it."""
    incident = build_incident(state=IncidentState.AWAITING_APPROVAL)
    action = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    ).require_assessed_action()
    approved = approval_engine.approve(
        approval_engine.request(
            approval_id="apr-001",
            action=action,
            agent=REMEDIATION,
            decision=policy_engine.evaluate(action, REMEDIATION),
        ),
        by="human:oncall",
    )

    quarantined = REMEDIATION.model_copy(update={"status": AgentLifecycleState.QUARANTINED})
    with pytest.raises(ApprovalConsumptionRefused):
        approval_engine.consume_for_execution(approved, action, quarantined)

    # With no authorization, the incident cannot leave AWAITING_APPROVAL for EXECUTING.
    with pytest.raises(InvalidIncidentTransition):
        machine.transition(
            incident,
            IncidentState.EXECUTING,
            reason="agent quarantined but trying anyway",
            actor="agent:remediation",
        )


# --- recovery -----------------------------------------------------------------------


def test_a_degraded_incident_recovers_back_through_investigation(
    machine: IncidentStateMachine,
) -> None:
    incident = build_incident(state=IncidentState.EXECUTING)
    for to_state in (
        IncidentState.DEGRADED,
        IncidentState.RECOVERING,
        IncidentState.INVESTIGATING,
    ):
        incident = machine.transition(
            incident, to_state, reason="tool timeout", actor="system:circuit-breaker"
        )
    assert incident.state is IncidentState.INVESTIGATING

    # And it still cannot shortcut to execution from there.
    with pytest.raises(InvalidIncidentTransition):
        machine.transition(
            incident, IncidentState.EXECUTING, reason="resume", actor="agent:remediation"
        )


# --- determinism --------------------------------------------------------------------


def test_the_whole_lifecycle_is_reproducible(
    clock: MovableClock,
    pipeline: AssessmentPipeline,
    policy_engine: PolicyEngine,
) -> None:
    """Two independent runs from the same inputs produce the same states and decisions."""
    from aegis.core.domain import to_json

    def run() -> tuple[str, str]:
        machine = IncidentStateMachine(clock=clock)
        engine = ApprovalEngine(policy_engine, clock=clock)
        incident = _advance_to_policy_check(machine)
        action = pipeline.assess(
            build_action(
                requesting_agent="remediation",
                capability="production.rollback",
                target_resource=PAYMENT_API,
            )
        ).require_assessed_action()
        decision = policy_engine.evaluate(action, REMEDIATION)
        incident = machine.transition(
            incident,
            IncidentState.AWAITING_APPROVAL,
            reason=decision.reason,
            actor="system:policy-engine",
            policy_decision=decision,
        )
        authorization = engine.consume_for_execution(
            engine.approve(
                engine.request(
                    approval_id="apr-001",
                    action=action,
                    agent=REMEDIATION,
                    decision=decision,
                ),
                by="human:oncall",
            ),
            action,
            REMEDIATION,
        )
        incident = machine.transition(
            incident,
            IncidentState.EXECUTING,
            reason="approved",
            actor="agent:remediation",
            authorization=authorization,
        )
        return to_json(incident), to_json(authorization)

    assert run() == run()
