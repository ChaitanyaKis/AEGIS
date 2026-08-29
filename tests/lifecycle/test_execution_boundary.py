"""Every way of reaching production without crossing the lifecycle, and why none works.

These test the boundary itself, not the orchestrator's source. Each one calls the real
`ActionExecutor` with the real world behind it and tries to make a mutation happen. The
assertion is always the same in substance: the world did not change.

The Prompt 12 weakness was that the lifecycle manager was a collaborator the orchestrator
*chose* to call, so "we do not bypass it" rested on review and discipline. What follows is
the replacement for that discipline.
"""

from __future__ import annotations

import ast
import pathlib
from datetime import UTC, datetime, timedelta

import pytest

from aegis.core.approval import action_fingerprint
from aegis.core.domain import IncidentState, RiskLevel
from aegis.enterprise import PAYMENT_API, ActionExecutor, EnterpriseWorld, ExecutionOutcome
from aegis.enterprise.mutations import UnauthorizedExecutionError
from aegis.lifecycle import (
    CircuitBreaker,
    CircuitState,
    FailureClass,
    LifecycleAction,
    LifecycleCoordinator,
    LifecycleDecision,
    LifecycleGate,
    LifecycleGateRejected,
    LifecycleManager,
    gate_seal,
)
from tests.fleet import REMEDIATION, build_action
from tests.orchestration.conftest import build_incident, build_orchestrator

START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def governed(clock):
    """A world, a coordinator and an executor wired exactly as production wires them."""
    world = EnterpriseWorld()
    manager = LifecycleManager(breaker=CircuitBreaker(clock=clock), clock=clock)
    manager.begin("INC-2026-0001")
    coordinator = LifecycleCoordinator(manager, clock=clock)
    executor = ActionExecutor(world, clock=clock, gate_verifier=coordinator.verifier)
    return world, coordinator, executor


def action(action_id: str = "act-001", incident_id: str = "INC-2026-0001"):
    """An action as the real assessment pipeline produces it.

    Assessed rather than hand-built: the approval engine refuses an action with no blast
    radius, and a test that bypassed assessment would be proving the boundary against an
    action production could never produce.
    """
    from aegis.core.assessment import AssessmentPipeline
    from aegis.enterprise import build_dependency_graph
    from tests.fleet import build_registry

    proposed = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_API,
        risk=RiskLevel.HIGH,
        action_id=action_id,
        incident_id=incident_id,
    ).model_copy(update={"arguments": {"target_version": "v4.7"}})
    pipeline = AssessmentPipeline(build_registry(), build_dependency_graph())
    return pipeline.assess(proposed).require_assessed_action()


def authorization_for(subject):
    """A genuine execution authorization, produced by the real approval engine."""
    from aegis.core.approval import ApprovalEngine
    from aegis.core.domain import PolicyDecisionType
    from aegis.core.policy import PolicyEngine
    from tests.fleet import build_registry, fixed_clock

    policy = PolicyEngine(build_registry(), clock=fixed_clock)
    engine = ApprovalEngine(policy, clock=fixed_clock)
    decision = policy.evaluate(subject, REMEDIATION)
    assert decision.decision is PolicyDecisionType.REQUIRE_APPROVAL
    pending = engine.request(
        approval_id="apr-boundary-001", action=subject, agent=REMEDIATION, decision=decision
    )
    granted = engine.approve(pending, by="human:oncall")
    return engine.consume_for_execution(granted, subject, REMEDIATION)


def gate_for(coordinator, subject):
    issue = coordinator.request_gate(
        subject,
        accountable_agent=REMEDIATION,
        incident_state=IncidentState.EXECUTING,
        lifecycle_decision=LifecycleDecision(
            action=LifecycleAction.CONTINUE,
            detail="within budget",
            counters=coordinator.manager.counters,
        ),
    )
    assert issue.issued, issue.refused_reason
    return issue.gate


def unchanged(world) -> bool:
    return world.state(PAYMENT_API).deployment == "v4.8"


class TestTheGovernedPathWorks:
    """The control. If the legitimate path did not execute, nothing below would prove much."""

    def test_a_full_governed_execution_applies(self, governed) -> None:
        world, coordinator, executor = governed
        subject = action()
        result = executor.execute(
            subject, authorization_for(subject), gate=gate_for(coordinator, subject)
        )
        assert result.outcome is ExecutionOutcome.APPLIED
        assert not unchanged(world)


class TestBothArtifactsAreRequired:
    def test_an_authorization_without_a_gate_executes_nothing(self, governed) -> None:
        # The headline change. Before Prompt 13 this succeeded.
        world, _, executor = governed
        subject = action()
        with pytest.raises(LifecycleGateRejected) as refusal:
            executor.execute(subject, authorization_for(subject))
        assert refusal.value.rejection.check == "presence"
        assert unchanged(world)

    def test_a_gate_without_an_authorization_executes_nothing(self, governed) -> None:
        world, coordinator, executor = governed
        subject = action()
        with pytest.raises(UnauthorizedExecutionError):
            executor.execute(subject, None, gate=gate_for(coordinator, subject))
        assert unchanged(world)

    def test_neither_artifact_executes_nothing(self, governed) -> None:
        world, _, executor = governed
        with pytest.raises(UnauthorizedExecutionError):
            executor.execute(action(), None)
        assert unchanged(world)

    def test_the_authorization_is_still_the_authority(self, governed) -> None:
        # A gate is not a substitute: an authorization for a different action still fails
        # even with a perfectly valid gate for the right one.
        world, coordinator, executor = governed
        subject = action()
        other = action(action_id="act-002")
        with pytest.raises(UnauthorizedExecutionError):
            executor.execute(subject, authorization_for(other), gate=gate_for(coordinator, subject))
        assert unchanged(world)


class TestForgedAndMisboundGates:
    def test_a_forged_gate_executes_nothing(self, governed) -> None:
        world, coordinator, executor = governed
        subject = action()
        draft = LifecycleGate(
            gate_id="gate-forged",
            incident_id=subject.incident_id,
            action_id=subject.action_id,
            action_fingerprint=action_fingerprint(subject),
            capability_id=subject.capability,
            resource=subject.target_resource,
            lifecycle_scope=coordinator.manager.scope_for(subject),
            lifecycle_decision="CONTINUE",
            lifecycle_state="EXECUTING",
            breaker_state=CircuitState.CLOSED,
            lifecycle_generation=0,
            steps_used=0,
            remediation_attempts=0,
            execution_count=0,
            issued_at=START,
            seal="0" * 64,
        )
        forged = draft.model_copy(update={"seal": gate_seal(draft)})
        with pytest.raises(LifecycleGateRejected) as refusal:
            executor.execute(subject, authorization_for(subject), gate=forged)
        assert refusal.value.rejection.check == "issuer"
        assert unchanged(world)

    def test_a_tampered_gate_executes_nothing(self, governed) -> None:
        world, coordinator, executor = governed
        subject = action()
        gate = gate_for(coordinator, subject)
        with pytest.raises(LifecycleGateRejected) as refusal:
            executor.execute(
                subject,
                authorization_for(subject),
                gate=gate.model_copy(update={"steps_used": 99}),
            )
        assert refusal.value.rejection.check == "seal"
        assert unchanged(world)

    def test_a_gate_for_another_action_executes_nothing(self, governed) -> None:
        world, coordinator, executor = governed
        first, second = action("act-001"), action("act-002")
        gate = gate_for(coordinator, first)
        with pytest.raises(LifecycleGateRejected):
            executor.execute(second, authorization_for(second), gate=gate)
        assert unchanged(world)

    def test_a_gate_for_another_incident_executes_nothing(self, governed) -> None:
        world, coordinator, executor = governed
        mine = action()
        gate = gate_for(coordinator, mine)
        other = action(incident_id="INC-2026-0002")
        with pytest.raises(LifecycleGateRejected):
            executor.execute(other, authorization_for(other), gate=gate)
        assert unchanged(world)

    def test_a_gate_for_another_fingerprint_executes_nothing(self, governed) -> None:
        world, coordinator, executor = governed
        subject = action()
        gate = gate_for(coordinator, subject)
        altered = subject.model_copy(update={"arguments": {"target_version": "v4.6"}})
        with pytest.raises(LifecycleGateRejected) as refusal:
            executor.execute(altered, authorization_for(altered), gate=gate)
        assert refusal.value.rejection.check == "fingerprint_binding"
        assert unchanged(world)

    def test_a_gate_from_another_lifecycle_context_executes_nothing(self, clock) -> None:
        world = EnterpriseWorld()
        subject = action()

        stranger = LifecycleCoordinator(
            LifecycleManager(breaker=CircuitBreaker(clock=clock), clock=clock), clock=clock
        )
        stranger.manager.begin(subject.incident_id)
        foreign_gate = gate_for(stranger, subject)

        mine = LifecycleCoordinator(
            LifecycleManager(breaker=CircuitBreaker(clock=clock), clock=clock), clock=clock
        )
        mine.manager.begin(subject.incident_id)
        executor = ActionExecutor(world, clock=clock, gate_verifier=mine.verifier)

        with pytest.raises(LifecycleGateRejected) as refusal:
            executor.execute(subject, authorization_for(subject), gate=foreign_gate)
        assert refusal.value.rejection.check == "issuer"
        assert unchanged(world)


class TestReplayAndStaleness:
    def test_a_gate_cannot_execute_twice(self, governed) -> None:
        world, coordinator, executor = governed
        subject = action()
        gate = gate_for(coordinator, subject)
        executor.execute(subject, authorization_for(subject), gate=gate)
        world.deploy(PAYMENT_API, "v4.8")

        with pytest.raises(LifecycleGateRejected) as refusal:
            executor.execute(subject, authorization_for(subject), gate=gate)
        assert refusal.value.rejection.check == "replay"
        assert unchanged(world)

    def test_a_stale_gate_executes_nothing(self, governed, clock) -> None:
        world, coordinator, executor = governed
        subject = action()
        gate = gate_for(coordinator, subject)
        clock.advance(61)
        with pytest.raises(LifecycleGateRejected) as refusal:
            executor.execute(subject, authorization_for(subject), gate=gate)
        assert refusal.value.rejection.check == "expiry"
        assert unchanged(world)

    def test_a_breaker_reopening_between_gate_and_execution_stops_it(self, governed) -> None:
        world, coordinator, executor = governed
        subject = action()
        gate = gate_for(coordinator, subject)

        scope = coordinator.manager.scope_for(subject)
        for _ in range(3):
            coordinator.manager.breaker.record(
                scope, FailureClass.EXECUTION_FAILURE, reason="failed elsewhere"
            )

        with pytest.raises(LifecycleGateRejected) as refusal:
            executor.execute(subject, authorization_for(subject), gate=gate)
        assert refusal.value.rejection.check in {"breaker_state", "lifecycle_generation"}
        assert unchanged(world)


class TestTheLifecycleCannotBeSkipped:
    def test_a_gate_cannot_be_obtained_when_the_lifecycle_refuses(self, governed) -> None:
        _, coordinator, _ = governed
        subject = action()
        refused = coordinator.request_gate(
            subject,
            accountable_agent=REMEDIATION,
            incident_state=IncidentState.EXECUTING,
            lifecycle_decision=LifecycleDecision(
                action=LifecycleAction.ESCALATE,
                detail="the remediation budget is exhausted",
                counters=coordinator.manager.counters,
            ),
        )
        assert not refused.issued
        assert "lifecycle refused" in refused.refused_reason

    def test_a_gate_cannot_be_obtained_while_the_breaker_is_open(self, governed) -> None:
        _, coordinator, _ = governed
        subject = action()
        scope = coordinator.manager.scope_for(subject)
        for _ in range(3):
            coordinator.manager.breaker.record(
                scope, FailureClass.EXECUTION_FAILURE, reason="failed"
            )
        refused = coordinator.request_gate(
            subject,
            accountable_agent=REMEDIATION,
            incident_state=IncidentState.EXECUTING,
            lifecycle_decision=LifecycleDecision(
                action=LifecycleAction.CONTINUE,
                detail="within budget",
                counters=coordinator.manager.counters,
            ),
        )
        assert not refused.issued
        assert "circuit breaker is open" in refused.refused_reason

    def test_the_orchestrator_never_calls_the_executor_without_a_gate(self) -> None:
        # Source inspection is a weak check on its own, which is why every test above
        # exercises the boundary itself. This one catches a *new* execution path being
        # added without one, which behaviour tests on existing paths would miss.
        source = pathlib.Path("src/aegis/orchestration/orchestrator.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "executor"
        ]
        assert calls, "the orchestrator must still execute somewhere"
        for call in calls:
            assert any(keyword.arg == "gate" for keyword in call.keywords), (
                "every executor call must pass a gate"
            )


class TestTheEndToEndPathStillHolds:
    def test_the_golden_incident_resolves_through_the_coordinator(self) -> None:
        orchestrator = build_orchestrator()
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        assert run.outcome.value == "RESOLVED"
        assert orchestrator.coordinator.verifier.issued_count == 1
        assert orchestrator.coordinator.verifier.consumed_count == 1

    def test_direct_execution_after_a_governed_run_is_refused(self) -> None:
        # The most realistic bypass: reuse the artifacts of a legitimate run.
        orchestrator = build_orchestrator()
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        orchestrator.world.deploy(PAYMENT_API, "v4.8")
        with pytest.raises(LifecycleGateRejected):
            orchestrator.executor.execute(run.action, run.authorization)
        assert orchestrator.world.state(PAYMENT_API).deployment == "v4.8"

    def test_every_execution_in_a_run_consumed_exactly_one_gate(self) -> None:
        from aegis.enterprise import FailureType

        world = EnterpriseWorld()
        world.inject_failure(FailureType.ROLLBACK_FAILURE)
        orchestrator = build_orchestrator(world=world, max_steps=9)
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        register = orchestrator.coordinator.verifier
        assert register.consumed_count == run.lifecycle.counters.execution_count
