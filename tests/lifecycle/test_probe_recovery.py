"""Automatic HALF_OPEN recovery, driven by the wired orchestrator.

The weakness this closes: Prompt 12 implemented and tested the probe machinery but nothing
called it, so in the wired system a breaker that opened stayed open for the life of the
process. A safety mechanism with no way back is an outage with extra steps.

The probe is a real governed execution — full assessment, policy, approval and
verification. HALF_OPEN is permission to *try once*, never permission to skip anything.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aegis.core.audit import reconstruct_incident_history
from aegis.core.domain import IncidentState, PolicyDecisionType
from aegis.core.verification import VerificationStatus
from aegis.enterprise import PAYMENT_API, EnterpriseWorld, FailureType, ServiceHealth
from aegis.lifecycle import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    FailureClass,
    InMemoryLifecycleState,
    verify_state_chain,
)
from aegis.orchestration import OrchestrationOutcome
from tests.orchestration.conftest import build_incident, build_orchestrator

START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
COOLDOWN = 300.0


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


def opened_breaker(clock, store=None, cooldown: float | None = COOLDOWN) -> CircuitBreaker:
    """A breaker already open for the golden incident's path, as earlier incidents left it."""
    breaker = CircuitBreaker(
        CircuitBreakerConfig(probe_cooldown_seconds=cooldown),
        clock=clock,
        persistence=store,
    )
    key = breaker.key_for(capability="production.rollback", resource=PAYMENT_API)
    for _ in range(3):
        breaker.record(key, FailureClass.EXECUTION_FAILURE, reason="failed in earlier incidents")
    assert breaker.state_of(key) is CircuitState.OPEN
    return breaker


class TestTheCooldownDrivesHalfOpen:
    def test_before_the_cooldown_the_breaker_refuses(self, clock) -> None:
        breaker = opened_breaker(clock)
        key = breaker.key_for(capability="production.rollback", resource=PAYMENT_API)
        clock.advance(COOLDOWN - 1)
        assert not breaker.check(key).allowed
        assert breaker.state_of(key) is CircuitState.OPEN

    def test_after_the_cooldown_one_probe_is_permitted(self, clock) -> None:
        breaker = opened_breaker(clock)
        key = breaker.key_for(capability="production.rollback", resource=PAYMENT_API)
        clock.advance(COOLDOWN + 1)
        decision = breaker.check(key)
        assert decision.allowed
        assert decision.is_probe
        assert decision.state is CircuitState.HALF_OPEN

    def test_only_one_probe_is_permitted_however_often_it_is_asked(self, clock) -> None:
        breaker = opened_breaker(clock)
        key = breaker.key_for(capability="production.rollback", resource=PAYMENT_API)
        clock.advance(COOLDOWN + 1)
        assert breaker.check(key).allowed
        for _ in range(5):
            assert not breaker.check(key).allowed

    def test_the_snapshot_says_when_a_probe_becomes_eligible(self, clock) -> None:
        # So an operator can see when automation will try again, rather than inferring it.
        breaker = opened_breaker(clock)
        key = breaker.key_for(capability="production.rollback", resource=PAYMENT_API)
        snapshot = breaker.snapshot(key)
        assert snapshot.probe_eligible_at == START + timedelta(seconds=COOLDOWN)

    def test_a_none_cooldown_never_becomes_eligible_on_its_own(self, clock) -> None:
        # A legitimate configuration for a capability nobody wants retried unattended.
        breaker = opened_breaker(clock, cooldown=None)
        key = breaker.key_for(capability="production.rollback", resource=PAYMENT_API)
        clock.advance(60 * 60 * 24 * 365)
        assert not breaker.check(key).allowed
        assert breaker.state_of(key) is CircuitState.OPEN

    def test_an_operator_can_still_permit_a_probe_explicitly(self, clock) -> None:
        breaker = opened_breaker(clock, cooldown=None)
        key = breaker.key_for(capability="production.rollback", resource=PAYMENT_API)
        breaker.allow_probe(key)
        assert breaker.check(key).is_probe

    def test_the_cooldown_uses_the_injected_clock(self, clock) -> None:
        # No ambient time anywhere: a frozen clock never becomes eligible.
        breaker = opened_breaker(clock)
        key = breaker.key_for(capability="production.rollback", resource=PAYMENT_API)
        for _ in range(10):
            assert not breaker.check(key).allowed

    def test_a_failed_probe_restarts_the_cooldown(self, clock) -> None:
        breaker = opened_breaker(clock)
        key = breaker.key_for(capability="production.rollback", resource=PAYMENT_API)
        clock.advance(COOLDOWN + 1)
        breaker.check(key)
        breaker.record_probe_failure(key, reason="still failing")
        assert breaker.state_of(key) is CircuitState.OPEN
        assert not breaker.check(key).allowed
        clock.advance(COOLDOWN + 1)
        assert breaker.check(key).is_probe

    def test_a_successful_probe_closes_and_stays_closed(self, clock) -> None:
        breaker = opened_breaker(clock)
        key = breaker.key_for(capability="production.rollback", resource=PAYMENT_API)
        clock.advance(COOLDOWN + 1)
        breaker.check(key)
        breaker.record_probe_success(key)
        assert breaker.state_of(key) is CircuitState.CLOSED
        assert breaker.snapshot(key).probe_eligible_at is None
        assert breaker.check(key).allowed


class TestTheOrchestratorDrivesTheProbe:
    """The wired system, not the component in isolation."""

    def test_a_run_after_the_cooldown_probes_and_recovers(self, clock) -> None:
        breaker = opened_breaker(clock)
        clock.advance(COOLDOWN + 1)
        orchestrator = build_orchestrator(breaker=breaker)
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)

        assert run.outcome is OrchestrationOutcome.RESOLVED
        assert run.execution is not None
        assert run.verification.status is VerificationStatus.VERIFIED
        key = breaker.key_for(capability="production.rollback", resource=PAYMENT_API)
        assert breaker.state_of(key) is CircuitState.CLOSED

    def test_the_probe_passed_full_governance(self, clock) -> None:
        # HALF_OPEN is permission to try once, never permission to skip anything.
        breaker = opened_breaker(clock)
        clock.advance(COOLDOWN + 1)
        orchestrator = build_orchestrator(breaker=breaker)
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)

        assert run.evaluation.decision.decision is PolicyDecisionType.REQUIRE_APPROVAL
        assert run.authorization is not None
        history = reconstruct_incident_history(
            orchestrator.audit.records(), run.incident.incident_id
        )
        states = [state.value for state in history.states]
        assert "POLICY_CHECK" in states
        assert "AWAITING_APPROVAL" in states
        assert "VERIFYING" in states

    def test_a_run_before_the_cooldown_is_still_refused(self, clock) -> None:
        breaker = opened_breaker(clock)
        clock.advance(COOLDOWN - 1)
        orchestrator = build_orchestrator(breaker=breaker)
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)

        assert run.execution is None
        assert run.incident.state is IncidentState.ESCALATED
        assert orchestrator.world.state(PAYMENT_API).deployment == "v4.8"

    def test_a_failing_probe_reopens_and_the_world_is_untouched(self, clock) -> None:
        world = EnterpriseWorld()
        world.inject_failure(FailureType.ROLLBACK_FAILURE)
        breaker = opened_breaker(clock)
        clock.advance(COOLDOWN + 1)
        orchestrator = build_orchestrator(breaker=breaker, world=world, max_steps=9)
        orchestrator.run(build_incident(), affected_resource=PAYMENT_API)

        key = breaker.key_for(capability="production.rollback", resource=PAYMENT_API)
        assert breaker.state_of(key) is CircuitState.OPEN
        assert world.state(PAYMENT_API).deployment == "v4.8"
        assert world.state(PAYMENT_API).health is not ServiceHealth.HEALTHY

    def test_recovery_after_a_restart_still_needs_the_cooldown(self, clock) -> None:
        # The two hardenings composed: durable state plus cooldown-driven recovery.
        store = InMemoryLifecycleState()
        opened_breaker(clock, store)

        restarted = CircuitBreaker(
            CircuitBreakerConfig(probe_cooldown_seconds=COOLDOWN),
            clock=clock,
            persistence=store,
        )
        blocked = build_orchestrator(breaker=restarted).run(
            build_incident(), affected_resource=PAYMENT_API
        )
        assert blocked.execution is None

        clock.advance(COOLDOWN + 1)
        recovered = build_orchestrator(breaker=restarted).run(
            build_incident(), affected_resource=PAYMENT_API
        )
        assert recovered.outcome is OrchestrationOutcome.RESOLVED

    def test_the_whole_cycle_leaves_a_verifiable_chain(self, clock) -> None:
        store = InMemoryLifecycleState()
        breaker = opened_breaker(clock, store)
        clock.advance(COOLDOWN + 1)
        build_orchestrator(breaker=breaker).run(build_incident(), affected_resource=PAYMENT_API)

        report = verify_state_chain(store.load())
        assert report.valid, report.reason
        transitions = [r.transition.value for r in store.load() if r.transition]
        assert "OPENED" in transitions
        assert "PROBE_PERMITTED" in transitions
        assert "PROBE_SUCCEEDED" in transitions

    def test_a_probe_does_not_bypass_the_lifecycle_budget(self, clock) -> None:
        from aegis.lifecycle import LifecycleLimits

        breaker = opened_breaker(clock)
        clock.advance(COOLDOWN + 1)
        limits = LifecycleLimits(max_steps=9, max_executions=1, max_recovery_attempts=1)
        run = build_orchestrator(breaker=breaker, limits=limits).run(
            build_incident(), affected_resource=PAYMENT_API
        )
        assert run.lifecycle.counters.execution_count <= 1


class TestTheHeldProbeIsNotABypass:
    """The probe a lifecycle holds across the two gates is bookkeeping, not permission.

    Added after mutation testing: removing the state re-check, and leaking held probes
    between incidents, both survived the suite as first written.
    """

    def manager(self, clock, store=None):
        from aegis.lifecycle import LifecycleLimits, LifecycleManager

        return LifecycleManager(
            limits=LifecycleLimits(),
            breaker=opened_breaker(clock, store),
            clock=clock,
        )

    def action(self):
        from aegis.core.domain import RiskLevel
        from tests.fleet import build_action

        return build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
            risk=RiskLevel.HIGH,
        )

    def test_a_breaker_that_reopens_between_the_gates_still_blocks(self, clock) -> None:
        # The half-open equivalent of the stale-authorization race: the probe was granted
        # at gate one, and the breaker opened before gate two. Holding a probe must not
        # carry the action through.
        lifecycle = self.manager(clock)
        clock.advance(COOLDOWN + 1)
        action = self.action()
        key = lifecycle.scope_for(action)

        assert not lifecycle.may_remediate(action).stopped, "the probe was granted"
        assert lifecycle.breaker.state_of(key) is CircuitState.HALF_OPEN

        # Something else drives the breaker back open before execution.
        lifecycle.breaker.record_probe_failure(key, reason="another path failed")
        assert lifecycle.breaker.state_of(key) is CircuitState.OPEN

        blocked = lifecycle.may_execute(action, "fingerprint")
        assert blocked.stopped
        assert blocked.stop_reason.value == "CIRCUIT_OPEN"

    def test_a_held_probe_does_not_leak_into_the_next_incident(self, clock) -> None:
        # The discriminating case: the breaker is *still* half-open with the first
        # incident's probe outstanding. A leaked claim would wave the second incident
        # through on a probe it never took — two attempts from one probe.
        lifecycle = self.manager(clock)
        clock.advance(COOLDOWN + 1)
        action = self.action()
        assert not lifecycle.may_remediate(action).stopped, "the first probe was granted"
        key = lifecycle.scope_for(action)
        assert lifecycle.breaker.state_of(key) is CircuitState.HALF_OPEN

        lifecycle.begin("INC-2")
        blocked = lifecycle.may_remediate(action)
        assert blocked.stopped, "a second incident must not inherit the first one's probe"
        assert blocked.stop_reason.value == "CIRCUIT_OPEN"

    def test_the_probe_is_released_once_its_outcome_is_recorded(self, clock) -> None:
        lifecycle = self.manager(clock)
        clock.advance(COOLDOWN + 1)
        action = self.action()
        lifecycle.may_remediate(action)
        lifecycle.record_outcome(
            action, execution_outcome="APPLIED", verification_status="VERIFIED"
        )
        key = lifecycle.scope_for(action)
        assert lifecycle.breaker.state_of(key) is CircuitState.CLOSED
        assert key not in lifecycle._held_probes

    def test_a_probe_outcome_is_classified_without_the_caller_saying_so(self, clock) -> None:
        # The manager knows it holds the probe; a caller cannot get it wrong by forgetting.
        lifecycle = self.manager(clock)
        clock.advance(COOLDOWN + 1)
        action = self.action()
        lifecycle.may_remediate(action)
        lifecycle.record_outcome(action, execution_outcome="FAILED", verification_status="FAILED")
        assert lifecycle.breaker.state_of(lifecycle.scope_for(action)) is CircuitState.OPEN
