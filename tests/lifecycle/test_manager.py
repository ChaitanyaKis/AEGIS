"""The lifecycle manager: bounded execution, retry accounting, terminal states.

The manager can stop things and can decline to stop them. Declining to stop is not
permission — a fact several of these tests assert directly, because it is the property
that keeps the manager from becoming an alternate authorizer.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from aegis.core.domain import IncidentState, PolicyDecisionType, RiskLevel, to_json
from aegis.lifecycle import (
    TERMINAL_STATES,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    FailureClass,
    LifecycleAction,
    LifecycleLimits,
    LifecycleManager,
    StopReason,
)
from tests.fleet import PAYMENT_API, build_action, fixed_clock


def manager(**limits) -> LifecycleManager:
    return LifecycleManager(
        limits=LifecycleLimits(**limits),
        breaker=CircuitBreaker(clock=fixed_clock),
        clock=fixed_clock,
    )


def action(action_id: str = "act-001", capability: str = "production.rollback"):
    return build_action(
        requesting_agent="remediation",
        capability=capability,
        target_resource=PAYMENT_API,
        risk=RiskLevel.HIGH,
        action_id=action_id,
    )


class TestBoundedExecution:
    def test_max_steps_of_one_stops_after_one_step(self) -> None:
        lifecycle = manager(max_steps=1, max_recovery_attempts=1)
        lifecycle.begin("INC-1")
        first = lifecycle.may_continue(IncidentState.INVESTIGATING)
        assert first.action is LifecycleAction.CONTINUE
        lifecycle.record_step()
        verdict = lifecycle.may_continue(IncidentState.INVESTIGATING)
        assert verdict.stopped
        assert verdict.stop_reason is StopReason.STEP_BUDGET_EXHAUSTED

    @pytest.mark.parametrize("budget", [1, 2, 5, 8])
    def test_max_steps_of_n_stops_after_n(self, budget: int) -> None:
        lifecycle = manager(max_steps=budget, max_recovery_attempts=1)
        lifecycle.begin("INC-1")
        for _ in range(budget):
            assert not lifecycle.may_continue(IncidentState.INVESTIGATING).stopped
            lifecycle.record_step()
        assert lifecycle.may_continue(IncidentState.INVESTIGATING).stopped

    def test_max_steps_of_zero_is_rejected_at_configuration(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            LifecycleLimits(max_steps=0)

    def test_raising_the_bound_is_explicit_configuration(self) -> None:
        # The only way to get more steps is to construct different limits.
        tight, loose = manager(max_steps=1, max_recovery_attempts=1), manager(max_steps=4)
        for lifecycle, budget in ((tight, 1), (loose, 4)):
            lifecycle.begin("INC-1")
            for _ in range(budget):
                lifecycle.record_step()
            assert lifecycle.may_continue(IncidentState.INVESTIGATING).stopped

    def test_the_step_budget_escalates_rather_than_stopping_quietly(self) -> None:
        # An incident that ran out of budget needs a human, not silence.
        lifecycle = manager(max_steps=1, max_recovery_attempts=1)
        lifecycle.begin("INC-1")
        lifecycle.record_step()
        assert lifecycle.may_continue(IncidentState.INVESTIGATING).escalates

    def test_the_verdict_names_the_limit_that_applied(self) -> None:
        lifecycle = manager(max_steps=2, max_recovery_attempts=1)
        lifecycle.begin("INC-1")
        lifecycle.record_step()
        lifecycle.record_step()
        verdict = lifecycle.may_continue(IncidentState.INVESTIGATING)
        assert verdict.limit_name == "max_steps"
        assert verdict.limit_value == 2


class TestTerminalStatesStopEverything:
    @pytest.mark.parametrize("state", [IncidentState.RESOLVED, IncidentState.ESCALATED])
    def test_a_terminal_state_stops_the_lifecycle(self, state) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        verdict = lifecycle.may_continue(state)
        assert verdict.stopped
        assert verdict.stop_reason is StopReason.TERMINAL_STATE

    @pytest.mark.parametrize("state", [IncidentState.RESOLVED, IncidentState.ESCALATED])
    def test_recovery_cannot_restart_a_terminal_lifecycle(self, state) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        verdict = lifecycle.may_recover(state)
        assert verdict.stopped
        assert verdict.stop_reason is StopReason.TERMINAL_STATE

    def test_a_terminal_state_is_not_asked_whether_it_has_budget(self) -> None:
        # Asking would imply the budget could bring it back.
        lifecycle = manager(max_steps=8)
        lifecycle.begin("INC-1")
        verdict = lifecycle.may_continue(IncidentState.RESOLVED)
        assert verdict.stop_reason is StopReason.TERMINAL_STATE
        assert verdict.limit_name is None

    def test_the_terminal_set_is_exactly_the_two_domain_terminal_states(self) -> None:
        # No new terminal state is invented by this package.
        assert {IncidentState.RESOLVED, IncidentState.ESCALATED} == TERMINAL_STATES

    def test_a_terminal_stop_does_not_escalate_a_resolved_incident(self) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        verdict = lifecycle.may_continue(IncidentState.RESOLVED)
        assert verdict.action is LifecycleAction.STOP
        assert not verdict.escalates


class TestRetryAccounting:
    def test_remediation_attempts_are_bounded(self) -> None:
        lifecycle = manager(max_remediation_attempts=2)
        lifecycle.begin("INC-1")
        for _ in range(2):
            assert not lifecycle.may_remediate().stopped
            lifecycle.record_remediation_attempt()
        verdict = lifecycle.may_remediate()
        assert verdict.stop_reason is StopReason.REMEDIATION_BUDGET_EXHAUSTED

    def test_recovery_attempts_are_bounded(self) -> None:
        lifecycle = manager(max_recovery_attempts=2)
        lifecycle.begin("INC-1")
        for _ in range(2):
            assert not lifecycle.may_recover(IncidentState.DEGRADED).stopped
            lifecycle.record_recovery()
        verdict = lifecycle.may_recover(IncidentState.DEGRADED)
        assert verdict.stop_reason is StopReason.RECOVERY_BUDGET_EXHAUSTED

    def test_consecutive_failures_escalate(self) -> None:
        lifecycle = manager(max_consecutive_failures=2)
        lifecycle.begin("INC-1")
        lifecycle.record_outcome(action(), execution_outcome="FAILED", verification_status="FAILED")
        assert not lifecycle.may_continue(IncidentState.INVESTIGATING).stopped
        lifecycle.record_outcome(action(), execution_outcome="FAILED", verification_status="FAILED")
        verdict = lifecycle.may_continue(IncidentState.INVESTIGATING)
        assert verdict.stop_reason is StopReason.CONSECUTIVE_FAILURES

    def test_a_retry_cannot_reset_the_failure_counter(self) -> None:
        # The whole point of the counter. Only a verified success clears it.
        lifecycle = manager()
        lifecycle.begin("INC-1")
        for _ in range(2):
            lifecycle.record_outcome(
                action(), execution_outcome="FAILED", verification_status="FAILED"
            )
            lifecycle.record_recovery()
            lifecycle.record_remediation_attempt()
        assert lifecycle.counters.consecutive_failures == 2

    def test_only_a_verified_success_clears_the_failure_counter(self) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        lifecycle.record_outcome(action(), execution_outcome="FAILED", verification_status="FAILED")
        assert lifecycle.counters.consecutive_failures == 1
        lifecycle.record_outcome(
            action(), execution_outcome="APPLIED", verification_status="VERIFIED"
        )
        assert lifecycle.counters.consecutive_failures == 0

    def test_an_applied_execution_with_a_failed_verification_is_still_a_failure(self) -> None:
        # Execution success is not verification (claude.md section 11).
        lifecycle = manager()
        lifecycle.begin("INC-1")
        lifecycle.record_outcome(
            action(), execution_outcome="APPLIED", verification_status="FAILED"
        )
        assert lifecycle.counters.consecutive_failures == 1

    def test_a_stale_verification_is_a_failure_for_the_lifecycle(self) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        lifecycle.record_outcome(action(), execution_outcome="APPLIED", verification_status="STALE")
        assert lifecycle.counters.consecutive_failures == 1

    def test_executions_are_bounded_in_total(self) -> None:
        lifecycle = manager(max_executions=2)
        lifecycle.begin("INC-1")
        for index in range(2):
            lifecycle.record_execution(f"fp-{index}")
        verdict = lifecycle.may_execute(action(), "fp-new")
        assert verdict.stop_reason is StopReason.EXECUTION_BUDGET_EXHAUSTED

    def test_the_execution_budget_is_checked_before_a_human_is_asked(self) -> None:
        # may_remediate and may_execute both enforce this bound. Mutation testing showed
        # removing it from may_remediate alone survives, because may_execute still holds —
        # so this pins the earlier gate independently. It matters: the earlier check is
        # what stops an approval being requested for an action that can never run.
        lifecycle = manager(max_executions=1)
        lifecycle.begin("INC-1")
        lifecycle.record_execution("fp-1")
        verdict = lifecycle.may_remediate(action())
        assert verdict.stopped
        assert verdict.stop_reason is StopReason.EXECUTION_BUDGET_EXHAUSTED

    def test_the_same_action_is_bounded_more_tightly(self) -> None:
        lifecycle = manager(max_executions=5, max_executions_per_fingerprint=2)
        lifecycle.begin("INC-1")
        for _ in range(2):
            lifecycle.record_execution("same-fingerprint")
        verdict = lifecycle.may_execute(action(), "same-fingerprint")
        assert verdict.stop_reason is StopReason.FINGERPRINT_BUDGET_EXHAUSTED
        assert not lifecycle.may_execute(action(), "different").stopped

    def test_beginning_a_new_incident_resets_counters_for_that_incident(self) -> None:
        # Per-incident counters are per incident. The breaker is what persists.
        lifecycle = manager()
        lifecycle.begin("INC-1")
        lifecycle.record_step()
        lifecycle.record_remediation_attempt()
        lifecycle.begin("INC-2")
        assert lifecycle.counters.steps_used == 0
        assert lifecycle.counters.remediation_attempts == 0


class TestTheBreakerGatesTheLifecycle:
    def test_an_open_breaker_blocks_remediation(self) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        subject = action()
        key = lifecycle.scope_for(subject)
        for _ in range(3):
            lifecycle.breaker.record(key, FailureClass.EXECUTION_FAILURE, reason="failed")
        verdict = lifecycle.may_remediate(subject)
        assert verdict.stop_reason is StopReason.CIRCUIT_OPEN
        assert verdict.escalates

    def test_an_open_breaker_blocks_execution(self) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        subject = action()
        key = lifecycle.scope_for(subject)
        for _ in range(3):
            lifecycle.breaker.record(key, FailureClass.EXECUTION_FAILURE, reason="failed")
        assert lifecycle.may_execute(subject, "fp").stop_reason is StopReason.CIRCUIT_OPEN

    def test_the_verdict_carries_the_breaker_snapshot(self) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        subject = action()
        key = lifecycle.scope_for(subject)
        for _ in range(3):
            lifecycle.breaker.record(key, FailureClass.EXECUTION_FAILURE, reason="failed")
        verdict = lifecycle.may_execute(subject, "fp")
        assert verdict.breaker is not None
        assert verdict.breaker.state is CircuitState.OPEN

    def test_a_closed_breaker_blocks_nothing(self) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        assert not lifecycle.may_remediate(action()).stopped
        assert not lifecycle.may_execute(action(), "fp").stopped

    def test_an_open_breaker_for_another_scope_does_not_block(self) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        other = action(capability="production.scale")
        key = lifecycle.scope_for(other)
        for _ in range(3):
            lifecycle.breaker.record(key, FailureClass.EXECUTION_FAILURE, reason="failed")
        assert not lifecycle.may_execute(action(), "fp").stopped

    def test_a_governance_anomaly_opens_the_breaker(self) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        subject = action()
        anomalies = lifecycle.record_governance_anomaly(
            subject,
            executed=True,
            authorization_present=False,
            policy_decision=PolicyDecisionType.REQUIRE_APPROVAL,
            authorized_action_id=None,
            verified_action_id=subject.action_id,
            audit_valid=True,
        )
        assert "execution_without_authorization" in anomalies
        assert lifecycle.breaker.state_of(lifecycle.scope_for(subject)) is CircuitState.OPEN

    def test_a_normal_deny_does_not_open_the_breaker(self) -> None:
        # The critical negative case for Part 13.
        lifecycle = manager()
        lifecycle.begin("INC-1")
        subject = action()
        for _ in range(5):
            anomalies = lifecycle.record_governance_anomaly(
                subject,
                executed=False,
                authorization_present=False,
                policy_decision=PolicyDecisionType.DENY,
                authorized_action_id=None,
                verified_action_id=None,
                audit_valid=True,
            )
            assert anomalies == ()
        assert lifecycle.breaker.state_of(lifecycle.scope_for(subject)) is CircuitState.CLOSED

    def test_a_probe_outcome_decides_the_breaker_directly(self) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        subject = action()
        key = lifecycle.scope_for(subject)
        for _ in range(3):
            lifecycle.breaker.record(key, FailureClass.EXECUTION_FAILURE, reason="failed")
        lifecycle.breaker.allow_probe(key)
        lifecycle.record_outcome(
            subject, execution_outcome="APPLIED", verification_status="VERIFIED", probe=True
        )
        assert lifecycle.breaker.state_of(key) is CircuitState.CLOSED

    def test_a_failed_probe_reopens_through_the_manager(self) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        subject = action()
        key = lifecycle.scope_for(subject)
        for _ in range(3):
            lifecycle.breaker.record(key, FailureClass.EXECUTION_FAILURE, reason="failed")
        lifecycle.breaker.allow_probe(key)
        lifecycle.record_outcome(
            subject, execution_outcome="FAILED", verification_status="FAILED", probe=True
        )
        assert lifecycle.breaker.state_of(key) is CircuitState.OPEN


class TestTheManagerGrantsNothing:
    def test_there_is_no_execute_action(self) -> None:
        # The manager can stop things and decline to stop them. It cannot say "go ahead".
        assert {member.value for member in LifecycleAction} == {
            "CONTINUE",
            "STOP",
            "ESCALATE",
        }

    def test_continue_is_not_permission(self) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        verdict = lifecycle.may_execute(action(), "fp")
        assert verdict.action is LifecycleAction.CONTINUE
        # It carries no authorization, no approval and no policy decision.
        fields = set(type(verdict).model_fields)
        assert not fields & {"authorization", "approval", "policy_decision", "allowed"}

    def test_the_manager_imports_no_governance_engine(self) -> None:
        source = pathlib.Path("src/aegis/lifecycle/manager.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        for forbidden in (
            "aegis.core.policy",
            "aegis.core.approval",
            "aegis.core.verification",
            "aegis.core.incidents",
            "aegis.enterprise",
            "aegis.memory",
            "aegis.agents",
            "aegis.orchestration",
        ):
            assert not any(m.startswith(forbidden) for m in imported), forbidden

    def test_the_manager_defines_no_competing_incident_state(self) -> None:
        # IncidentState remains authoritative; this package imports it rather than
        # redeclaring it.
        import aegis.lifecycle as package

        for name in dir(package):
            member = getattr(package, name)
            is_enum = (
                isinstance(member, type)
                and issubclass(member, str)
                and hasattr(member, "__members__")
            )
            if is_enum:
                assert "INVESTIGATING" not in member.__members__, name


class TestLifecycleRecords:
    def test_a_record_is_produced_for_every_finish(self) -> None:
        lifecycle = manager()
        lifecycle.begin("INC-1")
        record = lifecycle.finish(final_state=IncidentState.RESOLVED, detail="all good")
        assert record.incident_id == "INC-1"
        assert record.stop_reason is StopReason.NOT_STOPPED

    def test_a_stop_record_carries_the_limit_and_counters(self) -> None:
        lifecycle = manager(max_steps=1, max_recovery_attempts=1)
        lifecycle.begin("INC-1")
        lifecycle.record_step()
        verdict = lifecycle.may_continue(IncidentState.INVESTIGATING)
        record = lifecycle.finish(final_state=IncidentState.ESCALATED, decision=verdict)
        assert record.stop_reason is StopReason.STEP_BUDGET_EXHAUSTED
        assert record.limit_name == "max_steps"
        assert record.limit_value == 1
        assert record.counters.steps_used == 1
        assert record.escalation_reason is not None

    def test_a_record_is_frozen_and_serializes_canonically(self) -> None:
        from pydantic import ValidationError

        lifecycle = manager()
        lifecycle.begin("INC-1")
        record = lifecycle.finish(final_state=IncidentState.RESOLVED, detail="done")
        with pytest.raises(ValidationError):
            record.stop_reason = StopReason.CIRCUIT_OPEN  # type: ignore[misc]
        assert to_json(record) == to_json(record.model_copy())

    def test_every_stop_reason_is_a_declared_member(self) -> None:
        # No stop is unexplained.
        assert StopReason.NOT_STOPPED.value == "NOT_STOPPED"
        assert len(set(StopReason)) == 10


class TestDeterminism:
    def test_identical_sequences_produce_identical_records(self) -> None:
        def run() -> str:
            lifecycle = manager(max_steps=3, max_recovery_attempts=1)
            lifecycle.begin("INC-1")
            lifecycle.record_step()
            lifecycle.record_remediation_attempt("act-001")
            lifecycle.record_outcome(
                action(), execution_outcome="FAILED", verification_status="FAILED"
            )
            return to_json(lifecycle.finish(final_state=IncidentState.DEGRADED, detail="stop"))

        assert run() == run()

    def test_the_deadline_uses_the_injected_clock(self) -> None:
        lifecycle = LifecycleManager(
            limits=LifecycleLimits(max_wall_clock_seconds=60.0),
            breaker=CircuitBreaker(clock=fixed_clock),
            clock=fixed_clock,
        )
        lifecycle.begin("INC-1")
        # A frozen clock never advances, so the deadline never trips.
        assert not lifecycle.may_continue(IncidentState.INVESTIGATING).stopped

    def test_a_breaker_is_shared_across_incidents(self) -> None:
        breaker = CircuitBreaker(CircuitBreakerConfig(), clock=fixed_clock)
        lifecycle = LifecycleManager(breaker=breaker, clock=fixed_clock)
        subject = action()
        key = lifecycle.scope_for(subject)
        for incident in ("INC-1", "INC-2", "INC-3"):
            lifecycle.begin(incident)
            lifecycle.record_outcome(
                subject, execution_outcome="FAILED", verification_status="VERIFIED"
            )
        assert breaker.state_of(key) is CircuitState.OPEN
