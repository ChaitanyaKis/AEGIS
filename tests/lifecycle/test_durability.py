"""Lifecycle state survives a restart, and a restart never reopens automation.

The weakness this closes: a Prompt 12 breaker died with its process, so a restart loop
silently re-closed every breaker and zeroed every count. A restart is exactly when a broken
system would most like to forget it was broken.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aegis.lifecycle import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    CorruptionPolicy,
    FailureClass,
    InMemoryLifecycleState,
    JsonlLifecycleState,
    LifecycleLimits,
    LifecycleManager,
    LifecycleStateCorrupt,
    LifecycleStatePersistence,
    verify_state_chain,
)

ROLLBACK = "production.rollback"
PAYMENT = "service:payment-api"
START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


class Clock:
    """An advanceable clock. Injected, so cooldowns are deterministic."""

    def __init__(self, at: datetime = START) -> None:
        self.now = at

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store() -> InMemoryLifecycleState:
    return InMemoryLifecycleState()


def breaker(store, clock, **config) -> CircuitBreaker:
    return CircuitBreaker(CircuitBreakerConfig(**config), clock=clock, persistence=store)


def key(b: CircuitBreaker) -> str:
    return b.key_for(capability=ROLLBACK, resource=PAYMENT)


def trip(b: CircuitBreaker, k: str, times: int = 3) -> None:
    for _ in range(times):
        b.record(k, FailureClass.EXECUTION_FAILURE, reason="the rollback failed")


class TestBreakerStateSurvivesRestart:
    def test_an_open_breaker_is_still_open_after_restart(self, store, clock) -> None:
        first = breaker(store, clock)
        k = key(first)
        trip(first, k)
        assert first.state_of(k) is CircuitState.OPEN

        restarted = breaker(store, clock)
        assert restarted.state_of(k) is CircuitState.OPEN
        assert not restarted.check(k).allowed

    def test_a_restart_does_not_silently_reopen_automation(self, store, clock) -> None:
        # The whole point. A restart loop must not be a way to clear a breaker.
        trip(breaker(store, clock), key(breaker(store, clock)))
        for _ in range(5):
            restarted = breaker(store, clock)
            assert restarted.state_of(key(restarted)) is CircuitState.OPEN

    def test_failure_counts_survive_restart(self, store, clock) -> None:
        first = breaker(store, clock)
        k = key(first)
        trip(first, k, times=2)
        restarted = breaker(store, clock)
        assert restarted.snapshot(k).counts == {"EXECUTION_FAILURE": 2}

    def test_a_partial_failure_run_continues_across_restart(self, store, clock) -> None:
        # Two failures before the restart plus one after must open it. Counting from zero
        # again would mean a restart bought three more attempts.
        first = breaker(store, clock)
        k = key(first)
        trip(first, k, times=2)
        restarted = breaker(store, clock)
        trip(restarted, k, times=1)
        assert restarted.state_of(k) is CircuitState.OPEN

    def test_scope_survives_restart(self, store, clock) -> None:
        first = breaker(store, clock)
        trip(first, key(first))
        restarted = breaker(store, clock)
        other = restarted.key_for(capability=ROLLBACK, resource="service:order-service")
        assert restarted.state_of(key(restarted)) is CircuitState.OPEN
        assert restarted.state_of(other) is CircuitState.CLOSED

    def test_the_failure_class_that_tripped_it_survives(self, store, clock) -> None:
        first = breaker(store, clock, mismatch_threshold=1)
        k = key(first)
        first.record(k, FailureClass.VERIFICATION_MISMATCH, reason="sources disagreed")
        restarted = breaker(store, clock)
        assert restarted.snapshot(k).trip_class is FailureClass.VERIFICATION_MISMATCH

    def test_trip_information_survives(self, store, clock) -> None:
        first = breaker(store, clock)
        k = key(first)
        trip(first, k)
        before = first.snapshot(k)
        after = breaker(store, clock).snapshot(k)
        assert after.opened_at == before.opened_at
        assert after.opened_reason == before.opened_reason

    def test_half_open_survives_restart(self, store, clock) -> None:
        first = breaker(store, clock, probe_cooldown_seconds=60.0)
        k = key(first)
        trip(first, k)
        clock.advance(61)
        assert first.check(k).is_probe
        restarted = breaker(store, clock)
        assert restarted.state_of(k) is CircuitState.HALF_OPEN
        # The probe was already taken; a restart must not hand out a second one.
        assert not restarted.check(k).allowed

    def test_probe_failure_count_survives(self, store, clock) -> None:
        first = breaker(store, clock, probe_cooldown_seconds=60.0)
        k = key(first)
        trip(first, k)
        clock.advance(61)
        first.check(k)
        first.record_probe_failure(k, reason="still failing")
        assert breaker(store, clock).snapshot(k).consecutive_probe_failures == 1

    def test_a_closed_breaker_stays_closed_after_restart(self, store, clock) -> None:
        first = breaker(store, clock)
        k = key(first)
        trip(first, k, times=1)
        assert breaker(store, clock).check(k).allowed


class TestLifecycleCountersSurviveRestart:
    def manager(self, store, clock) -> LifecycleManager:
        return LifecycleManager(
            limits=LifecycleLimits(max_steps=8),
            breaker=breaker(store, clock),
            clock=clock,
        )

    def test_step_and_attempt_counters_survive(self, store, clock) -> None:
        first = self.manager(store, clock)
        first.begin("INC-1")
        first.record_step()
        first.record_step()
        first.record_remediation_attempt("act-001")

        restarted = self.manager(store, clock)
        assert restarted.restore("INC-1")
        assert restarted.counters.steps_used == 2
        assert restarted.counters.remediation_attempts == 1
        assert restarted.counters.last_action_id == "act-001"

    def test_execution_counts_survive(self, store, clock) -> None:
        first = self.manager(store, clock)
        first.begin("INC-1")
        first.record_execution("fingerprint-a")
        first.record_execution("fingerprint-b")
        restarted = self.manager(store, clock)
        restarted.restore("INC-1")
        assert restarted.counters.execution_count == 2

    def test_fingerprint_counts_survive(self, store, clock) -> None:
        first = self.manager(store, clock)
        first.begin("INC-1")
        first.record_execution("same")
        first.record_execution("same")
        restarted = self.manager(store, clock)
        restarted.restore("INC-1")
        assert restarted.counters.executions_of("same") == 2

    def test_recovery_counts_survive(self, store, clock) -> None:
        first = self.manager(store, clock)
        first.begin("INC-1")
        first.record_recovery()
        restarted = self.manager(store, clock)
        restarted.restore("INC-1")
        assert restarted.counters.recovery_attempts == 1

    def test_consecutive_failures_survive(self, store, clock) -> None:
        from aegis.core.domain import RiskLevel
        from tests.fleet import build_action

        action = build_action(
            requesting_agent="remediation",
            capability=ROLLBACK,
            target_resource=PAYMENT,
            risk=RiskLevel.HIGH,
        )
        first = self.manager(store, clock)
        first.begin("INC-1")
        first.record_outcome(action, execution_outcome="FAILED", verification_status="FAILED")
        restarted = self.manager(store, clock)
        restarted.restore("INC-1")
        assert restarted.counters.consecutive_failures == 1

    def test_a_restarted_budget_is_not_refunded(self, store, clock) -> None:
        # The security property: an incident cannot buy more attempts by restarting.
        first = self.manager(store, clock)
        first.begin("INC-1")
        for _ in range(3):
            first.record_remediation_attempt()
        restarted = self.manager(store, clock)
        restarted.restore("INC-1")
        assert restarted.may_remediate().stopped

    def test_restoring_an_unknown_incident_reports_nothing_restored(self, store, clock) -> None:
        assert self.manager(store, clock).restore("INC-NEVER-SEEN") is False

    def test_counters_for_another_incident_are_not_restored(self, store, clock) -> None:
        first = self.manager(store, clock)
        first.begin("INC-1")
        first.record_step()
        restarted = self.manager(store, clock)
        assert restarted.restore("INC-2") is False


class TestMissingAndCorruptState:
    def test_missing_state_has_a_well_defined_initial_state(self, clock, tmp_path) -> None:
        # A file that does not exist reads as "nothing has happened yet".
        state = JsonlLifecycleState(tmp_path / "never-written.jsonl")
        fresh = CircuitBreaker(clock=clock, persistence=state)
        k = key(fresh)
        assert fresh.state_of(k) is CircuitState.CLOSED
        assert fresh.check(k).allowed
        assert fresh.verify_integrity().valid

    def test_a_corrupt_chain_refuses_to_construct(self, store, clock) -> None:
        first = breaker(store, clock)
        trip(first, key(first))
        records = list(store.load())
        # The OPENED record, flipped back to CLOSED — the tamper an attacker would want.
        store._records[2] = records[2].model_copy(update={"circuit_state": CircuitState.CLOSED})
        with pytest.raises(LifecycleStateCorrupt):
            CircuitBreaker(clock=clock, persistence=store)

    def test_a_corrupt_chain_can_instead_quarantine_and_refuse_everything(
        self, store, clock
    ) -> None:
        # Failing closed the other way: keep running, refuse all automation.
        first = breaker(store, clock)
        trip(first, key(first))
        records = list(store.load())
        store._records[0] = records[0].model_copy(update={"digest": "f" * 64})

        quarantined = CircuitBreaker(
            clock=clock, persistence=store, on_corruption=CorruptionPolicy.QUARANTINE
        )
        assert quarantined.quarantined
        decision = quarantined.check(key(quarantined))
        assert not decision.allowed
        assert "quarantined" in decision.reason

    def test_a_quarantined_breaker_refuses_every_scope(self, store, clock) -> None:
        first = breaker(store, clock)
        trip(first, key(first))
        records = list(store.load())
        store._records[0] = records[0].model_copy(update={"digest": "f" * 64})
        quarantined = CircuitBreaker(
            clock=clock, persistence=store, on_corruption=CorruptionPolicy.QUARANTINE
        )
        for resource in ("service:order-service", "service:auth", "db:customer-database"):
            other = quarantined.key_for(capability="production.scale", resource=resource)
            assert not quarantined.check(other).allowed

    def test_a_persistence_failure_never_produces_permission(self, clock) -> None:
        # A backend that raises on load must not leave the breaker open for business.
        class _Broken:
            def load(self):
                raise LifecycleStateCorrupt("the disk is gone")

            def append(self, record) -> None:
                raise LifecycleStateCorrupt("the disk is gone")

        with pytest.raises(LifecycleStateCorrupt):
            CircuitBreaker(clock=clock, persistence=_Broken())

        quarantined = CircuitBreaker(
            clock=clock, persistence=_Broken(), on_corruption=CorruptionPolicy.QUARANTINE
        )
        assert not quarantined.check("anything").allowed

    def test_an_unreadable_line_is_reported_not_skipped(self, clock, tmp_path) -> None:
        path = tmp_path / "state.jsonl"
        state = JsonlLifecycleState(path)
        first = CircuitBreaker(clock=clock, persistence=state)
        trip(first, key(first))
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"sequence": 3\n')  # truncated mid-append
        with pytest.raises(LifecycleStateCorrupt, match="damaged"):
            CircuitBreaker(clock=clock, persistence=state)


class TestFileBackedPersistence:
    def test_state_survives_a_genuinely_new_object_graph(self, clock, tmp_path) -> None:
        path = tmp_path / "state.jsonl"
        first = CircuitBreaker(clock=clock, persistence=JsonlLifecycleState(path))
        k = key(first)
        trip(first, k)

        # A second process would build everything from scratch, as this does.
        restarted = CircuitBreaker(clock=clock, persistence=JsonlLifecycleState(path))
        assert restarted.state_of(k) is CircuitState.OPEN

    def test_one_line_per_record(self, clock, tmp_path) -> None:
        path = tmp_path / "state.jsonl"
        b = CircuitBreaker(clock=clock, persistence=JsonlLifecycleState(path))
        trip(b, key(b), times=2)
        assert len(path.read_text(encoding="utf-8").strip().splitlines()) == 2

    def test_the_file_is_appended_never_rewritten(self, clock, tmp_path) -> None:
        path = tmp_path / "state.jsonl"
        b = CircuitBreaker(clock=clock, persistence=JsonlLifecycleState(path))
        k = key(b)
        b.record(k, FailureClass.EXECUTION_FAILURE, reason="one")
        first = path.read_text(encoding="utf-8")
        b.record(k, FailureClass.EXECUTION_FAILURE, reason="two")
        assert path.read_text(encoding="utf-8").startswith(first)

    def test_records_round_trip_byte_identically(self, clock, tmp_path) -> None:
        from aegis.core.domain import to_json

        path = tmp_path / "state.jsonl"
        state = JsonlLifecycleState(path)
        b = CircuitBreaker(clock=clock, persistence=state)
        trip(b, key(b), times=1)
        written = state.load()[0]
        assert to_json(written) == path.read_text(encoding="utf-8").strip()

    def test_the_chain_verifies_after_reopening(self, clock, tmp_path) -> None:
        path = tmp_path / "state.jsonl"
        b = CircuitBreaker(clock=clock, persistence=JsonlLifecycleState(path))
        trip(b, key(b))
        reopened = CircuitBreaker(clock=clock, persistence=JsonlLifecycleState(path))
        assert reopened.verify_integrity().valid


class TestThePersistenceInterfaceOffersNoRewrite:
    def test_the_protocol_is_exactly_load_and_append(self) -> None:
        # No backend can offer the breaker a way to rewrite history.
        assert set(LifecycleStatePersistence.__protocol_attrs__) == {"load", "append"}

    def test_no_implementation_exposes_a_mutating_method(self, tmp_path) -> None:
        for backend in (InMemoryLifecycleState(), JsonlLifecycleState(tmp_path / "s.jsonl")):
            for forbidden in ("update", "delete", "truncate", "reset", "clear", "write"):
                assert not hasattr(backend, forbidden), f"{backend!r}.{forbidden}"


class TestDeterminism:
    def test_two_identical_histories_produce_identical_chains(self) -> None:
        from aegis.core.domain import to_json

        def build() -> InMemoryLifecycleState:
            state = InMemoryLifecycleState()
            b = CircuitBreaker(clock=Clock(), persistence=state)
            trip(b, key(b))
            return state

        first, second = build(), build()
        assert [to_json(r) for r in first.load()] == [to_json(r) for r in second.load()]

    def test_the_chain_is_valid_for_a_full_probe_cycle(self, store, clock) -> None:
        b = breaker(store, clock, probe_cooldown_seconds=60.0)
        k = key(b)
        trip(b, k)
        clock.advance(61)
        b.check(k)
        b.record_probe_failure(k, reason="still broken")
        clock.advance(61)
        b.check(k)
        b.record_probe_success(k)
        report = verify_state_chain(store.load())
        assert report.valid, report.reason
        assert b.state_of(k) is CircuitState.CLOSED
