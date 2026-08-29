"""Lifecycle limits and counters: explicit, immutable, and monotonic.

A limit that a retry could raise, or a counter a retry could clear, would measure nothing.
Most of this file is about the second half of that sentence.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.core.domain import to_json
from aegis.lifecycle import (
    DEFAULT_BREAKER_CONFIG,
    DEFAULT_LIFECYCLE_LIMITS,
    BreakerScope,
    CircuitBreakerConfig,
    InvalidLifecycleConfiguration,
    LifecycleCounters,
    LifecycleLimits,
)


class TestLimitsAreExplicit:
    def test_every_limit_has_a_conservative_default(self) -> None:
        limits = DEFAULT_LIFECYCLE_LIMITS
        assert limits.max_steps == 8
        assert limits.max_remediation_attempts == 3
        assert limits.max_recovery_attempts == 2
        assert limits.max_consecutive_failures == 3
        assert limits.max_executions == 3
        assert limits.max_executions_per_fingerprint == 2

    def test_the_recovery_budget_is_tighter_than_the_remediation_budget(self) -> None:
        # Recovery is the loop that most easily becomes perpetual.
        limits = DEFAULT_LIFECYCLE_LIMITS
        assert limits.max_recovery_attempts < limits.max_remediation_attempts

    def test_limits_are_frozen(self) -> None:
        with pytest.raises(ValidationError):
            DEFAULT_LIFECYCLE_LIMITS.max_steps = 999  # type: ignore[misc]

    def test_limits_reject_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            LifecycleLimits(max_steps=4, unlimited=True)

    def test_limits_serialize_canonically(self) -> None:
        limits = LifecycleLimits(max_steps=4)
        assert to_json(limits) == to_json(limits.model_copy())

    @pytest.mark.parametrize(
        "field",
        [
            "max_steps",
            "max_remediation_attempts",
            "max_recovery_attempts",
            "max_consecutive_failures",
            "max_executions",
            "max_executions_per_fingerprint",
        ],
    )
    def test_a_limit_of_zero_is_rejected(self, field: str) -> None:
        # Zero means "never allowed to start", which is a configuration error rather than
        # a very strict policy.
        with pytest.raises(ValidationError):
            LifecycleLimits(**{field: 0})

    @pytest.mark.parametrize(
        "field",
        ["max_steps", "max_remediation_attempts", "max_executions"],
    )
    def test_a_negative_limit_is_rejected(self, field: str) -> None:
        with pytest.raises(ValidationError):
            LifecycleLimits(**{field: -1})

    def test_there_is_no_unlimited_sentinel(self) -> None:
        # No field accepts None-meaning-infinite except the optional deadline, which is
        # safe because every other bound is finite.
        fields = LifecycleLimits.model_fields
        optional = {name for name, f in fields.items() if f.default is None}
        assert optional == {"max_wall_clock_seconds"}

    def test_a_recovery_budget_that_cannot_be_reached_is_refused(self) -> None:
        with pytest.raises(InvalidLifecycleConfiguration, match="could never be reached"):
            LifecycleLimits(max_steps=2, max_recovery_attempts=5)

    def test_a_deadline_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            LifecycleLimits(max_wall_clock_seconds=0.0)


class TestBreakerConfig:
    def test_thresholds_are_per_failure_class(self) -> None:
        config = DEFAULT_BREAKER_CONFIG
        assert config.execution_failure_threshold == 3
        assert config.verification_failure_threshold == 3
        assert config.stale_verification_threshold == 3
        assert config.mismatch_threshold == 2

    def test_a_governance_anomaly_trips_on_the_first_occurrence(self) -> None:
        # Every other threshold tolerates bad luck. This one describes something that
        # should be unreachable, so one occurrence is already the strongest signal.
        assert DEFAULT_BREAKER_CONFIG.governance_anomaly_threshold == 1

    def test_the_default_scope_is_capability_and_resource(self) -> None:
        assert DEFAULT_BREAKER_CONFIG.scope is BreakerScope.CAPABILITY_RESOURCE

    def test_thresholds_are_configurable(self) -> None:
        config = CircuitBreakerConfig(execution_failure_threshold=7)
        assert config.execution_failure_threshold == 7

    def test_a_threshold_of_zero_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CircuitBreakerConfig(execution_failure_threshold=0)

    def test_half_open_cannot_be_configured_to_allow_two_probes(self) -> None:
        # "Half-open allows two probes" is not a configuration a deployment can express.
        with pytest.raises(ValidationError):
            CircuitBreakerConfig(half_open_probes=2)

    def test_the_config_is_frozen(self) -> None:
        with pytest.raises(ValidationError):
            DEFAULT_BREAKER_CONFIG.execution_failure_threshold = 99  # type: ignore[misc]


class TestCountersOnlyEverRise:
    def test_counters_start_at_zero(self) -> None:
        counters = LifecycleCounters()
        assert counters.steps_used == 0
        assert counters.remediation_attempts == 0
        assert counters.consecutive_failures == 0
        assert counters.execution_count == 0

    def test_advancing_produces_a_new_frozen_value(self) -> None:
        first = LifecycleCounters()
        second = first.after_step()
        assert first.steps_used == 0
        assert second.steps_used == 1
        with pytest.raises(ValidationError):
            second.steps_used = 99  # type: ignore[misc]

    def test_a_remediation_attempt_counts_whether_or_not_it_succeeded(self) -> None:
        # Attempts, not failures: a denied proposal still reached for production.
        counters = LifecycleCounters().after_remediation_attempt("act-1")
        assert counters.remediation_attempts == 1
        assert counters.last_action_id == "act-1"

    def test_only_a_verified_success_clears_consecutive_failures(self) -> None:
        counters = LifecycleCounters().after_failure().after_failure()
        assert counters.consecutive_failures == 2
        assert counters.after_success().consecutive_failures == 0

    def test_success_does_not_refund_any_other_budget(self) -> None:
        # Doing something successfully once does not buy back the budget for doing it again.
        counters = (
            LifecycleCounters()
            .after_step()
            .after_remediation_attempt()
            .after_recovery()
            .after_execution("fp")
            .after_failure()
        )
        cleared = counters.after_success()
        assert cleared.consecutive_failures == 0
        assert cleared.steps_used == 1
        assert cleared.remediation_attempts == 1
        assert cleared.recovery_attempts == 1
        assert cleared.execution_count == 1
        assert cleared.executions_of("fp") == 1

    def test_no_counter_method_decrements_anything(self) -> None:
        # after_success is the only method that lowers a value, and only that one field.
        counters = LifecycleCounters(
            steps_used=5,
            remediation_attempts=4,
            recovery_attempts=3,
            consecutive_failures=2,
            execution_count=6,
        )
        methods = (
            "after_step",
            "after_remediation_attempt",
            "after_recovery",
            "after_failure",
        )
        fields = (
            "steps_used",
            "remediation_attempts",
            "recovery_attempts",
            "execution_count",
        )
        for method in methods:
            advanced = getattr(counters, method)()
            for field in fields:
                assert getattr(advanced, field) >= getattr(counters, field)

    def test_executions_are_counted_per_fingerprint(self) -> None:
        counters = (
            LifecycleCounters().after_execution("aaa").after_execution("aaa").after_execution("bbb")
        )
        assert counters.executions_of("aaa") == 2
        assert counters.executions_of("bbb") == 1
        assert counters.execution_count == 3

    def test_an_unseen_fingerprint_has_no_executions(self) -> None:
        assert LifecycleCounters().executions_of("never-seen") == 0
