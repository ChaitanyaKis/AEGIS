"""Explicit, immutable lifecycle limits and breaker thresholds.

Every bound AEGIS enforces on automated incident handling is declared here, as a frozen
model with a named field. Nothing is a magic number buried in a loop, nothing defaults to
"unlimited", and there is no code path that raises a limit at runtime.

Why that matters beyond tidiness
--------------------------------

Limits are the only thing standing between a confused agent and an unbounded retry loop
against production. If a limit could be adjusted by anything the model produces, it would
not be a limit — it would be a suggestion. These models are constructed by the operator who
wires the orchestrator and are never reachable from model output: a
:class:`~aegis.agents.decisions.CommanderDecision` has no field that names one, and the
orchestrator never copies model content into a configuration object.

Defaults are deliberately conservative. A system that stops too early escalates to a human;
a system that stops too late has already done the damage.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from aegis.core.domain import DomainModel
from aegis.lifecycle.errors import InvalidLifecycleConfiguration

__all__ = [
    "DEFAULT_BREAKER_CONFIG",
    "DEFAULT_LIFECYCLE_LIMITS",
    "BreakerScope",
    "CircuitBreakerConfig",
    "LifecycleLimits",
]


class BreakerScope(StrEnum):
    """What a breaker's counters are keyed by (Part 17).

    The trade-off is stated once here rather than rediscovered per deployment. Too wide and
    one bad incident disables unrelated safe automation; too narrow and repeated failures
    against the same dangerous capability never accumulate into a signal.
    """

    CAPABILITY_RESOURCE = "CAPABILITY_RESOURCE"
    """``capability@resource`` — the default, and the smallest scope that still
    accumulates.

    Repeated rollback failures against payment-api open the breaker for *that* pairing.
    A rollback of order-service is untouched, and so is a scale of payment-api. Failures
    persist across incidents, which is the point: three separate incidents each failing
    once against the same capability and resource is exactly the pattern a per-incident
    scope would miss.
    """

    CAPABILITY = "CAPABILITY"
    """``capability`` — every resource. Wider: use when a capability itself is suspect."""

    RESOURCE = "RESOURCE"
    """``resource`` — every capability. Use when one service is known to be unstable."""

    INCIDENT = "INCIDENT"
    """``incident`` — narrowest. Cannot accumulate across incidents, so it protects a
    single runaway incident and nothing else. Never the default for that reason."""

    GLOBAL = "GLOBAL"
    """One breaker for all automation. Available deliberately, because a governance
    anomaly may warrant stopping everything — but it is the blast radius of a mistake,
    so it is never the default."""


class LifecycleLimits(DomainModel):
    """Every bound on one incident's automated handling.

    All fields are ``ge=1``: a limit of zero would mean "never allowed to start", which is
    a configuration error rather than a very strict policy, and is rejected as one.
    """

    max_steps: int = Field(default=8, ge=1)
    """Commander decisions one incident may consume. The outer bound on everything."""

    max_remediation_attempts: int = Field(default=3, ge=1)
    """Distinct remediation proposals taken through governance, successful or not.

    Counts *attempts*, not failures: a proposal that policy denied still used one, because
    the cost being bounded is the number of times automation reaches for production.
    """

    max_recovery_attempts: int = Field(default=2, ge=1)
    """Times a degraded incident may re-enter investigation.

    Lower than the remediation budget on purpose. Recovery is the loop that most easily
    becomes perpetual, and each pass through it also spends a remediation attempt.
    """

    max_consecutive_failures: int = Field(default=3, ge=1)
    """Back-to-back failed remediations before the lifecycle escalates.

    Reset only by a *verified* success — see :meth:`LifecycleCounters.after_success`.
    Nothing else clears it, because a counter that a retry could reset would count nothing.
    """

    max_executions: int = Field(default=3, ge=1)
    """Executions attempted against the enterprise for this incident, in total."""

    max_executions_per_fingerprint: int = Field(default=2, ge=1)
    """Executions of the *same exact action*, by canonical fingerprint.

    Separate from ``max_executions`` because repeating one identical failing action is a
    different pathology from trying several different things, and deserves a tighter bound.
    """

    max_wall_clock_seconds: float | None = Field(default=None, gt=0.0)
    """Optional deadline, measured on the injected clock.

    ``None`` means no deadline, which is safe here because every other bound is finite —
    the lifecycle terminates on step count regardless. Offered for deployments where a
    slow external dependency could make a bounded run still take too long.
    """

    @model_validator(mode="after")
    def _recovery_fits_within_steps(self) -> LifecycleLimits:
        """A recovery budget larger than the step budget cannot be reached.

        Not a safety problem — the step bound still holds — but it is a configuration that
        does not mean what its author thinks, so it is refused rather than silently capped.
        """
        if self.max_recovery_attempts > self.max_steps:
            raise InvalidLifecycleConfiguration(
                f"max_recovery_attempts ({self.max_recovery_attempts}) exceeds max_steps "
                f"({self.max_steps}); the recovery budget could never be reached"
            )
        return self


class CircuitBreakerConfig(DomainModel):
    """Thresholds at which repeated trouble opens the breaker.

    Every failure class is counted and thresholded separately (Part 21). Collapsing them
    would destroy the diagnostic value of the count: "three execution failures" and "three
    stale telemetry readings" call for very different responses, and a single combined
    counter could open on a mixture that means nothing in particular.
    """

    execution_failure_threshold: int = Field(default=3, ge=1)
    """Executions that failed or were blocked by the enterprise."""

    verification_failure_threshold: int = Field(default=3, ge=1)
    """Verifications that ran and established the expected state was *not* reached."""

    stale_verification_threshold: int = Field(default=3, ge=1)
    """Verifications that could not establish anything because evidence was too old.

    Kept apart from a real failure: stale telemetry says the observation pipeline is
    unhealthy, not that the remediation did not work.
    """

    mismatch_threshold: int = Field(default=2, ge=1)
    """Verifications where sources disagreed. Tighter, because contradictory observations
    mean the picture of the enterprise is not trustworthy."""

    governance_anomaly_threshold: int = Field(default=1, ge=1)
    """Impossible states — execution with no authorization, an audit chain that does not
    verify, an approval bound to a different action.

    Defaults to **one**. Every other threshold tolerates a run of bad luck; this one
    describes something that should be unreachable, so a single occurrence is already the
    strongest signal the system can produce (Part 13).
    """

    scope: BreakerScope = BreakerScope.CAPABILITY_RESOURCE
    """What counters are keyed by. See :class:`BreakerScope` for the trade-off."""

    probe_cooldown_seconds: float | None = Field(default=300.0, gt=0.0)
    """How long an OPEN breaker waits before one probe becomes eligible.

    Five minutes by default: long enough that a transient upstream problem has a chance to
    clear, short enough that a recovered path is not stranded until someone notices. The
    cooldown is measured on the injected clock, so a run is reproducible.

    ``None`` means never automatically eligible — an operator must call ``allow_probe``.
    A legitimate configuration for a capability nobody wants retried unattended, so it is
    expressible rather than assumed away.
    """

    half_open_probes: int = Field(default=1, ge=1, le=1)
    """Probes permitted in HALF_OPEN. Fixed at one and bounded by the type.

    ``le=1`` rather than a runtime check: "half-open allows two probes" should not be a
    configuration a deployment can express, so it is not a value the model accepts.
    """


DEFAULT_LIFECYCLE_LIMITS = LifecycleLimits()
"""The limits used when a caller does not supply any. Conservative by construction."""

DEFAULT_BREAKER_CONFIG = CircuitBreakerConfig()
"""The thresholds used when a caller does not supply any."""
