"""Lifecycle counters, decisions and stop records.

Everything is frozen. Advancing a counter produces a new :class:`LifecycleCounters`, so an
incident's lifecycle history is a chain of values and no step can quietly rewrite an
earlier one — the same discipline the Commander context already follows.

The counters are the interesting part. A retry that could reset a security counter would
mean the counter measured nothing, so the ``after_*`` methods below are deliberately
asymmetric: failures accumulate, and only a *verified* success clears
``consecutive_failures``. There is no method that decrements anything.
"""

from __future__ import annotations

from enum import StrEnum

from aegis.core.domain import DomainModel, Identifier, IncidentState, NonEmptyStr, Timestamp
from aegis.lifecycle.limits import LifecycleLimits
from aegis.lifecycle.state import BreakerSnapshot, LifecycleCounters

__all__ = [
    "LifecycleAction",
    "LifecycleCounters",
    "LifecycleDecision",
    "LifecycleRecord",
    "StopReason",
]


class StopReason(StrEnum):
    """Why the lifecycle stopped. Closed, so no stop is unexplained (Part 9)."""

    NOT_STOPPED = "NOT_STOPPED"
    """The lifecycle may continue. Present so "still running" is a value, not an absence."""

    TERMINAL_STATE = "TERMINAL_STATE"
    """The incident reached RESOLVED or ESCALATED. Nothing further may happen."""

    STEP_BUDGET_EXHAUSTED = "STEP_BUDGET_EXHAUSTED"
    REMEDIATION_BUDGET_EXHAUSTED = "REMEDIATION_BUDGET_EXHAUSTED"
    RECOVERY_BUDGET_EXHAUSTED = "RECOVERY_BUDGET_EXHAUSTED"
    CONSECUTIVE_FAILURES = "CONSECUTIVE_FAILURES"
    EXECUTION_BUDGET_EXHAUSTED = "EXECUTION_BUDGET_EXHAUSTED"
    FINGERPRINT_BUDGET_EXHAUSTED = "FINGERPRINT_BUDGET_EXHAUSTED"
    """The same exact action has been executed as often as configuration permits."""

    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    CIRCUIT_OPEN = "CIRCUIT_OPEN"
    """The breaker refused. Automation stops; observation and audit continue."""


class LifecycleAction(StrEnum):
    """What the lifecycle manager tells the orchestrator to do next.

    Note what is absent: there is no ``EXECUTE``. The manager can stop things and can
    decline to stop them, but it never says "go ahead" — proceeding still requires passing
    assessment, policy, approval and execution authorization, none of which it can speak for.
    """

    CONTINUE = "CONTINUE"
    """Nothing in the lifecycle objects. Not permission — see above."""

    STOP = "STOP"
    """End the run at its current state, without escalating."""

    ESCALATE = "ESCALATE"
    """End the run by transitioning the incident to ESCALATED through the state machine."""


class LifecycleDecision(DomainModel):
    """One answer from the lifecycle manager, with everything needed to act and audit."""

    action: LifecycleAction
    stop_reason: StopReason = StopReason.NOT_STOPPED
    detail: NonEmptyStr
    counters: LifecycleCounters
    limit_name: NonEmptyStr | None = None
    """Which configured limit applied, when one did. Named so a reader does not have to
    infer which bound was hit from the counter values."""

    limit_value: int | None = None
    breaker: BreakerSnapshot | None = None

    @property
    def stopped(self) -> bool:
        return self.action is not LifecycleAction.CONTINUE

    @property
    def escalates(self) -> bool:
        return self.action is LifecycleAction.ESCALATE


class LifecycleRecord(DomainModel):
    """The structured account of why one lifecycle ended (Part 9).

    A record rather than a log line, because "why did automation stop" is a question a
    security investigator asks months later, and prose in a console is not an answer.
    """

    incident_id: Identifier
    final_state: IncidentState
    stop_reason: StopReason
    detail: NonEmptyStr
    counters: LifecycleCounters
    limits: LifecycleLimits
    limit_name: NonEmptyStr | None = None
    limit_value: int | None = None
    breaker: BreakerSnapshot | None = None
    escalation_reason: NonEmptyStr | None = None
    started_at: Timestamp
    completed_at: Timestamp

    @property
    def elapsed_seconds(self) -> float:
        return max((self.completed_at - self.started_at).total_seconds(), 0.0)
