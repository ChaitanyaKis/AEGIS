"""Lifecycle and circuit-breaker errors.

Every refusal is a distinct type. A lifecycle stop is not an exceptional condition to be
smoothed over — it is the component doing its job — so the ordinary stopping path returns
a structured decision rather than raising. These exist for the cases where a *caller* has
misused the machinery, and for the one refusal that must be impossible to ignore.
"""

from __future__ import annotations

__all__ = [
    "CircuitOpen",
    "InvalidLifecycleConfiguration",
    "LifecycleError",
    "LifecycleGateRejected",
    "LifecycleStateCorrupt",
    "ProbeAlreadyInFlight",
]


class LifecycleError(Exception):
    """Base class for everything this package raises."""


class InvalidLifecycleConfiguration(LifecycleError):
    """Limits or thresholds that would not bound anything.

    Raised at construction rather than at the moment a bound fails to hold, so a
    misconfigured system cannot start and then discover it never stops.
    """


class CircuitOpen(LifecycleError):
    """An operation was attempted while the breaker was open.

    Raised only by callers that treat a refusal as fatal. The orchestrator does not: it
    asks :meth:`~aegis.lifecycle.circuit_breaker.CircuitBreaker.check` and routes the
    answer, because a blocked action must become a recorded stop, never an exception that
    something upstream might swallow into success.
    """

    def __init__(self, scope: str, reason: str) -> None:
        self.scope = scope
        self.reason = reason
        super().__init__(f"circuit breaker open for {scope}: {reason}")


class ProbeAlreadyInFlight(LifecycleError):
    """A second half-open probe was requested while one was outstanding.

    Half-open permits exactly one probe. Two concurrent probes would let a breaker that is
    meant to be testing the water take two swings at production instead.
    """

    def __init__(self, scope: str) -> None:
        self.scope = scope
        super().__init__(f"a half-open probe is already in flight for {scope}")


class LifecycleStateCorrupt(LifecycleError):
    """Persisted lifecycle state failed its integrity or legality check.

    Raised at load, and raising is itself the fail-closed behaviour: a process that cannot
    trust its own record of which breakers are open must not start as though every breaker
    were closed. A caller that must keep observing can construct the breaker with
    :data:`~aegis.lifecycle.circuit_breaker.CorruptionPolicy.QUARANTINE` instead, which
    refuses every scope rather than refusing to start.
    """

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"lifecycle state is not trustworthy: {detail}")


class LifecycleGateRejected(LifecycleError):
    """A lifecycle gate failed one of its bindings and cannot be consumed.

    Raised rather than returned, deliberately. An executor that ignored a returned refusal
    would execute anyway, and a refusal that can be ignored is not a boundary. The
    :class:`~aegis.lifecycle.gate.GateRejection` it carries names the exact binding that
    failed, so the refusal is auditable rather than merely fatal.
    """

    def __init__(self, rejection) -> None:
        self.rejection = rejection
        super().__init__(
            f"lifecycle gate {rejection.gate_id} rejected at {rejection.check}: {rejection.reason}"
        )
