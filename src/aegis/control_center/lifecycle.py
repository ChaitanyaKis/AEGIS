"""Why automation stopped, and what the breaker is doing about it.

Parts 9 and 10. Two views, both strictly read-only, and both careful about one thing: an
unreadable source is ``UNKNOWN``, never a comfortable default.

That matters more here than anywhere else in the package. A lifecycle whose persisted state
could not be read is not a lifecycle that is fine, and a breaker whose state is unavailable
is emphatically not ``CLOSED``. AEGIS fails closed by design; a control center that
rendered *unavailable* as *open for business* would invert the property the whole system is
built on (Part 16).

There is no control here
------------------------

No ``reset``, no ``force_open``, no ``force_close``, no ``extend_budget``. Not because they
are guarded, but because they do not exist: this module builds frozen values out of frozen
values. The only way breaker state changes remains the existing lifecycle mechanism.
"""

from __future__ import annotations

from pydantic import Field

from aegis.control_center.capture import ControlCenterInput
from aegis.control_center.models import (
    Completeness,
    Fact,
    Provenance,
    Tri,
    ViewSource,
)
from aegis.core.domain import DomainModel, NonEmptyStr, Timestamp

__all__ = ["BreakerView", "LifecycleView", "build_breakers", "build_lifecycle"]


class LifecycleView(DomainModel):
    """Counters, limits and why automation stopped. Displayed; never adjustable."""

    incident_id: NonEmptyStr
    final_state: Fact
    stop_reason: Fact
    """One of the closed ``StopReason`` values. ``NOT_STOPPED`` is itself a value, so
    "still running" is stated rather than implied by an absence."""

    stop_detail: Fact
    limit_name: Fact
    limit_value: int | None = None

    steps_used: int | None = None
    remediation_attempts: int | None = None
    recovery_attempts: int | None = None
    execution_count: int | None = None
    consecutive_failures: int | None = None
    executions_by_fingerprint: tuple[tuple[NonEmptyStr, int], ...] = Field(default_factory=tuple)
    """Per-fingerprint execution counts, sorted. ``None``-vs-empty matters: an empty tuple
    with counters present means nothing executed, while a view with every counter ``None``
    means the record could not be read."""

    escalation_reason: Fact
    started_at: Timestamp | None = None
    completed_at: Timestamp | None = None
    elapsed_seconds: float | None = None
    breaker: NonEmptyStr | None = None
    """The breaker scope named by the lifecycle record, when one was."""

    stopped: Tri = Tri.UNKNOWN
    provenance: Provenance

    def __repr__(self) -> str:
        return (
            f"LifecycleView({self.incident_id} {self.stop_reason.value} {self.final_state.value})"
        )


def build_lifecycle(data: ControlCenterInput) -> LifecycleView:
    """The lifecycle record as a view, or an honestly empty one.

    Every counter is ``None`` when no record was produced. A zero would be a claim -- "no
    steps were used" -- and a crashed run used steps that nobody counted.
    """
    record = getattr(data.run, "lifecycle", None) if data.run is not None else None
    if record is None or not data.lifecycle_available:
        return LifecycleView(
            incident_id=data.incident_id,
            final_state=Fact.unknown(),
            stop_reason=Fact.unknown(),
            stop_detail=Fact.unknown(),
            limit_name=Fact.unknown(),
            escalation_reason=Fact.unknown(),
            stopped=Tri.UNKNOWN,
            provenance=Provenance.unavailable(
                data.captured_at,
                "no lifecycle record was captured; counters and stop reason are unknown",
            ),
        )

    counters = record.counters
    return LifecycleView(
        incident_id=str(record.incident_id),
        final_state=Fact.observed(record.final_state, str(record.incident_id)),
        stop_reason=Fact.observed(record.stop_reason, str(record.incident_id)),
        stop_detail=Fact.observed(record.detail),
        limit_name=Fact.observed(record.limit_name) if record.limit_name else Fact.unknown(),
        limit_value=record.limit_value,
        steps_used=counters.steps_used,
        remediation_attempts=counters.remediation_attempts,
        recovery_attempts=counters.recovery_attempts,
        execution_count=counters.execution_count,
        consecutive_failures=counters.consecutive_failures,
        executions_by_fingerprint=tuple(sorted(counters.executions_by_fingerprint.items())),
        escalation_reason=(
            Fact.observed(record.escalation_reason) if record.escalation_reason else Fact.unknown()
        ),
        started_at=record.started_at,
        completed_at=record.completed_at,
        elapsed_seconds=record.elapsed_seconds,
        breaker=record.breaker.scope_key if record.breaker is not None else None,
        stopped=Tri.of(record.stop_reason.value != "NOT_STOPPED"),
        provenance=Provenance(
            source=ViewSource.LIFECYCLE_STATE,
            as_of=data.captured_at,
            completeness=Completeness.COMPLETE,
        ),
    )


class BreakerView(DomainModel):
    """One breaker scope, as an operator needs to see it.

    ``state`` is a :class:`~aegis.control_center.models.Fact` rather than a bare enum so
    that an unreadable breaker reports ``UNKNOWN``. A ``CircuitState`` field would have had
    to hold *something*, and whatever that something was would have been a lie.
    """

    scope_key: NonEmptyStr
    state: Fact
    """CLOSED, OPEN or HALF_OPEN -- the three the operator must be able to tell apart."""

    opened_at: Timestamp | None = None
    opened_reason: Fact
    trip_class: Fact
    failure_counts: tuple[tuple[NonEmptyStr, int], ...] = Field(default_factory=tuple)
    probe_in_flight: Tri = Tri.UNKNOWN
    consecutive_probe_failures: int | None = None
    probe_eligible_at: Timestamp | None = None
    """When a probe becomes permissible. Shown so an operator can see *when* automation
    will try again rather than inferring it from a threshold and a log line."""

    half_open_eligible: Tri = Tri.UNKNOWN
    quarantined: Tri = Tri.UNKNOWN
    """Set when the breaker was built over state it could not verify. Not the same as OPEN,
    and worth its own field: one is a decision, the other is an admission."""

    provenance: Provenance

    @property
    def open(self) -> Tri:
        """Whether automation is currently blocked for this scope."""
        if not self.state.known:
            return Tri.UNKNOWN
        return Tri.of(self.state.value == "OPEN")

    def __repr__(self) -> str:
        return f"BreakerView({self.scope_key}={self.state.value})"


def build_breakers(data: ControlCenterInput) -> tuple[BreakerView, ...]:
    """One view per captured breaker scope, sorted by scope key.

    When the lifecycle source was unavailable this returns an empty tuple **and** the
    projection reports the source as unknown -- the caller must not read "no breakers" as
    "no breaker is open". :class:`~aegis.control_center.projection.IncidentProjection`
    carries that distinction; see its ``breaker_state`` helper.
    """
    if not data.lifecycle_available:
        return ()
    provenance = Provenance(
        source=ViewSource.BREAKER,
        as_of=data.captured_at,
        completeness=Completeness.COMPLETE,
    )
    views = [
        BreakerView(
            scope_key=snapshot.scope_key,
            state=Fact.observed(snapshot.state, snapshot.scope_key),
            opened_at=snapshot.opened_at,
            opened_reason=(
                Fact.observed(snapshot.opened_reason) if snapshot.opened_reason else Fact.unknown()
            ),
            trip_class=(
                Fact.observed(snapshot.trip_class) if snapshot.trip_class else Fact.unknown()
            ),
            failure_counts=tuple(sorted(snapshot.counts.items())),
            probe_in_flight=Tri.of(snapshot.probe_in_flight),
            consecutive_probe_failures=snapshot.consecutive_probe_failures,
            probe_eligible_at=snapshot.probe_eligible_at,
            half_open_eligible=Tri.of(snapshot.state.value == "HALF_OPEN"),
            quarantined=Tri.of(snapshot.quarantined),
            provenance=provenance,
        )
        for snapshot in data.breakers
    ]
    return tuple(sorted(views, key=lambda view: view.scope_key))
