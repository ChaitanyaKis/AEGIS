"""Durable lifecycle state: the record, the chain, and the legality of a transition.

Prompt 12 left the breaker correct but ephemeral — a restart silently re-closed every
breaker and zeroed every count, which meant a restart loop defeated it entirely. This
module is what makes lifecycle state survive a process and makes tampering with it visible.

Three properties, and the third is the one that is easy to miss.

**Durable.** Every state-affecting event is appended as a record carrying the resulting
state for its scope. Replaying the log rebuilds the breaker exactly.

**Tamper-evident.** Records are chained by SHA-256 over canonical JSON, the same
construction the audit and memory logs use. Modification, insertion, deletion and
reordering all break the chain, and the verifier reports where.

**Monotonic.** A chain that verifies is not automatically a chain that *means* what it
says. Appending an old ``CLOSED`` snapshot after an ``OPEN`` one produces a perfectly valid
chain describing an illegal history, and replaying it would close an open breaker — a blind
reset smuggled in through the persistence layer. So each record also names the
:class:`BreakerTransition` that produced it, and :func:`verify_state_chain` checks that
every transition is a legal edge from the previous state of that scope. ``CLOSED`` after
``OPEN`` is reachable only through ``PROBE_SUCCEEDED``.

Persisted state is historical evidence. It is never an authority to override the breaker.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from enum import StrEnum

from pydantic import Field

from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp, to_json
from aegis.lifecycle.conditions import FailureClass

__all__ = [
    "LIFECYCLE_GENESIS_DIGEST",
    "BreakerSnapshot",
    "BreakerTransition",
    "CircuitState",
    "LifecycleCounters",
    "LifecycleStateRecord",
    "StateIntegrityReport",
    "StateRecordKind",
    "legal_transition",
    "state_digest",
    "verify_state_chain",
]

LIFECYCLE_GENESIS_DIGEST = "0" * 64
"""The ``previous_digest`` of the first record. Fixed and documented, like the audit and
memory chains: the chain detects modification, it does not establish identity."""


class CircuitState(StrEnum):
    """The breaker's state. Closed and total.

    Lives here rather than in :mod:`aegis.lifecycle.circuit_breaker` because the persisted
    record needs it and the breaker needs the record — it is the shared vocabulary, so it
    belongs in the module both depend on. Re-exported from the breaker and the package for
    callers who expect it there.
    """

    CLOSED = "CLOSED"
    """Normal operation. The breaker objects to nothing."""

    OPEN = "OPEN"
    """Automation is blocked. Observation, audit and escalation continue."""

    HALF_OPEN = "HALF_OPEN"
    """One bounded probe may be attempted, through the full governance path."""


class StateRecordKind(StrEnum):
    """What a persisted record describes."""

    BREAKER = "BREAKER"
    """One scope's circuit state after an event."""

    COUNTERS = "COUNTERS"
    """One incident's lifecycle counters after an event."""


class BreakerTransition(StrEnum):
    """The event that produced a breaker record. Closed, and checked on load.

    This is what stops the persistence layer becoming a blind reset. Without it a valid
    chain could still describe ``OPEN`` followed by ``CLOSED`` with no probe in between,
    and replaying it would close a breaker that nothing had earned the right to close.
    """

    FAILURE_RECORDED = "FAILURE_RECORDED"
    """A classified failure was counted. Never closes anything."""

    SUCCESS_RECORDED = "SUCCESS_RECORDED"
    """A verified success cleared the counters for an already-closed scope."""

    OPENED = "OPENED"
    PROBE_PERMITTED = "PROBE_PERMITTED"
    """OPEN moved to HALF_OPEN because the cooldown elapsed and a probe was allowed."""

    PROBE_TAKEN = "PROBE_TAKEN"
    """The single half-open probe was consumed."""

    PROBE_SUCCEEDED = "PROBE_SUCCEEDED"
    """The only transition that may result in CLOSED from a non-closed state."""

    PROBE_FAILED = "PROBE_FAILED"
    COUNTERS_UPDATED = "COUNTERS_UPDATED"
    """A lifecycle-counter record. Carries no circuit state."""


_LEGAL: frozenset[tuple[BreakerTransition, CircuitState, CircuitState]] = frozenset(
    {
        # (transition, state before, state after) — explicit edges, not a cross product.
        #
        # Written out one edge at a time deliberately. An earlier version paired a set of
        # permitted starting states with a set of permitted results, which quietly made
        # OPEN -> CLOSED legal under FAILURE_RECORDED — the exact replay hole the
        # transition table exists to close. A cross product is not a state machine.
        (BreakerTransition.FAILURE_RECORDED, CircuitState.CLOSED, CircuitState.CLOSED),
        (BreakerTransition.FAILURE_RECORDED, CircuitState.CLOSED, CircuitState.OPEN),
        (BreakerTransition.FAILURE_RECORDED, CircuitState.OPEN, CircuitState.OPEN),
        (BreakerTransition.FAILURE_RECORDED, CircuitState.HALF_OPEN, CircuitState.HALF_OPEN),
        (BreakerTransition.FAILURE_RECORDED, CircuitState.HALF_OPEN, CircuitState.OPEN),
        (BreakerTransition.SUCCESS_RECORDED, CircuitState.CLOSED, CircuitState.CLOSED),
        (BreakerTransition.OPENED, CircuitState.CLOSED, CircuitState.OPEN),
        (BreakerTransition.OPENED, CircuitState.HALF_OPEN, CircuitState.OPEN),
        (BreakerTransition.PROBE_PERMITTED, CircuitState.OPEN, CircuitState.HALF_OPEN),
        (BreakerTransition.PROBE_TAKEN, CircuitState.HALF_OPEN, CircuitState.HALF_OPEN),
        (BreakerTransition.PROBE_SUCCEEDED, CircuitState.HALF_OPEN, CircuitState.CLOSED),
        (BreakerTransition.PROBE_FAILED, CircuitState.HALF_OPEN, CircuitState.OPEN),
    }
)
"""Every legal edge in the persisted state machine.

Exactly one edge results in ``CLOSED`` from a non-closed state:
``(PROBE_SUCCEEDED, HALF_OPEN, CLOSED)``. That single line is what makes "a breaker can
only be closed by a probe that verified" a property of the *stored history* and not merely
of the running code — a log that claims otherwise is refused on load.
"""


def legal_transition(
    transition: BreakerTransition,
    *,
    previous: CircuitState,
    resulting: CircuitState,
) -> bool:
    """Whether one recorded transition is a legal edge.

    Used on load rather than on write, deliberately: a writer that had been compromised
    would happily record whatever it liked, so the check that matters is the one performed
    by the reader against the chain it was handed.
    """
    return (transition, previous, resulting) in _LEGAL


class BreakerSnapshot(DomainModel):
    """The breaker's public state: a frozen value, safe to hand anywhere.

    Handing out a snapshot rather than the breaker itself is deliberate. A caller that held
    the live object could call ``record_probe_success``; a caller holding this can read the
    state and nothing else. It is what travels into run results, audit correlation and
    evaluation observations.
    """

    scope_key: NonEmptyStr
    state: CircuitState
    opened_at: Timestamp | None = None
    opened_reason: NonEmptyStr | None = None
    trip_class: FailureClass | None = None
    """Which failure class crossed its threshold. Kept so an investigator does not have to
    infer why the breaker opened from the counts."""

    counts: Mapping[str, int] = Field(default_factory=dict)
    """Failures by class, for the scope. Diagnostic; never re-thresholded by a reader."""

    probe_in_flight: bool = False
    consecutive_probe_failures: int = Field(default=0, ge=0)
    probe_eligible_at: Timestamp | None = None
    """When the cooldown elapses and a probe may be permitted. ``None`` while closed.

    Reported so an operator can see *when* automation will try again, rather than having
    to infer it from a threshold and a log timestamp.
    """

    quarantined: bool = False
    """Set when the breaker was constructed over state it could not verify. Every scope
    refuses while this is true."""

    @property
    def blocks_execution(self) -> bool:
        """Whether the breaker currently refuses production work.

        HALF_OPEN does not block: it permits exactly one probe, and the probe is a real
        governed execution. The single-probe bound lives in :meth:`CircuitBreaker.check`,
        not here, because a snapshot must not be able to authorize a second one.
        """
        return self.state is CircuitState.OPEN


class LifecycleCounters(DomainModel):
    """Everything the lifecycle counts about one incident. Frozen; only ever increases."""

    steps_used: int = Field(default=0, ge=0)
    remediation_attempts: int = Field(default=0, ge=0)
    recovery_attempts: int = Field(default=0, ge=0)
    consecutive_failures: int = Field(default=0, ge=0)
    execution_count: int = Field(default=0, ge=0)
    executions_by_fingerprint: dict[str, int] = Field(default_factory=dict)
    last_action_id: Identifier | None = None
    last_verification_id: Identifier | None = None

    def after_step(self) -> LifecycleCounters:
        return self.model_copy(update={"steps_used": self.steps_used + 1})

    def after_remediation_attempt(self, action_id: str | None = None) -> LifecycleCounters:
        """Count a remediation attempt, successful or not.

        Attempts rather than failures: a proposal policy denied still reached for
        production, and that is the cost being bounded.
        """
        return self.model_copy(
            update={
                "remediation_attempts": self.remediation_attempts + 1,
                "last_action_id": action_id or self.last_action_id,
            }
        )

    def after_recovery(self) -> LifecycleCounters:
        return self.model_copy(update={"recovery_attempts": self.recovery_attempts + 1})

    def after_execution(self, fingerprint: str) -> LifecycleCounters:
        by_fingerprint = dict(self.executions_by_fingerprint)
        by_fingerprint[fingerprint] = by_fingerprint.get(fingerprint, 0) + 1
        return self.model_copy(
            update={
                "execution_count": self.execution_count + 1,
                "executions_by_fingerprint": by_fingerprint,
            }
        )

    def after_failure(self, verification_id: str | None = None) -> LifecycleCounters:
        return self.model_copy(
            update={
                "consecutive_failures": self.consecutive_failures + 1,
                "last_verification_id": verification_id or self.last_verification_id,
            }
        )

    def after_success(self, verification_id: str | None = None) -> LifecycleCounters:
        """Clear the consecutive-failure run. **The only method that clears anything.**

        Reachable only from a verified remediation. Every other counter — attempts,
        recoveries, executions, per-fingerprint executions — is untouched, because those
        bound how much automation may *do*, and doing it successfully once does not buy
        back the budget.
        """
        return self.model_copy(
            update={
                "consecutive_failures": 0,
                "last_verification_id": verification_id or self.last_verification_id,
            }
        )

    def executions_of(self, fingerprint: str) -> int:
        return self.executions_by_fingerprint.get(fingerprint, 0)


class LifecycleStateRecord(DomainModel):
    """One persisted lifecycle event, with its chain digests.

    A single record type covers both breaker state and lifecycle counters. Two types would
    mean two chains or a tagged union in the digest payload; one type with a ``kind`` keeps
    a single ordered history, which is what makes "was this reordered" answerable at all.
    """

    sequence: int = Field(ge=0)
    kind: StateRecordKind
    recorded_at: Timestamp

    # --- breaker -------------------------------------------------------------------
    scope_key: NonEmptyStr | None = None
    transition: BreakerTransition | None = None
    circuit_state: CircuitState | None = None
    trip_class: FailureClass | None = None
    failure_counts: Mapping[str, int] = Field(default_factory=dict)
    opened_at: Timestamp | None = None
    opened_reason: NonEmptyStr | None = None
    probe_in_flight: bool = False
    consecutive_probe_failures: int = Field(default=0, ge=0)

    # --- counters ------------------------------------------------------------------
    incident_id: Identifier | None = None
    counters: LifecycleCounters | None = None

    previous_digest: str = Field(min_length=64, max_length=64)
    digest: str = Field(min_length=64, max_length=64)


class _DigestPayload(DomainModel):
    """Exactly the fields a lifecycle digest covers.

    A declared model rather than an ad-hoc dict, so adding or dropping a covered field is a
    visible code change with a test behind it. Everything the prompt requires be
    tamper-evident is here: state, counts, scope, failure class, sequence and the link.
    """

    circuit_state: CircuitState | None
    consecutive_probe_failures: int
    counters: LifecycleCounters | None
    failure_counts: Mapping[str, int]
    incident_id: NonEmptyStr | None
    kind: StateRecordKind
    opened_at: Timestamp | None
    opened_reason: NonEmptyStr | None
    previous_digest: str
    probe_in_flight: bool
    recorded_at: Timestamp
    scope_key: NonEmptyStr | None
    sequence: int = Field(ge=0)
    transition: BreakerTransition | None
    trip_class: FailureClass | None


def state_digest(record: LifecycleStateRecord) -> str:
    """The digest a record should carry, as 64 lowercase hex characters.

    Canonicalisation is the project's existing :func:`~aegis.core.domain.to_json` — sorted
    keys, compact separators, UTC ISO-8601 — so a record round-trips through a file without
    its integrity check changing. A structured document is hashed rather than concatenated
    strings, so no field value can be crafted to imitate a field boundary.
    """
    document = to_json(
        _DigestPayload(
            circuit_state=record.circuit_state,
            consecutive_probe_failures=record.consecutive_probe_failures,
            counters=record.counters,
            failure_counts=dict(sorted(record.failure_counts.items())),
            incident_id=record.incident_id,
            kind=record.kind,
            opened_at=record.opened_at,
            opened_reason=record.opened_reason,
            previous_digest=record.previous_digest,
            probe_in_flight=record.probe_in_flight,
            recorded_at=record.recorded_at,
            scope_key=record.scope_key,
            sequence=record.sequence,
            transition=record.transition,
            trip_class=record.trip_class,
        )
    )
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


class StateIntegrityReport(DomainModel):
    """The outcome of verifying a lifecycle chain.

    Reports; never repairs. A log that has been tampered with stays tampered with, and the
    report names where the damage starts so the surviving prefix can still be read.
    """

    valid: bool
    checked: int = Field(ge=0)
    first_invalid_index: int | None = None
    reason: NonEmptyStr | None = None

    @property
    def trusted_prefix(self) -> int:
        """How many records from the start are still internally consistent."""
        return self.checked if self.valid else (self.first_invalid_index or 0)


def verify_state_chain(records: Sequence[LifecycleStateRecord]) -> StateIntegrityReport:
    """Check position, link, digest and transition legality for every record.

    Four independent checks, because each catches something the others do not:

    * **sequence** — deletion and reordering, which can leave digests self-consistent;
    * **previous_digest** — insertion and truncation of the link structure;
    * **digest** — modification of any covered field, circuit state and counts included;
    * **transition legality** — a chain that is cryptographically perfect but describes an
      impossible history, which is what a replayed old snapshot looks like.
    """
    previous = LIFECYCLE_GENESIS_DIGEST
    scope_states: dict[str, CircuitState] = {}

    for index, record in enumerate(records):

        def fail(reason: str, position: int = index) -> StateIntegrityReport:
            return StateIntegrityReport(
                valid=False, checked=position, first_invalid_index=position, reason=reason
            )

        if record.sequence != index:
            return fail(
                f"record at position {index} claims sequence {record.sequence}",
            )
        if record.previous_digest != previous:
            return fail(f"record {index} does not link to the record before it")
        if record.digest != state_digest(record):
            return fail(f"record {index} does not match its digest")

        if record.kind is StateRecordKind.BREAKER:
            if record.scope_key is None or record.circuit_state is None:
                return fail(f"breaker record {index} names no scope or state")
            if record.transition is None:
                return fail(f"breaker record {index} names no transition")
            was = scope_states.get(record.scope_key, CircuitState.CLOSED)
            if not legal_transition(
                record.transition, previous=was, resulting=record.circuit_state
            ):
                return fail(
                    f"record {index} claims {record.transition} moving {record.scope_key} "
                    f"from {was} to {record.circuit_state}, which is not a legal edge"
                )
            scope_states[record.scope_key] = record.circuit_state

        previous = record.digest

    return StateIntegrityReport(valid=True, checked=len(records))
