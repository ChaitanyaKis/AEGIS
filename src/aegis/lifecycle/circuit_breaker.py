"""The circuit breaker: a gate that can only ever say no.

    CLOSED  ──(threshold reached)──►  OPEN  ──(probe permitted)──►  HALF_OPEN
       ▲                               ▲                                │
       └────(probe succeeded)──────────┴────(probe failed)──────────────┘

What it is
----------

A deterministic counter with thresholds, and a gate that reads them. It answers exactly one
question — *is this automation path currently allowed to keep operating?* — and the only
answers are "yes" and "no, because".

What it deliberately is not
---------------------------

**It is not an authorizer.** There is no method that returns permission. ``check`` returns
``allowed=True`` meaning "nothing here objects", which is not the same as "you may proceed":
the caller still has to pass assessment, policy, approval and execution authorization,
every one of which can independently refuse. A closed breaker adds nothing to a caller's
rights, and that is why it can never be a way around anything.

**It is not a policy engine.** It imports no ``PolicyEngine``, no ``ApprovalEngine``, no
``VerificationEngine`` and no ``ActionExecutor`` — asserted by test. It is handed a
:class:`~aegis.lifecycle.conditions.FailureClass` that someone else computed and counts it.
It cannot re-interpret a verification or second-guess a decision because it is never given
the artifacts to do so.

**It does not execute anything.** It sits in front of the governance path as a gate, and
the components behind it are unchanged.

Durable and tamper-evident
--------------------------

Every state-affecting event is appended to a :class:`LifecycleStatePersistence` as a
chained record, so the breaker survives a restart with its counts, its open state and its
probe bookkeeping intact. A restart is exactly when a broken system would most like to
forget that it was broken, so it is exactly where forgetting must not be possible.

Loading verifies the chain *and* the legality of every transition. A chain can be
cryptographically perfect and still describe an impossible history — ``OPEN`` followed by
``CLOSED`` with no probe in between — and replaying that would be a blind reset smuggled in
through storage. See :mod:`aegis.lifecycle.state`.

Fail-closed (Part 14)
---------------------

While OPEN, production execution, new remediation attempts and delegation toward
remediation are all refused. Observation, audit, reporting and escalation continue: the
point of stopping is to find out what is wrong, which requires still being able to look.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from enum import StrEnum

from aegis.core.domain import DomainModel, NonEmptyStr, utc_now
from aegis.lifecycle.conditions import FailureClass
from aegis.lifecycle.errors import LifecycleStateCorrupt, ProbeAlreadyInFlight
from aegis.lifecycle.limits import DEFAULT_BREAKER_CONFIG, BreakerScope, CircuitBreakerConfig
from aegis.lifecycle.state import (
    LIFECYCLE_GENESIS_DIGEST,
    BreakerSnapshot,
    BreakerTransition,
    CircuitState,
    LifecycleStateRecord,
    StateIntegrityReport,
    StateRecordKind,
    state_digest,
    verify_state_chain,
)

__all__ = [
    "BreakerDecision",
    "BreakerSnapshot",
    "CircuitBreaker",
    "CircuitState",
    "CorruptionPolicy",
    "scope_key",
]


class CorruptionPolicy(StrEnum):
    """What to do when persisted lifecycle state cannot be trusted.

    Both options fail closed; they differ in *how*. Neither can result in a breaker that
    was open coming back closed, which is the only outcome that would actually be unsafe.
    """

    RAISE = "RAISE"
    """Refuse to construct. The process cannot start with untrustworthy state — the
    strongest form of failing closed, and the default."""

    QUARANTINE = "QUARANTINE"
    """Construct, but refuse every scope. For deployments that must keep observing and
    escalating while a human works out what happened to the log."""


class BreakerDecision(DomainModel):
    """The answer to one ``check``. Never a permission — at most an absence of objection."""

    allowed: bool
    state: CircuitState
    scope_key: NonEmptyStr
    reason: NonEmptyStr
    is_probe: bool = False
    """True when this check consumed the single half-open probe. The caller must report
    the probe's outcome back, or the breaker stays half-open with a probe outstanding."""


def scope_key(
    scope: BreakerScope,
    *,
    capability: str | None = None,
    resource: str | None = None,
    incident_id: str | None = None,
) -> str:
    """The counter key for one action under a scope (Part 17).

    Deterministic and total: a missing component renders as ``*`` rather than raising, so a
    partially-specified action still lands in a stable bucket instead of escaping counting
    altogether. Failing *open* here would mean unattributable failures accumulate nowhere.
    """
    capability = capability or "*"
    resource = resource or "*"
    incident_id = incident_id or "*"
    if scope is BreakerScope.CAPABILITY_RESOURCE:
        return f"{capability}@{resource}"
    if scope is BreakerScope.CAPABILITY:
        return capability
    if scope is BreakerScope.RESOURCE:
        return resource
    if scope is BreakerScope.INCIDENT:
        return incident_id
    return "global"


_THRESHOLD_FIELD: dict[FailureClass, str] = {
    FailureClass.EXECUTION_FAILURE: "execution_failure_threshold",
    FailureClass.VERIFICATION_FAILURE: "verification_failure_threshold",
    FailureClass.STALE_VERIFICATION: "stale_verification_threshold",
    FailureClass.INSUFFICIENT_EVIDENCE: "stale_verification_threshold",
    FailureClass.VERIFICATION_MISMATCH: "mismatch_threshold",
    FailureClass.GOVERNANCE_ANOMALY: "governance_anomaly_threshold",
}
"""Which configured threshold governs which failure class.

A declared mapping rather than a chain of conditionals, so "which classes are counted" is
readable in one place and a new class without a threshold is a visible omission.
``INSUFFICIENT_EVIDENCE`` shares the stale threshold: both mean verification could not see.
"""


class _ScopeState:
    """Mutable per-scope bookkeeping. Never handed out — callers get snapshots."""

    __slots__ = (
        "counts",
        "opened_at",
        "opened_reason",
        "probe_eligible_at",
        "probe_failures",
        "probe_in_flight",
        "state",
        "trip_class",
    )

    def __init__(self) -> None:
        self.counts: dict[FailureClass, int] = {}
        self.state = CircuitState.CLOSED
        self.opened_at: datetime | None = None
        self.opened_reason: str | None = None
        self.trip_class: FailureClass | None = None
        self.probe_in_flight = False
        self.probe_failures = 0
        self.probe_eligible_at: datetime | None = None


class CircuitBreaker:
    """Deterministic per-scope breaker over classified failures.

    Args:
        config: Thresholds and scope. Frozen, supplied by the operator, unreachable from
            model output.
        clock: Injected, so two identical failure sequences produce identical snapshots.

    Scoping is per :class:`~aegis.lifecycle.limits.BreakerScope`, defaulting to
    ``capability@resource``. Counters persist across incidents within one breaker instance,
    which is what lets three incidents that each fail once against the same capability add
    up to a signal — and is also why the breaker's lifetime is a deployment decision
    documented in the report rather than assumed here.
    """

    def __init__(
        self,
        config: CircuitBreakerConfig | None = None,
        *,
        clock: Callable[[], datetime] = utc_now,
        persistence=None,
        on_corruption: CorruptionPolicy = CorruptionPolicy.RAISE,
    ) -> None:
        self.config = config if config is not None else DEFAULT_BREAKER_CONFIG
        self._clock = clock
        self._scopes: dict[str, _ScopeState] = {}
        self._persistence = persistence
        self._sequence = 0
        self._previous_digest = LIFECYCLE_GENESIS_DIGEST
        self.quarantined = False
        """Set when construction found state it could not verify. Every scope refuses."""

        if persistence is not None:
            self._restore(on_corruption)

    # --- durability -----------------------------------------------------------------

    def _restore(self, on_corruption: CorruptionPolicy) -> None:
        """Rebuild scope state by replaying a verified chain.

        Verification comes first and covers transition legality as well as digests, so a
        log describing an impossible history is refused rather than replayed. A missing or
        empty log is the well-defined initial state: every scope closed, nothing counted.
        """
        try:
            records = tuple(self._persistence.load())
        except LifecycleStateCorrupt as error:
            # The backend's own account of the damage is more useful than a generic one:
            # "line 4 is not a readable record" tells an investigator where to look.
            self._quarantine(on_corruption, error.detail)
            return

        report = verify_state_chain(records)
        if not report.valid:
            self._quarantine(on_corruption, report.reason or "the lifecycle chain is broken")
            return

        for record in records:
            if record.kind is not StateRecordKind.BREAKER or record.scope_key is None:
                continue
            state = self._scopes.setdefault(record.scope_key, _ScopeState())
            state.state = record.circuit_state or CircuitState.CLOSED
            state.counts = {
                FailureClass(name): count for name, count in record.failure_counts.items()
            }
            state.opened_at = record.opened_at
            state.opened_reason = record.opened_reason
            state.trip_class = record.trip_class
            state.probe_in_flight = record.probe_in_flight
            state.probe_failures = record.consecutive_probe_failures
            state.probe_eligible_at = self._eligible_at(record.opened_at)

        if records:
            self._sequence = len(records)
            self._previous_digest = records[-1].digest

    def _quarantine(self, policy: CorruptionPolicy, detail: str) -> None:
        """Fail closed, in whichever of the two ways the caller chose."""
        if policy is CorruptionPolicy.RAISE:
            raise LifecycleStateCorrupt(detail)
        self.quarantined = True

    def _eligible_at(self, opened_at: datetime | None) -> datetime | None:
        """When an open breaker may be probed. ``None`` when it is not open."""
        if opened_at is None or self.config.probe_cooldown_seconds is None:
            return None
        return opened_at + timedelta(seconds=self.config.probe_cooldown_seconds)

    def _persist(self, key: str, transition: BreakerTransition) -> None:
        """Append one record describing the scope's resulting state.

        Called after the in-memory state has already moved, so the record is a statement of
        what *is* rather than of what was intended. Nothing here can refuse a transition —
        persistence records history and never gates it.
        """
        if self._persistence is None:
            return
        state = self._scopes[key]
        record = LifecycleStateRecord(
            sequence=self._sequence,
            kind=StateRecordKind.BREAKER,
            recorded_at=self._clock(),
            scope_key=key,
            transition=transition,
            circuit_state=state.state,
            trip_class=state.trip_class,
            failure_counts={cls.value: count for cls, count in sorted(state.counts.items())},
            opened_at=state.opened_at,
            opened_reason=state.opened_reason,
            probe_in_flight=state.probe_in_flight,
            consecutive_probe_failures=state.probe_failures,
            previous_digest=self._previous_digest,
            digest="0" * 64,
        )
        record = record.model_copy(update={"digest": state_digest(record)})
        self._persistence.append(record)
        self._sequence += 1
        self._previous_digest = record.digest

    def persist_counters(self, incident_id: str, counters) -> None:
        """Append one lifecycle-counter record, so counts survive a restart too."""
        if self._persistence is None:
            return
        record = LifecycleStateRecord(
            sequence=self._sequence,
            kind=StateRecordKind.COUNTERS,
            recorded_at=self._clock(),
            transition=BreakerTransition.COUNTERS_UPDATED,
            incident_id=incident_id,
            counters=counters,
            previous_digest=self._previous_digest,
            digest="0" * 64,
        )
        record = record.model_copy(update={"digest": state_digest(record)})
        self._persistence.append(record)
        self._sequence += 1
        self._previous_digest = record.digest

    def counters_for(self, incident_id: str):
        """The most recently persisted counters for an incident, or ``None``.

        Read back from the log rather than held in memory, so a restarted process restores
        the same value a verifier would compute from the history.
        """
        if self._persistence is None:
            return None
        latest = None
        for record in self._persistence.load():
            if record.kind is StateRecordKind.COUNTERS and record.incident_id == incident_id:
                latest = record.counters
        return latest

    def verify_integrity(self):
        """Check the persisted chain. Reports; never repairs."""
        if self._persistence is None:
            return verify_state_chain(())
        try:
            return verify_state_chain(tuple(self._persistence.load()))
        except LifecycleStateCorrupt as error:
            return StateIntegrityReport(
                valid=False, checked=0, first_invalid_index=0, reason=error.detail
            )

    # --- reading --------------------------------------------------------------------

    def key_for(
        self,
        *,
        capability: str | None = None,
        resource: str | None = None,
        incident_id: str | None = None,
    ) -> str:
        """The scope key this breaker would use for an action."""
        return scope_key(
            self.config.scope,
            capability=capability,
            resource=resource,
            incident_id=incident_id,
        )

    def snapshot(self, key: str) -> BreakerSnapshot:
        """The public state for one scope. A frozen value with no route back to the breaker."""
        state = self._scopes.get(key)
        if state is None:
            return BreakerSnapshot(
                scope_key=key,
                state=CircuitState.OPEN if self.quarantined else CircuitState.CLOSED,
                quarantined=self.quarantined,
            )
        return BreakerSnapshot(
            scope_key=key,
            state=state.state,
            opened_at=state.opened_at,
            opened_reason=state.opened_reason,
            trip_class=state.trip_class,
            counts={cls.value: count for cls, count in sorted(state.counts.items())},
            probe_in_flight=state.probe_in_flight,
            consecutive_probe_failures=state.probe_failures,
            probe_eligible_at=state.probe_eligible_at,
            quarantined=self.quarantined,
        )

    def state_of(self, key: str) -> CircuitState:
        state = self._scopes.get(key)
        return state.state if state is not None else CircuitState.CLOSED

    # --- the gate -------------------------------------------------------------------

    def check(self, key: str) -> BreakerDecision:
        """Ask whether this automation path may continue. **Never grants anything.**

        CLOSED allows. OPEN refuses. HALF_OPEN allows exactly one probe and refuses every
        request after it until the probe's outcome is reported — the single-probe bound
        lives here rather than in the snapshot, so nothing that merely *reads* state can
        authorize a second attempt.
        """
        if self.quarantined:
            # State could not be verified at load. Refusing everything is the only safe
            # reading of "I do not know which breakers are open".
            return BreakerDecision(
                allowed=False,
                state=CircuitState.OPEN,
                scope_key=key,
                reason="lifecycle state could not be verified; automation is quarantined",
            )

        state = self._scopes.get(key)
        if state is None or state.state is CircuitState.CLOSED:
            return BreakerDecision(
                allowed=True,
                state=CircuitState.CLOSED,
                scope_key=key,
                reason="breaker closed; no objection from this gate",
            )

        if state.state is CircuitState.OPEN:
            # The cooldown is the only thing that moves an open breaker to half-open, and
            # it does so here rather than on a timer: the transition happens when someone
            # asks, so it is always attributable to a request and always auditable.
            if not self._cooldown_elapsed(state):
                return BreakerDecision(
                    allowed=False,
                    state=CircuitState.OPEN,
                    scope_key=key,
                    reason=state.opened_reason or "breaker open",
                )
            state.state = CircuitState.HALF_OPEN
            state.probe_in_flight = False
            self._persist(key, BreakerTransition.PROBE_PERMITTED)

        if state.probe_in_flight:
            return BreakerDecision(
                allowed=False,
                state=CircuitState.HALF_OPEN,
                scope_key=key,
                reason="a half-open probe is already in flight",
            )

        state.probe_in_flight = True
        self._persist(key, BreakerTransition.PROBE_TAKEN)
        return BreakerDecision(
            allowed=True,
            state=CircuitState.HALF_OPEN,
            scope_key=key,
            reason="half-open: one bounded probe permitted through full governance",
            is_probe=True,
        )

    def _cooldown_elapsed(self, state: _ScopeState) -> bool:
        """Whether an open breaker has waited long enough to earn a probe.

        ``None`` cooldown means never automatically eligible — an operator must call
        :meth:`allow_probe`. That is a legitimate configuration for a capability nobody
        wants retried unattended, so it is expressible rather than assumed away.
        """
        if state.probe_eligible_at is None:
            return False
        return self._clock() >= state.probe_eligible_at

    def permit_probe(self, key: str) -> BreakerDecision:
        """Explicitly take the half-open probe, refusing if one is outstanding.

        Raises:
            ProbeAlreadyInFlight: when a probe is already outstanding. ``check`` returns a
                refusal for the same case; this raises, for callers that treat a double
                probe as a programming error rather than a routing outcome.
        """
        state = self._scopes.get(key)
        if state is not None and state.state is CircuitState.HALF_OPEN and state.probe_in_flight:
            raise ProbeAlreadyInFlight(key)
        return self.check(key)

    # --- recording ------------------------------------------------------------------

    def record(self, key: str, failure_class: FailureClass, *, reason: str) -> BreakerSnapshot:
        """Count one classified outcome and open the breaker if a threshold is crossed.

        ``FailureClass.NONE`` clears the counters for the scope: a verified success is
        evidence the path works, and is the only thing that clears them. Note this is not
        the same as the lifecycle's ``consecutive_failures``, which only a *verified*
        remediation resets — the breaker is per-path and the lifecycle is per-incident.

        A class with no configured threshold is counted and never trips, which is how a
        future failure class fails safe rather than tripping on its first occurrence.
        """
        state = self._scopes.setdefault(key, _ScopeState())

        if failure_class is FailureClass.NONE:
            state.counts.clear()
            # Only recorded as a success when the scope is genuinely closed. Clearing
            # counts on an open breaker would be a reset wearing a different name, and the
            # transition table refuses SUCCESS_RECORDED from any other state.
            if state.state is CircuitState.CLOSED:
                self._persist(key, BreakerTransition.SUCCESS_RECORDED)
            return self.snapshot(key)

        state.counts[failure_class] = state.counts.get(failure_class, 0) + 1

        field = _THRESHOLD_FIELD.get(failure_class)
        if field is None:
            self._persist(key, BreakerTransition.FAILURE_RECORDED)
            return self.snapshot(key)

        threshold = getattr(self.config, field)
        if state.counts[failure_class] >= threshold and state.state is not CircuitState.OPEN:
            self._open(
                state,
                failure_class,
                f"{failure_class} reached its threshold of {threshold}: {reason}",
            )
            self._persist(key, BreakerTransition.OPENED)
        else:
            self._persist(key, BreakerTransition.FAILURE_RECORDED)
        return self.snapshot(key)

    def record_probe_success(self, key: str) -> BreakerSnapshot:
        """A probe verified. Close the breaker and clear the counters.

        The only route from OPEN back to CLOSED, and it requires a real governed execution
        that a real verification confirmed. There is deliberately no ``reset()``: a method
        that closed the breaker without evidence would be the single largest hole this
        component could have (Part 16).
        """
        state = self._scopes.setdefault(key, _ScopeState())
        state.state = CircuitState.CLOSED
        state.counts.clear()
        state.probe_in_flight = False
        state.probe_failures = 0
        state.opened_at = None
        state.opened_reason = None
        state.trip_class = None
        state.probe_eligible_at = None
        self._persist(key, BreakerTransition.PROBE_SUCCEEDED)
        return self.snapshot(key)

    def record_probe_failure(self, key: str, *, reason: str) -> BreakerSnapshot:
        """A probe did not verify. Back to OPEN.

        The probe failing is itself the evidence, so this reopens directly rather than
        adding to a counter and waiting for a threshold. Nothing here can close anything.
        """
        state = self._scopes.setdefault(key, _ScopeState())
        state.probe_in_flight = False
        state.probe_failures += 1
        self._open(state, state.trip_class, f"half-open probe failed: {reason}")
        self._persist(key, BreakerTransition.PROBE_FAILED)
        return self.snapshot(key)

    def allow_probe(self, key: str) -> BreakerSnapshot:
        """Move an open breaker to HALF_OPEN so one probe may be attempted.

        Called by the lifecycle manager, never by an agent and never by the breaker itself
        on a timer: something with the authority to decide a retry is worth attempting has
        to ask for it, and that decision is auditable.
        """
        state = self._scopes.get(key)
        if state is None or state.state is not CircuitState.OPEN:
            return self.snapshot(key)
        state.state = CircuitState.HALF_OPEN
        state.probe_in_flight = False
        self._persist(key, BreakerTransition.PROBE_PERMITTED)
        return self.snapshot(key)

    def _open(self, state: _ScopeState, trip_class: FailureClass | None, reason: str) -> None:
        state.state = CircuitState.OPEN
        state.opened_at = self._clock()
        state.opened_reason = reason
        state.trip_class = trip_class
        state.probe_in_flight = False
        state.probe_eligible_at = self._eligible_at(state.opened_at)

    def __repr__(self) -> str:
        open_scopes = sum(
            1 for state in self._scopes.values() if state.state is not CircuitState.CLOSED
        )
        return f"{type(self).__name__}(scope={self.config.scope}, non_closed={open_scopes})"
