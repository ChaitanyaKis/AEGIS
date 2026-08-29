"""The lifecycle manager: coordination, and no authority whatsoever.

It answers one question — *may the incident lifecycle continue?* — and it answers it from
counters, configured limits, the incident's own state and the breaker's snapshot. That is
the whole of its input, and none of it is model output.

What it owns
------------

Bounded execution, retry accounting, recovery limits, terminal-state handling, escalation
conditions and stop reasons. All of these are questions about *how much automation has
happened*, which no other component tracks.

What it does not own
--------------------

Whether a particular action is permitted (policy), whether a human agreed (approval),
whether the enterprise actually changed (verification), whether the history is intact
(audit), how dangerous something is (assessment). It calls none of those and re-derives
none of them. :class:`~aegis.lifecycle.models.LifecycleAction` deliberately has no
``EXECUTE`` member: the manager can stop things and can decline to stop them, and
"declining to stop" is not permission — every gate downstream still gets its say.

Determinism
-----------

Given the same limits, the same artifact sequence and the same injected clock, every
decision is byte-identical. No randomness, no ambient time, no environment lookup, no
threshold that depends on a model.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from aegis.core.domain import Action, IncidentState, utc_now
from aegis.lifecycle.circuit_breaker import BreakerDecision, BreakerSnapshot, CircuitBreaker
from aegis.lifecycle.conditions import (
    FailureClass,
    classify_execution,
    classify_verification,
    detect_governance_anomaly,
)
from aegis.lifecycle.limits import DEFAULT_LIFECYCLE_LIMITS, LifecycleLimits
from aegis.lifecycle.models import (
    LifecycleAction,
    LifecycleDecision,
    LifecycleRecord,
    StopReason,
)
from aegis.lifecycle.state import CircuitState, LifecycleCounters

__all__ = ["TERMINAL_STATES", "LifecycleManager"]

TERMINAL_STATES: frozenset[IncidentState] = frozenset(
    {IncidentState.RESOLVED, IncidentState.ESCALATED}
)
"""The states after which nothing further may happen (``claude.md`` section 8).

Read from the existing :class:`~aegis.core.domain.IncidentState`; this package defines no
competing lifecycle enum and adds no terminal state of its own.
"""


class LifecycleManager:
    """Coordinates one incident's automated handling within explicit bounds.

    Args:
        limits: Every bound, frozen. Supplied by the operator who wires the orchestrator.
        breaker: The gate. Shared across incidents on purpose, so repeated failures against
            one capability and resource accumulate rather than resetting each time.
        clock: Injected, so lifecycle records are reproducible.

    One manager handles one incident. The breaker outlives it.
    """

    def __init__(
        self,
        *,
        limits: LifecycleLimits | None = None,
        breaker: CircuitBreaker | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.limits = limits if limits is not None else DEFAULT_LIFECYCLE_LIMITS
        self.breaker = breaker if breaker is not None else CircuitBreaker(clock=clock)
        self._clock = clock
        self._counters = LifecycleCounters()
        self._incident_id: str | None = None
        self._started_at: datetime | None = None
        self._escalation_reason: str | None = None
        self._last_scope_key: str | None = None
        self._held_probes: set[str] = set()
        """Scopes whose single half-open probe this lifecycle is currently holding.

        The breaker is asked twice per remediation — once before approval, once before
        execution — and in HALF_OPEN the first ask *consumes* the probe. Without this the
        second ask would refuse the very attempt the first one authorised, and a recovering
        breaker could never complete a probe. Holding it is not a bypass: the second check
        still runs, and still refuses if the breaker has since opened.
        """

    # --- reading --------------------------------------------------------------------

    @property
    def counters(self) -> LifecycleCounters:
        """The current counters, frozen. A caller holding this cannot change them."""
        return self._counters

    @property
    def escalation_reason(self) -> str | None:
        return self._escalation_reason

    def begin(self, incident_id: str) -> None:
        """Start tracking one incident. Counters start at zero and only ever rise."""
        self._incident_id = incident_id
        self._started_at = self._clock()
        self._counters = LifecycleCounters()
        self._escalation_reason = None
        self._held_probes = set()

    def scope_for(self, action: Action) -> str:
        """The breaker scope key for an action, under the configured scope."""
        return self.breaker.key_for(
            capability=action.capability,
            resource=action.target_resource,
            incident_id=action.incident_id,
        )

    # --- the lifecycle question -----------------------------------------------------

    def may_continue(self, state: IncidentState) -> LifecycleDecision:
        """May the loop take another step?

        Checked in a fixed order, terminal state first. A resolved incident is not asked
        whether it has budget left — it is finished, and asking would imply the budget
        could bring it back.
        """
        if state in TERMINAL_STATES:
            return self._stop(
                StopReason.TERMINAL_STATE,
                f"incident is {state}; no further work is permitted",
            )

        if self._counters.steps_used >= self.limits.max_steps:
            return self._escalate(
                StopReason.STEP_BUDGET_EXHAUSTED,
                f"the {self.limits.max_steps}-step budget is exhausted",
                limit_name="max_steps",
                limit_value=self.limits.max_steps,
            )

        if self._counters.consecutive_failures >= self.limits.max_consecutive_failures:
            return self._escalate(
                StopReason.CONSECUTIVE_FAILURES,
                f"{self._counters.consecutive_failures} consecutive remediation failures",
                limit_name="max_consecutive_failures",
                limit_value=self.limits.max_consecutive_failures,
            )

        deadline = self._deadline_exceeded()
        if deadline is not None:
            return deadline

        return self._continue("lifecycle may continue")

    def may_remediate(self, action: Action | None = None) -> LifecycleDecision:
        """May another remediation be taken through governance?

        The breaker is consulted **here**, before approval is requested, so a blocked path
        does not spend a human approval it cannot use (Part 19). It is consulted again
        immediately before execution by :meth:`may_execute`, because a breaker that opens
        in between must still stop the action.
        """
        if self._counters.remediation_attempts >= self.limits.max_remediation_attempts:
            return self._escalate(
                StopReason.REMEDIATION_BUDGET_EXHAUSTED,
                f"the {self.limits.max_remediation_attempts}-remediation budget is exhausted",
                limit_name="max_remediation_attempts",
                limit_value=self.limits.max_remediation_attempts,
            )

        if self._counters.execution_count >= self.limits.max_executions:
            return self._escalate(
                StopReason.EXECUTION_BUDGET_EXHAUSTED,
                f"the {self.limits.max_executions}-execution budget is exhausted",
                limit_name="max_executions",
                limit_value=self.limits.max_executions,
            )

        if action is not None:
            blocked = self._breaker_blocks(action)
            if blocked is not None:
                return blocked

        return self._continue("remediation is within lifecycle budget")

    def may_execute(self, action: Action, fingerprint: str) -> LifecycleDecision:
        """The last lifecycle gate before the enterprise is touched.

        Re-checks the breaker deliberately. An authorization obtained while the breaker was
        closed confers nothing once it has opened: a consumed approval is evidence a human
        agreed to the action, not a token that outranks a stop (Part 20).
        """
        if self._counters.executions_of(fingerprint) >= self.limits.max_executions_per_fingerprint:
            return self._escalate(
                StopReason.FINGERPRINT_BUDGET_EXHAUSTED,
                (
                    f"this exact action has already been executed "
                    f"{self._counters.executions_of(fingerprint)} time(s)"
                ),
                limit_name="max_executions_per_fingerprint",
                limit_value=self.limits.max_executions_per_fingerprint,
            )

        if self._counters.execution_count >= self.limits.max_executions:
            return self._escalate(
                StopReason.EXECUTION_BUDGET_EXHAUSTED,
                f"the {self.limits.max_executions}-execution budget is exhausted",
                limit_name="max_executions",
                limit_value=self.limits.max_executions,
            )

        blocked = self._breaker_blocks(action)
        if blocked is not None:
            return blocked

        return self._continue("execution is within lifecycle budget and the breaker is closed")

    def may_recover(self, state: IncidentState) -> LifecycleDecision:
        """May a degraded incident re-enter investigation?

        Recovery re-enters at investigation and never at execution — the transition table
        has no edge from either recovery state to EXECUTING, so a second remediation walks
        POLICY_CHECK, approval and verification exactly like the first. This method bounds
        *how often*; the state machine enforces *through what*.
        """
        if state in TERMINAL_STATES:
            return self._stop(
                StopReason.TERMINAL_STATE,
                f"incident is {state}; recovery cannot restart a finished lifecycle",
            )

        if self._counters.recovery_attempts >= self.limits.max_recovery_attempts:
            return self._escalate(
                StopReason.RECOVERY_BUDGET_EXHAUSTED,
                f"the {self.limits.max_recovery_attempts}-recovery budget is exhausted",
                limit_name="max_recovery_attempts",
                limit_value=self.limits.max_recovery_attempts,
            )

        if self._counters.steps_used >= self.limits.max_steps:
            return self._escalate(
                StopReason.STEP_BUDGET_EXHAUSTED,
                f"the {self.limits.max_steps}-step budget is exhausted",
                limit_name="max_steps",
                limit_value=self.limits.max_steps,
            )

        return self._continue("recovery is within lifecycle budget")

    # --- counting -------------------------------------------------------------------

    def _checkpoint(self) -> LifecycleCounters:
        """Persist the counters so a restart resumes where the incident left off.

        Called after every counter change rather than at the end: an incident interrupted
        mid-flight is exactly the one whose budget must not silently reset, and a
        checkpoint only written on a clean finish would never cover it.
        """
        if self._incident_id is not None:
            self.breaker.persist_counters(self._incident_id, self._counters)
        return self._counters

    def restore(self, incident_id: str) -> bool:
        """Resume an incident's counters from persisted state.

        Returns whether anything was restored. Deliberately explicit rather than automatic
        in :meth:`begin`: resuming an incident is a decision, and silently continuing a
        half-finished lifecycle after a restart would be surprising in the other direction.
        """
        restored = self.breaker.counters_for(incident_id)
        if restored is None:
            return False
        self._incident_id = incident_id
        self._counters = restored
        if self._started_at is None:
            self._started_at = self._clock()
        return True

    def record_step(self) -> LifecycleCounters:
        self._counters = self._counters.after_step()
        return self._checkpoint()

    def record_remediation_attempt(self, action_id: str | None = None) -> LifecycleCounters:
        self._counters = self._counters.after_remediation_attempt(action_id)
        return self._checkpoint()

    def record_recovery(self) -> LifecycleCounters:
        self._counters = self._counters.after_recovery()
        return self._checkpoint()

    def record_execution(self, fingerprint: str) -> LifecycleCounters:
        self._counters = self._counters.after_execution(fingerprint)
        return self._checkpoint()

    def record_outcome(
        self,
        action: Action,
        *,
        execution_outcome: object,
        verification_status: object,
        verification_id: str | None = None,
        probe: bool | None = None,
    ) -> BreakerSnapshot:
        """Classify one completed remediation and feed the result to the breaker.

        Execution and verification are classified **separately** (Part 21). An action the
        enterprise refused and an action that ran but did not take effect are different
        problems with different thresholds, and collapsing them would destroy the signal.

        A verified success clears the consecutive-failure run; nothing else does, and no
        counter is ever decremented.
        """
        key = self.scope_for(action)
        self._last_scope_key = key
        # The manager knows whether this remediation was the half-open probe; a caller
        # should not have to work it out and cannot get it wrong by forgetting.
        probe = key in self._held_probes if probe is None else probe
        self._held_probes.discard(key)

        execution_class = classify_execution(execution_outcome)
        verification_class = classify_verification(verification_status)
        verified = verification_class is FailureClass.NONE and execution_class is FailureClass.NONE

        if probe:
            # A probe's outcome decides the breaker directly rather than accumulating
            # toward a threshold: the probe exists to answer exactly this question.
            if verified:
                snapshot = self.breaker.record_probe_success(key)
            else:
                snapshot = self.breaker.record_probe_failure(
                    key, reason=f"execution {execution_outcome}, verification {verification_status}"
                )
        else:
            if execution_class is not FailureClass.NONE:
                self.breaker.record(
                    key, execution_class, reason=f"execution reported {execution_outcome}"
                )
            if verification_class is not FailureClass.NONE:
                self.breaker.record(
                    key,
                    verification_class,
                    reason=f"verification reported {verification_status}",
                )
            if verified:
                self.breaker.record(key, FailureClass.NONE, reason="verified success")
            snapshot = self.breaker.snapshot(key)

        self._counters = (
            self._counters.after_success(verification_id)
            if verified
            else self._counters.after_failure(verification_id)
        )
        self._checkpoint()
        return snapshot

    def record_governance_anomaly(
        self,
        action: Action,
        *,
        executed: bool,
        authorization_present: bool,
        policy_decision: object,
        authorized_action_id: str | None,
        verified_action_id: str | None,
        audit_valid: bool,
    ) -> tuple[str, ...]:
        """Detect anomalies in one remediation and open the breaker on any of them.

        A policy DENY is never among them. Refusing an action is the control plane working,
        and a breaker that opened on it would turn correct governance into a self-inflicted
        outage the first time AEGIS said no (Part 13).
        """
        anomalies = detect_governance_anomaly(
            executed=executed,
            authorization_present=authorization_present,
            policy_decision=policy_decision,  # type: ignore[arg-type]
            action_id=action.action_id,
            authorized_action_id=authorized_action_id,
            verified_action_id=verified_action_id,
            audit_valid=audit_valid,
        )
        if anomalies:
            key = self.scope_for(action)
            self._last_scope_key = key
            self.breaker.record(
                key,
                FailureClass.GOVERNANCE_ANOMALY,
                reason=f"governance anomaly: {', '.join(anomalies)}",
            )
        return anomalies

    # --- finishing ------------------------------------------------------------------

    def finish(
        self,
        *,
        final_state: IncidentState,
        decision: LifecycleDecision | None = None,
        detail: str | None = None,
    ) -> LifecycleRecord:
        """The structured account of why this lifecycle ended.

        Always produced, including for an ordinary resolution, so "why did automation
        stop" is answerable for every run rather than only the alarming ones.
        """
        now = self._clock()
        stop_reason = decision.stop_reason if decision is not None else StopReason.NOT_STOPPED
        return LifecycleRecord(
            incident_id=self._incident_id or "INC-UNKNOWN",
            final_state=final_state,
            stop_reason=stop_reason,
            detail=detail or (decision.detail if decision is not None else "lifecycle ended"),
            counters=self._counters,
            limits=self.limits,
            limit_name=decision.limit_name if decision is not None else None,
            limit_value=decision.limit_value if decision is not None else None,
            breaker=(
                self.breaker.snapshot(self._last_scope_key)
                if self._last_scope_key is not None
                else None
            ),
            escalation_reason=self._escalation_reason,
            started_at=self._started_at or now,
            completed_at=now,
        )

    # --- internals ------------------------------------------------------------------

    def _breaker_blocks(self, action: Action) -> LifecycleDecision | None:
        """Ask the gate, and translate a refusal into a lifecycle stop.

        A refusal escalates rather than merely stopping: a breaker that opened means
        something needs a human, and quietly ending the run would leave the incident
        unattended.
        """
        key = self.scope_for(action)
        self._last_scope_key = key

        if key in self._held_probes:
            # This lifecycle already holds the probe for this scope. Re-asking would
            # consume a second one that does not exist. The state is still checked: a
            # breaker that opened since the probe was granted refuses here.
            if self.breaker.state_of(key) is CircuitState.HALF_OPEN:
                return None
            self._held_probes.discard(key)

        verdict: BreakerDecision = self.breaker.check(key)
        if verdict.is_probe:
            self._held_probes.add(key)
        if verdict.allowed:
            return None
        return self._escalate(
            StopReason.CIRCUIT_OPEN,
            f"circuit breaker refused {key}: {verdict.reason}",
            breaker=self.breaker.snapshot(key),
        )

    def _deadline_exceeded(self) -> LifecycleDecision | None:
        if self.limits.max_wall_clock_seconds is None or self._started_at is None:
            return None
        elapsed = (self._clock() - self._started_at).total_seconds()
        if elapsed < self.limits.max_wall_clock_seconds:
            return None
        return self._escalate(
            StopReason.DEADLINE_EXCEEDED,
            f"the {self.limits.max_wall_clock_seconds}s lifecycle deadline elapsed",
            limit_name="max_wall_clock_seconds",
        )

    def _continue(self, detail: str) -> LifecycleDecision:
        return LifecycleDecision(
            action=LifecycleAction.CONTINUE, detail=detail, counters=self._counters
        )

    def _stop(self, reason: StopReason, detail: str) -> LifecycleDecision:
        return LifecycleDecision(
            action=LifecycleAction.STOP,
            stop_reason=reason,
            detail=detail,
            counters=self._counters,
        )

    def _escalate(
        self,
        reason: StopReason,
        detail: str,
        *,
        limit_name: str | None = None,
        limit_value: int | None = None,
        breaker: BreakerSnapshot | None = None,
    ) -> LifecycleDecision:
        self._escalation_reason = detail
        return LifecycleDecision(
            action=LifecycleAction.ESCALATE,
            stop_reason=reason,
            detail=detail,
            counters=self._counters,
            limit_name=limit_name,
            limit_value=limit_value,
            breaker=breaker,
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(incident={self._incident_id!r}, "
            f"steps={self._counters.steps_used})"
        )
