"""The lifecycle coordinator: a sequencing boundary, emphatically not another engine.

    lifecycle limits → breaker → policy → approval → gate → execute → verify → record

It owns exactly one thing nothing else owns: the *order*, and the proof that the order was
followed. Every decision inside that order is made by the component that already owned it.

What it must never become
-------------------------

Not a second policy engine, approval engine, authorization engine or verification engine.
It has no method that returns permission, none that approves anything, none that builds an
:class:`~aegis.core.approval.ExecutionAuthorization`, and none that marks a verification
successful or resolves an incident. It calls the real engines and routes their answers.

The one artifact it does construct is a :class:`~aegis.lifecycle.gate.LifecycleGate`, and a
gate is deliberately not permission — see that module. It proves the lifecycle was crossed
and binds itself to one execution. Holding one entitles a caller to nothing, because the
executor demands an authorization as well.

Why a coordinator at all
------------------------

Because "the orchestrator calls the lifecycle manager" was a convention. A convention is
held up by review and tests, and neither survives someone adding a new execution path in a
hurry. Routing production mutation through one object that *cannot* skip its own steps —
because the executor refuses anything that arrives without the gate those steps produce —
turns the convention into a property of the code.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from aegis.core.domain import Action, Agent, DomainModel, NonEmptyStr, utc_now
from aegis.lifecycle.conditions import FailureClass
from aegis.lifecycle.gate import DEFAULT_GATE_TTL_SECONDS, GateRegister, LifecycleGate
from aegis.lifecycle.manager import LifecycleManager
from aegis.lifecycle.models import LifecycleDecision
from aegis.lifecycle.restriction import (
    AgentRestrictionRegistry,
    RestrictionVerdict,
)
from aegis.lifecycle.state import CircuitState

__all__ = ["GateIssue", "LifecycleCoordinator"]


class GateIssue(DomainModel):
    """The outcome of asking for a gate: one was issued, or one was refused and why."""

    gate: LifecycleGate | None = None
    decision: LifecycleDecision | None = None
    restriction: RestrictionVerdict | None = None
    refused_reason: NonEmptyStr | None = None

    @property
    def issued(self) -> bool:
        return self.gate is not None


class LifecycleCoordinator:
    """Sequences lifecycle governance and issues the proof that it happened.

    Args:
        manager: The lifecycle manager. Consulted, never spoken for.
        restrictions: Agent abuse containment. Optional; absent means no agent-scoped
            accounting, which is the Prompt 12 behaviour.
        clock: Injected, so gates and quarantines are reproducible.
        gate_ttl_seconds: How long an issued gate stays usable.

    The register this builds is the executor's verifier. It is held privately: a caller
    that could reach it could mint gates, so it is exposed only as the narrow
    :meth:`verifier` handle the executor needs.
    """

    def __init__(
        self,
        manager: LifecycleManager,
        *,
        restrictions: AgentRestrictionRegistry | None = None,
        clock: Callable[[], datetime] = utc_now,
        gate_ttl_seconds: float | None = DEFAULT_GATE_TTL_SECONDS,
    ) -> None:
        self.manager = manager
        self.restrictions = restrictions
        self._clock = clock
        self._generations: dict[str, int] = {}
        self._register = GateRegister(
            clock=clock,
            ttl_seconds=gate_ttl_seconds,
            breaker_state=self._breaker_state,
            generation=self._generation_of,
        )

    # --- the executor's handle ------------------------------------------------------

    @property
    def verifier(self) -> GateRegister:
        """The register, for the executor to verify and consume gates against.

        Deliberately the same object rather than a copy: authenticity *is* "this register
        issued it", so a copy would verify gates it never handed out.
        """
        return self._register

    def _breaker_state(self, scope_key: str) -> CircuitState:
        return self.manager.breaker.state_of(scope_key)

    def _generation_of(self, scope_key: str) -> int:
        return self._generations.get(scope_key, 0)

    def _bump_generation(self, scope_key: str) -> None:
        """Invalidate outstanding gates for a scope.

        Called when the breaker for that scope opens. A gate issued before the open is
        then stale by construction, which catches "the breaker reopened between the gate
        and the execution" even where no clock has moved.
        """
        self._generations[scope_key] = self._generations.get(scope_key, 0) + 1

    # --- the sequence ---------------------------------------------------------------

    def request_gate(
        self,
        action: Action,
        *,
        accountable_agent: Agent,
        incident_state,
        lifecycle_decision: LifecycleDecision,
    ) -> GateIssue:
        """Issue a gate if, and only if, the lifecycle permits this execution.

        Args:
            action: The assessed action. Authoritative — capability, resource and
                fingerprint are read from it, never from anything a model supplied.
            accountable_agent: The registered agent record the failure will be attributed
                to. Comes from the orchestrator's wiring, so a model naming a different
                agent changes nothing.
            incident_state: Current incident state, recorded on the gate.
            lifecycle_decision: The manager's verdict from :meth:`may_execute`. Passed in
                rather than recomputed, so there is exactly one lifecycle decision per
                execution and this method cannot quietly reach a different one.

        Returns:
            A :class:`GateIssue`. A refusal is a value, not an exception: the orchestrator
            has to route it into an escalation and an audit record, and an exception is
            easier to swallow than a returned refusal is to ignore.
        """
        from aegis.core.approval.fingerprint import action_fingerprint

        if lifecycle_decision.stopped:
            return GateIssue(
                decision=lifecycle_decision,
                refused_reason=f"lifecycle refused: {lifecycle_decision.detail}",
            )

        scope_key = self.manager.scope_for(action)

        if self.manager.breaker.state_of(scope_key) is CircuitState.OPEN:
            self._bump_generation(scope_key)
            return GateIssue(
                decision=lifecycle_decision,
                refused_reason=f"the circuit breaker is open for {scope_key}",
            )

        verdict = self.check_restriction(action, accountable_agent=accountable_agent)
        if verdict is not None and not verdict.permitted:
            return GateIssue(
                decision=lifecycle_decision,
                restriction=verdict,
                refused_reason=(
                    f"agent {accountable_agent.agent_id} is quarantined for "
                    f"{verdict.scope_key}: {verdict.reason}"
                ),
            )

        counters = self.manager.counters
        gate = self._register.issue(
            incident_id=action.incident_id,
            action_id=action.action_id,
            action_fingerprint=action_fingerprint(action),
            capability_id=action.capability,
            resource=action.target_resource,
            lifecycle_scope=scope_key,
            lifecycle_decision=lifecycle_decision.action.value,
            lifecycle_state=str(getattr(incident_state, "value", incident_state)),
            breaker_state=self.manager.breaker.state_of(scope_key),
            lifecycle_generation=self._generation_of(scope_key),
            steps_used=counters.steps_used,
            remediation_attempts=counters.remediation_attempts,
            execution_count=counters.execution_count,
        )
        return GateIssue(gate=gate, decision=lifecycle_decision, restriction=verdict)

    def check_restriction(
        self, action: Action, *, accountable_agent: Agent
    ) -> RestrictionVerdict | None:
        """Whether the accountable agent may keep participating. Never "is this allowed"."""
        if self.restrictions is None:
            return None
        return self.restrictions.check(
            accountable_agent.agent_id,
            capability=action.capability,
            resource=action.target_resource,
        )

    # --- recording ------------------------------------------------------------------

    def record_outcome(
        self,
        action: Action,
        *,
        accountable_agent: Agent,
        execution_outcome: object,
        verification_status: object,
        verification_id: str | None = None,
    ):
        """Feed one completed remediation to the breaker and to agent accounting.

        Both are told the same classified outcome, and each draws its own conclusion: the
        breaker about the path, the restriction registry about the actor. Attribution uses
        ``accountable_agent.agent_id`` and the *action's* capability and resource, so a
        model cannot redirect the blame by describing the work differently.
        """
        snapshot = self.manager.record_outcome(
            action,
            execution_outcome=execution_outcome,
            verification_status=verification_status,
            verification_id=verification_id,
        )
        scope_key = self.manager.scope_for(action)
        if snapshot.state is CircuitState.OPEN:
            self._bump_generation(scope_key)

        if self.restrictions is not None:
            from aegis.lifecycle.conditions import classify_execution, classify_verification

            execution_class = classify_execution(execution_outcome)
            verification_class = classify_verification(verification_status)
            if execution_class is not FailureClass.NONE:
                self.restrictions.record_failure(
                    accountable_agent.agent_id,
                    execution_class,
                    capability=action.capability,
                    resource=action.target_resource,
                    reason=f"execution reported {execution_outcome}",
                )
            if verification_class is not FailureClass.NONE:
                self.restrictions.record_failure(
                    accountable_agent.agent_id,
                    verification_class,
                    capability=action.capability,
                    resource=action.target_resource,
                    reason=f"verification reported {verification_status}",
                )
            if execution_class is FailureClass.NONE and verification_class is FailureClass.NONE:
                self.restrictions.record_failure(
                    accountable_agent.agent_id,
                    FailureClass.NONE,
                    capability=action.capability,
                    resource=action.target_resource,
                )
        return snapshot

    def record_governance_anomaly(
        self, action: Action, *, accountable_agent: Agent, **artifacts
    ) -> tuple[str, ...]:
        """Detect anomalies and attribute any found to the accountable agent."""
        anomalies = self.manager.record_governance_anomaly(action, **artifacts)
        if anomalies:
            scope_key = self.manager.scope_for(action)
            self._bump_generation(scope_key)
            if self.restrictions is not None:
                self.restrictions.record_failure(
                    accountable_agent.agent_id,
                    FailureClass.GOVERNANCE_ANOMALY,
                    capability=action.capability,
                    resource=action.target_resource,
                    reason=", ".join(anomalies),
                )
        return anomalies

    def __repr__(self) -> str:
        return f"{type(self).__name__}(register={self._register!r})"
