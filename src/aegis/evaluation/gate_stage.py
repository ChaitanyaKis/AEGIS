"""Benchmark control group for the execution boundary.

Everything here exists to *attack* the lifecycle gate, so the benchmark can measure whether
the boundary holds rather than assert that it does. Each tamper is applied to what reaches
the real :class:`~aegis.enterprise.ActionExecutor` — the executor itself is never replaced,
because a test that swapped it out would be measuring the substitute.

None of these can cause an execution. That is the point, and the scenarios that use them
assert it against the world rather than against anything the lifecycle reported.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from aegis.core.approval.fingerprint import action_fingerprint
from aegis.evaluation.scenario import GateTamper, Scenario
from aegis.lifecycle import FailureClass, LifecycleGate, gate_seal

__all__ = ["TamperingExecutor", "seed_restrictions", "unrelated_scopes_clear"]

UNRELATED_AGENTS = ("commander", "diagnostic", "security", "business-impact")
UNRELATED_CAPABILITIES = ("production.scale", "customer.notify")
UNRELATED_RESOURCES = ("service:order-service", "service:auth", "db:customer-database")


class TamperingExecutor:
    """Wraps the real executor and interferes with the gate on its way in.

    **BENCHMARK CONTROL GROUP.** It has no power of its own: it cannot execute, cannot
    forge an authorization, and cannot reach the register. All it does is decide what gate
    the executor is handed — which is exactly the surface a caller trying to bypass the
    lifecycle would have.
    """

    def __init__(self, inner, tamper: GateTamper, *, clock: Callable[[], datetime]) -> None:
        self._inner = inner
        self._tamper = tamper
        self._clock = clock
        self._spent: LifecycleGate | None = None

    @property
    def world(self):
        return self._inner.world

    def execute(self, action, authorization, *, at=None, gate=None):
        """Hand the real executor a gate the scenario chose, and let it refuse."""
        return self._inner.execute(
            action, authorization, at=at, gate=self._substitute(action, gate)
        )

    def _substitute(self, action, gate: LifecycleGate | None) -> LifecycleGate | None:
        tamper = self._tamper
        if gate is None or tamper is GateTamper.NONE:
            return gate
        if tamper is GateTamper.DROP:
            return None
        if tamper is GateTamper.REPLAY:
            # Reuse the previous gate; on the first execution there is nothing to replay,
            # so the run proceeds and the second attempt is the one that is refused.
            replayed = self._spent or gate
            self._spent = gate
            return replayed
        if tamper is GateTamper.EXPIRE:
            return _reseal(gate, issued_at=gate.issued_at - timedelta(days=1))
        if tamper is GateTamper.TAMPER:
            # Altered and *not* resealed: the crude tamper, caught by the seal.
            return gate.model_copy(update={"steps_used": gate.steps_used + 99})
        if tamper is GateTamper.FORGE:
            return _forge(action, gate)
        if tamper is GateTamper.WRONG_ACTION:
            return _reseal(gate, action_id="act-somewhere-else")
        if tamper is GateTamper.WRONG_INCIDENT:
            return _reseal(gate, incident_id="INC-somewhere-else")
        if tamper is GateTamper.WRONG_FINGERPRINT:
            return _reseal(gate, action_fingerprint="f" * 64)
        if tamper is GateTamper.WRONG_SCOPE:
            return _reseal(gate, lifecycle_scope="production.scale@service:auth")
        return gate

    def __repr__(self) -> str:
        return f"{type(self).__name__}(tamper={self._tamper})"


def _reseal(gate: LifecycleGate, **updates) -> LifecycleGate:
    """Alter a binding and recompute the seal — the attacker who reads the source.

    The seal formula is public, so an interesting attacker reseals. What they cannot do is
    put the result into the issuer's register, which is where authenticity actually lives.
    """
    changed = gate.model_copy(update=updates)
    return changed.model_copy(update={"seal": gate_seal(changed)})


def _forge(action, template: LifecycleGate) -> LifecycleGate:
    """A gate built from scratch, correctly sealed, that no register ever issued."""
    draft = LifecycleGate(
        gate_id="gate-forged-by-the-benchmark",
        incident_id=action.incident_id,
        action_id=action.action_id,
        action_fingerprint=action_fingerprint(action),
        capability_id=action.capability,
        resource=action.target_resource,
        lifecycle_scope=template.lifecycle_scope,
        lifecycle_decision="CONTINUE",
        lifecycle_state=template.lifecycle_state,
        breaker_state=template.breaker_state,
        lifecycle_generation=template.lifecycle_generation,
        steps_used=template.steps_used,
        remediation_attempts=template.remediation_attempts,
        execution_count=template.execution_count,
        issued_at=template.issued_at,
        seal="0" * 64,
    )
    return draft.model_copy(update={"seal": gate_seal(draft)})


def seed_restrictions(registry, scenario: Scenario) -> None:
    """Quarantine the scenario's declared agent, through the real accounting path.

    Driven to the threshold rather than set directly, so the arrangement exercises the same
    route production takes. A scenario that could stamp a quarantine into place would be
    testing a state the system might have no way of reaching.
    """
    agent_id = scenario.pre_quarantined_agent
    if not agent_id:
        return
    threshold = registry.config.execution_failure_threshold
    for _ in range(threshold):
        registry.record_failure(
            agent_id,
            FailureClass.EXECUTION_FAILURE,
            capability="production.rollback",
            resource=scenario.affected_resource,
            reason="failed repeatedly in earlier incidents",
        )


def unrelated_scopes_clear(registry, scenario: Scenario) -> bool:
    """Whether containment stayed inside its scope.

    Sweeps agents, capabilities and resources the scenario never touched. Containment that
    leaks is the denial-of-service it was built to prevent, so this is checked on every
    scenario that uses restrictions rather than only on the isolation cases.
    """
    if registry is None:
        return True
    quarantined = scenario.pre_quarantined_agent
    for agent_id in UNRELATED_AGENTS:
        if agent_id == quarantined:
            continue
        for capability in UNRELATED_CAPABILITIES:
            for resource in UNRELATED_RESOURCES:
                if not registry.check(agent_id, capability=capability, resource=resource).permitted:
                    return False
    for capability in UNRELATED_CAPABILITIES:
        for resource in UNRELATED_RESOURCES:
            if not registry.check(
                "remediation", capability=capability, resource=resource
            ).permitted:
                return False
    return True
