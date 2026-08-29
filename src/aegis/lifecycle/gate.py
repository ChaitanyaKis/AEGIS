"""The lifecycle gate: proof that governance was crossed, and nothing more.

Prompt 12 left the lifecycle manager as a collaborator the orchestrator *chose* to call.
Nothing forced the calls, so "the orchestrator does not bypass the lifecycle" was a
discipline boundary held up by tests and review. This module turns it into a structural
one: the executor refuses a production mutation that arrives without a gate, so bypassing
the lifecycle is no longer something a caller can simply neglect to do.

What a gate is
--------------

Evidence, addressed to one exact execution. It proves four things and asserts nothing else:

* lifecycle limits were checked;
* breaker state was checked;
* the required lifecycle stage was reached;
* **this gate applies to this exact execution** — same incident, same action, same
  fingerprint, same capability, same resource, same breaker scope.

What a gate is not
------------------

**It is not authorization.** It carries no policy decision, no approval, no risk, no blast
radius and no verification. Holding one entitles a caller to nothing: the executor demands
an :class:`~aegis.core.approval.ExecutionAuthorization` as well, and that authorization is
still the thing a human granted. A gate without an authorization executes nothing, and an
authorization without a gate executes nothing. Two independent artifacts, two independent
origins, and neither is sufficient.

Unforgeability, honestly
------------------------

A gate carries a deterministic seal over its bound fields, so altering any binding is
detectable. That is integrity, not authenticity — the seal formula is in this file, and
anything running in this process can compute it.

Authenticity comes from somewhere the attacker cannot recompute: the issuer's own register
of gates it actually handed out. :class:`GateRegister` is created and held by the
coordinator, and a gate is valid only if that register issued it and has not yet consumed
it. A hand-built gate with a perfect seal still fails, because no register ever issued it.

This does not stop code that can reach the coordinator's register from asking it for a
gate. Nothing in-process can. What it stops is the far more likely failure: a caller
reaching the executor directly and skipping the lifecycle entirely.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime, timedelta

from pydantic import Field

from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp, to_json, utc_now
from aegis.lifecycle.errors import LifecycleGateRejected
from aegis.lifecycle.state import CircuitState

__all__ = [
    "DEFAULT_GATE_TTL_SECONDS",
    "GateRegister",
    "GateRejection",
    "LifecycleGate",
    "gate_seal",
]

DEFAULT_GATE_TTL_SECONDS = 60.0
"""How long a gate stays usable. Short on purpose.

A gate is issued moments before execution in the same governed sequence, so a minute is
generous. The point of a bound at all is that a gate found lying around later — in a log, a
retry queue, a serialized run — is already dead.
"""


class GateRejection(DomainModel):
    """Why a gate was refused. A value, so a refusal is reportable and auditable."""

    gate_id: NonEmptyStr
    reason: NonEmptyStr
    check: NonEmptyStr
    """The named binding that failed, e.g. ``action_binding``. Machine-readable so a
    caller can branch without parsing prose."""


class LifecycleGate(DomainModel):
    """Frozen, bound, single-use proof that the lifecycle gate was satisfied.

    Every field is a binding. Together they say "this and only this execution", which is
    what makes a gate useless for anything other than the execution it was issued for.
    """

    gate_id: Identifier
    incident_id: Identifier
    action_id: Identifier
    action_fingerprint: str = Field(min_length=64, max_length=64)
    capability_id: NonEmptyStr
    resource: NonEmptyStr
    lifecycle_scope: NonEmptyStr
    """The breaker scope key this execution falls under."""

    lifecycle_decision: NonEmptyStr
    """The lifecycle manager's verdict, recorded for audit. Not a permission — the only
    verdict that reaches here is CONTINUE, and CONTINUE means "nothing objects"."""

    lifecycle_state: NonEmptyStr
    """The incident state when the gate was issued."""

    breaker_state: CircuitState
    lifecycle_generation: int = Field(ge=0)
    """Which generation of lifecycle state this gate was issued against.

    Bumped whenever the breaker for a scope opens. A gate issued before an intervening
    open is stale by construction, which is what catches "the breaker reopened between
    the gate and the execution" even if the timestamp has not moved.
    """

    steps_used: int = Field(ge=0)
    remediation_attempts: int = Field(ge=0)
    execution_count: int = Field(ge=0)
    issued_at: Timestamp
    seal: str = Field(min_length=64, max_length=64)
    """Deterministic digest over every binding. Detects modification; see the module
    docstring for why it is integrity rather than authenticity."""

    def rebind_check(self) -> bool:
        """Whether the seal still matches the bindings."""
        return self.seal == gate_seal(self)


def gate_seal(gate: LifecycleGate) -> str:
    """The seal a gate should carry, as 64 lowercase hex characters.

    Covers every binding. A structured document is hashed rather than concatenated
    strings, so no field value can be crafted to imitate a field boundary, and
    canonicalisation is the project's existing :func:`~aegis.core.domain.to_json`, so a
    gate seals identically across processes and runs.
    """
    document = to_json(
        _SealPayload(
            action_fingerprint=gate.action_fingerprint,
            action_id=gate.action_id,
            breaker_state=gate.breaker_state,
            capability_id=gate.capability_id,
            execution_count=gate.execution_count,
            gate_id=gate.gate_id,
            incident_id=gate.incident_id,
            issued_at=gate.issued_at,
            lifecycle_decision=gate.lifecycle_decision,
            lifecycle_generation=gate.lifecycle_generation,
            lifecycle_scope=gate.lifecycle_scope,
            lifecycle_state=gate.lifecycle_state,
            remediation_attempts=gate.remediation_attempts,
            resource=gate.resource,
            steps_used=gate.steps_used,
        )
    )
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


class _SealPayload(DomainModel):
    """Exactly the fields the seal covers.

    A declared model rather than an ad-hoc dict, so adding a binding without sealing it is
    a visible code change with a test behind it.
    """

    action_fingerprint: str
    action_id: NonEmptyStr
    breaker_state: CircuitState
    capability_id: NonEmptyStr
    execution_count: int
    gate_id: NonEmptyStr
    incident_id: NonEmptyStr
    issued_at: Timestamp
    lifecycle_decision: NonEmptyStr
    lifecycle_generation: int
    lifecycle_scope: NonEmptyStr
    lifecycle_state: NonEmptyStr
    remediation_attempts: int
    resource: NonEmptyStr
    steps_used: int


class GateRegister:
    """The issuer's record of gates it handed out, and the only source of authenticity.

    Held by :class:`~aegis.lifecycle.coordinator.LifecycleCoordinator` and handed to the
    executor as a verifier. The executor cannot issue; it can only ask whether this
    register issued a gate and has not spent it.

    Args:
        clock: Injected, so expiry is deterministic.
        ttl_seconds: How long a gate stays usable. ``None`` disables expiry, which is
            available for tests and never the default.
        breaker_state: How to read the current circuit state for a scope. A callable
            rather than the breaker itself, so this class cannot reach anything else on it
            — it can ask one question and take one answer.
        generation: How to read the current lifecycle generation for a scope.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = utc_now,
        ttl_seconds: float | None = DEFAULT_GATE_TTL_SECONDS,
        breaker_state: Callable[[str], CircuitState] | None = None,
        generation: Callable[[str], int] | None = None,
    ) -> None:
        self._clock = clock
        self._ttl = ttl_seconds
        self._breaker_state = breaker_state
        self._generation = generation
        self._issued: dict[str, LifecycleGate] = {}
        self._consumed: set[str] = set()
        self._sequence = 0

    # --- issuing --------------------------------------------------------------------

    def issue(self, **bindings) -> LifecycleGate:
        """Mint one gate. **Only the coordinator should hold a reference to this.**

        The gate id is deterministic — incident, action and a per-register sequence — so
        two identical runs produce byte-identical artifacts. Unpredictability is not what
        makes a gate unforgeable; being in this register is.
        """
        incident_id = bindings["incident_id"]
        action_id = bindings["action_id"]
        gate_id = f"gate-{incident_id}-{action_id}-{self._sequence}"
        self._sequence += 1

        draft = LifecycleGate(
            gate_id=gate_id,
            issued_at=self._clock(),
            seal="0" * 64,
            **bindings,
        )
        gate = draft.model_copy(update={"seal": gate_seal(draft)})
        self._issued[gate.gate_id] = gate
        return gate

    # --- verifying ------------------------------------------------------------------

    def validate(self, gate: LifecycleGate, action) -> GateRejection | None:
        """Check every binding without consuming. Returns the first failure, or ``None``.

        Order matters only for which reason is reported; every check is independent.
        """
        if not gate.rebind_check():
            return GateRejection(
                gate_id=gate.gate_id, check="seal", reason="the gate's bindings were altered"
            )

        issued = self._issued.get(gate.gate_id)
        if issued is None:
            return GateRejection(
                gate_id=gate.gate_id,
                check="issuer",
                reason="no lifecycle coordinator issued this gate",
            )
        if issued != gate:
            return GateRejection(
                gate_id=gate.gate_id,
                check="issuer",
                reason="the gate does not match the one that was issued",
            )
        if gate.gate_id in self._consumed:
            return GateRejection(
                gate_id=gate.gate_id, check="replay", reason="the gate was already consumed"
            )

        if gate.action_id != action.action_id:
            return GateRejection(
                gate_id=gate.gate_id,
                check="action_binding",
                reason=f"the gate was issued for action {gate.action_id}",
            )
        if gate.incident_id != action.incident_id:
            return GateRejection(
                gate_id=gate.gate_id,
                check="incident_binding",
                reason=f"the gate was issued for incident {gate.incident_id}",
            )
        if gate.capability_id != action.capability:
            return GateRejection(
                gate_id=gate.gate_id,
                check="capability_binding",
                reason=f"the gate was issued for capability {gate.capability_id}",
            )
        if gate.resource != action.target_resource:
            return GateRejection(
                gate_id=gate.gate_id,
                check="resource_binding",
                reason=f"the gate was issued for resource {gate.resource}",
            )

        from aegis.core.approval.fingerprint import action_fingerprint

        if gate.action_fingerprint != action_fingerprint(action):
            return GateRejection(
                gate_id=gate.gate_id,
                check="fingerprint_binding",
                reason="the gate does not match this exact action",
            )

        if self._ttl is not None:
            age = (self._clock() - gate.issued_at).total_seconds()
            if age >= self._ttl:
                return GateRejection(
                    gate_id=gate.gate_id,
                    check="expiry",
                    reason=f"the gate is {age:.0f}s old and expires at {self._ttl:.0f}s",
                )

        if self._breaker_state is not None:
            current = self._breaker_state(gate.lifecycle_scope)
            if current is CircuitState.OPEN:
                return GateRejection(
                    gate_id=gate.gate_id,
                    check="breaker_state",
                    reason="the breaker opened after this gate was issued",
                )

        if self._generation is not None:
            current_generation = self._generation(gate.lifecycle_scope)
            if current_generation != gate.lifecycle_generation:
                return GateRejection(
                    gate_id=gate.gate_id,
                    check="lifecycle_generation",
                    reason=(
                        f"lifecycle state moved on: the gate is generation "
                        f"{gate.lifecycle_generation}, current is {current_generation}"
                    ),
                )

        return None

    def consume(self, gate: LifecycleGate, action) -> LifecycleGate:
        """Validate and spend a gate. The only route to a usable gate at the executor.

        Raises:
            LifecycleGateRejected: naming the binding that failed. Raising rather than
                returning a value is deliberate here: an executor that ignored a returned
                refusal would execute anyway, and a refusal that can be ignored is not a
                boundary.
        """
        rejection = self.validate(gate, action)
        if rejection is not None:
            raise LifecycleGateRejected(rejection)
        self._consumed.add(gate.gate_id)
        return gate

    # --- reading --------------------------------------------------------------------

    def was_issued(self, gate_id: str) -> bool:
        return gate_id in self._issued

    def was_consumed(self, gate_id: str) -> bool:
        return gate_id in self._consumed

    @property
    def issued_count(self) -> int:
        return len(self._issued)

    @property
    def consumed_count(self) -> int:
        return len(self._consumed)

    def expires_at(self, gate: LifecycleGate) -> datetime | None:
        if self._ttl is None:
            return None
        return gate.issued_at + timedelta(seconds=self._ttl)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(issued={len(self._issued)}, consumed={len(self._consumed)})"
