"""Agent abuse containment: restricting *who* may keep participating, never *what* is allowed.

The problem this solves (Prompt 12, §10): an agent that repeatedly proposes actions it knows
will fail can open a capability@resource breaker and deny that automation to everyone. The
circuit breaker cannot tell the difference between a genuinely broken service and an agent
manufacturing failures against a healthy one, because it is scoped to the *path*, not the
actor.

So this is a second, deliberately separate mechanism:

    CIRCUIT BREAKER          protects a capability@resource from repeated failure
    AGENT RESTRICTION        protects the system from an agent causing repeated failures

They are kept apart because they answer different questions and must be able to disagree.
A genuinely broken service should open a breaker without blaming the agent that reported it;
an agent failing against three healthy services should be restricted without disabling any
of them.

Restriction is not authorization
--------------------------------

This is the line that matters. Restriction never answers *"is this action allowed?"* — the
policy engine answers that, and nothing here can change its answer. Restriction answers only
*"is this accountable agent currently permitted to keep participating in governed
automation?"*

A non-quarantined agent still needs proposal authority, assessment, policy, approval, a
lifecycle gate, an execution authorization, execution and verification. Restriction removes
a participant; it never adds a permission, and an ACTIVE agent is not thereby entitled to
anything.

Identity is authoritative, never claimed
----------------------------------------

Everything here is keyed on the accountable agent identity the orchestrator holds — the
registered :class:`~aegis.core.domain.Agent` record — and never on anything a model
produced. A model that names itself ``remediation`` while the accountable identity is
``commander`` is attributed to ``commander``, because the identity comes from the wiring
rather than from the text.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from enum import StrEnum

from pydantic import Field

from aegis.core.domain import AgentRef, DomainModel, NonEmptyStr, Timestamp, utc_now
from aegis.lifecycle.conditions import FailureClass

__all__ = [
    "DEFAULT_RESTRICTION_CONFIG",
    "AgentRestriction",
    "AgentRestrictionConfig",
    "AgentRestrictionRegistry",
    "RestrictionScope",
    "RestrictionVerdict",
]


class AgentRestriction(StrEnum):
    """Whether an accountable agent may keep participating.

    Two states, outside :class:`~aegis.core.domain.IncidentState` and outside
    :class:`~aegis.core.domain.AgentLifecycleState`. The domain enums describe an
    incident's progress and an agent's registration standing; this describes a *runtime
    availability* decision made from observed failures, which is a third thing.
    """

    ACTIVE = "ACTIVE"
    """Participating normally. Not a permission — every gate downstream still applies."""

    QUARANTINED = "QUARANTINED"
    """Barred from participating in governed automation for this scope.

    An availability restriction. It removes a participant; it never grants anything, and
    it never overrides a policy decision in either direction.
    """


class RestrictionScope(StrEnum):
    """What restriction counters are keyed by.

    The trade-off is stated once here rather than rediscovered per deployment. Too wide and
    one agent's bad afternoon disables unrelated safe work; too narrow and an agent failing
    everywhere is never contained.
    """

    AGENT_CAPABILITY_RESOURCE = "AGENT_CAPABILITY_RESOURCE"
    """``agent@capability@resource`` — the default, and the narrowest that contains anything.

    An agent failing repeatedly at rolling back payment-api is restricted from *that*, and
    stays free to roll back order-service or to scale payment-api. Chosen as the default
    because a containment mechanism that over-reaches is itself a denial-of-service: the
    cure would have the same shape as the disease.
    """

    AGENT_CAPABILITY = "AGENT_CAPABILITY"
    """``agent@capability`` — every resource. For an agent that cannot be trusted with a
    capability at all."""

    AGENT = "AGENT"
    """``agent`` — everything it does. The widest per-agent scope; a deliberate escalation,
    never the default."""


class AgentRestrictionConfig(DomainModel):
    """When an accountable agent becomes quarantined. Explicit, frozen configuration.

    Thresholds per failure class, like the breaker's, and for the same reason: repeated
    execution failures, repeated verification failures and governance anomalies are
    different pathologies, and one combined counter could quarantine on a mixture that
    means nothing in particular.
    """

    execution_failure_threshold: int = Field(default=3, ge=1)
    verification_failure_threshold: int = Field(default=3, ge=1)
    governance_anomaly_threshold: int = Field(default=2, ge=1)
    """Two rather than the breaker's one.

    The breaker's job is to stop a *path* the instant something impossible happens, and
    stopping a path is cheap. Quarantining an agent removes a participant from every
    incident it would have handled, so it waits for a second occurrence — enough to
    distinguish a corrupted run from a pattern.
    """

    scope: RestrictionScope = RestrictionScope.AGENT_CAPABILITY_RESOURCE

    quarantine_cooldown_seconds: float | None = Field(default=None, gt=0.0)
    """Optional automatic release. ``None`` by default: a quarantined agent stays
    quarantined until an operator acts.

    Deliberately not time-decayed. An agent restricted for causing governance anomalies is
    not made trustworthy by the passage of time, and a containment that expires on its own
    is one an attacker can simply wait out.
    """


DEFAULT_RESTRICTION_CONFIG = AgentRestrictionConfig()
"""Used when a caller supplies none. Narrow scope, conservative thresholds."""


class RestrictionVerdict(DomainModel):
    """The answer to "may this agent keep participating?" — never "is this allowed?"."""

    agent_id: AgentRef
    scope_key: NonEmptyStr
    restriction: AgentRestriction
    permitted: bool
    reason: NonEmptyStr
    failure_counts: Mapping[str, int] = Field(default_factory=dict)
    quarantined_at: Timestamp | None = None
    trip_class: FailureClass | None = None

    @property
    def quarantined(self) -> bool:
        return self.restriction is AgentRestriction.QUARANTINED


class _AgentState:
    """Mutable per-scope bookkeeping. Never handed out — callers get verdicts."""

    __slots__ = ("counts", "quarantined_at", "reason", "restriction", "trip_class")

    def __init__(self) -> None:
        self.counts: dict[FailureClass, int] = {}
        self.restriction = AgentRestriction.ACTIVE
        self.quarantined_at: datetime | None = None
        self.reason: str | None = None
        self.trip_class: FailureClass | None = None


_THRESHOLD_FIELD: dict[FailureClass, str] = {
    FailureClass.EXECUTION_FAILURE: "execution_failure_threshold",
    FailureClass.VERIFICATION_FAILURE: "verification_failure_threshold",
    FailureClass.STALE_VERIFICATION: "verification_failure_threshold",
    FailureClass.INSUFFICIENT_EVIDENCE: "verification_failure_threshold",
    FailureClass.VERIFICATION_MISMATCH: "verification_failure_threshold",
    FailureClass.GOVERNANCE_ANOMALY: "governance_anomaly_threshold",
}
"""Which configured threshold governs which failure class.

Every verification-flavoured class shares one threshold here, unlike the breaker which
separates them. The distinction the breaker draws is diagnostic — *which pipeline broke* —
and that question is about the path, not the actor. From the actor's side they are all
"this agent proposed something that did not work".
"""


class AgentRestrictionRegistry:
    """Deterministic, agent-scoped failure accounting and quarantine.

    Args:
        config: Thresholds and scope. Frozen, operator-supplied, unreachable from any model.
        clock: Injected, so quarantine timestamps are reproducible.

    Nothing here is reachable from model output. There is no method an agent can call, no
    field in a :class:`~aegis.agents.decisions.CommanderDecision` that names a threshold,
    and no way to clear a quarantine from inside the agent plane — asserted structurally.
    """

    def __init__(
        self,
        config: AgentRestrictionConfig | None = None,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.config = config if config is not None else DEFAULT_RESTRICTION_CONFIG
        self._clock = clock
        self._scopes: dict[str, _AgentState] = {}

    # --- scoping --------------------------------------------------------------------

    def key_for(
        self, agent_id: str, *, capability: str | None = None, resource: str | None = None
    ) -> str:
        """The counter key for one accountable agent under the configured scope.

        Deterministic and total: a missing component renders as ``*`` rather than raising,
        so a partially-specified action still lands in a stable bucket instead of escaping
        accounting altogether.
        """
        capability = capability or "*"
        resource = resource or "*"
        if self.config.scope is RestrictionScope.AGENT:
            return agent_id
        if self.config.scope is RestrictionScope.AGENT_CAPABILITY:
            return f"{agent_id}@{capability}"
        return f"{agent_id}@{capability}@{resource}"

    # --- the question this component answers ----------------------------------------

    def check(
        self, agent_id: str, *, capability: str | None = None, resource: str | None = None
    ) -> RestrictionVerdict:
        """May this accountable agent keep participating in governed automation?

        Never "is this action allowed". A ``permitted=True`` verdict is the absence of a
        restriction, not the presence of a permission: policy, approval, the lifecycle gate
        and the execution authorization all still apply, and any of them can refuse.
        """
        key = self.key_for(agent_id, capability=capability, resource=resource)
        state = self._scopes.get(key)
        if state is None or state.restriction is AgentRestriction.ACTIVE:
            self._release_if_due(state)
        state = self._scopes.get(key)

        if state is None:
            return RestrictionVerdict(
                agent_id=agent_id,
                scope_key=key,
                restriction=AgentRestriction.ACTIVE,
                permitted=True,
                reason="no restriction on this agent for this scope",
            )
        if state.restriction is AgentRestriction.QUARANTINED and self._cooldown_elapsed(state):
            self._release(state)

        permitted = state.restriction is AgentRestriction.ACTIVE
        return RestrictionVerdict(
            agent_id=agent_id,
            scope_key=key,
            restriction=state.restriction,
            permitted=permitted,
            reason=(
                state.reason or "quarantined"
                if not permitted
                else "no restriction on this agent for this scope"
            ),
            failure_counts={cls.value: n for cls, n in sorted(state.counts.items())},
            quarantined_at=state.quarantined_at,
            trip_class=state.trip_class,
        )

    def restriction_of(
        self, agent_id: str, *, capability: str | None = None, resource: str | None = None
    ) -> AgentRestriction:
        return self.check(agent_id, capability=capability, resource=resource).restriction

    # --- recording ------------------------------------------------------------------

    def record_failure(
        self,
        agent_id: str,
        failure_class: FailureClass,
        *,
        capability: str | None = None,
        resource: str | None = None,
        reason: str = "",
    ) -> RestrictionVerdict:
        """Attribute one classified failure to an accountable agent.

        ``agent_id`` must already be the authoritative identity; this class has no way to
        check that and does not try. The binding is enforced where it can be — at the
        coordinator, which reads the identity from the registered agent record rather than
        from anything a model said.

        ``FailureClass.NONE`` clears the counters for the scope: a verified success is
        evidence the agent can do this, and is the only thing that clears them. It never
        releases an existing quarantine, because a quarantined agent does not get to
        succeed its way out — it cannot participate in the first place.
        """
        key = self.key_for(agent_id, capability=capability, resource=resource)
        state = self._scopes.setdefault(key, _AgentState())

        if failure_class is FailureClass.NONE:
            if state.restriction is AgentRestriction.ACTIVE:
                state.counts.clear()
            return self.check(agent_id, capability=capability, resource=resource)

        state.counts[failure_class] = state.counts.get(failure_class, 0) + 1
        field = _THRESHOLD_FIELD.get(failure_class)
        if field is None:
            return self.check(agent_id, capability=capability, resource=resource)

        threshold = getattr(self.config, field)
        if (
            state.counts[failure_class] >= threshold
            and state.restriction is AgentRestriction.ACTIVE
        ):
            state.restriction = AgentRestriction.QUARANTINED
            state.quarantined_at = self._clock()
            state.trip_class = failure_class
            state.reason = (
                f"{failure_class} reached its threshold of {threshold} for {key}"
                f"{f': {reason}' if reason else ''}"
            )
        return self.check(agent_id, capability=capability, resource=resource)

    # --- release --------------------------------------------------------------------

    def _cooldown_elapsed(self, state: _AgentState) -> bool:
        cooldown = self.config.quarantine_cooldown_seconds
        if cooldown is None or state.quarantined_at is None:
            return False
        return (self._clock() - state.quarantined_at).total_seconds() >= cooldown

    def _release_if_due(self, state: _AgentState | None) -> None:
        if (
            state is not None
            and state.restriction is AgentRestriction.QUARANTINED
            and self._cooldown_elapsed(state)
        ):
            self._release(state)

    def _release(self, state: _AgentState) -> None:
        """Return a scope to ACTIVE. Reachable only from an elapsed configured cooldown.

        There is deliberately no public ``clear``, ``release`` or ``reset``: a method that
        lifted a quarantine on request is exactly what a compromised agent would look for,
        and one that exists can be called.
        """
        state.restriction = AgentRestriction.ACTIVE
        state.counts.clear()
        state.quarantined_at = None
        state.reason = None
        state.trip_class = None

    def __repr__(self) -> str:
        quarantined = sum(
            1
            for state in self._scopes.values()
            if state.restriction is AgentRestriction.QUARANTINED
        )
        return f"{type(self).__name__}(scope={self.config.scope}, quarantined={quarantined})"
