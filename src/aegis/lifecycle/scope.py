"""Resource scope verification: a pre-execution gate on agent x capability x resource.

The question
------------

Before any production mutation executes, one additional deterministic question must be
answered:

    Does the action's target_resource fall inside the scope declared by the capability?

This is already checked by the policy engine (which reads ``Capability.resource_scope``),
but the coordinator asks it again immediately before issuing the lifecycle gate. Two
independent checks on different code paths mean a regression in one does not silently
authorize out-of-scope execution.

Why here
--------

The policy engine's answer was given at proposal time. Between proposal and execution,
nothing should have changed — but "nothing should" is a convention and a policy bug could
make it wrong. Checking again at the gate is the independent verification principle
applied to scope authorization instead of enterprise state.

What this is not
----------------

It is not a second policy engine. It makes no risk decision, sets no blast radius, grants
no approval, and creates no authorization. It answers one yes/no question and produces a
:class:`ScopeVerdict`. A DENY from this check is a gate refusal; the coordinator routes
it into escalation exactly as it routes other gate refusals.
"""

from __future__ import annotations

from enum import StrEnum

from aegis.core.capabilities import CapabilityRegistry
from aegis.core.domain import Action, Agent, DomainModel, NonEmptyStr

__all__ = ["ResourceScopeDecision", "ResourceScopeVerdict", "ResourceScopeVerifier"]


class ResourceScopeDecision(StrEnum):
    """Whether the action's resource is within the capability's declared scope."""

    ALLOW = "ALLOW"
    """The resource is in scope. The gate may proceed."""

    DENY = "DENY"
    """The resource is out of scope. The gate must be refused."""


class ResourceScopeVerdict(DomainModel):
    """The result of one scope check."""

    decision: ResourceScopeDecision
    detail: NonEmptyStr
    capability_id: NonEmptyStr
    target_resource: NonEmptyStr
    agent_id: NonEmptyStr

    @property
    def allowed(self) -> bool:
        return self.decision is ResourceScopeDecision.ALLOW

    @property
    def denied(self) -> bool:
        return self.decision is ResourceScopeDecision.DENY

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({self.decision} "
            f"{self.agent_id!r} x {self.capability_id!r} → {self.target_resource!r})"
        )


class ResourceScopeVerifier:
    """Deterministic pre-execution scope check.

    Args:
        capability_registry: The authoritative capability definitions.

    Instantiate once and reuse — it holds no mutable state.
    """

    def __init__(self, capability_registry: CapabilityRegistry) -> None:
        self._registry = capability_registry

    def verify(self, action: Action, accountable_agent: Agent) -> ResourceScopeVerdict:
        """Check that the action's resource is in the capability's declared scope.

        Args:
            action: The action about to execute. Reads ``capability`` and
                ``target_resource`` from the authoritative action record, never from
                model-supplied fields.
            accountable_agent: The agent the action will be attributed to.

        Returns:
            ALLOW if the resource is in scope, DENY otherwise.
        """
        capability_id = action.capability
        target_resource = action.target_resource

        # Unknown capability: deny (fail-closed — unknown scope is no scope)
        if not self._registry.exists(capability_id):
            return ResourceScopeVerdict(
                decision=ResourceScopeDecision.DENY,
                detail=(
                    f"capability {capability_id!r} is not registered; "
                    f"resource scope cannot be verified"
                ),
                capability_id=capability_id,
                target_resource=target_resource,
                agent_id=accountable_agent.agent_id,
            )

        # Agent not authorized for the capability: deny
        if not self._registry.has_capability(accountable_agent, capability_id):
            return ResourceScopeVerdict(
                decision=ResourceScopeDecision.DENY,
                detail=(
                    f"agent {accountable_agent.agent_id!r} does not hold "
                    f"capability {capability_id!r}"
                ),
                capability_id=capability_id,
                target_resource=target_resource,
                agent_id=accountable_agent.agent_id,
            )

        # Resource not in scope: deny
        if not self._registry.resource_in_scope(capability_id, target_resource):
            capability = self._registry.get(capability_id)
            declared_scope = ", ".join(sorted(capability.resource_scope)) or "(empty)"
            return ResourceScopeVerdict(
                decision=ResourceScopeDecision.DENY,
                detail=(
                    f"resource {target_resource!r} is not in the declared scope of "
                    f"capability {capability_id!r}; declared: [{declared_scope}]"
                ),
                capability_id=capability_id,
                target_resource=target_resource,
                agent_id=accountable_agent.agent_id,
            )

        return ResourceScopeVerdict(
            decision=ResourceScopeDecision.ALLOW,
            detail=(
                f"resource {target_resource!r} is within the declared scope of "
                f"capability {capability_id!r} for agent {accountable_agent.agent_id!r}"
            ),
            capability_id=capability_id,
            target_resource=target_resource,
            agent_id=accountable_agent.agent_id,
        )
