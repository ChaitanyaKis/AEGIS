"""The in-process capability registry.

The authoritative source of capability *definitions* for the running AEGIS process
(``claude.md`` section 6). It resolves ``capability_id`` to a :class:`Capability` and
answers the three deterministic questions the policy engine needs:

* does this capability exist?
* does this agent hold it?
* is this resource inside its declared scope?

Scope
-----

This is a process-local registry, not a persistent production registry and not the
Google Agent Registry. A registry adapter for the latter belongs in
:mod:`aegis.integrations` and does not exist. Nothing here reaches the network,
the filesystem or a model.

Fail-closed by construction
---------------------------

Every method refuses rather than guesses. An unknown capability raises; it never
resolves to a permissive default. A duplicate registration raises; it never overwrites.
An empty ``resource_scope`` or ``allowed_agents`` grants nothing; neither is a wildcard.
"""

from __future__ import annotations

from collections.abc import Iterable

from aegis.core.capabilities.errors import (
    DuplicateCapabilityError,
    UnknownCapabilityError,
)
from aegis.core.domain import Agent, Capability, CapabilityRef, NonEmptyStr

__all__ = ["CapabilityRegistry"]


class CapabilityRegistry:
    """A deterministic, in-memory collection of capability definitions.

    The registry is mutable by design — capabilities are registered at startup — but its
    contents are not: :class:`Capability` is frozen, so a caller holding a returned
    capability cannot mutate registry state through it.

    Determinism: :meth:`list` returns capabilities sorted by ``capability_id``, so
    output does not depend on registration order.
    """

    def __init__(self, capabilities: Iterable[Capability] = ()) -> None:
        self._capabilities: dict[str, Capability] = {}
        for capability in capabilities:
            self.register(capability)

    # --- registration ---------------------------------------------------------------

    def register(self, capability: Capability) -> None:
        """Add a capability definition.

        Raises:
            DuplicateCapabilityError: if the id is already registered. Registration is
                never an overwrite — see :class:`DuplicateCapabilityError`.
        """
        if capability.capability_id in self._capabilities:
            raise DuplicateCapabilityError(capability.capability_id)
        self._capabilities[capability.capability_id] = capability

    # --- resolution -----------------------------------------------------------------

    def get(self, capability_id: CapabilityRef) -> Capability:
        """Resolve a capability id to its definition.

        Raises:
            UnknownCapabilityError: if the id is not registered. An unknown capability is
                never resolved to a permissive default.
        """
        try:
            return self._capabilities[capability_id]
        except KeyError:
            raise UnknownCapabilityError(capability_id) from None

    def exists(self, capability_id: CapabilityRef) -> bool:
        """Whether a capability id is registered."""
        return capability_id in self._capabilities

    def list(self) -> tuple[Capability, ...]:
        """Every registered capability, sorted by ``capability_id``."""
        return tuple(self._capabilities[key] for key in sorted(self._capabilities))

    # --- deterministic questions ----------------------------------------------------

    def has_capability(self, agent: Agent, capability_id: CapabilityRef) -> bool:
        """Whether ``agent`` holds ``capability_id``.

        Ownership is a two-sided declaration and both sides must agree:

        * the agent's ``capabilities`` must list the id — the control plane granted it;
        * the capability's ``allowed_agents`` must list the agent — the capability
          permits that holder.

        Requiring both is the conservative reading: either side alone revoking is enough
        to revoke. An unregistered capability is never held, regardless of what an agent
        record claims.

        Ownership is derived only from these declared references. It is never inferred
        from an agent's name, role, description or any model output.
        """
        capability = self._capabilities.get(capability_id)
        if capability is None:
            return False
        return capability_id in agent.capabilities and agent.agent_id in capability.allowed_agents

    def resource_in_scope(self, capability_id: CapabilityRef, resource: NonEmptyStr) -> bool:
        """Whether ``resource`` is inside the capability's declared ``resource_scope``.

        Matching is **exact string equality** against the entries of ``resource_scope``.
        See :func:`resource_in_scope` for why, and for what this deliberately excludes.

        An unregistered capability scopes nothing and returns ``False``.
        """
        capability = self._capabilities.get(capability_id)
        if capability is None:
            return False
        return resource_in_scope(capability, resource)

    # --- container protocol ---------------------------------------------------------

    def __contains__(self, capability_id: object) -> bool:
        return capability_id in self._capabilities

    def __len__(self) -> int:
        return len(self._capabilities)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({len(self._capabilities)} capabilities)"


def resource_in_scope(capability: Capability, resource: NonEmptyStr) -> bool:
    """Whether ``resource`` is inside ``capability.resource_scope``.

    **Matching is exact string equality.** ``resource_scope`` is a tuple of opaque
    strings in the domain contract; nothing about that representation carries hierarchy,
    so exact match is the simplest deterministic interpretation of it. Documented
    consequences:

    * An empty scope matches nothing. It is not a wildcard.
    * There is no prefix, glob, wildcard or hierarchical matching. A capability scoped to
      ``"service:payment-api"`` does not cover ``"service:payment-api/replica-1"``.
      Widening that is a deliberate future change to the scope model, not a quiet
      relaxation of this function.
    * There is no fuzzy matching, normalisation beyond the domain layer's own whitespace
      stripping, and no semantic similarity. A resource either appears verbatim in the
      declared scope or it is out of scope.
    """
    return resource in capability.resource_scope
