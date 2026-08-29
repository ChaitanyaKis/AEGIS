"""The mutable simulated world, changeable only through declared operations.

**CONTROLLED SIMULATION** (``claude.md`` sections 14, 17). Synthetic services, synthetic
state, no real customer data, no real deployments.

The world holds state and can change. What it does not do is let anyone change that state
sideways: there is no accessor that hands out the internal mapping, every read returns a
frozen snapshot or a frozen :class:`~aegis.enterprise.models.ResourceState`, and the only
way to move the world is one of the operations below.

There is no randomness anywhere in this module, and therefore nothing to seed. Two worlds
built from the same topology and given the same operations are identical — a stronger
guarantee than a fixed RNG seed, because there is no generator to get out of step.
"""

from __future__ import annotations

from collections.abc import Iterable

from aegis.core.dependencies import DependencyGraph, UnknownResourceError
from aegis.enterprise.failures import FailureType
from aegis.enterprise.models import ResourceState, ServiceHealth, WorldSnapshot
from aegis.enterprise.topology import ENTERPRISE_TOPOLOGY, ResourceDefinition

__all__ = ["EnterpriseWorld", "UnsupportedOperationError"]


class UnsupportedOperationError(Exception):
    """The simulated world was asked to do something it does not model.

    Deploying an undeclared version, for instance. The world refuses rather than inventing
    behaviour for a version whose effects nobody declared — an invented effect would make
    the whole simulation unreproducible.
    """


class EnterpriseWorld:
    """The synthetic enterprise: current state, declared topology, injected failures.

    Args:
        topology: Resource definitions. Defaults to the project's one declared enterprise.

    The world knows nothing about policy, approval or verification, and never calls them.
    It is acted upon; it does not decide.
    """

    def __init__(self, topology: Iterable[ResourceDefinition] = ENTERPRISE_TOPOLOGY) -> None:
        self._definitions: dict[str, ResourceDefinition] = {}
        self._states: dict[str, ResourceState] = {}
        for definition in topology:
            if definition.resource_id in self._definitions:
                raise ValueError(f"duplicate resource: {definition.resource_id!r}")
            self._definitions[definition.resource_id] = definition
            self._states[definition.resource_id] = definition.initial_state()
        self._failures: set[FailureType] = set()

    # --- reading --------------------------------------------------------------------

    def contains(self, resource_id: str) -> bool:
        """Whether the resource is declared. Exact match."""
        return resource_id in self._definitions

    def resources(self) -> tuple[str, ...]:
        """Every declared resource id, sorted."""
        return tuple(sorted(self._definitions))

    def state(self, resource_id: str) -> ResourceState:
        """Current state of one resource, as a frozen value.

        Raises:
            UnknownResourceError: if the resource is not declared. Never a default state —
                an undeclared resource has no state, and inventing a healthy one would be
                exactly the silent optimism the control plane is built to refuse.
        """
        try:
            return self._states[resource_id]
        except KeyError:
            raise UnknownResourceError(resource_id) from None

    def definition(self, resource_id: str) -> ResourceDefinition:
        """Declared definition of one resource.

        Raises:
            UnknownResourceError: if the resource is not declared.
        """
        try:
            return self._definitions[resource_id]
        except KeyError:
            raise UnknownResourceError(resource_id) from None

    def snapshot(self) -> WorldSnapshot:
        """An immutable, deterministically ordered view of the whole world."""
        return WorldSnapshot(
            resources=tuple(self._states[resource_id] for resource_id in sorted(self._states)),
            active_failures=tuple(sorted(failure.value for failure in self._failures)),
        )

    def dependency_graph(self) -> DependencyGraph:
        """The dependency graph for **this world's** declared topology.

        Built from the definitions this world holds, not from the default enterprise: a
        world constructed with extra resources must report a graph describing those
        resources, or the blast-radius engine would reason about a different enterprise
        than the one being acted on.
        """
        return DependencyGraph(definition.to_node() for definition in self._definitions.values())

    # --- controlled mutation --------------------------------------------------------

    def deploy(self, resource_id: str, version: str) -> ResourceState:
        """Move a resource onto a declared version, applying that version's behaviour.

        The new error rate and health come from the version's
        :class:`~aegis.enterprise.models.DeploymentProfile`, not from the caller. A
        deployment cannot claim an outcome it was not declared to have.

        Raises:
            UnknownResourceError: if the resource is not declared.
            UnsupportedOperationError: if the version is not declared for it.
        """
        definition = self.definition(resource_id)
        profile = definition.profile(version)
        if profile is None:
            raise UnsupportedOperationError(f"{resource_id} has no declared version {version!r}")
        self._states[resource_id] = ResourceState(
            resource_id=resource_id,
            deployment=profile.version,
            error_rate=profile.error_rate,
            health=profile.health,
        )
        return self._states[resource_id]

    def rollback(self, resource_id: str, to_version: str) -> ResourceState:
        """Deploy a previous version.

        Identical in effect to :meth:`deploy`; separate because a rollback is a distinct
        operation in the capability catalogue and refuses to be a no-op.

        Raises:
            UnknownResourceError: if the resource is not declared.
            UnsupportedOperationError: if the version is undeclared, or already current.
        """
        current = self.state(resource_id)
        if current.deployment == to_version:
            raise UnsupportedOperationError(
                f"{resource_id} is already running {to_version!r}; nothing to roll back to"
            )
        return self.deploy(resource_id, to_version)

    def set_error_rate(self, resource_id: str, error_rate: float) -> ResourceState:
        """Override a resource's error rate, for scenario setup.

        Raises:
            UnknownResourceError: if the resource is not declared.
            ValidationError: if the value is outside 0-100.
        """
        current = self.state(resource_id)
        # Rebuilt rather than copied: model_copy skips validation, and an override is
        # exactly where an out-of-range value would otherwise slip into the world.
        self._states[resource_id] = ResourceState(
            resource_id=current.resource_id,
            deployment=current.deployment,
            error_rate=error_rate,
            health=current.health,
        )
        return self._states[resource_id]

    def set_health(self, resource_id: str, health: ServiceHealth) -> ResourceState:
        """Override a resource's health, for scenario setup.

        Raises:
            UnknownResourceError: if the resource is not declared.
        """
        current = self.state(resource_id)
        self._states[resource_id] = ResourceState(
            resource_id=current.resource_id,
            deployment=current.deployment,
            error_rate=current.error_rate,
            health=health,
        )
        return self._states[resource_id]

    # --- failure injection ----------------------------------------------------------

    def inject_failure(self, failure: FailureType) -> None:
        """Turn on a simulation control."""
        self._failures.add(failure)

    def clear_failure(self, failure: FailureType) -> None:
        """Turn one off. Clearing an inactive failure is a no-op."""
        self._failures.discard(failure)

    def clear_failures(self) -> None:
        """Turn them all off."""
        self._failures.clear()

    def is_failing(self, failure: FailureType) -> bool:
        """Whether a specific failure is currently injected."""
        return failure in self._failures

    def active_failures(self) -> frozenset[FailureType]:
        """Every injected failure, as an immutable set."""
        return frozenset(self._failures)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({len(self._states)} resources, {len(self._failures)} failures)"
        )
