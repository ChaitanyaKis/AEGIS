"""A minimal, declarative resource dependency graph.

Its only job is to answer two questions deterministically:

* what does this resource depend on?
* what depends on this resource?

That is enough for the blast-radius engine and no more. This is **not** the simulated
enterprise (``claude.md`` section 14): there is no telemetry, no deployment history, no
customers and no behaviour here — just declared edges. When the simulated enterprise
arrives it will *supply* a graph, not replace this abstraction.

Known-empty is not unknown
--------------------------

The graph distinguishes "a registered resource that nothing depends on" from "a resource
I have never heard of". The first is a fact; the second is missing information, and
missing information must never be read as safety (``claude.md`` section 2). Lookups on
an unregistered resource raise :class:`UnknownResourceError` rather than returning an
empty set that would silently look like zero impact.

Matching is exact string equality throughout. No prefixes, no globs, no substrings, no
normalisation, no semantic similarity.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from pydantic import Field, model_validator

from aegis.core.domain import DomainModel, NonEmptyStr, RiskLevel

__all__ = [
    "DependencyGraph",
    "ResourceNode",
    "UnknownResourceError",
]


class UnknownResourceError(KeyError):
    """Raised when a resource is not registered in the graph.

    Deliberately an error rather than an empty result: an unknown resource carries no
    information about its impact, and the caller must decide how to fail closed.
    """

    def __init__(self, resource: str) -> None:
        self.resource = resource
        super().__init__(f"unknown resource: {resource!r}")


class ResourceNode(DomainModel):
    """One declared resource and the resources it depends on.

    ``criticality`` is required. It is declared business criticality, and there is no
    safe default for it: a graph author who has not decided must say so explicitly
    rather than inherit a quietly reassuring value.
    """

    resource_id: NonEmptyStr
    depends_on: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    """Resources this one calls or reads. Edges point *downstream*."""

    criticality: RiskLevel
    """How much it matters if this resource is disrupted."""

    @model_validator(mode="after")
    def _no_self_dependency(self) -> ResourceNode:
        if self.resource_id in self.depends_on:
            raise ValueError(f"resource {self.resource_id!r} cannot depend on itself")
        return self


class DependencyGraph:
    """An immutable directed graph of declared resource dependencies.

    Edges point from a resource to what it depends on. Impact therefore propagates in
    the opposite direction: disrupting a resource affects the things that depend on it,
    which is what :meth:`dependents` and :meth:`transitive_dependents` return.

    The graph is fully built at construction and never changes afterwards; both adjacency
    maps are computed once and handed out as tuples, so a caller cannot mutate it.

    Raises:
        ValueError: if a node is declared twice, or an edge names a resource that was
            never declared. A dangling edge is a graph authoring error, not something to
            paper over — silently dropping it would understate blast radius.
    """

    def __init__(self, nodes: Iterable[ResourceNode]) -> None:
        by_id: dict[str, ResourceNode] = {}
        for node in nodes:
            if node.resource_id in by_id:
                raise ValueError(f"duplicate resource: {node.resource_id!r}")
            by_id[node.resource_id] = node

        dependents: dict[str, set[str]] = {resource: set() for resource in by_id}
        for node in by_id.values():
            for dependency in node.depends_on:
                if dependency not in by_id:
                    raise ValueError(
                        f"resource {node.resource_id!r} depends on undeclared resource "
                        f"{dependency!r}"
                    )
                dependents[dependency].add(node.resource_id)

        self._nodes: Mapping[str, ResourceNode] = by_id
        self._dependents: Mapping[str, tuple[str, ...]] = {
            resource: tuple(sorted(values)) for resource, values in dependents.items()
        }

    # --- membership -----------------------------------------------------------------

    def contains(self, resource: str) -> bool:
        """Whether ``resource`` is declared. The only lookup that tolerates a miss."""
        return resource in self._nodes

    def node(self, resource: str) -> ResourceNode:
        """The declared node for ``resource``.

        Raises:
            UnknownResourceError: if the resource is not declared.
        """
        try:
            return self._nodes[resource]
        except KeyError:
            raise UnknownResourceError(resource) from None

    def criticality(self, resource: str) -> RiskLevel:
        """Declared criticality of ``resource``.

        Raises:
            UnknownResourceError: if the resource is not declared.
        """
        return self.node(resource).criticality

    # --- adjacency ------------------------------------------------------------------

    def dependencies(self, resource: str) -> tuple[str, ...]:
        """What ``resource`` directly depends on, sorted.

        Raises:
            UnknownResourceError: if the resource is not declared. An empty tuple means
                "declared, depends on nothing" — never "never heard of it".
        """
        return tuple(sorted(self.node(resource).depends_on))

    def dependents(self, resource: str) -> tuple[str, ...]:
        """What directly depends on ``resource``, sorted.

        Raises:
            UnknownResourceError: if the resource is not declared.
        """
        if resource not in self._nodes:
            raise UnknownResourceError(resource)
        return self._dependents[resource]

    def transitive_dependents(self, resource: str) -> tuple[str, ...]:
        """Everything that depends on ``resource``, directly or indirectly, sorted.

        Breadth-first over the reverse edges, excluding ``resource`` itself. Cycles are
        tolerated — each resource is visited once — so a cyclic declaration cannot hang
        the control plane.

        Raises:
            UnknownResourceError: if the resource is not declared.
        """
        if resource not in self._nodes:
            raise UnknownResourceError(resource)

        seen: set[str] = set()
        frontier = [resource]
        while frontier:
            current = frontier.pop()
            for dependent in self._dependents[current]:
                if dependent not in seen and dependent != resource:
                    seen.add(dependent)
                    frontier.append(dependent)
        return tuple(sorted(seen))

    # --- container protocol ---------------------------------------------------------

    def resources(self) -> tuple[str, ...]:
        """Every declared resource, sorted."""
        return tuple(sorted(self._nodes))

    def __contains__(self, resource: object) -> bool:
        return resource in self._nodes

    def __len__(self) -> int:
        return len(self._nodes)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({len(self._nodes)} resources)"
