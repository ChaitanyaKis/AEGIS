"""Declared resource dependency graph.

A deterministic, in-memory description of which resources depend on which. Consumed by
the blast-radius engine to work out what an action would actually reach.

Not the simulated enterprise: no telemetry, no deployments, no behaviour. The simulated
enterprise will later *supply* a graph through this same abstraction.
"""

from aegis.core.dependencies.graph import (
    DependencyGraph,
    ResourceNode,
    UnknownResourceError,
)

__all__ = [
    "DependencyGraph",
    "ResourceNode",
    "UnknownResourceError",
]
