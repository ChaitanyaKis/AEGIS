"""The blast-radius engine — how far an action actually reaches.

Turns a proposed action, its capability and a declared dependency graph into the
:class:`~aegis.core.domain.action.BlastRadius` contract the domain already defines. Pure:
declared metadata and declared edges in, a frozen result out. No network, no model, no
clock, no randomness.

Direction of impact
-------------------

Graph edges point from a resource to what it *depends on*. Disruption travels the other
way: rolling back ``service:payment-api`` disturbs everything that calls it, not the
database it reads. Blast radius is therefore the target plus its **transitive
dependents**.

Not every action disturbs its target
------------------------------------

Reading telemetry from a service does not take down the services that call it, so a read
must not inherit a mutation's reach. The deterministic discriminator is
``Capability.risk_class``: a capability the organisation itself declared LOW risk is
treated as non-disruptive and reaches only its target; anything above LOW is treated as
potentially disruptive and propagates to dependents. The uncertainty is resolved towards
propagation, so a mis-declared capability over-states its reach rather than hiding it.

Sensitivity is deliberately *not* folded in here — blast radius measures disruption, and
reaching restricted data is scored separately as its own risk factor.

Unknown resources
-----------------

An unregistered target yields no assessment at all — :meth:`BlastRadiusEngine.assess`
returns ``None``. It never yields "zero dependents", because zero dependents is a
measurement and an unknown resource has not been measured (``claude.md`` section 2).
"""

from __future__ import annotations

from pydantic import Field

from aegis.core.assessment.scale import max_risk
from aegis.core.dependencies import DependencyGraph
from aegis.core.domain import (
    Action,
    BlastRadius,
    Capability,
    DomainModel,
    NonEmptyStr,
    RiskLevel,
)

__all__ = [
    "REACH_THRESHOLDS",
    "BlastRadiusAssessment",
    "BlastRadiusEngine",
    "is_disruptive",
]

REACH_THRESHOLDS: tuple[tuple[int, RiskLevel], ...] = (
    (1, RiskLevel.LOW),
    (3, RiskLevel.MEDIUM),
    (6, RiskLevel.HIGH),
)
"""Reach-derived impact bands, as ``(inclusive upper bound, level)`` in ascending order.

One resource affected is LOW, two or three MEDIUM, four to six HIGH, and anything beyond
CRITICAL. Deliberately a small published table rather than a formula: a reviewer can
check a blast-radius level by counting, and these bands are the only tunable numbers in
the engine.
"""


def is_disruptive(capability: Capability) -> bool:
    """Whether exercising this capability can disturb resources downstream of its target.

    ``True`` unless the capability's declared ``risk_class`` is LOW. See the module
    docstring for why this is the chosen deterministic proxy and which way it errs.
    """
    return capability.risk_class is not RiskLevel.LOW


def _reach_level(affected_count: int) -> RiskLevel:
    """Impact band for a number of affected resources. Non-decreasing in the count."""
    for upper_bound, level in REACH_THRESHOLDS:
        if affected_count <= upper_bound:
            return level
    return RiskLevel.CRITICAL


class BlastRadiusAssessment(DomainModel):
    """A computed blast radius together with the facts it was derived from.

    The extra fields exist because :class:`~aegis.core.domain.action.BlastRadius` holds
    only ``scope`` and ``impact``, and widening a domain contract for reporting would be
    the wrong trade. Everything here is recomputable from the same graph and capability —
    it is a record of arithmetic, not an explanation.

    Note the deliberate split: ``direct_dependents`` and ``transitive_dependents`` are
    topological facts about the *resource*, reported whether or not they are affected;
    ``blast_radius.scope`` is what this particular *action* would actually reach.
    """

    blast_radius: BlastRadius
    """The domain contract, ready to attach to an assessed action."""

    target: NonEmptyStr
    disruptive: bool
    """Whether impact propagates past the target. See :func:`is_disruptive`."""

    direct_dependents: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    """What depends on the target directly, per the graph."""

    transitive_dependents: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    """Everything downstream of the target, per the graph, direct dependents included."""

    affected_count: int = Field(ge=1)
    """Size of ``blast_radius.scope``. At least one: the target is always affected."""

    reach_impact: RiskLevel
    """Impact implied by ``affected_count`` alone, via :data:`REACH_THRESHOLDS`."""

    max_criticality: RiskLevel
    """Highest declared criticality among the affected resources."""


class BlastRadiusEngine:
    """Computes how far an action reaches, from declared metadata only.

    Args:
        graph: The declared dependency graph. Held by reference and never mutated.
    """

    def __init__(self, graph: DependencyGraph) -> None:
        self._graph = graph

    @property
    def graph(self) -> DependencyGraph:
        return self._graph

    def assess(self, action: Action, capability: Capability) -> BlastRadiusAssessment | None:
        """Compute the blast radius of ``action``.

        Any ``blast_radius`` already present on the action is ignored. A proposing agent
        does not get to describe its own reach (``claude.md`` section 2).

        Args:
            action: The proposed action. Only ``target_resource`` is consulted.
            capability: The resolved capability it would exercise.

        Returns:
            The assessment, or ``None`` when the target resource is not declared in the
            graph. ``None`` means *unmeasured*, and the caller must fail closed on it —
            it is never equivalent to an empty blast radius.
        """
        target = action.target_resource
        if not self._graph.contains(target):
            return None

        transitive = self._graph.transitive_dependents(target)
        disruptive = is_disruptive(capability)
        scope: tuple[str, ...] = (target, *transitive) if disruptive else (target,)

        reach_impact = _reach_level(len(scope))
        max_criticality = max_risk(self._graph.criticality(resource) for resource in scope)
        impact = max_risk((reach_impact, max_criticality)) if disruptive else RiskLevel.LOW

        return BlastRadiusAssessment(
            blast_radius=BlastRadius(scope=scope, impact=impact),
            target=target,
            disruptive=disruptive,
            direct_dependents=self._graph.dependents(target),
            transitive_dependents=transitive,
            affected_count=len(scope),
            reach_impact=reach_impact,
            max_criticality=max_criticality,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(graph={self._graph!r})"
