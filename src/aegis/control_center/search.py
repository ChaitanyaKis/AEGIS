"""Finding incidents. Observation only, and scoped to what the caller already holds.

Part 22. Search narrows; it never widens. A query cannot reach an incident the control
center was not given, cannot merge two incidents' artifacts, and cannot produce a record an
operator could not have read by opening the incident directly.

Why an ``UNKNOWN`` field never matches
--------------------------------------

A filter on ``verified=True`` matches only incidents whose verification is *known* to be
true. An incident whose verification could not be read does not match -- and, importantly,
neither does it match ``verified=False``. It is excluded from both, which is the only
honest treatment: a filter that swept unknowns into the negative side would let an operator
searching for unverified executions miss the ones nobody could check, which are the ones
that matter most.

:meth:`IncidentQuery.unknown_for` names them, so an operator can ask for exactly that set
rather than being quietly denied it.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from aegis.control_center.models import Tri
from aegis.control_center.projection import IncidentProjection, IncidentSummary
from aegis.core.domain import DomainModel, NonEmptyStr

__all__ = ["UNKNOWABLE_FIELDS", "IncidentQuery", "search", "unknown_for"]


class IncidentQuery(DomainModel):
    """A filter over projections. Frozen, declarative, and unable to widen anything.

    Every field is optional and every supplied field narrows the result. There is no field
    that adds incidents, no wildcard that crosses an incident boundary, and no way to
    express "everything including what I was not given".
    """

    incident_id: NonEmptyStr | None = None
    state: NonEmptyStr | None = None
    severity: NonEmptyStr | None = None
    risk: NonEmptyStr | None = None
    agent: NonEmptyStr | None = None
    """Matches an incident in which this agent appears as a registered participant."""

    resource: NonEmptyStr | None = None
    capability: NonEmptyStr | None = None
    policy_decision: NonEmptyStr | None = None
    approval_status: NonEmptyStr | None = None
    lifecycle_stop_reason: NonEmptyStr | None = None
    breaker_state: NonEmptyStr | None = None

    executed: Tri | None = None
    verified: Tri | None = None
    resolved: Tri | None = None
    """Compared against the projection's tri-state. Asking for ``TRUE`` excludes
    ``UNKNOWN``; asking for ``UNKNOWN`` returns exactly the incidents nobody could read."""

    restricted_agents: bool | None = None
    since: datetime | None = None
    until: datetime | None = None

    @property
    def specified(self) -> tuple[str, ...]:
        """Which filters this query actually applies, sorted. For rendering and for tests."""
        return tuple(sorted(name for name, value in self.model_dump().items() if value is not None))

    def __repr__(self) -> str:
        return f"IncidentQuery({', '.join(self.specified) or 'unfiltered'})"


def search(
    projections: tuple[IncidentProjection, ...], query: IncidentQuery
) -> tuple[IncidentProjection, ...]:
    """Every projection matching the query, in incident-id order.

    Deterministic and total: the same projections and the same query always produce the
    same tuple. An unfiltered query returns everything the caller was given -- which is not
    a widening, because the caller already held it.
    """
    matches = [projection for projection in projections if _matches(projection, query)]
    return tuple(sorted(matches, key=lambda projection: projection.incident_id))


_UNKNOWABLE: dict[str, Callable[[IncidentSummary], Tri]] = {
    "executed": lambda summary: summary.executed,
    "verified": lambda summary: summary.verified,
    "resolved": lambda summary: summary.resolved,
    "escalated": lambda summary: summary.escalated,
    "breaker_open": lambda summary: summary.breaker_open,
    "agents_restricted": lambda summary: summary.agents_restricted,
}
"""The tri-state summary fields :func:`unknown_for` will look at, and how to read each.

An explicit dispatch table rather than ``getattr``. ``unknown_for`` takes a field name from
a caller, and a caller is ultimately an operator typing something -- a table means the
reachable set of attributes is written here, in the source, rather than being whatever
string arrives.
"""

UNKNOWABLE_FIELDS: frozenset[str] = frozenset(_UNKNOWABLE)
"""The field names :func:`unknown_for` accepts."""


def unknown_for(
    projections: tuple[IncidentProjection, ...], field: str
) -> tuple[IncidentProjection, ...]:
    """Incidents whose named tri-state field could not be determined.

    The set a ``TRUE``/``FALSE`` filter deliberately excludes. Exposed as its own function
    because "which incidents can nobody answer this about" is an operator question in its
    own right, and one a control center that hid unknowns would make unaskable.

    Raises:
        ValueError: for a field outside :data:`UNKNOWABLE_FIELDS`. A caller-supplied string
            must not become an attribute name -- that is the one way data could choose which
            code runs here, and a dispatch table is how it does not.
    """
    read = _UNKNOWABLE.get(field)
    if read is None:
        raise ValueError(
            f"{field!r} is not a tri-state summary field; "
            f"available: {', '.join(sorted(UNKNOWABLE_FIELDS))}"
        )
    return tuple(
        projection
        for projection in sorted(projections, key=lambda p: p.incident_id)
        if read(projection.summary) is Tri.UNKNOWN
    )


def _matches(projection: IncidentProjection, query: IncidentQuery) -> bool:
    summary = projection.summary

    if query.incident_id is not None and projection.incident_id != query.incident_id:
        return False
    if not _fact_matches(summary.state, query.state):
        return False
    if not _fact_matches(summary.severity, query.severity):
        return False
    if not _fact_matches(projection.governance.risk, query.risk):
        return False
    if not _fact_matches(summary.resource, query.resource):
        return False
    if not _fact_matches(projection.governance.capability, query.capability):
        return False
    if not _fact_matches(summary.policy_decision, query.policy_decision):
        return False
    if not _fact_matches(summary.approval_status, query.approval_status):
        return False
    if not _fact_matches(projection.lifecycle.stop_reason, query.lifecycle_stop_reason):
        return False

    if query.breaker_state is not None and not any(
        view.state.value == query.breaker_state for view in projection.breakers
    ):
        return False
    if query.agent is not None and not any(
        view.agent_id == query.agent for view in projection.agents
    ):
        return False
    if query.restricted_agents is not None:
        restricted = any(view.quarantined.is_true for view in projection.agents)
        if restricted is not query.restricted_agents:
            return False

    for tri_field in ("executed", "verified", "resolved"):
        wanted = getattr(query, tri_field)
        if wanted is not None and getattr(summary, tri_field) is not wanted:
            return False

    detected = summary.detected_at
    if query.since is not None and (detected is None or detected < query.since):
        return False
    return not (query.until is not None and (detected is None or detected > query.until))


def _fact_matches(fact, wanted: str | None) -> bool:
    """Whether a :class:`~aegis.control_center.models.Fact` equals a wanted value.

    An unknown fact never matches. Not "matches everything" and not "matches nothing in
    particular" -- a filter is a question about a known value, and a value nobody could read
    is not an answer to it.
    """
    if wanted is None:
        return True
    return fact.known and fact.value == wanted
