"""Incident — the aggregate the fleet works on."""

from __future__ import annotations

from pydantic import Field, model_validator

from aegis.core.domain.base import (
    AgentRef,
    DomainModel,
    Identifier,
    IncidentRef,
    NonEmptyStr,
    Timestamp,
)
from aegis.core.domain.enums import IncidentState, RiskLevel
from aegis.core.domain.evidence import Evidence

__all__ = ["Incident"]


class Incident(DomainModel):
    """An enterprise incident under governed investigation (``claude.md`` section 8).

    The incident is the evidence aggregate root:
    :class:`~aegis.core.domain.evidence.Evidence` is *embedded* here, while agents and
    proposed actions are *referenced* by id so that each object has exactly one home.

    Incidents are immutable values. Advancing the workflow means producing a new
    ``Incident`` via ``model_copy(update=...)``; the deterministic state machine that
    decides which transitions are legal is a later milestone, and this class
    intentionally permits any state so that state-machine tests can construct both
    valid and invalid transitions.
    """

    incident_id: IncidentRef
    source: NonEmptyStr
    """Origin of the incident report, e.g. ``monitoring.alerting`` or ``human:oncall``.

    Zone A untrusted input (``claude.md`` section 4): treated as data, never instruction.
    """

    severity: RiskLevel
    state: IncidentState
    evidence: tuple[Evidence, ...] = Field(default_factory=tuple)
    assigned_agents: tuple[AgentRef, ...] = Field(default_factory=tuple)
    proposed_actions: tuple[Identifier, ...] = Field(default_factory=tuple)
    """Ids of proposed :class:`~aegis.core.domain.action.Action` objects.

    Referenced rather than embedded: an ``Action`` carries its own ``incident_id``
    back-reference, so embedding would duplicate the relationship.
    """

    created_at: Timestamp
    updated_at: Timestamp

    @model_validator(mode="after")
    def _timestamps_are_ordered(self) -> Incident:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        return self
