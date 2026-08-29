"""Capability — an explicit, metadata-bearing grant of authority."""

from __future__ import annotations

from pydantic import Field

from aegis.core.domain.base import (
    AgentRef,
    CapabilityRef,
    DomainModel,
    NonEmptyStr,
)
from aegis.core.domain.enums import ApprovalRequirement, DataClassification, RiskLevel

__all__ = ["Capability"]


class Capability(DomainModel):
    """A named unit of authority an agent may be granted (``claude.md`` section 6).

    Authority in AEGIS is capability-based and least-privilege: an agent can only do
    what some capability describes, and only where ``resource_scope`` and
    ``allowed_agents`` permit. Every field here is *declarative metadata*. Deciding
    whether a concrete action is permitted is the policy engine's job and is not
    implemented in this milestone.
    """

    capability_id: CapabilityRef
    """Namespaced identifier, e.g. ``telemetry.read`` or ``production.rollback``."""

    description: NonEmptyStr
    risk_class: RiskLevel
    """Inherent risk of the capability itself, independent of any concrete action."""

    resource_scope: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    """Resource patterns this capability may reach, e.g. ``("service:payment-api",)``.

    An empty scope grants nothing. It is *not* a wildcard — fail-closed by construction.
    """

    data_classification: DataClassification
    reversible: bool
    """Whether the effect can be undone. Feeds risk and approval reasoning later."""

    approval_requirement: ApprovalRequirement
    allowed_agents: tuple[AgentRef, ...] = Field(default_factory=tuple)
    """Agents permitted to hold this capability. Empty means no agent may hold it."""
