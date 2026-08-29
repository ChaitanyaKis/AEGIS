"""Action — a proposed or authorized operation against an enterprise resource."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated

from pydantic import AfterValidator, Field, JsonValue

from aegis.core.domain.base import (
    AgentRef,
    CapabilityRef,
    DomainModel,
    EvidenceRef,
    Identifier,
    IncidentRef,
    NonEmptyStr,
)
from aegis.core.domain.enums import RiskLevel

__all__ = ["Action", "BlastRadius"]


def _sorted_arguments(value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """Normalise argument keys to sorted order for deterministic serialization."""
    return dict(sorted(value.items()))


_Arguments = Annotated[Mapping[str, JsonValue], AfterValidator(_sorted_arguments)]


class BlastRadius(DomainModel):
    """The assessed reach of an action (``claude.md`` section 3, Blast-Radius Engine).

    This is a *result contract*, not a calculation. AEGIS does not compute blast radius
    in this milestone; the blast-radius engine populates this structure later. A
    ``BlastRadius`` present on an :class:`Action` therefore means "assessed", and its
    absence means "not yet assessed" — never "small".
    """

    scope: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    """Resources the action can affect, e.g. ``("service:payment-api", "db:payment")``."""

    impact: RiskLevel
    """Assessed severity of the reach. Required: there is no safe default."""


class Action(DomainModel):
    """An operation an agent proposes to perform against an enterprise resource.

    An ``Action`` is a *proposal* until the control plane authorizes it
    (``claude.md`` section 2: LLMs propose, deterministic systems authorize). It is
    constructed by the agent plane, which is not authoritative for authorization, and
    must always be re-checked before execution.

    ``risk`` and ``blast_radius`` are deliberately optional and default to ``None``.
    They are outputs of the deterministic risk and blast-radius engines, not claims a
    requesting agent is allowed to make about itself. Consumers must treat ``None`` as
    *unassessed* and fail closed — never as low risk.
    """

    action_id: Identifier
    incident_id: IncidentRef
    """Every action exists in the context of an incident. Required."""

    requesting_agent: AgentRef
    """The agent accountable for the proposal. Required, so nothing is anonymous."""

    capability: CapabilityRef
    """Id of the capability this action would exercise."""

    target_resource: NonEmptyStr
    """The concrete resource acted upon, e.g. ``service:payment-api``."""

    arguments: _Arguments = Field(default_factory=dict)
    """JSON-safe parameters. Normalised to sorted key order."""

    evidence: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
    """Ids of evidence recorded on the incident that justifies this action."""

    risk: RiskLevel | None = None
    """Assessed risk, or ``None`` when the risk engine has not yet run."""

    blast_radius: BlastRadius | None = None
    """Assessed reach, or ``None`` when the blast-radius engine has not yet run."""
