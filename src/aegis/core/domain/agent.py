"""Agent — a governed participant in the fleet, and its endpoint metadata."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated

from pydantic import AfterValidator, Field

from aegis.core.domain.base import (
    AgentRef,
    CapabilityRef,
    DomainModel,
    NonEmptyStr,
)
from aegis.core.domain.enums import AgentLifecycleState

__all__ = ["Agent", "AgentEndpoint"]


def _sorted_mapping(value: Mapping[str, str]) -> dict[str, str]:
    """Normalise a metadata mapping to sorted key order for deterministic output."""
    return dict(sorted(value.items()))


_Metadata = Annotated[Mapping[str, str], AfterValidator(_sorted_mapping)]


class AgentEndpoint(DomainModel):
    """Where an agent can be reached, expressed as an adapter-resolved reference.

    AEGIS never dials an endpoint from the domain layer. ``kind`` names which adapter
    knows how to resolve ``reference``; the adapters (local, and later a Google Agent
    Registry / Agent Runtime adapter per ``claude.md`` section 18) live under
    ``aegis.integrations`` and do not exist yet. Nothing here implies that any
    particular platform integration is configured.
    """

    kind: NonEmptyStr
    """Adapter discriminator, e.g. ``local``. Resolved by an integration adapter."""

    reference: NonEmptyStr
    """Opaque address or resource name understood only by the matching adapter."""

    metadata: _Metadata = Field(default_factory=dict)
    """Adapter-specific non-authoritative metadata. Normalised to sorted key order."""


class Agent(DomainModel):
    """A registered member of the agent fleet (``claude.md`` sections 7, 9).

    An ``Agent`` is a control-plane record *about* an agent, not the agent's reasoning.
    It carries identity, lifecycle position and the capabilities the control plane has
    granted. Holding a capability id here is a grant record, not an authorization:
    every individual action is still checked against policy at execution time.
    """

    agent_id: AgentRef
    name: NonEmptyStr
    version: NonEmptyStr
    """Version of the agent implementation. Required so that evaluation results,
    audit records and lifecycle decisions always attach to a specific build."""

    status: AgentLifecycleState
    identity_reference: NonEmptyStr
    """Reference to the agent's managed identity, resolved by an identity adapter.

    Opaque to the domain layer; no identity provider is integrated in this milestone.
    """

    capabilities: tuple[CapabilityRef, ...] = Field(default_factory=tuple)
    """Granted capability ids. Empty means least privilege: nothing granted."""

    endpoint: AgentEndpoint | None = None
    """Absent while an agent is registered but not yet reachable."""
