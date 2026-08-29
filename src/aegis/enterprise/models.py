"""State models for the simulated enterprise.

**CONTROLLED SIMULATION** (``claude.md`` sections 14, 17). Nothing here is production
infrastructure, real telemetry, a real deployment or live customer data. Every value is
synthetic and declared.

The world can change, but only through the operations on
:class:`~aegis.enterprise.world.EnterpriseWorld`. Everything a caller is handed back is a
frozen snapshot, so reading the world can never alter it.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from aegis.core.domain import DomainModel, NonEmptyStr

__all__ = ["DeploymentProfile", "ResourceState", "ServiceHealth", "WorldSnapshot"]


class ServiceHealth(StrEnum):
    """How a simulated resource is behaving.

    Values are lowercase because they are compared directly by verification predicates
    (``health EQUALS "healthy"``), and the predicate system is exact-match with no
    normalisation. One categorical field covers both availability and operational status
    rather than carrying two fields that could disagree.
    """

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    OFFLINE = "offline"


class DeploymentProfile(DomainModel):
    """How a resource behaves when running one particular version.

    This is what makes rollback meaningful rather than magical: a rollback does not "heal"
    a service, it deploys a version whose declared behaviour happens to be healthy. Change
    the profile and the same rollback stops producing a healthy world.
    """

    version: NonEmptyStr
    error_rate: float = Field(ge=0.0, le=100.0)
    """Percentage of requests failing, 0 to 100."""

    health: ServiceHealth


class ResourceState(DomainModel):
    """The current simulated state of one resource. Frozen — a change is a new value."""

    resource_id: NonEmptyStr
    deployment: NonEmptyStr
    error_rate: float = Field(ge=0.0, le=100.0)
    health: ServiceHealth

    @property
    def healthy(self) -> bool:
        return self.health is ServiceHealth.HEALTHY


class WorldSnapshot(DomainModel):
    """An immutable view of the whole simulated enterprise at one moment.

    Deterministically ordered: resources sorted by id, failures sorted by name. Two worlds
    in the same condition serialize identically.
    """

    resources: tuple[ResourceState, ...] = Field(default_factory=tuple)
    active_failures: tuple[str, ...] = Field(default_factory=tuple)
    """Names of the injected failures currently in force. Simulation controls, not faults."""

    @model_validator(mode="after")
    def _deterministically_ordered(self) -> WorldSnapshot:
        ids = [resource.resource_id for resource in self.resources]
        if ids != sorted(ids):
            raise ValueError("snapshot resources must be sorted by resource_id")
        if list(self.active_failures) != sorted(self.active_failures):
            raise ValueError("snapshot failures must be sorted")
        return self

    def resource(self, resource_id: str) -> ResourceState | None:
        """State of one resource by exact id, or ``None`` if it is not declared."""
        for resource in self.resources:
            if resource.resource_id == resource_id:
                return resource
        return None
