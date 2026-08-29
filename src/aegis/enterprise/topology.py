"""The single authoritative definition of the simulated enterprise.

**CONTROLLED SIMULATION** (``claude.md`` sections 14, 17).

One definition feeds everything: the dependency graph the blast-radius engine reads, the
initial state of the world, and the observations the verification engine consumes. There
is deliberately no second topology anywhere in the project — ``tests/fleet.py`` imports
this one, so a change here changes every consumer at once and the graph can never drift
out of step with the world.

The shape is the section 14 topology:

    api-gateway
     ├── auth
     ├── payment-api
     │    └── payment-db
     ├── order-service
     │    ├── payment-api
     │    └── order-db
     └── notification

plus ``db:customer-database``, declared but depended on by nothing — which is what makes
it a useful case of "known resource, zero dependents" as distinct from an unknown one.
"""

from __future__ import annotations

from pydantic import Field, model_validator

from aegis.core.dependencies import DependencyGraph, ResourceNode
from aegis.core.domain import DomainModel, NonEmptyStr, RiskLevel
from aegis.enterprise.models import DeploymentProfile, ResourceState, ServiceHealth

__all__ = [
    "API_GATEWAY",
    "AUTH_SERVICE",
    "CUSTOMER_DATABASE",
    "ENTERPRISE_TOPOLOGY",
    "NOTIFICATION_SERVICE",
    "ORDER_DB",
    "ORDER_SERVICE",
    "PAYMENT_API",
    "PAYMENT_API_FAULTY_VERSION",
    "PAYMENT_API_GOOD_VERSION",
    "PAYMENT_DB",
    "ResourceDefinition",
    "build_dependency_graph",
    "dependency_nodes",
]

API_GATEWAY = "service:api-gateway"
AUTH_SERVICE = "service:auth"
PAYMENT_API = "service:payment-api"
ORDER_SERVICE = "service:order-service"
NOTIFICATION_SERVICE = "service:notification"
PAYMENT_DB = "db:payment"
ORDER_DB = "db:order"
CUSTOMER_DATABASE = "db:customer-database"

PAYMENT_API_FAULTY_VERSION = "v4.8"
"""The deployment that caused the golden incident (``claude.md`` section 16)."""

PAYMENT_API_GOOD_VERSION = "v4.7"
"""The deployment a rollback returns to."""


class ResourceDefinition(DomainModel):
    """One declared resource: its place in the graph and how it behaves per version."""

    resource_id: NonEmptyStr
    criticality: RiskLevel
    """Declared business criticality, consumed by the blast-radius engine."""

    depends_on: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    deployments: tuple[DeploymentProfile, ...] = Field(min_length=1)
    """Every version this resource can be running. Deploying anything else is unsupported."""

    initial_deployment: NonEmptyStr

    @model_validator(mode="after")
    def _initial_deployment_is_known(self) -> ResourceDefinition:
        versions = [profile.version for profile in self.deployments]
        if len(versions) != len(set(versions)):
            raise ValueError(f"{self.resource_id}: duplicate deployment versions")
        if self.initial_deployment not in versions:
            raise ValueError(
                f"{self.resource_id}: initial deployment {self.initial_deployment!r} is not "
                f"a declared version"
            )
        return self

    def profile(self, version: str) -> DeploymentProfile | None:
        """The declared behaviour of one version, or ``None`` if it is not declared."""
        for candidate in self.deployments:
            if candidate.version == version:
                return candidate
        return None

    def initial_state(self) -> ResourceState:
        """The resource's state when the world is first built."""
        profile = self.profile(self.initial_deployment)
        assert profile is not None  # guaranteed by the validator
        return ResourceState(
            resource_id=self.resource_id,
            deployment=profile.version,
            error_rate=profile.error_rate,
            health=profile.health,
        )

    def to_node(self) -> ResourceNode:
        """The dependency-graph node for this resource."""
        return ResourceNode(
            resource_id=self.resource_id,
            depends_on=self.depends_on,
            criticality=self.criticality,
        )


def _steady(resource_id: str, criticality: RiskLevel, version: str, **kwargs) -> ResourceDefinition:
    """A resource with a single healthy version — everything except payment-api."""
    return ResourceDefinition(
        resource_id=resource_id,
        criticality=criticality,
        deployments=(
            DeploymentProfile(version=version, error_rate=0.0, health=ServiceHealth.HEALTHY),
        ),
        initial_deployment=version,
        **kwargs,
    )


ENTERPRISE_TOPOLOGY: tuple[ResourceDefinition, ...] = (
    _steady(
        API_GATEWAY,
        RiskLevel.HIGH,
        "v2.1",
        depends_on=(AUTH_SERVICE, PAYMENT_API, ORDER_SERVICE, NOTIFICATION_SERVICE),
    ),
    _steady(AUTH_SERVICE, RiskLevel.HIGH, "v3.0"),
    ResourceDefinition(
        resource_id=PAYMENT_API,
        criticality=RiskLevel.HIGH,
        depends_on=(PAYMENT_DB,),
        deployments=(
            # The golden incident: v4.8 is the bad deploy, v4.7 the known-good one.
            DeploymentProfile(
                version=PAYMENT_API_FAULTY_VERSION,
                error_rate=37.0,
                health=ServiceHealth.UNHEALTHY,
            ),
            DeploymentProfile(
                version=PAYMENT_API_GOOD_VERSION,
                error_rate=0.7,
                health=ServiceHealth.HEALTHY,
            ),
        ),
        initial_deployment=PAYMENT_API_FAULTY_VERSION,
    ),
    _steady(PAYMENT_DB, RiskLevel.CRITICAL, "schema-11"),
    _steady(ORDER_SERVICE, RiskLevel.MEDIUM, "v5.2", depends_on=(PAYMENT_API, ORDER_DB)),
    _steady(ORDER_DB, RiskLevel.HIGH, "schema-7"),
    _steady(NOTIFICATION_SERVICE, RiskLevel.LOW, "v1.4"),
    _steady(CUSTOMER_DATABASE, RiskLevel.CRITICAL, "schema-4"),
)
"""The declared enterprise. Criticalities and edges match what the control plane expects."""


def dependency_nodes() -> tuple[ResourceNode, ...]:
    """The topology as dependency-graph nodes, in declaration order."""
    return tuple(definition.to_node() for definition in ENTERPRISE_TOPOLOGY)


def build_dependency_graph() -> DependencyGraph:
    """The dependency graph the blast-radius engine reads.

    Built from the same definitions the world is built from, so the graph and the world
    can never describe different enterprises.
    """
    return DependencyGraph(dependency_nodes())
