"""A fixed, deterministic capability set and agent fleet for control-plane tests.

Shared by the registry and policy suites so that both authorize against the same world.
Every value is a literal — no clocks, no randomness, no I/O. Loosely modelled on the
capability examples in ``claude.md`` section 6 and the fleet in section 7, but this is
test data, not a production capability catalogue.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from aegis.core.capabilities import CapabilityRegistry
from aegis.core.dependencies import DependencyGraph, ResourceNode
from aegis.core.domain import (
    Action,
    Agent,
    AgentLifecycleState,
    ApprovalRequirement,
    Capability,
    DataClassification,
    Evidence,
    EvidenceType,
    Incident,
    IncidentState,
    RiskLevel,
)
from aegis.core.verification import Observation

# Resource ids and the golden expectation are re-exported from the one declared
# enterprise so that every existing suite keeps importing them from here. The
# redundant aliases mark them as deliberate re-exports rather than unused imports.
from aegis.enterprise import (
    API_GATEWAY as API_GATEWAY,
)
from aegis.enterprise import (
    AUTH_SERVICE as AUTH_SERVICE,
)
from aegis.enterprise import (
    CUSTOMER_DATABASE as CUSTOMER_DATABASE,
)
from aegis.enterprise import (
    NOTIFICATION_SERVICE as NOTIFICATION_SERVICE,
)
from aegis.enterprise import (
    ORDER_DB as ORDER_DB,
)
from aegis.enterprise import (
    ORDER_SERVICE as ORDER_SERVICE,
)
from aegis.enterprise import (
    PAYMENT_API as PAYMENT_API,
)
from aegis.enterprise import (
    PAYMENT_API_RECOVERED as PAYMENT_API_RECOVERED,
)
from aegis.enterprise import (
    PAYMENT_DB as PAYMENT_DB,
)
from aegis.enterprise import (
    dependency_nodes as dependency_nodes,
)

FIXED_EVALUATION_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def fixed_clock() -> datetime:
    """A clock that never moves, so decisions are byte-reproducible."""
    return FIXED_EVALUATION_TIME


# Resource ids come from the declared enterprise; this module never invents its own.


# --- capabilities -------------------------------------------------------------------

TELEMETRY_READ = Capability(
    capability_id="telemetry.read",
    description="Read service telemetry.",
    risk_class=RiskLevel.LOW,
    resource_scope=(PAYMENT_API, ORDER_SERVICE),
    data_classification=DataClassification.INTERNAL,
    reversible=True,
    approval_requirement=ApprovalRequirement.NONE,
    allowed_agents=("diagnostic", "commander", "security", "business-impact", "remediation"),
)
"""Unambiguously low-authority: LOW, reversible, no approval. Not privileged."""

LOGS_READ = Capability(
    capability_id="logs.read",
    description="Read service logs.",
    risk_class=RiskLevel.LOW,
    resource_scope=(PAYMENT_API,),
    data_classification=DataClassification.CONFIDENTIAL,
    reversible=True,
    approval_requirement=ApprovalRequirement.NONE,
    allowed_agents=("diagnostic",),
)
"""Not privileged. Granted to diagnostic only."""

DEPLOYMENT_READ = Capability(
    capability_id="deployment.read",
    description="Read service deployment history.",
    risk_class=RiskLevel.LOW,
    resource_scope=(PAYMENT_API, ORDER_SERVICE),
    data_classification=DataClassification.INTERNAL,
    reversible=True,
    approval_requirement=ApprovalRequirement.NONE,
    allowed_agents=("diagnostic", "commander", "security", "remediation"),
)

SECURITY_READ = Capability(
    capability_id="security.read",
    description="Read security events.",
    risk_class=RiskLevel.MEDIUM,
    resource_scope=(PAYMENT_API,),
    data_classification=DataClassification.RESTRICTED,
    reversible=True,
    approval_requirement=ApprovalRequirement.NONE,
    allowed_agents=("security",),
)
"""Privileged purely because its risk class is MEDIUM, though it is a read."""

PRODUCTION_ROLLBACK = Capability(
    capability_id="production.rollback",
    description="Roll a service back to a previously deployed version.",
    risk_class=RiskLevel.HIGH,
    resource_scope=(PAYMENT_API, ORDER_SERVICE),
    data_classification=DataClassification.INTERNAL,
    reversible=True,
    approval_requirement=ApprovalRequirement.ALWAYS,
    allowed_agents=("remediation",),
)
"""Privileged production mutation. Always requires human approval."""

PRODUCTION_SCALE = Capability(
    capability_id="production.scale",
    description="Change the replica count of a service.",
    risk_class=RiskLevel.MEDIUM,
    resource_scope=(PAYMENT_API,),
    data_classification=DataClassification.INTERNAL,
    reversible=True,
    approval_requirement=ApprovalRequirement.RISK_BASED,
    allowed_agents=("remediation",),
)
"""Privileged production mutation whose approval depends on the assessed risk."""

CUSTOMER_NOTIFY = Capability(
    capability_id="customer.notify",
    description="Send a customer-facing incident notification.",
    risk_class=RiskLevel.LOW,
    resource_scope=(PAYMENT_API,),
    data_classification=DataClassification.CONFIDENTIAL,
    reversible=False,
    approval_requirement=ApprovalRequirement.NONE,
    allowed_agents=("remediation",),
)
"""Privileged only because it is irreversible: a sent notification cannot be unsent."""

ALL_CAPABILITIES: tuple[Capability, ...] = (
    TELEMETRY_READ,
    LOGS_READ,
    DEPLOYMENT_READ,
    SECURITY_READ,
    PRODUCTION_ROLLBACK,
    PRODUCTION_SCALE,
    CUSTOMER_NOTIFY,
)


# --- agents -------------------------------------------------------------------------


def _agent(
    agent_id: str,
    *,
    status: AgentLifecycleState,
    capabilities: tuple[str, ...],
) -> Agent:
    return Agent(
        agent_id=agent_id,
        name=f"{agent_id.title()} Agent",
        version="1.0.0",
        status=status,
        identity_reference=f"aegis:identity:{agent_id}",
        capabilities=capabilities,
    )


DIAGNOSTIC = _agent(
    "diagnostic",
    status=AgentLifecycleState.ACTIVE,
    capabilities=("telemetry.read", "logs.read", "deployment.read"),
)
"""Read-only specialist. Notably does not hold production.rollback."""

COMMANDER = _agent(
    "commander",
    status=AgentLifecycleState.ACTIVE,
    capabilities=("telemetry.read", "deployment.read"),
)
"""The orchestrating agent.

Holds reads and nothing else. It deliberately does **not** hold ``production.rollback``:
``claude.md`` section 7 forbids the Commander from performing production mutation, and the
policy engine is what enforces that rather than the Commander's good manners.
"""

SECURITY = _agent(
    "security",
    status=AgentLifecycleState.ACTIVE,
    capabilities=("telemetry.read", "logs.read", "security.read", "deployment.read"),
)
"""Security specialist. Reads security-relevant signals; holds no mutation."""

BUSINESS_IMPACT = _agent(
    "business-impact",
    status=AgentLifecycleState.ACTIVE,
    capabilities=("telemetry.read",),
)
"""Business-impact specialist. Derives reach from health and the dependency graph."""

REMEDIATION = _agent(
    "remediation",
    status=AgentLifecycleState.ACTIVE,
    capabilities=(
        "telemetry.read",
        "deployment.read",
        "production.rollback",
        "production.scale",
        "customer.notify",
    ),
)
"""The most privileged agent in the initial fleet."""

RESTRICTED_REMEDIATION = REMEDIATION.model_copy(update={"status": AgentLifecycleState.RESTRICTED})
QUARANTINED_REMEDIATION = REMEDIATION.model_copy(update={"status": AgentLifecycleState.QUARANTINED})
RETIRED_REMEDIATION = REMEDIATION.model_copy(update={"status": AgentLifecycleState.RETIRED})
REGISTERED_REMEDIATION = REMEDIATION.model_copy(update={"status": AgentLifecycleState.REGISTERED})

RESTRICTED_DIAGNOSTIC = DIAGNOSTIC.model_copy(update={"status": AgentLifecycleState.RESTRICTED})

UNREGISTERED = _agent(
    "rogue",
    status=AgentLifecycleState.ACTIVE,
    capabilities=("production.rollback",),
)
"""An agent record claiming a capability whose definition does not permit it."""


# --- helpers ------------------------------------------------------------------------


def build_registry() -> CapabilityRegistry:
    """A registry holding the full capability set."""
    return CapabilityRegistry(ALL_CAPABILITIES)


def build_action(
    *,
    requesting_agent: str,
    capability: str,
    target_resource: str = PAYMENT_API,
    risk: RiskLevel | None = None,
    action_id: str = "act-001",
    incident_id: str = "INC-2026-0001",
) -> Action:
    """A proposed action. ``risk`` defaults to ``None`` — unassessed, as proposed."""
    return Action(
        action_id=action_id,
        incident_id=incident_id,
        requesting_agent=requesting_agent,
        capability=capability,
        target_resource=target_resource,
        risk=risk,
    )


# --- dependency graph ---------------------------------------------------------------

UNKNOWN_RESOURCE = "service:totally-unknown"
"""Deliberately never declared in any graph built here."""

BASE_TOPOLOGY: tuple[ResourceNode, ...] = dependency_nodes()
"""The dependency nodes of the one declared enterprise.

Sourced from :mod:`aegis.enterprise.topology` rather than restated here, so the graph the
control plane reasons about and the world the simulator mutates can never diverge.
"""


def build_graph(extra: Iterable[ResourceNode] = ()) -> DependencyGraph:
    """The base topology, optionally with additional nodes appended."""
    return DependencyGraph((*BASE_TOPOLOGY, *extra))


# --- incidents ----------------------------------------------------------------------

INCIDENT_CREATED_AT = datetime(2026, 1, 1, 11, 0, 0, tzinfo=UTC)
"""Before :data:`FIXED_EVALUATION_TIME`, so a transition stamped at the fixed clock
always satisfies the ``updated_at >= created_at`` invariant."""


def build_incident(
    *,
    state: IncidentState = IncidentState.RECEIVED,
    incident_id: str = "INC-2026-0001",
    severity: RiskLevel = RiskLevel.HIGH,
    proposed_actions: tuple[str, ...] = ("act-001",),
) -> Incident:
    """A deterministic incident in the requested state."""
    return Incident(
        incident_id=incident_id,
        source="monitoring.alerting",
        severity=severity,
        state=state,
        assigned_agents=("commander", "diagnostic", "remediation"),
        proposed_actions=proposed_actions,
        created_at=INCIDENT_CREATED_AT,
        updated_at=INCIDENT_CREATED_AT,
    )


# --- verification -------------------------------------------------------------------

TELEMETRY_SOURCE = "telemetry.payment-api"
DEPLOYMENT_SOURCE = "deployments.payment-api"
UNTRUSTED_SOURCE = "external.status-page"

# PAYMENT_API_RECOVERED is imported from the enterprise scenario above.


def build_observation(
    *,
    values: dict[str, float | str],
    observation_id: str = "obs-001",
    resource: str = PAYMENT_API,
    source: str = TELEMETRY_SOURCE,
    observed_at: datetime | None = None,
    evidence_type: EvidenceType = EvidenceType.TELEMETRY,
    confidence: float = 0.95,
) -> Observation:
    """A deterministic observation, fresh as of :data:`FIXED_EVALUATION_TIME` by default."""
    return Observation(
        evidence=Evidence(
            evidence_id=observation_id,
            source=source,
            reference=f"query:{observation_id}",
            timestamp=observed_at or FIXED_EVALUATION_TIME,
            type=evidence_type,
            confidence=confidence,
        ),
        resource=resource,
        values=values,
    )


def healthy_observations(*, observed_at: datetime | None = None) -> tuple[Observation, ...]:
    """Observations that satisfy :data:`PAYMENT_API_RECOVERED`."""
    return (
        build_observation(
            observation_id="obs-health",
            values={"health": "healthy", "error_rate": 0.7},
            observed_at=observed_at,
        ),
        build_observation(
            observation_id="obs-deployment",
            values={"deployment": "v4.7"},
            source=DEPLOYMENT_SOURCE,
            evidence_type=EvidenceType.DEPLOYMENT,
            observed_at=observed_at,
        ),
    )
