"""Simulated enterprise — CONTROLLED SIMULATION (``claude.md`` sections 14, 15, 17).

Trust zone D: protected resources the control plane reaches only through governed
capabilities. Everything in this package is **synthetic and deliberately reproducible**.
None of it is production infrastructure, real telemetry, a real deployment or live
customer data, and nothing here should ever be described as such.

    authorized action -> simulated mutation -> changed world -> observations

The enterprise is acted upon; it does not decide. It never calls the policy engine, never
authorizes anything, and never forces a verification outcome — it changes state and
reports what its sources see, leaving every judgement to the control plane.

There is no randomness anywhere in this package, so there is nothing to seed: determinism
comes from construction rather than from a fixed generator state.
"""

from aegis.enterprise.failures import STALE_TELEMETRY_OFFSET, FailureType
from aegis.enterprise.models import (
    DeploymentProfile,
    ResourceState,
    ServiceHealth,
    WorldSnapshot,
)
from aegis.enterprise.mutations import (
    SUPPORTED_CAPABILITIES,
    ActionExecutor,
    ExecutionOutcome,
    ExecutionResult,
    UnauthorizedExecutionError,
)
from aegis.enterprise.observations import OBSERVATION_CONFIDENCE, ObservationSource
from aegis.enterprise.scenarios import (
    GOLDEN_ACTION_ID,
    GOLDEN_APPROVAL_ID,
    GOLDEN_INCIDENT_ID,
    GOLDEN_VERIFICATION_ID,
    PAYMENT_API_RECOVERED,
    GoldenIncidentRun,
    GoldenIncidentScenario,
)
from aegis.enterprise.topology import (
    API_GATEWAY,
    AUTH_SERVICE,
    CUSTOMER_DATABASE,
    ENTERPRISE_TOPOLOGY,
    NOTIFICATION_SERVICE,
    ORDER_DB,
    ORDER_SERVICE,
    PAYMENT_API,
    PAYMENT_API_FAULTY_VERSION,
    PAYMENT_API_GOOD_VERSION,
    PAYMENT_DB,
    ResourceDefinition,
    build_dependency_graph,
    dependency_nodes,
)
from aegis.enterprise.world import EnterpriseWorld, UnsupportedOperationError

__all__ = [
    "API_GATEWAY",
    "AUTH_SERVICE",
    "CUSTOMER_DATABASE",
    "ENTERPRISE_TOPOLOGY",
    "GOLDEN_ACTION_ID",
    "GOLDEN_APPROVAL_ID",
    "GOLDEN_INCIDENT_ID",
    "GOLDEN_VERIFICATION_ID",
    "NOTIFICATION_SERVICE",
    "OBSERVATION_CONFIDENCE",
    "ORDER_DB",
    "ORDER_SERVICE",
    "PAYMENT_API",
    "PAYMENT_API_FAULTY_VERSION",
    "PAYMENT_API_GOOD_VERSION",
    "PAYMENT_API_RECOVERED",
    "PAYMENT_DB",
    "STALE_TELEMETRY_OFFSET",
    "SUPPORTED_CAPABILITIES",
    "ActionExecutor",
    "DeploymentProfile",
    "EnterpriseWorld",
    "ExecutionOutcome",
    "ExecutionResult",
    "FailureType",
    "GoldenIncidentRun",
    "GoldenIncidentScenario",
    "ObservationSource",
    "ResourceDefinition",
    "ResourceState",
    "ServiceHealth",
    "UnauthorizedExecutionError",
    "UnsupportedOperationError",
    "WorldSnapshot",
    "build_dependency_graph",
    "dependency_nodes",
]
