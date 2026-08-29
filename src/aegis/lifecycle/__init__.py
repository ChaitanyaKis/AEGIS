"""Lifecycle management and the circuit breaker (``claude.md`` sections 8, 10).

Two components with sharply separated jobs:

    LifecycleManager  — "should the incident lifecycle continue?"
    CircuitBreaker    — "is this automation path allowed to keep operating?"

Neither grants authority. Between them they can stop automation and can decline to stop it,
and declining to stop is not permission: proceeding still requires passing assessment,
policy, approval and execution authorization, every one of which can independently refuse.
:class:`~aegis.lifecycle.models.LifecycleAction` has no ``EXECUTE`` member for exactly that
reason.

What each owns
--------------

The manager owns bounded execution, retry accounting, recovery limits, terminal-state
handling, escalation conditions and stop reasons — all questions about *how much automation
has happened*, which nothing else tracks. The breaker owns emergency stopping: repeated
failures of a classified kind, per scope, with CLOSED / OPEN / HALF_OPEN and a single
bounded probe as the only route back.

What neither owns
-----------------

Whether an action is permitted (policy), whether a human agreed (approval), whether the
enterprise changed (verification), whether history is intact (audit), how dangerous
something is (assessment). The breaker imports none of those engines — asserted by test —
and the manager calls them through the orchestrator rather than speaking for them.

Fail-closed and deterministic. A model failure, a tool failure and a blocked execution all
stop the lifecycle; none of them becomes success, and none of them becomes permission.
"""

from aegis.lifecycle.circuit_breaker import (
    BreakerDecision,
    CircuitBreaker,
    CorruptionPolicy,
    scope_key,
)
from aegis.lifecycle.conditions import (
    GOVERNANCE_ANOMALIES,
    FailureClass,
    FailureSignal,
    classify_execution,
    classify_verification,
    detect_governance_anomaly,
    is_governance_anomaly,
)
from aegis.lifecycle.coordinator import GateIssue, LifecycleCoordinator
from aegis.lifecycle.errors import (
    CircuitOpen,
    InvalidLifecycleConfiguration,
    LifecycleError,
    LifecycleGateRejected,
    LifecycleStateCorrupt,
    ProbeAlreadyInFlight,
)
from aegis.lifecycle.gate import (
    DEFAULT_GATE_TTL_SECONDS,
    GateRegister,
    GateRejection,
    LifecycleGate,
    gate_seal,
)
from aegis.lifecycle.limits import (
    DEFAULT_BREAKER_CONFIG,
    DEFAULT_LIFECYCLE_LIMITS,
    BreakerScope,
    CircuitBreakerConfig,
    LifecycleLimits,
)
from aegis.lifecycle.manager import TERMINAL_STATES, LifecycleManager
from aegis.lifecycle.models import (
    LifecycleAction,
    LifecycleDecision,
    LifecycleRecord,
    StopReason,
)
from aegis.lifecycle.persistence import (
    InMemoryLifecycleState,
    JsonlLifecycleState,
    LifecycleStatePersistence,
)
from aegis.lifecycle.restriction import (
    DEFAULT_RESTRICTION_CONFIG,
    AgentRestriction,
    AgentRestrictionConfig,
    AgentRestrictionRegistry,
    RestrictionScope,
    RestrictionVerdict,
)
from aegis.lifecycle.scope import (
    ResourceScopeDecision,
    ResourceScopeVerdict,
    ResourceScopeVerifier,
)
from aegis.lifecycle.state import (
    LIFECYCLE_GENESIS_DIGEST,
    BreakerSnapshot,
    BreakerTransition,
    CircuitState,
    LifecycleCounters,
    LifecycleStateRecord,
    StateIntegrityReport,
    StateRecordKind,
    legal_transition,
    state_digest,
    verify_state_chain,
)

__all__ = [
    "DEFAULT_BREAKER_CONFIG",
    "DEFAULT_GATE_TTL_SECONDS",
    "DEFAULT_LIFECYCLE_LIMITS",
    "DEFAULT_RESTRICTION_CONFIG",
    "GOVERNANCE_ANOMALIES",
    "LIFECYCLE_GENESIS_DIGEST",
    "TERMINAL_STATES",
    "AgentRestriction",
    "AgentRestrictionConfig",
    "AgentRestrictionRegistry",
    "BreakerDecision",
    "BreakerScope",
    "BreakerSnapshot",
    "BreakerTransition",
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitOpen",
    "CircuitState",
    "CorruptionPolicy",
    "FailureClass",
    "FailureSignal",
    "GateIssue",
    "GateRegister",
    "GateRejection",
    "InMemoryLifecycleState",
    "InvalidLifecycleConfiguration",
    "JsonlLifecycleState",
    "LifecycleAction",
    "LifecycleCoordinator",
    "LifecycleCounters",
    "LifecycleDecision",
    "LifecycleError",
    "LifecycleGate",
    "LifecycleGateRejected",
    "LifecycleLimits",
    "LifecycleManager",
    "LifecycleRecord",
    "LifecycleStateCorrupt",
    "LifecycleStatePersistence",
    "LifecycleStateRecord",
    "ProbeAlreadyInFlight",
    "RestrictionScope",
    "RestrictionVerdict",
    "ResourceScopeDecision",
    "ResourceScopeVerdict",
    "ResourceScopeVerifier",
    "StateIntegrityReport",
    "StateRecordKind",
    "StopReason",
    "classify_execution",
    "classify_verification",
    "detect_governance_anomaly",
    "gate_seal",
    "is_governance_anomaly",
    "legal_transition",
    "scope_key",
    "state_digest",
    "verify_state_chain",
]
