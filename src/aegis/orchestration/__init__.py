"""Orchestration — the wiring between the agent plane and the control plane.

Thin by design. It connects the Commander to policy, approval, the state machine, the
enterprise, verification and audit, and it decides nothing itself: no risk, no
authorization, no approval, no state transition, no verification outcome. Each of those is
a call into the component that owns it.

    COMMANDER -> ORCHESTRATOR -> POLICY / APPROVAL / STATE MACHINE
                              -> ENTERPRISE -> OBSERVATIONS -> VERIFICATION -> AUDIT
"""

from aegis.orchestration.approval import (
    ApprovalProvider,
    ApprovalVerdict,
    DeterministicApprovalProvider,
)
from aegis.orchestration.delegation import (
    DELEGATION_MATRIX,
    DelegationOutcome,
    DelegationResult,
    SpecialistRegistry,
)
from aegis.orchestration.orchestrator import (
    COMMANDER_TOOLS,
    DEFAULT_MAX_STEPS,
    PROPOSAL_AUTHORITY,
    IncidentOrchestrator,
    OrchestrationOutcome,
    OrchestrationRun,
)
from aegis.orchestration.tools import (
    READ_TOOLS,
    GovernedToolbox,
    ToolDefinition,
    ToolKind,
    ToolOutcome,
    ToolRegistry,
    ToolResult,
)

__all__ = [
    "COMMANDER_TOOLS",
    "DEFAULT_MAX_STEPS",
    "DELEGATION_MATRIX",
    "PROPOSAL_AUTHORITY",
    "READ_TOOLS",
    "ApprovalProvider",
    "ApprovalVerdict",
    "DelegationOutcome",
    "DelegationResult",
    "DeterministicApprovalProvider",
    "GovernedToolbox",
    "IncidentOrchestrator",
    "OrchestrationOutcome",
    "OrchestrationRun",
    "SpecialistRegistry",
    "ToolDefinition",
    "ToolKind",
    "ToolOutcome",
    "ToolRegistry",
    "ToolResult",
]
