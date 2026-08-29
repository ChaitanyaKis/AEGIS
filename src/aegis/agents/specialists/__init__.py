"""The four specialist agents (``claude.md`` section 7).

Trust zone B. Each reasons inside one domain, reads through governed tools, and returns an
advisory :class:`~aegis.agents.findings.AgentFinding`. None of them can authorize, approve,
execute, verify or resolve, and a static test asserts that no module here imports the
policy engine, the approval engine, the state machine, the verification engine, the audit
store or the enterprise.

Only :class:`RemediationAgent` may *propose* a production mutation, and even that reaches
the enterprise solely through assessment, policy, approval and execution.
"""

from aegis.agents.specialists.base import (
    DEFAULT_SPECIALIST_STEPS,
    SpecialistAgent,
    SpecialistOutcome,
    SpecialistResult,
    SpecialistTask,
    Toolbox,
)
from aegis.agents.specialists.models import (
    INJECTION_MARKERS,
    BusinessImpactModel,
    DiagnosticModel,
    FailingSpecialistModel,
    RemediationModel,
    SecurityModel,
)
from aegis.agents.specialists.roles import (
    SPECIALIST_TOOLS,
    BusinessImpactAgent,
    DiagnosticAgent,
    RemediationAgent,
    SecurityAgent,
)

__all__ = [
    "DEFAULT_SPECIALIST_STEPS",
    "INJECTION_MARKERS",
    "SPECIALIST_TOOLS",
    "BusinessImpactAgent",
    "BusinessImpactModel",
    "DiagnosticAgent",
    "DiagnosticModel",
    "FailingSpecialistModel",
    "RemediationAgent",
    "RemediationModel",
    "SecurityAgent",
    "SecurityModel",
    "SpecialistAgent",
    "SpecialistOutcome",
    "SpecialistResult",
    "SpecialistTask",
    "Toolbox",
]
