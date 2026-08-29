"""The four specialists (``claude.md`` section 7).

Each is a thin declaration on top of :class:`~aegis.agents.specialists.base.SpecialistAgent`:
an identity, the one task type it handles, the one finding type it produces, and — for
Remediation alone — the capabilities it may propose.

The authority separation is data, not behaviour. Diagnostic, Security and Business Impact
declare ``propose_capabilities = frozenset()``, so a finding from any of them carrying a
proposal is rejected before it leaves the agent. Only Remediation declares
``production.rollback``, and even that is a *proposal*: it reaches the enterprise solely
through assessment, policy, approval and execution.
"""

from __future__ import annotations

from aegis.agents.decisions import TaskType
from aegis.agents.findings import FindingType
from aegis.agents.specialists.base import SpecialistAgent

__all__ = [
    "SPECIALIST_TOOLS",
    "BusinessImpactAgent",
    "DiagnosticAgent",
    "RemediationAgent",
    "SecurityAgent",
]


class DiagnosticAgent(SpecialistAgent):
    """Technical health: telemetry, deployments, dependencies, likely cause.

    Read-only. It cannot execute, authorize, approve, verify or resolve, and it cannot
    propose a remediation — naming the cause is not the same authority as fixing it.
    """

    agent_id = "diagnostic"
    role = "technical diagnosis"
    task_type = TaskType.DIAGNOSE_SERVICE
    finding_type = FindingType.TECHNICAL_DIAGNOSIS


class SecurityAgent(SpecialistAgent):
    """Security signals: suspicious content, injection attempts, bypass attempts.

    Its findings are *detection*, and detection is not enforcement. A SecurityAgent that
    says "safe" changes nothing about what policy permits, and one that says "malicious"
    blocks nothing by itself. The two layers are deliberately independent: probabilistic
    detection alongside deterministic enforcement (``claude.md`` section 13).
    """

    agent_id = "security"
    role = "security assessment"
    task_type = TaskType.INVESTIGATE_SECURITY
    finding_type = FindingType.SECURITY_ASSESSMENT


class BusinessImpactAgent(SpecialistAgent):
    """Who is affected: dependent services, customer-facing reach, severity.

    Impact is derived from the declared dependency graph and observed health, not from a
    customer database — the simulated enterprise does not model customers, and inventing a
    reading would be worse than reporting what is actually known.
    """

    agent_id = "business-impact"
    role = "business impact"
    task_type = TaskType.ASSESS_BUSINESS_IMPACT
    finding_type = FindingType.BUSINESS_IMPACT


class RemediationAgent(SpecialistAgent):
    """Proposes a fix, and only proposes it.

    The single agent with proposal authority over a production mutation, and still unable
    to carry one out: it holds no executor, no authorization and no world. Its finding goes
    to the same deterministic adapter every other proposal goes to, and its Action arrives
    at assessment with ``risk = None`` like all the others.
    """

    agent_id = "remediation"
    role = "remediation"
    task_type = TaskType.PROPOSE_REMEDIATION
    finding_type = FindingType.REMEDIATION_PROPOSAL
    propose_capabilities = frozenset({"production.rollback"})


SPECIALIST_TOOLS: dict[str, frozenset[str]] = {
    DiagnosticAgent.agent_id: frozenset(
        {
            "get_service_health",
            "get_metrics",
            "get_recent_deployments",
            "get_dependency_health",
        }
    ),
    SecurityAgent.agent_id: frozenset(
        {"get_security_signals", "get_recent_deployments", "get_service_health"}
    ),
    BusinessImpactAgent.agent_id: frozenset({"get_service_health", "get_dependency_health"}),
    RemediationAgent.agent_id: frozenset({"get_service_health", "get_recent_deployments"}),
}
"""Which read tools each specialist may name.

Least privilege at the tool layer, on top of the capability checks the governed toolbox
already performs. Business Impact gets no deployment history because knowing which version
is running is not its job; Security gets no dependency walk for the same reason.

No tool was invented to give every agent a matching interface. Where the simulated
enterprise does not model something — customer records, log streams — the specialist works
from what is actually observable and says so.
"""
