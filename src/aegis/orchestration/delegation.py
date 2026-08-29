"""Who may delegate what to whom.

Delegation is configuration, not model output. The registry names the specialists that
exist, the matrix names the edges that are permitted, and neither is reachable from a
model. A delegating agent supplies an id and a task type; everything else — the incident,
the step, the bound — is supplied by the orchestrator from authoritative state.

    Commander -> Diagnostic | Security | BusinessImpact | Remediation      ALLOW
    Specialist -> anyone                                                   DENY

The specialist row is the important one. If a specialist could delegate, an agent with no
authority could reach an agent with proposal authority and manufacture a chain that ends in
a production mutation. Cutting every specialist edge means the only route to a remediation
proposal runs through the Commander, and the only route from there to the enterprise runs
through assessment, policy, approval and execution.

Lookup is exact. An agent id is a dictionary key — never an attribute name, a module path
or anything that becomes a callable — so an invented name can only produce "unknown agent".
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType

from aegis.agents.decisions import TaskType
from aegis.agents.specialists import (
    SpecialistAgent,
    SpecialistResult,
    SpecialistTask,
)
from aegis.core.domain import DomainModel, NonEmptyStr
from aegis.registry import AgentRegistry

__all__ = [
    "DELEGATION_MATRIX",
    "DelegationOutcome",
    "DelegationResult",
    "SpecialistRegistry",
]


DELEGATION_MATRIX: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "commander": frozenset({"diagnostic", "security", "business-impact", "remediation"}),
        "diagnostic": frozenset(),
        "security": frozenset(),
        "business-impact": frozenset(),
        "remediation": frozenset(),
    }
)
"""Every permitted delegation edge. An agent absent from the map may delegate to nobody."""


class DelegationOutcome(StrEnum):
    """How a delegation attempt ended."""

    COMPLETED = "COMPLETED"
    UNKNOWN_AGENT = "UNKNOWN_AGENT"
    NOT_PERMITTED = "NOT_PERMITTED"
    """The matrix has no edge from the delegating agent to the target."""

    UNKNOWN_TASK = "UNKNOWN_TASK"
    """The target does not handle that task type."""

    FAILED = "FAILED"
    REJECTED = "REJECTED"
    """The specialist produced something outside its declared authority."""

    REGISTRY_INELIGIBLE = "REGISTRY_INELIGIBLE"
    """The agent registry refused this agent (suspended, revoked, not approved, etc.).

    Distinct from UNKNOWN_AGENT (not in the local specialist fleet) and NOT_PERMITTED
    (matrix has no edge): an agent can be locally registered and matrix-permitted and
    still be administratively ineligible. Either can refuse independently.
    """


class DelegationResult(DomainModel):
    """What one delegation produced.

    Only ``COMPLETED`` carries a specialist result, and only a completed specialist result
    carries a finding. A refusal never yields a hollow finding a caller might act on.
    """

    delegating_agent: NonEmptyStr
    target_agent_id: NonEmptyStr
    task_type: TaskType
    outcome: DelegationOutcome
    detail: NonEmptyStr
    result: SpecialistResult | None = None

    @property
    def completed(self) -> bool:
        return self.outcome is DelegationOutcome.COMPLETED

    @property
    def finding(self):
        """The finding, if one was produced. Advisory in every case."""
        return self.result.finding if self.result is not None else None


class SpecialistRegistry:
    """The specialists that exist, and who may reach them.

    Args:
        specialists: Constructed specialist agents, keyed by their declared ``agent_id``.
        matrix: Permitted delegation edges. Defaults to :data:`DELEGATION_MATRIX`.
        agent_registry: Optional governed agent registry. When supplied, every dispatch
            checks registry eligibility *before* the specialist runs. An ineligible agent
            (suspended, revoked, awaiting approval) is refused with
            :attr:`DelegationOutcome.REGISTRY_INELIGIBLE`, regardless of what the local
            fleet contains or what the matrix permits. When absent, the pre-existing
            fleet + matrix checks apply without registry enforcement.

    Static: no discovery, no dynamic class loading, no model-controlled imports. Every
    entry was constructed by the application before any model ran.
    """

    def __init__(
        self,
        specialists: tuple[SpecialistAgent, ...],
        *,
        matrix: Mapping[str, frozenset[str]] = DELEGATION_MATRIX,
        agent_registry: AgentRegistry | None = None,
    ) -> None:
        self._agents: dict[str, SpecialistAgent] = {}
        for specialist in specialists:
            if specialist.agent_id in self._agents:
                raise ValueError(f"duplicate specialist: {specialist.agent_id!r}")
            self._agents[specialist.agent_id] = specialist
        self._matrix = matrix
        self._agent_registry = agent_registry

    def get(self, agent_id: str) -> SpecialistAgent | None:
        """The specialist with this exact id, or ``None``."""
        return self._agents.get(agent_id)

    def ids(self) -> tuple[str, ...]:
        """Every registered specialist id, sorted."""
        return tuple(sorted(self._agents))

    def targets_for(self, delegating_agent: str) -> tuple[str, ...]:
        """Who this agent may delegate to, sorted. Empty for every specialist."""
        permitted = self._matrix.get(delegating_agent, frozenset())
        return tuple(sorted(permitted & set(self._agents)))

    def permits(self, delegating_agent: str, target_agent_id: str) -> bool:
        """Whether the matrix has an edge. Exact match on both ends."""
        return target_agent_id in self._matrix.get(delegating_agent, frozenset())

    def dispatch(
        self, delegating_agent: str, target_agent_id: str, task: SpecialistTask
    ) -> DelegationResult:
        """Run one delegated task, refusing anything the configuration does not permit.

        Checks in order:
        1. the target exists in the local fleet
        2. the matrix has an edge from delegating_agent to target
        3. the target handles the requested task type
        4. the agent registry (if wired) considers the target eligible
        5. the specialist runs

        Step 4 is independent of steps 1-3: an agent can be fleet-registered,
        matrix-permitted and task-capable and still be administratively ineligible
        (suspended, revoked, awaiting approval). Both the fleet and the registry must agree
        before any work is dispatched.
        """

        def refuse(outcome: DelegationOutcome, detail: str) -> DelegationResult:
            return DelegationResult(
                delegating_agent=delegating_agent,
                target_agent_id=target_agent_id or "<empty>",
                task_type=task.task_type,
                outcome=outcome,
                detail=detail,
            )

        specialist = self._agents.get(target_agent_id)
        if specialist is None:
            return refuse(
                DelegationOutcome.UNKNOWN_AGENT,
                f"no specialist {target_agent_id!r} is registered; available: "
                f"{', '.join(self.ids()) or 'none'}",
            )
        if not self.permits(delegating_agent, target_agent_id):
            return refuse(
                DelegationOutcome.NOT_PERMITTED,
                f"{delegating_agent} may not delegate to {target_agent_id}; permitted: "
                f"{', '.join(self.targets_for(delegating_agent)) or 'none'}",
            )
        if specialist.task_type is not task.task_type:
            return refuse(
                DelegationOutcome.UNKNOWN_TASK,
                f"{target_agent_id} handles {specialist.task_type}, not {task.task_type}",
            )

        # Registry eligibility check — administrative standing.
        # Runs after fleet+matrix checks so the refusal message names the most
        # informative reason ("unknown agent" is more precise than "registry unknown").
        if self._agent_registry is not None:
            verdict = self._agent_registry.eligibility(target_agent_id)
            if not verdict.eligible:
                return refuse(
                    DelegationOutcome.REGISTRY_INELIGIBLE,
                    f"agent registry refused {target_agent_id!r}: {verdict.detail} "
                    f"(refusal={verdict.refusal})",
                )

        result = specialist.run(task)
        outcome = {
            "COMPLETED": DelegationOutcome.COMPLETED,
            "FAILED": DelegationOutcome.FAILED,
            "REJECTED": DelegationOutcome.REJECTED,
        }[result.outcome.value]
        return DelegationResult(
            delegating_agent=delegating_agent,
            target_agent_id=target_agent_id,
            task_type=task.task_type,
            outcome=outcome,
            detail=result.detail,
            result=result,
        )

    def __len__(self) -> int:
        return len(self._agents)

    def __contains__(self, agent_id: object) -> bool:
        return agent_id in self._agents

    def __repr__(self) -> str:
        return f"{type(self).__name__}({len(self._agents)} specialists)"
