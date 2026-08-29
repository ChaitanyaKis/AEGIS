"""The shape every specialist shares.

Trust zone B (``claude.md`` sections 4, 7). A specialist reasons inside one domain, reads
through governed tools, and returns a finding. That is all it can do.

Structurally powerless, like the Commander
------------------------------------------

A specialist holds a model client, a toolbox handed to it, and its own declared profile.
It imports nothing from the policy engine, the approval engine, the state machine, the
verification engine, the audit store or the enterprise — a static test over every module
in this package enforces that. The toolbox arrives as a :class:`Toolbox` *protocol*, so
even the type annotation cannot drag the control plane in.

Proposal authority is declared, not assumed
-------------------------------------------

``propose_capabilities`` is empty for every specialist except Remediation. A finding
carrying a proposal outside that set is rejected here, before it reaches the orchestrator —
and rejected again there. An agent cannot widen its own authority by returning a
better-argued finding.

Bounded, like everything else
-----------------------------

A specialist runs a fixed number of steps. Every failure — model, tool, malformed output,
exhaustion — produces a structured :class:`SpecialistResult` with no finding, never a
finding that happens to be empty.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from pydantic import Field, JsonValue

from aegis.agents.decisions import TaskType
from aegis.agents.findings import AgentFinding
from aegis.agents.model import ModelClient, ModelError, ModelRequest
from aegis.core.domain import (
    AgentRef,
    DomainModel,
    EvidenceRef,
    IncidentRef,
    NonEmptyStr,
)

DEFAULT_SPECIALIST_STEPS = 1
"""Model turns one delegated task may consume.

One today: a specialist gathers its evidence, concludes once, and returns. The bound is
explicit and configurable so that a future multi-turn specialist is still bounded.
"""

__all__ = [
    "DEFAULT_SPECIALIST_STEPS",
    "SpecialistAgent",
    "SpecialistOutcome",
    "SpecialistResult",
    "SpecialistTask",
    "Toolbox",
]


@runtime_checkable
class Toolbox(Protocol):
    """The only way a specialist reaches the world.

    Structural, so specialists never import the governed toolbox and, through it, the
    policy engine. Whatever satisfies this shape has already put policy in front of every
    read before a specialist sees a result.
    """

    def available_tool_ids(self) -> tuple[str, ...]: ...

    def invoke(self, tool_id: str, arguments: Mapping[str, JsonValue]) -> Any: ...


class SpecialistOutcome(StrEnum):
    """How a delegated task ended."""

    COMPLETED = "COMPLETED"
    """A finding was produced. Advisory — never authorization or verification."""

    FAILED = "FAILED"
    """The model or a tool did not deliver. No finding, and nothing may proceed on it."""

    REJECTED = "REJECTED"
    """The specialist produced something outside its declared authority."""


class SpecialistTask(DomainModel):
    """One bounded unit of delegated work, as dispatched.

    Built by the orchestrator, never by a model: the incident, step and bound are
    authoritative values the delegating agent cannot misstate.
    """

    incident_id: IncidentRef
    task_type: TaskType
    target_resource: NonEmptyStr | None = None
    evidence_refs: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
    incident_payload: Mapping[str, JsonValue] = Field(default_factory=dict)
    """The incident as received. Untrusted (``claude.md`` section 4, zone A)."""

    step: int = Field(ge=0)
    max_steps: int = Field(ge=1)


class SpecialistResult(DomainModel):
    """What a delegation produced, whether or not it worked."""

    agent_id: AgentRef
    task_type: TaskType
    outcome: SpecialistOutcome
    finding: AgentFinding | None = None
    """Present only on COMPLETED. A failure never yields a hollow finding."""

    detail: NonEmptyStr
    steps_used: int = Field(ge=0)
    observations: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
    """Observation ids the specialist actually read, kept separate from its conclusions."""

    @property
    def completed(self) -> bool:
        return self.outcome is SpecialistOutcome.COMPLETED


class SpecialistAgent:
    """A domain expert with no authority.

    Args:
        model: Its reasoning provider, behind the shared :class:`ModelClient` boundary.
        toolbox: Governed tool access, already scoped to this agent's identity.
        clock: Timestamp source for findings. Injected, so runs stay reproducible.
        max_steps: How many model turns one task may consume.

    Subclasses set ``agent_id``, ``role``, ``task_type``, ``finding_type`` and
    ``propose_capabilities`` as class attributes. Nothing else varies.
    """

    agent_id: str = "specialist"
    role: str = "specialist"
    task_type: TaskType
    finding_type: Any
    propose_capabilities: frozenset[str] = frozenset()
    system_prompt: str = ""

    def __init__(
        self,
        model: ModelClient,
        *,
        toolbox: Toolbox,
        clock,
        max_steps: int = DEFAULT_SPECIALIST_STEPS,
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be at least 1")
        self._model = model
        self._toolbox = toolbox
        self._clock = clock
        self.max_steps = max_steps

    @property
    def model_name(self) -> str:
        return self._model.name

    def run(self, task: SpecialistTask) -> SpecialistResult:
        """Carry out one delegated task and return a structured result.

        Gathers evidence through the toolbox, asks the model for a conclusion, and checks
        that conclusion against this agent's declared authority before returning it.
        """
        if task.task_type is not self.task_type:
            return self._reject(
                task, f"{self.agent_id} handles {self.task_type}, not {task.task_type}", 0
            )

        observations: dict[str, JsonValue] = {}
        evidence: list[str] = []
        unavailable: list[str] = []
        for tool_id in self._toolbox.available_tool_ids():
            result = self._toolbox.invoke(tool_id, {"resource": task.target_resource or ""})
            if getattr(result, "ok", False):
                observations.update(dict(result.data))
                evidence.extend(result.evidence)
            else:
                unavailable.append(f"{tool_id}:{result.outcome}")

        try:
            finding = self._model.decide(
                ModelRequest(
                    task=self._task_instruction(task),
                    data={
                        "incident": {
                            "incident_id": task.incident_id,
                            "target_resource": task.target_resource,
                            **dict(task.incident_payload),
                        },
                        "observations": observations,
                        "unavailable_tools": unavailable,
                        "evidence_references": evidence,
                    },
                    available_tools=self._toolbox.available_tool_ids(),
                    step=task.step,
                    max_steps=self.max_steps,
                )
            )
        except ModelError as error:
            return SpecialistResult(
                agent_id=self.agent_id,
                task_type=task.task_type,
                outcome=SpecialistOutcome.FAILED,
                detail=f"model failed: {type(error).__name__}: {error}",
                steps_used=1,
                observations=tuple(evidence),
            )

        return self._accept(task, finding, tuple(evidence), unavailable)

    # --- authority checks -----------------------------------------------------------

    def _accept(
        self,
        task: SpecialistTask,
        finding: Any,
        evidence: tuple[str, ...],
        unavailable: list[str],
    ) -> SpecialistResult:
        """Check a model's finding against this agent's declared authority."""
        if not isinstance(finding, AgentFinding):
            return self._reject(task, "model did not produce a finding", 1, evidence)
        if finding.agent_id != self.agent_id:
            return self._reject(task, f"finding claims agent {finding.agent_id!r}", 1, evidence)
        if finding.finding_type is not self.finding_type:
            return self._reject(
                task, f"{self.agent_id} does not produce {finding.finding_type}", 1, evidence
            )
        if finding.proposal is not None:
            capability = finding.proposal.capability_id
            if capability not in self.propose_capabilities:
                return self._reject(
                    task,
                    f"{self.agent_id} is not authorised to propose {capability!r}",
                    1,
                    evidence,
                )
        if not evidence and not unavailable:
            return self._reject(task, "finding cites no evidence and read nothing", 1)

        return SpecialistResult(
            agent_id=self.agent_id,
            task_type=task.task_type,
            outcome=SpecialistOutcome.COMPLETED,
            finding=finding,
            detail=f"{self.agent_id} completed {task.task_type}",
            steps_used=1,
            observations=evidence,
        )

    def _reject(
        self,
        task: SpecialistTask,
        detail: str,
        steps: int,
        evidence: tuple[str, ...] = (),
    ) -> SpecialistResult:
        return SpecialistResult(
            agent_id=self.agent_id,
            task_type=task.task_type,
            outcome=SpecialistOutcome.REJECTED,
            detail=detail,
            steps_used=steps,
            observations=evidence,
        )

    def _task_instruction(self, task: SpecialistTask) -> str:
        """The per-task instruction. Written by AEGIS, never from incident content."""
        return (
            f"Carry out {task.task_type} for the named resource, using only the "
            f"observations provided, and report one finding."
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(agent_id={self.agent_id!r}, model={self.model_name!r})"
