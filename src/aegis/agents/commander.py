"""The Commander — an intelligent orchestrator with no authority.

Trust zone B (``claude.md`` sections 4, 7). The Commander interprets an incident, decides
what to find out next, and eventually proposes a remediation. That is the whole of it.

What makes this safe is not the prompt but the wiring: the Commander holds a model client
and nothing else. It has no reference to the policy engine, the approval engine, the
executor, the verification engine, the state machine, the audit store or the world, and it
cannot acquire one. Even a model that decides to disable policy has nothing to call.

The session context is a frozen value. Each step produces a new context through an explicit
``with_*`` transition, so an incident's reasoning history is a chain of values rather than
a mutable scratchpad — and each step is inspectable after the fact.

The context lives for one incident, in process, and is discarded. It may *carry*
organizational history supplied by the caller, but it neither reads nor writes the memory
subsystem: history arrives as opaque JSON and travels to the model as data.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, JsonValue

from aegis.agents.decisions import CommanderDecision, CommanderProposal
from aegis.agents.model import ModelClient, ModelRequest, ToolSpecification
from aegis.core.domain import (
    DomainModel,
    EvidenceRef,
    IncidentRef,
    IncidentState,
    NonEmptyStr,
)

__all__ = ["COMMANDER_TASK", "Commander", "CommanderContext", "CommanderStep"]

COMMANDER_TASK = (
    "Decide the single next step for this incident. Investigate with a registered tool if "
    "you still need evidence, delegate to a registered specialist to get a diagnosis, a "
    "security opinion, an impact assessment or a remediation proposal, or escalate if you "
    "cannot proceed safely."
)
"""The per-step instruction. Written by AEGIS, never derived from incident content."""


class CommanderStep(DomainModel):
    """One completed step of the loop, kept for inspection.

    ``observation`` holds what a tool returned, as JSON-safe data. It is untrusted content
    recorded verbatim — the Commander's summary of it lives in ``decision`` and carries no
    weight anywhere else.
    """

    step: int = Field(ge=0)
    decision: CommanderDecision
    observation: Mapping[str, JsonValue] = Field(default_factory=dict)
    note: NonEmptyStr
    """What the orchestrator did with the decision, in deterministic words."""


class CommanderContext(DomainModel):
    """Everything the Commander knows about one incident, right now.

    Frozen. Advancing means producing a new context, so the history of an incident's
    reasoning is recoverable and no step can quietly rewrite an earlier one.
    """

    incident_id: IncidentRef
    incident_payload: Mapping[str, JsonValue] = Field(default_factory=dict)
    """The incident as received. Untrusted (``claude.md`` section 4, zone A)."""

    lifecycle_state: IncidentState
    step: int = Field(default=0, ge=0)
    history: tuple[CommanderStep, ...] = Field(default_factory=tuple)
    evidence_references: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
    """Observations gathered so far, by id. The control plane works from these, not from
    any summary the model wrote about them."""

    findings: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    """The Commander's own summaries. Recorded and shown; authoritative for nothing."""

    proposals: tuple[CommanderProposal, ...] = Field(default_factory=tuple)
    last_decision: CommanderDecision | None = None

    historical_memory: Mapping[str, JsonValue] = Field(default_factory=dict)
    """Organizational history, as opaque JSON supplied by the caller.

    Deliberately a plain mapping rather than a memory object: this module must not import
    :mod:`aegis.memory`, or the agent plane would gain a route into a subsystem it is only
    ever allowed to *read as data*. What arrives here is whatever
    ``MemoryContext.as_model_data()`` produced, and this class neither parses it nor acts
    on it.

    It reaches the model through ``ModelRequest.data`` and nowhere else (Part 14). Like the
    incident payload, it is untrusted: history is context for reasoning, never instruction
    and never permission.
    """

    def with_step(
        self,
        *,
        decision: CommanderDecision,
        note: str,
        observation: Mapping[str, JsonValue] | None = None,
        evidence: tuple[str, ...] = (),
        lifecycle_state: IncidentState | None = None,
    ) -> CommanderContext:
        """Record one completed step and return the resulting context."""
        proposals = self.proposals
        if decision.proposal is not None:
            proposals = (*proposals, decision.proposal)
        return self.model_copy(
            update={
                "step": self.step + 1,
                "history": (
                    *self.history,
                    CommanderStep(
                        step=self.step,
                        decision=decision,
                        observation=dict(observation or {}),
                        note=note,
                    ),
                ),
                "evidence_references": (*self.evidence_references, *evidence),
                "findings": (*self.findings, decision.reasoning_summary),
                "proposals": proposals,
                "last_decision": decision,
                "lifecycle_state": lifecycle_state or self.lifecycle_state,
            }
        )

    def with_lifecycle_state(self, state: IncidentState) -> CommanderContext:
        """Record that the state machine moved the incident.

        The Commander observes its lifecycle state; it never sets it. Only
        :class:`~aegis.core.incidents.machine.IncidentStateMachine` decides transitions,
        and this method just keeps the context's view of them current.
        """
        return self.model_copy(update={"lifecycle_state": state})

    def as_model_data(self) -> dict[str, Any]:
        """The untrusted material to show the model this step.

        Everything here is data: incident content the reporter supplied and output the
        tools returned. None of it is treated as instruction.
        """
        return {
            "incident": {
                "incident_id": self.incident_id,
                "lifecycle_state": self.lifecycle_state.value,
                **dict(self.incident_payload),
            },
            "observations": [
                {"step": entry.step, "result": dict(entry.observation)}
                for entry in self.history
                if entry.observation
            ],
            "evidence_references": list(self.evidence_references),
            "your_previous_findings": list(self.findings),
            "historical_memory": dict(self.historical_memory),
        }


class Commander:
    """Decides one step at a time, using a model, and nothing else.

    Args:
        model: The reasoning provider. The only collaborator the Commander has.
        agent_id: The control-plane identity actions are proposed under. Whether that
            agent may exercise a capability is the policy engine's question, asked later
            and elsewhere.
        max_steps: The loop ceiling shown to the model so it can see time running out.
            The orchestrator enforces it; this is only what the model is told.
    """

    def __init__(
        self, model: ModelClient, *, agent_id: str = "commander", max_steps: int = 8
    ) -> None:
        self._model = model
        self.agent_id = agent_id
        self.max_steps = max_steps

    @property
    def model_name(self) -> str:
        return self._model.name

    def decide(
        self,
        context: CommanderContext,
        *,
        available_tools: tuple[str, ...],
        tool_specifications: tuple[ToolSpecification, ...] = (),
        available_specialists: tuple[str, ...] = (),
    ) -> CommanderDecision:
        """Ask for the next step.

        Args:
            context: The session so far.
            available_tools: Exactly the tool ids that may be requested.
            tool_specifications: What those tools do and what to pass them. Optional, and
                empty means the model is shown ids alone.
            available_specialists: Exactly the agent ids that may be delegated to, from
                the caller's delegation matrix. Optional, and empty means none.

        These are all *narrowing* lists. They tell the model what it may name; whether
        naming it is permitted is settled afterwards, by the toolbox and by the matrix,
        neither of which the Commander holds.

        Returns:
            A validated decision. Never a default and never ``None``.

        Raises:
            ModelError: on timeout, unavailability or malformed output. The caller must
                treat that as "no decision", never as permission.
        """
        return self._model.decide(
            ModelRequest(
                task=COMMANDER_TASK,
                data=context.as_model_data(),
                available_tools=available_tools,
                tool_specifications=tool_specifications,
                available_specialists=available_specialists,
                step=context.step,
                max_steps=self.max_steps,
            )
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(agent_id={self.agent_id!r}, model={self.model_name!r})"
