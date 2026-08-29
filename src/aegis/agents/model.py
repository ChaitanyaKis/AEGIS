"""The model boundary.

One narrow interface separates the Commander from whatever produces its reasoning. The
Commander knows nothing about providers, SDKs, prompts-as-strings, retries or transports;
it hands over a :class:`ModelRequest` and receives a validated
:class:`~aegis.agents.decisions.CommanderDecision` or an exception.

Why the request has no instruction field
----------------------------------------

Untrusted content — the incident payload, tool output, telemetry, deployment metadata —
travels only in :attr:`ModelRequest.data`. The system instruction is a module constant in
:mod:`aegis.agents.prompt` that no caller passes in and no field can carry. There is
therefore no channel through which an incident could place text into the instruction
position: it is not that injection is filtered, it is that the wire does not exist
(``claude.md`` section 4, zone A).

Failure is never permission
---------------------------

Every way a model can fail raises. A timeout, an unavailable provider and malformed output
are three distinct exceptions, and none of them has a value that a caller could mistake for
a decision. There is no default decision, no "assume investigate", and nothing that could
degrade into an ALLOW.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from pydantic import Field, JsonValue, ValidationError

from aegis.agents.decisions import CommanderDecision
from aegis.agents.findings import AgentFinding
from aegis.core.domain import DomainModel, NonEmptyStr

__all__ = [
    "MalformedModelOutput",
    "ModelClient",
    "ModelError",
    "ModelOutput",
    "ModelRefused",
    "ModelRequest",
    "ModelTimeout",
    "ModelUnavailable",
    "ToolSpecification",
    "parse_decision",
    "parse_finding",
]

type ModelOutput = CommanderDecision | AgentFinding
"""Everything a provider may return.

One interface serves the Commander and the specialists: the Commander asks for a decision,
a specialist asks for a finding, and both go through the same boundary, the same failure
types and the same data-only request. There is no second provider interface to keep in
step.
"""


class ModelError(Exception):
    """Base class for every way the model boundary can fail.

    Callers catch this and treat it as "no decision was made". A model failure preserves
    incident state, executes nothing and resolves nothing.
    """


class ModelTimeout(ModelError):
    """The model did not answer within its deadline."""


class ModelUnavailable(ModelError):
    """The provider could not be reached, configured or imported."""


class MalformedModelOutput(ModelError):
    """The model answered with something that is not a valid decision.

    Raised rather than repaired. Asking a second model to fix the first one's output would
    put an unvalidated interpretation in the path of a governance decision.
    """


class ModelRefused(ModelError):
    """The provider declined to answer.

    A safety filter, a content block, a stopped generation with no candidate. Distinct
    from :class:`MalformedModelOutput` because "the model would not speak" and "the model
    spoke nonsense" are different facts about a run, and an operator reading the trail
    needs to tell them apart. Identical in consequence: both are :class:`ModelError`, both
    mean no decision was made, and every existing ``except ModelError`` already catches
    this one.
    """


class ToolSpecification(DomainModel):
    """One tool as the model is *told* about it: what it does and what to pass it.

    A narrowed projection of :class:`~aegis.tools.contracts.ToolDefinition`, built by the
    orchestrator from the registry. Deliberately not the definition itself: a definition
    also names the ``capability_id`` a tool exercises, and
    :meth:`~aegis.orchestration.tools.GovernedToolbox.available_tool_ids` is explicit that
    an agent should not learn the shape of capabilities it was never given. Description and
    argument names are what a caller needs to call correctly; the capability behind the tool
    is the policy engine's business.

    This grants nothing. Knowing that ``get_recent_deployments`` takes a ``resource`` does
    not make the read authorized — every invocation still builds a real ``Action`` and asks
    the real policy engine.
    """

    tool_id: NonEmptyStr
    description: NonEmptyStr
    arguments: Mapping[str, str] = Field(default_factory=dict)
    """Argument name to JSON type, copied from the tool's declared ``input_schema``.

    Every declared argument is required and anything else is rejected, exactly as the
    registry enforces it. Passed through rather than restated, so the schema has one
    definition and this cannot drift from it.
    """


class ModelRequest(DomainModel):
    """Everything the model is given for one step.

    Args:
        task: What to decide, written by AEGIS. Trusted, and never derived from incident
            or tool content.
        data: Untrusted material — the incident payload, prior tool results, prior
            findings. Structured JSON, quoted into the user channel, never the instruction
            channel.
        available_tools: The exact tool ids that may be requested. A model asking for
            anything else gets "unknown tool".
        tool_specifications: The same tools, with their purpose and argument names. Empty
            when the caller supplies only ids, in which case the prompt falls back to the
            bare list.
        available_specialists: The exact agent ids this agent may delegate to, taken from
            the delegation matrix. A model naming anything else gets "unknown agent".
        step: Which step of the bounded loop this is, from zero.
        max_steps: The loop's hard ceiling, so the model can see it is running out.

    ``available_tools`` and ``available_specialists`` are both *narrowing* facts: they say
    what a request may name, and naming something outside them produces a refusal rather
    than an action. Telling a model what it may ask for is not telling it what it may do.
    """

    task: NonEmptyStr
    data: Mapping[str, JsonValue] = Field(default_factory=dict)
    available_tools: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    tool_specifications: tuple[ToolSpecification, ...] = Field(default_factory=tuple)
    available_specialists: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    step: int = Field(ge=0)
    max_steps: int = Field(ge=1)

    @property
    def steps_remaining(self) -> int:
        return max(self.max_steps - self.step, 0)


@runtime_checkable
class ModelClient(Protocol):
    """Anything that can turn a request into a Commander decision.

    Implementations must either return a validated decision or raise a
    :class:`ModelError`. Returning ``None``, a partial decision or a default is not
    permitted, because every one of those would be a silent judgement made outside the
    control plane.
    """

    name: str
    """Identifies the provider in audit and orchestration output."""

    def decide(self, request: ModelRequest) -> ModelOutput:
        """Produce one structured output, or raise a :class:`ModelError`."""
        ...


def parse_decision(raw: str) -> CommanderDecision:
    """Validate a model's JSON output into a decision.

    Shared by providers so that structured-output parsing has exactly one implementation
    and one set of rules.

    Raises:
        MalformedModelOutput: if the text is not JSON, is not an object, or does not
            satisfy the decision contract — including when it carries a field the contract
            forbids, such as a self-assessed risk.
    """
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise MalformedModelOutput(f"model output was not JSON: {error}") from error
    if not isinstance(payload, dict):
        raise MalformedModelOutput(
            f"model output was {type(payload).__name__}, expected a JSON object"
        )
    try:
        return CommanderDecision.model_validate(payload)
    except ValidationError as error:
        raise MalformedModelOutput(f"model output is not a valid decision: {error}") from error


def parse_finding(raw: str) -> AgentFinding:
    """Validate a specialist model's JSON output into a finding.

    Raises:
        MalformedModelOutput: if the text is not JSON, is not an object, or does not
            satisfy the finding contract.
    """
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise MalformedModelOutput(f"model output was not JSON: {error}") from error
    if not isinstance(payload, dict):
        raise MalformedModelOutput(
            f"model output was {type(payload).__name__}, expected a JSON object"
        )
    try:
        return AgentFinding.model_validate(payload)
    except ValidationError as error:
        raise MalformedModelOutput(f"model output is not a valid finding: {error}") from error
