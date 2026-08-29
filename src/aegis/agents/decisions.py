"""What the Commander is allowed to say.

Trust zone B (``claude.md`` section 4): useful for reasoning, authoritative for nothing.
These contracts are the narrow channel through which a language model's output enters
AEGIS, and their job is to make most bad output *unrepresentable* rather than merely
detected later.

Three properties do the work:

* **Closed schemas.** Every model here inherits ``extra="forbid"``. A model that emits a
  ``risk`` or ``blast_radius`` field does not produce a decision with a risk in it — it
  produces a validation error. Governance values cannot arrive through this door.
* **A closed decision vocabulary.** Four decision types, each with exactly the payload it
  needs. There is no "other" and no free-form command.
* **No authority anywhere.** Nothing here can express an approval, a policy decision, a
  verification outcome or a state transition. The Commander proposes; it does not decide.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, Field, JsonValue, model_validator

from aegis.core.domain import DomainModel, EvidenceRef, NonEmptyStr

__all__ = [
    "FORBIDDEN_PROPOSAL_FIELDS",
    "CommanderDecision",
    "CommanderProposal",
    "DecisionType",
    "DelegationRequest",
    "TaskType",
    "ToolRequest",
]

FORBIDDEN_PROPOSAL_FIELDS = frozenset(
    {"risk", "blast_radius", "decision", "approval", "verification", "policy_reference"}
)
"""Names a proposal may never carry, listed so the guarantee is greppable.

Enforced structurally by ``extra="forbid"`` rather than by this set — the constant exists
so that a test can assert each one really is rejected.
"""


def _sorted_arguments(value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    return dict(sorted(value.items()))


_Arguments = Annotated[Mapping[str, JsonValue], AfterValidator(_sorted_arguments)]


class DecisionType(StrEnum):
    """The complete set of things the Commander can decide to do next."""

    INVESTIGATE = "INVESTIGATE"
    """Call one registered read tool to learn something."""

    PROPOSE_ACTION = "PROPOSE_ACTION"
    """Put a remediation to the control plane. A proposal, never an instruction."""

    WAIT = "WAIT"
    """Take no action this step. Still consumes a step, so it cannot stall forever."""

    DELEGATE = "DELEGATE"
    """Hand a bounded task to one named specialist and wait for its finding."""

    ESCALATE = "ESCALATE"
    """Hand the incident to humans. The one decision that ends the loop by itself."""


class TaskType(StrEnum):
    """The complete set of tasks that may be delegated.

    A closed vocabulary on purpose. There is no "run this prompt" task, so a delegation
    can never carry arbitrary instructions for another agent to follow — the task names
    what kind of work is wanted, and the specialist's own fixed prompt decides how.
    """

    DIAGNOSE_SERVICE = "DIAGNOSE_SERVICE"
    INVESTIGATE_SECURITY = "INVESTIGATE_SECURITY"
    ASSESS_BUSINESS_IMPACT = "ASSESS_BUSINESS_IMPACT"
    PROPOSE_REMEDIATION = "PROPOSE_REMEDIATION"


class ToolRequest(DomainModel):
    """A request to call one registered tool.

    ``tool_id`` is matched exactly against the registry. It is never used to look up a
    Python attribute, import a module or build a callable, so an invented name can only
    ever produce "unknown tool", never execution.
    """

    tool_id: NonEmptyStr
    arguments: _Arguments = Field(default_factory=dict)


class DelegationRequest(DomainModel):
    """A request to hand one bounded task to one named specialist.

    ``target_agent_id`` is matched exactly against the specialist registry and is never
    used to look up an attribute, import a module or build a callable. An invented agent
    name can only produce "unknown agent".

    Deliberately narrow: it names *who* and *what kind of work*, and carries the resource
    and evidence the specialist should start from. It cannot carry instructions, because
    there is no field for them.
    """

    target_agent_id: NonEmptyStr
    task_type: TaskType
    target_resource: NonEmptyStr | None = None
    evidence_refs: tuple[EvidenceRef, ...] = Field(default_factory=tuple)


class CommanderProposal(DomainModel):
    """A remediation the Commander thinks should happen.

    Deliberately *not* an :class:`~aegis.core.domain.action.Action`. A proposal names a
    capability and a target and stops there; the deterministic adapter turns it into an
    Action, and the assessment pipeline is what puts risk and blast radius on that Action.
    A proposal carrying its own risk is rejected at parse time.
    """

    capability_id: NonEmptyStr
    target_resource: NonEmptyStr
    arguments: _Arguments = Field(default_factory=dict)
    evidence_references: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
    """Ids of observations already gathered that justify this proposal.

    References, never contents: a model-written summary of telemetry is not evidence, and
    the control plane continues to work from the observations themselves.
    """


class CommanderDecision(DomainModel):
    """One step of Commander reasoning, in structured form.

    ``reasoning_summary`` is a short human-readable rationale. It is recorded and shown;
    it is never parsed, never re-interpreted by another model, and never consulted by any
    deterministic component. A validator enforces that each decision type carries exactly
    the payload it needs and nothing it does not.
    """

    decision_type: DecisionType
    reasoning_summary: NonEmptyStr
    tool_request: ToolRequest | None = None
    proposal: CommanderProposal | None = None
    delegation: DelegationRequest | None = None

    @model_validator(mode="after")
    def _payload_matches_decision(self) -> CommanderDecision:
        expected = {
            DecisionType.INVESTIGATE: "tool_request",
            DecisionType.PROPOSE_ACTION: "proposal",
            DecisionType.DELEGATE: "delegation",
        }.get(self.decision_type)
        carried = {
            name
            for name in ("tool_request", "proposal", "delegation")
            if getattr(self, name) is not None
        }
        if expected is None:
            if carried:
                raise ValueError(f"{self.decision_type} must not carry a payload")
        elif expected not in carried:
            raise ValueError(f"{self.decision_type} requires a {expected}")
        elif carried != {expected}:
            raise ValueError(
                f"{self.decision_type} must carry only a {expected}, got {sorted(carried)}"
            )
        return self
