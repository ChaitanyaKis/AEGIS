"""AEGIS agent plane.

Zone B of the trust model (``claude.md`` section 4): useful for reasoning, authoritative
for nothing. The Commander (section 7) lives here and proposes; the deterministic control
plane in :mod:`aegis.core` independently decides whether any proposal is permitted.

The Commander holds a model client and nothing else — no policy engine, no approval
engine, no executor, no verification engine, no audit store and no world. That is what
makes the boundary structural rather than behavioural: a model that decides to bypass
governance has nothing here to call.

Currently populated: the Commander only. The Diagnostic, Security, Business Impact and
Remediation agents are later milestones.
"""

from aegis.agents.commander import COMMANDER_TASK, Commander, CommanderContext, CommanderStep
from aegis.agents.decisions import (
    FORBIDDEN_PROPOSAL_FIELDS,
    CommanderDecision,
    CommanderProposal,
    DecisionType,
    ToolRequest,
)
from aegis.agents.deterministic import DeterministicCommanderModel, ScriptedCommanderModel
from aegis.agents.model import (
    MalformedModelOutput,
    ModelClient,
    ModelError,
    ModelRequest,
    ModelTimeout,
    ModelUnavailable,
    parse_decision,
)
from aegis.agents.prompt import COMMANDER_SYSTEM_PROMPT, render

__all__ = [
    "COMMANDER_SYSTEM_PROMPT",
    "COMMANDER_TASK",
    "FORBIDDEN_PROPOSAL_FIELDS",
    "Commander",
    "CommanderContext",
    "CommanderDecision",
    "CommanderProposal",
    "CommanderStep",
    "DecisionType",
    "DeterministicCommanderModel",
    "MalformedModelOutput",
    "ModelClient",
    "ModelError",
    "ModelRequest",
    "ModelTimeout",
    "ModelUnavailable",
    "ScriptedCommanderModel",
    "ToolRequest",
    "parse_decision",
    "render",
]
