"""DETERMINISTIC TEST MODEL — not a language model, and not pretending to be one.

This is a small rule-based stand-in for the Commander's reasoning. It exists so the test
suite can exercise orchestration, governance, failure handling and the golden incident
**without credentials, without network and without Gemini**. It makes no claim to be
Gemini, to approximate Gemini, or to behave as a language model would.

It reads the same untrusted data a real model would, and its rules are driven by that data:
which tools have already answered, and what the deployment feed reported. That is enough to
drive the golden incident end to end and to keep the run reproducible.

Two deliberate properties:

* **Reproducible.** The same context always yields the same decision. There is no clock,
  no randomness and no hidden state.
* **Indifferent to injected instructions.** It never reads incident prose as a command,
  because it never reads prose at all. That makes it a poor adversary for injection tests —
  which is why those tests drive a deliberately *compromised* model instead, and prove the
  control plane holds anyway.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from aegis.agents.decisions import (
    CommanderDecision,
    DecisionType,
    DelegationRequest,
    TaskType,
    ToolRequest,
)
from aegis.agents.model import ModelError, ModelRequest

__all__ = ["DeterministicCommanderModel", "ScriptedCommanderModel"]

_INVESTIGATION_ORDER = (
    ("get_service_health", "health"),
    ("get_metrics", "error_rate"),
    ("get_recent_deployments", "current_deployment"),
)
"""Which tool to call next, and the observation key that shows it has answered."""

_DELEGATION_ORDER: tuple[tuple[str, TaskType], ...] = (
    ("diagnostic", TaskType.DIAGNOSE_SERVICE),
    ("security", TaskType.INVESTIGATE_SECURITY),
    ("business-impact", TaskType.ASSESS_BUSINESS_IMPACT),
    ("remediation", TaskType.PROPOSE_REMEDIATION),
)
"""Who to consult, in order. Diagnosis, then security, then impact, then a proposed fix.

The Commander no longer drafts a remediation itself: ``claude.md`` section 7 gives
remediation proposals to the Remediation agent, and the proposal-authority map enforces it.
Reaching a rollback therefore means delegating, which is the point of having specialists.
"""


class DeterministicCommanderModel:
    """A rule-based Commander stand-in. **DETERMINISTIC TEST MODEL.**

    Args:
        rollback_target: Version to propose rolling back to when the deployment feed does
            not name a previous one. The feed normally supplies it.
    """

    name = "deterministic-test-model"

    def __init__(self, *, rollback_target: str = "v4.7") -> None:
        self._rollback_target = rollback_target

    def decide(self, request: ModelRequest) -> CommanderDecision:
        """Choose the next step from what has already been observed."""
        data = dict(request.data)
        seen = _observed_keys(data)
        available = set(request.available_tools)

        attempted = _attempted_tools(data)
        for tool_id, produced_key in _INVESTIGATION_ORDER:
            if produced_key not in seen and tool_id in available and tool_id not in attempted:
                return CommanderDecision(
                    decision_type=DecisionType.INVESTIGATE,
                    reasoning_summary=f"No {produced_key} observed yet; calling {tool_id}.",
                    tool_request=ToolRequest(
                        tool_id=tool_id,
                        arguments={"resource": _target_resource(data)},
                    ),
                )

        consulted = _consulted_agents(data)
        resource = _target_resource(data)

        # Each recovery earns exactly one more remediation attempt. Without the count
        # the rule would fire on every step after the first proposal, because a delegation
        # itself leaves the incident in INVESTIGATING.
        recoveries = _recovery_markers(data)
        attempts = _remediation_attempts(data)
        if recoveries > 0 and attempts <= recoveries:
            return CommanderDecision(
                decision_type=DecisionType.DELEGATE,
                reasoning_summary=(
                    "The previous remediation did not verify and the incident has "
                    "recovered to investigation; asking for another proposal."
                ),
                delegation=DelegationRequest(
                    target_agent_id="remediation",
                    task_type=TaskType.PROPOSE_REMEDIATION,
                    target_resource=resource,
                    evidence_refs=tuple(data.get("evidence_references") or ()),
                ),
            )

        for agent_id, task_type in _DELEGATION_ORDER:
            if agent_id not in consulted:
                return CommanderDecision(
                    decision_type=DecisionType.DELEGATE,
                    reasoning_summary=f"No {agent_id} finding yet; delegating {task_type}.",
                    delegation=DelegationRequest(
                        target_agent_id=agent_id,
                        task_type=task_type,
                        target_resource=resource,
                        evidence_refs=tuple(data.get("evidence_references") or ()),
                    ),
                )

        return CommanderDecision(
            decision_type=DecisionType.ESCALATE,
            reasoning_summary=(
                "Every specialist has reported and no remediation verified; escalating."
            ),
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r})"


class ScriptedCommanderModel:
    """Replays a fixed sequence of decisions. **DETERMINISTIC TEST MODEL.**

    For tests that need one exact decision — a malformed proposal, an unknown tool, a
    forbidden capability — rather than a plausible investigation. A callable may be given
    instead of a decision to raise a :class:`~aegis.agents.model.ModelError` at that step.

    Running past the end of the script raises, so a test cannot accidentally depend on
    what an exhausted script would have said next.
    """

    name = "scripted-test-model"

    def __init__(
        self,
        *decisions: CommanderDecision | Callable[[ModelRequest], CommanderDecision],
        name: str | None = None,
    ) -> None:
        self._decisions = decisions
        self._calls = 0
        if name is not None:
            self.name = name

    @property
    def calls(self) -> int:
        """How many times the model has been asked. Lets tests assert on retry behaviour."""
        return self._calls

    def decide(self, request: ModelRequest) -> CommanderDecision:
        index = self._calls
        self._calls += 1
        if index >= len(self._decisions):
            raise ModelError(f"scripted model exhausted after {len(self._decisions)} decisions")
        entry = self._decisions[index]
        if callable(entry):
            return entry(request)
        return entry

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r}, scripted={len(self._decisions)})"


def _observed_keys(data: Mapping[str, Any]) -> set[str]:
    """Every key any tool has returned so far."""
    keys: set[str] = set()
    for entry in data.get("observations") or ():
        result = entry.get("result") if isinstance(entry, dict) else None
        if isinstance(result, dict):
            keys.update(result)
    return keys


def _consulted_agents(data: Mapping[str, Any]) -> set[str]:
    """Which specialists have already been asked, whether or not they answered.

    An *attempt* counts, not just a finding. A specialist whose model failed is not asked
    again in the same run: retrying it indefinitely would burn the step budget without
    learning anything, and the Commander's remaining options — consult someone else, or
    escalate — are more useful than another identical failure.
    """
    agents: set[str] = set()
    for entry in data.get("observations") or ():
        result = entry.get("result") if isinstance(entry, dict) else None
        if isinstance(result, dict):
            for key in ("finding_from_agent", "delegation_attempted"):
                value = result.get(key)
                if isinstance(value, str):
                    agents.add(value)
    return agents


def _results(data: Mapping[str, Any]):
    """Every tool or delegation result recorded so far."""
    for entry in data.get("observations") or ():
        result = entry.get("result") if isinstance(entry, dict) else None
        if isinstance(result, dict):
            yield result


def _attempted_tools(data: Mapping[str, Any]) -> set[str]:
    """Tools already called, whether or not they answered.

    A denied or unavailable read is not retried: repeating it cannot change the answer,
    and burning the step budget on it is strictly worse than moving on.
    """
    return {
        result["tool_attempted"]
        for result in _results(data)
        if isinstance(result.get("tool_attempted"), str)
    }


def _recovery_markers(data: Mapping[str, Any]) -> int:
    """How many times the incident has degraded and recovered."""
    return sum(1 for result in _results(data) if result.get("recovery_attempt"))


def _remediation_attempts(data: Mapping[str, Any]) -> int:
    """How many times a remediation has already been requested."""
    return sum(
        1
        for result in _results(data)
        if result.get("delegation_attempted") == "remediation"
        or result.get("finding_from_agent") == "remediation"
    )


def _target_resource(data: Mapping[str, Any]) -> str:
    incident = data.get("incident")
    if isinstance(incident, dict):
        affected = incident.get("affected_resource")
        if isinstance(affected, str) and affected:
            return affected
    return "service:payment-api"


def _previous_version(data: Mapping[str, Any], fallback: str) -> str:
    """The version the deployment feed named as previous, if it named one."""
    for entry in data.get("observations") or ():
        result = entry.get("result") if isinstance(entry, dict) else None
        if isinstance(result, dict):
            previous = result.get("previous_deployment")
            if isinstance(previous, str) and previous:
                return previous
    return fallback
