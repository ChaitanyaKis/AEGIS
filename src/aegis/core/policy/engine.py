"""The deterministic policy engine — AEGIS's first authoritative security boundary.

    LLMs propose. Deterministic systems authorize.

This module is the "authorize" half. It reads frozen domain objects and registered
capability definitions, applies the predicates in :mod:`aegis.core.policy.rules` in a
fixed order, and returns a :class:`~aegis.core.domain.policy.PolicyDecision`. It has no
network access, no filesystem access, no model access, no randomness and no hidden
mutable state. Given the same action, agent and registry contents it returns the same
decision, every time.

Fail closed
-----------

Every gate is phrased as "deny unless proven permitted". Absence of information is never
read as permission: an unknown agent, an unknown capability, an empty resource scope and
an unassessed risk all deny. Nothing an agent asserts about itself can widen its
authority — the engine reads declared control-plane metadata only.

Precedence
----------

``DENY > REQUIRE_APPROVAL > ALLOW`` is structural, not a post-hoc sort. Each hard-deny
gate returns immediately, so evaluation never reaches the approval or allow branches.
Approval cannot repair an authorization failure.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from aegis.core.capabilities import CapabilityRegistry, resource_in_scope
from aegis.core.domain import (
    Action,
    Agent,
    DomainModel,
    PolicyDecision,
    PolicyDecisionType,
    utc_now,
)
from aegis.core.policy.rules import (
    PolicyRule,
    approval_is_required,
    lifecycle_is_operational,
    lifecycle_permits_capability,
    requires_risk_assessment,
)

__all__ = ["PolicyChecks", "PolicyEngine", "PolicyEvaluation"]


class PolicyChecks(DomainModel):
    """The deterministic facts a decision was derived from.

    Every field is tri-state: ``True`` or ``False`` once the check ran, and ``None`` when
    an earlier hard deny terminated evaluation before it was reached. That distinction
    matters for audit — "not held" and "never checked" are different claims.

    These are recorded facts, not obligations. ``risk_assessed`` is ``False`` whenever the
    action carries no assessed risk, including when the capability did not require one;
    the decision itself is carried by
    :attr:`~aegis.core.domain.policy.PolicyDecision.policy_reference`.

    This is a structured record, not a model explanation. It contains no chain-of-thought
    and nothing that could not be recomputed from the same inputs.
    """

    agent_known: bool | None = None
    agent_lifecycle_permitted: bool | None = None
    capability_exists: bool | None = None
    capability_held: bool | None = None
    resource_in_scope: bool | None = None
    risk_assessed: bool | None = None
    approval_required: bool | None = None


CHECK_FIELDS: tuple[str, ...] = tuple(PolicyChecks.model_fields)
"""Names of every check, in evaluation-report order."""


class PolicyEvaluation(DomainModel):
    """A :class:`PolicyDecision` together with the checks that produced it.

    The decision is the authoritative output. The checks exist so that a Control Center
    can answer "why was this denied?" from structured data, with no LLM involved.
    """

    decision: PolicyDecision
    checks: PolicyChecks


class PolicyEngine:
    """Evaluates proposed actions against registered capabilities.

    Args:
        registry: The capability definitions to authorize against. Held by reference:
            the engine adds no state of its own, so "same inputs and same registry
            contents" fully determines the decision.
        clock: Source of the decision's ``evaluated_at`` stamp. Injectable so that tests
            are byte-reproducible. **Time is never an authorization input** — the clock
            is read once, after the decision is already determined, and no gate consults
            it (``claude.md`` section 5; time-based policy is a later milestone).
    """

    def __init__(
        self,
        registry: CapabilityRegistry,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._registry = registry
        self._clock = clock

    @property
    def registry(self) -> CapabilityRegistry:
        return self._registry

    def evaluate(self, action: Action, agent: Agent | None) -> PolicyDecision:
        """Authorize ``action`` for ``agent``.

        Args:
            action: The proposed action. Its ``risk`` is consulted only as an input the
                deterministic risk engine will supply; the engine never accepts an
                agent's own risk claim as a substitute for assessment, because an
                unassessed action simply denies.
            agent: The control-plane record for the requesting agent, or ``None`` when
                the caller could not resolve one. Resolving ``action.requesting_agent``
                to an :class:`~aegis.core.domain.agent.Agent` is the caller's job; the
                engine only decides, and an unresolved agent is denied.

        Returns:
            One of ALLOW, DENY or REQUIRE_APPROVAL, always with a reason and a
            machine-readable ``policy_reference``.
        """
        return self.evaluate_detailed(action, agent).decision

    def evaluate_detailed(self, action: Action, agent: Agent | None) -> PolicyEvaluation:
        """Like :meth:`evaluate`, but also returns the :class:`PolicyChecks` record."""
        checks: dict[str, bool | None] = dict.fromkeys(CHECK_FIELDS)

        def decide(decision: PolicyDecisionType, rule: PolicyRule, reason: str) -> PolicyEvaluation:
            return PolicyEvaluation(
                decision=PolicyDecision(
                    decision=decision,
                    reason=reason,
                    policy_reference=rule.value,
                    evaluated_at=self._clock(),
                ),
                checks=PolicyChecks(**checks),
            )

        def deny(rule: PolicyRule, reason: str) -> PolicyEvaluation:
            return decide(PolicyDecisionType.DENY, rule, reason)

        # 1. The requesting agent must be a control-plane record we were handed, and it
        #    must be the agent the action claims to come from.
        if agent is None:
            checks["agent_known"] = False
            return deny(
                PolicyRule.AGENT_UNKNOWN,
                f"unknown agent: no agent record supplied for requesting agent "
                f"{action.requesting_agent!r}",
            )
        if agent.agent_id != action.requesting_agent:
            checks["agent_known"] = False
            return deny(
                PolicyRule.AGENT_IDENTITY_MISMATCH,
                f"agent identity mismatch: supplied agent {agent.agent_id!r} is not the "
                f"requesting agent {action.requesting_agent!r}",
            )
        checks["agent_known"] = True

        # 2. Lifecycle gate: is this agent operational at all?
        if not lifecycle_is_operational(agent.status):
            checks["agent_lifecycle_permitted"] = False
            return deny(
                PolicyRule.AGENT_LIFECYCLE_NOT_OPERATIONAL,
                f"agent {agent.agent_id!r} is {agent.status} and may not exercise any capability",
            )

        # 3. The capability must be defined. An unknown capability is never an ALLOW.
        if not self._registry.exists(action.capability):
            checks["capability_exists"] = False
            return deny(
                PolicyRule.CAPABILITY_UNKNOWN,
                f"unknown capability: {action.capability!r} is not registered",
            )
        checks["capability_exists"] = True
        capability = self._registry.get(action.capability)

        # 4. Lifecycle gate, refined now that the capability's privilege level is known.
        if not lifecycle_permits_capability(agent.status, capability):
            checks["agent_lifecycle_permitted"] = False
            return deny(
                PolicyRule.AGENT_LIFECYCLE_FORBIDS_CAPABILITY,
                f"agent {agent.agent_id!r} is {agent.status} and may not exercise "
                f"privileged capability {capability.capability_id!r}",
            )
        checks["agent_lifecycle_permitted"] = True

        # 5. The agent must actually hold the capability, on both sides of the grant.
        if not self._registry.has_capability(agent, action.capability):
            checks["capability_held"] = False
            return deny(
                PolicyRule.CAPABILITY_NOT_HELD,
                f"agent {agent.agent_id!r} does not hold capability {capability.capability_id!r}",
            )
        checks["capability_held"] = True

        # 6. The target must be inside the capability's declared scope. Exact match; an
        #    empty scope reaches nothing.
        if not resource_in_scope(capability, action.target_resource):
            checks["resource_in_scope"] = False
            return deny(
                PolicyRule.RESOURCE_OUT_OF_SCOPE,
                f"resource {action.target_resource!r} is outside the declared scope of "
                f"capability {capability.capability_id!r}",
            )
        checks["resource_in_scope"] = True

        # 7. A privileged capability may not be exercised on an unassessed action.
        #    Missing risk means UNASSESSED, never LOW.
        checks["risk_assessed"] = action.risk is not None
        if requires_risk_assessment(capability) and action.risk is None:
            return deny(
                PolicyRule.RISK_UNASSESSED,
                f"capability {capability.capability_id!r} requires an assessed risk; "
                f"action {action.action_id!r} has not been risk-assessed",
            )

        # 8. Only now may approval and allow be considered.
        checks["approval_required"] = approval_is_required(capability, action.risk)
        if checks["approval_required"]:
            return decide(
                PolicyDecisionType.REQUIRE_APPROVAL,
                PolicyRule.APPROVAL_REQUIRED,
                f"capability {capability.capability_id!r} requires human approval"
                + (f" at {action.risk} risk" if action.risk is not None else ""),
            )

        return decide(
            PolicyDecisionType.ALLOW,
            PolicyRule.ALLOWED,
            f"agent {agent.agent_id!r} may exercise capability "
            f"{capability.capability_id!r} on {action.target_resource!r}",
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(registry={self._registry!r})"
