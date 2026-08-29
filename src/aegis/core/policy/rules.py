"""The deterministic predicates the policy engine is built from.

Separated from the engine so that *what the rules are* can be read, tested and argued
about independently of *how they are sequenced*. Every function here is pure: it reads
declared metadata off frozen domain objects and returns a boolean. No I/O, no clock, no
model, no hidden state.
"""

from __future__ import annotations

from enum import StrEnum

from aegis.core.domain import (
    AgentLifecycleState,
    ApprovalRequirement,
    Capability,
    RiskLevel,
)

__all__ = [
    "APPROVAL_RISK_LEVELS",
    "OPERATIONAL_LIFECYCLE_STATES",
    "PolicyRule",
    "approval_is_required",
    "is_privileged",
    "lifecycle_is_operational",
    "lifecycle_permits_capability",
    "requires_risk_assessment",
]

POLICY_SET = "policy:aegis/v1"
"""Identifier of the rule set implemented in this module.

Versioned so that an audit record naming a rule stays meaningful after the rules change.
"""


class PolicyRule(StrEnum):
    """The rule that produced a decision, recorded as ``PolicyDecision.policy_reference``.

    Machine-readable by design: a Control Center can answer "why was this denied?" by
    reading this value, with no LLM explanation involved.
    """

    AGENT_UNKNOWN = f"{POLICY_SET}#agent-unknown"
    AGENT_IDENTITY_MISMATCH = f"{POLICY_SET}#agent-identity-mismatch"
    AGENT_LIFECYCLE_NOT_OPERATIONAL = f"{POLICY_SET}#agent-lifecycle-not-operational"
    AGENT_LIFECYCLE_FORBIDS_CAPABILITY = f"{POLICY_SET}#agent-lifecycle-forbids-capability"
    CAPABILITY_UNKNOWN = f"{POLICY_SET}#capability-unknown"
    CAPABILITY_NOT_HELD = f"{POLICY_SET}#capability-not-held"
    RESOURCE_OUT_OF_SCOPE = f"{POLICY_SET}#resource-out-of-scope"
    RISK_UNASSESSED = f"{POLICY_SET}#risk-unassessed"
    APPROVAL_REQUIRED = f"{POLICY_SET}#approval-required"
    ALLOWED = f"{POLICY_SET}#allowed"


OPERATIONAL_LIFECYCLE_STATES = frozenset(
    {
        AgentLifecycleState.ACTIVE,
        AgentLifecycleState.CANARY,
        AgentLifecycleState.RESTRICTED,
    }
)
"""Lifecycle states in which an agent may exercise any capability at all.

An allowlist, not a denylist — a state that is not named here is denied, so adding a
lifecycle state cannot accidentally grant authority (``claude.md`` section 9: newly
registered agents never hold production authority).

Deliberately excluded: REGISTERED, EVALUATING and APPROVED have not reached operation;
SANDBOXED may act only inside a sandbox, and AEGIS has no sandbox boundary yet, so it
fails closed; QUARANTINED and RETIRED have had their authority withdrawn.
"""

APPROVAL_RISK_LEVELS = frozenset({RiskLevel.HIGH, RiskLevel.CRITICAL})
"""Assessed risk levels that trigger human approval for a RISK_BASED capability."""


def is_privileged(capability: Capability) -> bool:
    """Whether a capability carries enough authority to need extra assurance.

    Stated fail-closed: a capability is privileged **unless it is unambiguously
    low-authority**, meaning all three of its declared properties are benign —

    * ``risk_class`` is LOW, and
    * the effect is ``reversible``, and
    * it needs no approval (``ApprovalRequirement.NONE``).

    Anything else is privileged. So a MEDIUM read is privileged, an irreversible LOW
    action is privileged, and a capability the organisation already marked as needing
    sign-off is privileged regardless of its risk class.

    Derived only from declared capability metadata, never from an agent's claim about
    itself.
    """
    unambiguously_low_authority = (
        capability.risk_class is RiskLevel.LOW
        and capability.reversible
        and capability.approval_requirement is ApprovalRequirement.NONE
    )
    return not unambiguously_low_authority


def requires_risk_assessment(capability: Capability) -> bool:
    """Whether an action using this capability must carry an assessed risk.

    The same question as :func:`is_privileged`: a capability that carries real authority
    may not be exercised on an unassessed action. Kept as a separate, explicitly named
    function because the two obligations are separate in the constitution even though
    one predicate answers both today.
    """
    return is_privileged(capability)


def lifecycle_is_operational(state: AgentLifecycleState) -> bool:
    """Whether an agent in ``state`` may exercise any capability at all."""
    return state in OPERATIONAL_LIFECYCLE_STATES


def lifecycle_permits_capability(state: AgentLifecycleState, capability: Capability) -> bool:
    """Whether an agent in ``state`` may exercise this particular capability.

    Non-operational states permit nothing. RESTRICTED is operational but reduced: it
    permits only non-privileged capabilities, which is what "restricted" has to mean if
    it is to differ from both ACTIVE and QUARANTINED. ACTIVE and CANARY permit any
    capability the agent actually holds.
    """
    if not lifecycle_is_operational(state):
        return False
    if state is AgentLifecycleState.RESTRICTED:
        return not is_privileged(capability)
    return True


def approval_is_required(capability: Capability, risk: RiskLevel | None) -> bool:
    """Whether exercising this capability at this assessed risk needs human approval.

    * ``ALWAYS`` — always, whatever the risk.
    * ``RISK_BASED`` — when the assessed risk is HIGH or CRITICAL. An unassessed risk
      (``None``) also requires approval; this function is only ever reached after the
      engine has established that risk is assessed where it must be, so ``None`` here
      means a capability that needs no assessment, and treating it as needing approval
      keeps the fallback closed rather than open.
    * ``NONE`` — never on the capability's own account.
    """
    match capability.approval_requirement:
        case ApprovalRequirement.ALWAYS:
            return True
        case ApprovalRequirement.RISK_BASED:
            return risk is None or risk in APPROVAL_RISK_LEVELS
        case ApprovalRequirement.NONE:
            return False
    return True  # pragma: no cover - unreachable while ApprovalRequirement is closed
