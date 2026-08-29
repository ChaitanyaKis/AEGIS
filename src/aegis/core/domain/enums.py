"""Authoritative state and classification enums for the AEGIS domain.

These enums are *contracts*. Components across the control plane, the agent plane and
the evaluation harness compare against them directly, so their members are load-bearing.

Rules (see ``claude.md`` sections 5, 8, 9):

* There is exactly one spelling of every concept. Do not add synonyms, aliases or
  parallel scales (e.g. no separate ``IncidentSeverity``: incident severity and action
  risk share the single :class:`RiskLevel` scale).
* Values are stable strings so that serialized payloads, audit records and stored
  evaluation fixtures remain readable and comparable across versions.
* Removing or renaming a member is a breaking change to the domain contract.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "AgentLifecycleState",
    "ApprovalRequirement",
    "DataClassification",
    "EvidenceType",
    "IncidentState",
    "PolicyDecisionType",
    "RiskLevel",
]


class IncidentState(StrEnum):
    """States of the deterministic incident state machine (``claude.md`` section 8).

    Normal path: RECEIVED → CLASSIFIED → INVESTIGATING → IMPACT_ASSESSED →
    PLAN_PROPOSED → POLICY_CHECK → AWAITING_APPROVAL → EXECUTING → VERIFYING → RESOLVED.

    Recovery path: any state → DEGRADED → RECOVERING → continue or escalate.

    Terminal escalation: ESCALATED.

    The permitted transitions themselves are *not* defined here; the incident state
    machine owns them and is built in a later milestone.
    """

    RECEIVED = "RECEIVED"
    CLASSIFIED = "CLASSIFIED"
    INVESTIGATING = "INVESTIGATING"
    IMPACT_ASSESSED = "IMPACT_ASSESSED"
    PLAN_PROPOSED = "PLAN_PROPOSED"
    POLICY_CHECK = "POLICY_CHECK"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    RESOLVED = "RESOLVED"
    DEGRADED = "DEGRADED"
    RECOVERING = "RECOVERING"
    ESCALATED = "ESCALATED"


class AgentLifecycleState(StrEnum):
    """Governed lifecycle of an agent (``claude.md`` section 9).

    A newly registered agent never holds production authority; authority is granted by
    progressing through the lifecycle, and withdrawn by RESTRICTED / QUARANTINED /
    RETIRED. The lifecycle manager that enforces the progression is a later milestone.
    """

    REGISTERED = "REGISTERED"
    EVALUATING = "EVALUATING"
    SANDBOXED = "SANDBOXED"
    APPROVED = "APPROVED"
    CANARY = "CANARY"
    ACTIVE = "ACTIVE"
    RESTRICTED = "RESTRICTED"
    QUARANTINED = "QUARANTINED"
    RETIRED = "RETIRED"


class RiskLevel(StrEnum):
    """The single ordered risk/severity scale used across AEGIS.

    Used for incident severity, capability risk class and assessed action risk so that
    the project has exactly one scale rather than several near-identical ones.

    Members are declared low → critical; ordering comparisons are deliberately *not*
    implemented here because risk comparison is policy behaviour, which arrives with the
    risk and policy engines.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyDecisionType(StrEnum):
    """The only authoritative policy decisions in AEGIS (``claude.md`` section 5).

    Precedence, enforced later by the policy engine, is
    ``DENY > REQUIRE_APPROVAL > ALLOW``. An explicit DENY can never be overridden by an
    LLM, and human approval does not override a hard denial. No fourth decision may be
    introduced.
    """

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class DataClassification(StrEnum):
    """Sensitivity of the data a capability can reach (``claude.md`` section 6)."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class ApprovalRequirement(StrEnum):
    """Declared human-approval requirement of a capability (``claude.md`` sections 6, 4-E).

    This is a *declaration* attached to a capability, not a decision. Turning it into a
    :class:`PolicyDecisionType` is the policy engine's job.

    * ``NONE`` — the capability never requires human approval on its own.
    * ``RISK_BASED`` — approval depends on the assessed risk of the concrete action.
    * ``ALWAYS`` — every use requires human approval.
    """

    NONE = "NONE"
    RISK_BASED = "RISK_BASED"
    ALWAYS = "ALWAYS"


class EvidenceType(StrEnum):
    """Kind of artifact a piece of evidence points at (``claude.md`` sections 11, 12, 20)."""

    TELEMETRY = "TELEMETRY"
    LOG = "LOG"
    DEPLOYMENT = "DEPLOYMENT"
    DEPENDENCY = "DEPENDENCY"
    SECURITY_EVENT = "SECURITY_EVENT"
    CUSTOMER_IMPACT = "CUSTOMER_IMPACT"
    MEMORY = "MEMORY"
    AGENT_FINDING = "AGENT_FINDING"
    TOOL_RESULT = "TOOL_RESULT"
    VERIFICATION = "VERIFICATION"
    HUMAN_INPUT = "HUMAN_INPUT"
