"""PolicyDecision — the authoritative outcome of a policy evaluation."""

from __future__ import annotations

from pydantic import Field

from aegis.core.domain.base import (
    DomainModel,
    EvidenceRef,
    NonEmptyStr,
    Timestamp,
)
from aegis.core.domain.enums import PolicyDecisionType

__all__ = ["PolicyDecision"]


class PolicyDecision(DomainModel):
    """The result of evaluating a proposed action against policy (``claude.md`` section 5).

    This is a *record* of a decision. The policy engine that produces it is a later
    milestone; this contract exists now so that audit, approval and evaluation
    components can be written against a stable shape.

    Three properties are load-bearing:

    * ``decision`` is restricted to the three authoritative outcomes by
      :class:`~aegis.core.domain.enums.PolicyDecisionType`. There is no fourth outcome
      and no "unknown" — a component that cannot decide must DENY.
    * ``reason`` and ``policy_reference`` are both required. A decision that cannot be
      explained and traced to a rule is not auditable, and an unauditable decision is
      indistinguishable from an arbitrary one.
    * The record is immutable. A changed decision is a new decision.
    """

    decision: PolicyDecisionType
    reason: NonEmptyStr
    """Human-readable justification. Required — no silent decisions."""

    policy_reference: NonEmptyStr
    """Identifier of the rule or policy set that produced the decision."""

    evaluated_at: Timestamp
    evidence: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
    """Ids of evidence the evaluation relied on."""
