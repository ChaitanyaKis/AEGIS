"""Approval artifacts.

An approval is not a permission grant. It is a **time-bounded authorisation for one
exact action under one specific policy context** (``claude.md`` section 4, zone E), and
every field here exists to keep one of those three qualifiers checkable:

* *one exact action* — ``action_fingerprint``
* *time-bounded* — ``created_at`` / ``expires_at``
* *one policy context* — ``policy_decision``, re-checked at consumption

Approvals are frozen values like everything else in AEGIS. Approving, rejecting, expiring
and consuming each produce a **new** record, so the history of an approval is a chain of
immutable states rather than a mutated row — which is what will make the audit trail
trustworthy when the audit store arrives.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import model_validator

from aegis.core.domain import (
    AgentRef,
    BlastRadius,
    DomainModel,
    Identifier,
    IncidentRef,
    NonEmptyStr,
    PolicyDecision,
    RiskLevel,
    Timestamp,
)

__all__ = ["Approval", "ApprovalStatus", "ExecutionAuthorization"]


class ApprovalStatus(StrEnum):
    """Lifecycle of one approval artifact.

    ``PENDING -> APPROVED -> CONSUMED`` is the only path to execution. ``REJECTED`` and
    ``EXPIRED`` are terminal, and neither can be walked back: a lapsed approval is
    replaced by a new request, never renewed (``claude.md`` section 5 — human approval
    does not override hard constraints, and a stale one authorises nothing).
    """

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


class Approval(DomainModel):
    """One human-approval artifact bound to one proposed action.

    ``risk`` and ``blast_radius`` are copied from the action at request time on purpose:
    they are what the approving human was shown, and an approval record that cannot show
    what was approved is not reviewable. There is no divergence risk, because
    ``action_fingerprint`` covers those fields too — change either and the fingerprint
    stops matching.
    """

    approval_id: Identifier
    incident_id: IncidentRef
    action_id: Identifier
    action_fingerprint: str
    """SHA-256 of the action's canonical JSON. See :mod:`aegis.core.approval.fingerprint`."""

    requesting_agent: AgentRef
    policy_decision: PolicyDecision
    """The REQUIRE_APPROVAL decision this artifact was raised from."""

    risk: RiskLevel
    """Assessed risk at request time. Required — an unassessed action cannot be approved."""

    blast_radius: BlastRadius
    """Assessed reach at request time. Required, for the same reason."""

    reason: NonEmptyStr
    """Why approval is being asked for, taken from the policy decision."""

    status: ApprovalStatus
    created_at: Timestamp
    expires_at: Timestamp
    decided_at: Timestamp | None = None
    decided_by: NonEmptyStr | None = None
    """The human who approved or rejected, e.g. ``human:oncall``. Never an agent."""

    consumed_at: Timestamp | None = None

    @model_validator(mode="after")
    def _lifecycle_is_coherent(self) -> Approval:
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")

        decided = self.status in {
            ApprovalStatus.APPROVED,
            ApprovalStatus.REJECTED,
            ApprovalStatus.CONSUMED,
        }
        if decided and (self.decided_at is None or self.decided_by is None):
            raise ValueError(f"{self.status} approval requires decided_at and decided_by")
        if not decided and (self.decided_at is not None or self.decided_by is not None):
            raise ValueError(f"{self.status} approval must not carry a decision")

        if self.status is ApprovalStatus.CONSUMED and self.consumed_at is None:
            raise ValueError("CONSUMED approval requires consumed_at")
        if self.status is not ApprovalStatus.CONSUMED and self.consumed_at is not None:
            raise ValueError(f"{self.status} approval must not carry consumed_at")

        if self.fingerprint_is_malformed:
            raise ValueError("action_fingerprint must be 64 lowercase hex characters")
        return self

    @property
    def fingerprint_is_malformed(self) -> bool:
        return len(self.action_fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in self.action_fingerprint
        )

    def is_expired(self, now: datetime) -> bool:
        """Whether this approval has lapsed as of ``now``.

        Computed from ``expires_at`` rather than trusting ``status``: nothing guarantees
        that anyone called an expiry sweep, so consumption must decide from the clock.
        """
        return now >= self.expires_at


class ExecutionAuthorization(DomainModel):
    """Permission for one specific execution, produced by consuming an approval.

    This artifact **does not execute anything**. It records that, at ``authorized_at``,
    a named action was re-checked against current policy and found still to hold a valid
    human approval. The executor is a later milestone; until it exists, this is the last
    word the control plane says before the tool layer would act.
    """

    approval: Approval
    """The consumed approval, in its CONSUMED state."""

    incident_id: IncidentRef
    action_id: Identifier
    action_fingerprint: str
    agent_id: AgentRef
    policy_decision: PolicyDecision
    """The decision from re-evaluation at consumption time, not the one from request time."""

    authorized_at: Timestamp
