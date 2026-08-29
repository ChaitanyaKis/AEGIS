"""Machine-readable refusals from the approval engine.

Every refusal carries a :class:`ApprovalRefusal` code rather than only a message, so a
future Control Center or audit store can answer "why could this approval not be used?"
from structured data, with no model involved.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "ApprovalConsumptionRefused",
    "ApprovalCreationRefused",
    "ApprovalError",
    "ApprovalRefusal",
]


class ApprovalRefusal(StrEnum):
    """Why the approval engine refused.

    Stable identifiers: these land in operator-facing output and, later, audit records.
    """

    # Creation
    POLICY_DOES_NOT_REQUIRE_APPROVAL = "POLICY_DOES_NOT_REQUIRE_APPROVAL"
    """The supplied decision was not REQUIRE_APPROVAL — an ALLOW needs no artifact."""

    POLICY_DENIES = "POLICY_DENIES"
    """Policy denies the action. No human artifact may be created for it, ever."""

    AGENT_MISMATCH = "AGENT_MISMATCH"
    INCIDENT_MISMATCH = "INCIDENT_MISMATCH"
    ACTION_IDENTITY_MISMATCH = "ACTION_IDENTITY_MISMATCH"
    RISK_UNASSESSED = "RISK_UNASSESSED"
    BLAST_RADIUS_UNASSESSED = "BLAST_RADIUS_UNASSESSED"

    # Lifecycle
    NOT_APPROVED = "NOT_APPROVED"
    """The approval is PENDING, REJECTED or EXPIRED — a human has not authorised it."""

    EXPIRED = "EXPIRED"
    ALREADY_CONSUMED = "ALREADY_CONSUMED"
    ALREADY_DECIDED = "ALREADY_DECIDED"

    # Consumption-time context
    ACTION_FINGERPRINT_MISMATCH = "ACTION_FINGERPRINT_MISMATCH"
    """The action changed after approval. The artifact authorises the old one only."""

    POLICY_NO_LONGER_REQUIRES_APPROVAL = "POLICY_NO_LONGER_REQUIRES_APPROVAL"
    """Re-evaluation returned something other than REQUIRE_APPROVAL."""


class ApprovalError(Exception):
    """Base class for approval-engine refusals.

    Attributes:
        refusal: The machine-readable reason.
    """

    def __init__(self, refusal: ApprovalRefusal, message: str) -> None:
        self.refusal = refusal
        super().__init__(f"{refusal}: {message}")


class ApprovalCreationRefused(ApprovalError):
    """An approval artifact could not be created for this action."""


class ApprovalConsumptionRefused(ApprovalError):
    """An existing approval may not authorise this execution."""
