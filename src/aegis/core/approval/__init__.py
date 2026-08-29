"""Human approval — trust zone E (``claude.md`` section 4).

Manages the artifacts that carry human authority for actions the policy engine escalated.
It is not a second policy engine: it can never permit what policy forbids, and it re-asks
policy rather than trusting a decision handed to it earlier.

An approval authorises one exact action, for a bounded time, under one policy context,
exactly once. Nothing here executes anything.
"""

from aegis.core.approval.engine import DEFAULT_APPROVAL_TTL, ApprovalEngine
from aegis.core.approval.errors import (
    ApprovalConsumptionRefused,
    ApprovalCreationRefused,
    ApprovalError,
    ApprovalRefusal,
)
from aegis.core.approval.fingerprint import action_fingerprint
from aegis.core.approval.models import (
    Approval,
    ApprovalStatus,
    ExecutionAuthorization,
)

__all__ = [
    "DEFAULT_APPROVAL_TTL",
    "Approval",
    "ApprovalConsumptionRefused",
    "ApprovalCreationRefused",
    "ApprovalEngine",
    "ApprovalError",
    "ApprovalRefusal",
    "ApprovalStatus",
    "ExecutionAuthorization",
    "action_fingerprint",
]
