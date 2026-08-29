"""Registry status, the legal transitions between statuses, and the registration record.

    REGISTER -> VERSION -> PUBLISH -> DISCOVER -> APPROVE -> ACTIVATE -> SUSPEND -> REVOKE

Two things in this module carry the security of the whole package.

**The transition table is data, not code.** :data:`LEGAL_TRANSITIONS` is a frozen mapping
from status to the statuses reachable from it. Every transition goes through one function
that consults it, so there is exactly one place where "may this agent move from here to
there" is answered, and no method can quietly permit an edge the table forbids.

**REVOKED is terminal.** It has no outgoing edges. An agent that has been revoked cannot
be reinstated by any call on the registry — the only path back is a new registration,
which starts at DRAFT and has to earn approval again. That asymmetry is deliberate:
revocation is the response to an agent that turned out to be untrustworthy, and a
mechanism that can undo it is a mechanism an attacker can use.

Status is not authorization. An ACTIVE registration means an agent may *receive delegated
work*; it grants nothing. Every action the agent then proposes is still assessed, policed,
approved, gated, executed and verified exactly as before.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType

from pydantic import Field

from aegis.core.domain import (
    AgentRef,
    CapabilityRef,
    DomainModel,
    NonEmptyStr,
    Timestamp,
)
from aegis.registry.versions import AgentVersion

__all__ = [
    "ELIGIBLE_STATUSES",
    "LEGAL_TRANSITIONS",
    "AgentRegistration",
    "ApprovalStatus",
    "RegistryStatus",
    "RegistryTransition",
    "transition_is_legal",
]


class RegistryStatus(StrEnum):
    """Where a registration sits in its governed lifecycle. Closed and total."""

    DRAFT = "DRAFT"
    """Registered and nothing more. Not discoverable, not eligible, cannot execute."""

    PUBLISHED = "PUBLISHED"
    """Discoverable so a human can find and review it. Still not eligible.

    The gap between PUBLISHED and APPROVED is the point of having both: publishing is how
    an agent becomes *visible* for review, and it must not be how it becomes usable.
    """

    APPROVED = "APPROVED"
    """A human approved this exact version. Still not eligible until activated.

    Approval and activation are separate so that approving a build and putting it into
    service are two decisions with two audit records, and so an approved-but-not-yet-
    activated agent is a state the registry can actually represent.
    """

    ACTIVE = "ACTIVE"
    """In service. The only status that may receive newly delegated work."""

    SUSPENDED = "SUSPENDED"
    """Temporarily barred from new work. Reversible by re-activation."""

    REVOKED = "REVOKED"
    """Permanently barred. Terminal: no transition leads out of it."""


class ApprovalStatus(StrEnum):
    """Whether a human has approved this exact version.

    Tracked separately from :class:`RegistryStatus` because it answers a different and
    longer-lived question. A suspended agent is still an approved build; forgetting that
    would mean re-approval on every resume, and a re-approval that is routine is a
    re-approval nobody reads.
    """

    PENDING = "PENDING"
    GRANTED = "GRANTED"
    REJECTED = "REJECTED"
    """Explicitly refused. Like REVOKED, never reversed in place."""


ELIGIBLE_STATUSES: frozenset[RegistryStatus] = frozenset({RegistryStatus.ACTIVE})
"""The statuses that may receive newly delegated work.

Exactly one. Written as a set rather than an ``is ACTIVE`` comparison so the answer to
"which statuses can be delegated to" is a value a test can assert on and a reader can
find, instead of a condition spread across call sites.
"""

LEGAL_TRANSITIONS: Mapping[RegistryStatus, frozenset[RegistryStatus]] = MappingProxyType(
    {
        RegistryStatus.DRAFT: frozenset({RegistryStatus.PUBLISHED, RegistryStatus.REVOKED}),
        RegistryStatus.PUBLISHED: frozenset({RegistryStatus.APPROVED, RegistryStatus.REVOKED}),
        RegistryStatus.APPROVED: frozenset({RegistryStatus.ACTIVE, RegistryStatus.REVOKED}),
        RegistryStatus.ACTIVE: frozenset({RegistryStatus.SUSPENDED, RegistryStatus.REVOKED}),
        RegistryStatus.SUSPENDED: frozenset({RegistryStatus.ACTIVE, RegistryStatus.REVOKED}),
        RegistryStatus.REVOKED: frozenset(),
    }
)
"""Every legal edge. Note what is absent.

There is no ``DRAFT -> ACTIVE`` and no ``DRAFT -> APPROVED``: a newly registered agent
cannot reach service without being published and approved first, which is ``claude.md``
section 9's rule that registration never confers authority. There is no
``PUBLISHED -> ACTIVE``: discovery is not approval. And nothing leaves ``REVOKED``.
"""


def transition_is_legal(before: RegistryStatus, after: RegistryStatus) -> bool:
    """Whether ``before -> after`` is an edge in :data:`LEGAL_TRANSITIONS`.

    A self-transition is never legal, including ``ACTIVE -> ACTIVE``. Re-activating an
    already-active agent is a no-op that would otherwise produce an audit record implying
    something changed.
    """
    return after in LEGAL_TRANSITIONS.get(before, frozenset())


class RegistryTransition(DomainModel):
    """One status change, with everything needed to audit it.

    Emitted by the registry, never constructed by a caller who wants a status changed:
    the registry produces these as a *result* of a checked transition, so a record's
    existence means the transition was legal and happened.
    """

    agent_id: AgentRef
    version: AgentVersion
    before: RegistryStatus
    after: RegistryStatus
    actor: NonEmptyStr
    """Who caused it. A human id for approvals, a component name otherwise. Supplied by
    the caller from authoritative wiring — never taken from model output."""

    reason: NonEmptyStr
    occurred_at: Timestamp


class AgentRegistration(DomainModel):
    """The control-plane record of one *version* of one agent.

    Frozen, like every domain model here: a status change produces a new registration and
    the registry swaps it in, so ``before``/``after`` in the emitted
    :class:`RegistryTransition` are two objects that both still exist rather than one
    object's history that has been overwritten.

    ``capabilities`` is a declaration of what this build is *built to do*. It is not a
    grant and it is not an authorization: the capability registry decides what an agent
    holds, and the policy engine decides what it may exercise, on each action. Listing
    ``production.rollback`` here gets an agent discovered by that capability and nothing
    else.
    """

    agent_id: AgentRef
    version: AgentVersion
    name: NonEmptyStr
    description: NonEmptyStr
    owner: NonEmptyStr
    """The accountable human or team. Required, because an agent nobody owns is an agent
    nobody suspends."""

    department: NonEmptyStr
    capabilities: tuple[CapabilityRef, ...] = Field(default_factory=tuple)
    status: RegistryStatus
    approval_status: ApprovalStatus
    identity: NonEmptyStr
    """Reference to the agent's managed identity, resolved by an identity adapter.

    Opaque here, exactly as :attr:`aegis.core.domain.Agent.identity_reference` is opaque.
    The registry stores it and compares it; it never resolves it.
    """

    created_at: Timestamp
    updated_at: Timestamp
    approved_by: NonEmptyStr | None = None
    approved_at: Timestamp | None = None
    status_reason: NonEmptyStr | None = None
    """Why the registration is in its current status. Carries the suspension or revocation
    reason, so "why can this agent not be delegated to" is answerable from the record."""

    @property
    def key(self) -> tuple[str, str]:
        """The registry key: agent id and version string."""
        return (self.agent_id, str(self.version))

    @property
    def coordinate(self) -> str:
        """``agent-id@1.2.0`` — the human-readable form used in refusals and audit."""
        return f"{self.agent_id}@{self.version}"

    @property
    def eligible(self) -> bool:
        """Whether this registration may receive newly delegated work.

        Both conditions, deliberately. Status alone would let a hand-built record with
        ``ACTIVE`` and ``PENDING`` through, and approval alone ignores suspension.
        """
        return self.status in ELIGIBLE_STATUSES and self.approval_status is ApprovalStatus.GRANTED

    def declares(self, capability: str) -> bool:
        """Whether this build declares ``capability``. Exact match, never a prefix."""
        return capability in self.capabilities
