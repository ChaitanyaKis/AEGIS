"""Closed vocabularies, and the shapes memory needs from the control plane.

Two things live here.

**Vocabularies.** What may be remembered, what state a record is in, and what established
it are all closed enums. An open vocabulary would let a caller invent a memory kind or a
provenance source that no test covers.

**Structural contracts.** Memory must not become another route into the control plane
(``claude.md`` section 13, and Part 24 of this milestone). So instead of importing the
verification engine, the incident state machine or the approval engine, this module
declares *protocols* describing the minimum shape an artifact must have for memory to
reason about it. The real :class:`~aegis.core.verification.VerificationResult` and
:class:`~aegis.core.domain.Action` satisfy them structurally, without memory depending on
either package.

The dependency direction matters: memory depends on descriptions of what it is given, and
nothing in the control plane depends on memory at all.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

__all__ = [
    "REQUIRED_VERIFICATION_STATUS",
    "ActionLike",
    "MemorySource",
    "MemoryStatus",
    "MemoryType",
    "VerifiedOutcome",
]


class MemoryType(StrEnum):
    """What a memory record is about. Closed: memory kinds are a reviewed vocabulary."""

    VERIFIED_INCIDENT_OUTCOME = "VERIFIED_INCIDENT_OUTCOME"
    """How an incident actually ended, established by verification."""

    VERIFIED_ROOT_CAUSE = "VERIFIED_ROOT_CAUSE"
    """What was actually wrong, where a verified remediation established it."""

    REMEDIATION_OUTCOME = "REMEDIATION_OUTCOME"
    """What a specific remediation actually did to the enterprise."""

    OPERATIONAL_PATTERN = "OPERATIONAL_PATTERN"
    """A recurring operational regularity, each instance of which was verified."""


class MemoryStatus(StrEnum):
    """A record's standing. Only AUTHORITATIVE is returned as trusted history."""

    CANDIDATE = "CANDIDATE"
    """Proposed, not admitted. Carries no authority and is never returned as history."""

    AUTHORITATIVE = "AUTHORITATIVE"
    """Admitted against a verified outcome. The only status retrieval will vouch for.

    Reachable exclusively through :class:`~aegis.memory.admission.MemoryAdmission`. See
    :class:`~aegis.memory.models.MemoryCandidate`, which has no status field at all — the
    type a caller can construct is structurally incapable of claiming this.
    """

    REVOKED = "REVOKED"
    """Withdrawn. The record remains in the chain; it is never returned as authoritative."""


class MemorySource(StrEnum):
    """What established a record. Closed, because this is the provenance claim itself."""

    VERIFIED_OUTCOME = "VERIFIED_OUTCOME"
    """A VERIFIED verification artifact bound to a specific incident and action.

    The only source that can support AUTHORITATIVE status. Everything below is recorded
    for traceability and can never be promoted.
    """

    AGENT_PROPOSAL = "AGENT_PROPOSAL"
    """An agent suggested this. Advisory (``claude.md`` section 7); never authority."""

    HUMAN_ASSERTION = "HUMAN_ASSERTION"
    """A person wrote it down. Still not a verified enterprise outcome."""

    TOOL_RESULT = "TOOL_RESULT"
    """A tool reported success. Section 11: that is not proof the operation succeeded."""


REQUIRED_VERIFICATION_STATUS = "VERIFIED"
"""The only verification status that can support authoritative memory.

Compared as a string rather than against
:class:`~aegis.core.verification.VerificationStatus`, so this package does not import the
verification engine. The coupling is not lost, only made explicit: a test pins this literal
against the real enum member, so renaming it there fails a memory test loudly instead of
silently admitting unverified outcomes.
"""


@runtime_checkable
class VerifiedOutcome(Protocol):
    """The shape memory needs from a verification artifact.

    Satisfied structurally by :class:`~aegis.core.verification.VerificationResult`. Memory
    reads these fields and never calls back into verification: it cannot re-run, re-check
    or re-interpret a verification, only read the one it was handed.
    """

    verification_id: str
    incident_id: str
    action_id: str
    action_fingerprint: str
    resource: str
    observations_used: Sequence[str]
    evaluated_at: datetime

    @property
    def status(self) -> object:
        """The verification status. Compared by its string form against
        :data:`REQUIRED_VERIFICATION_STATUS`."""
        ...


@runtime_checkable
class ActionLike(Protocol):
    """The shape memory needs from an action.

    Satisfied structurally by :class:`~aegis.core.domain.Action`. Memory reads identity and
    target; it never reads ``risk`` or ``blast_radius``, because it has no business
    reasoning about either (Part 13).
    """

    action_id: str
    incident_id: str
    capability: str
    target_resource: str
