"""Verification outcomes and the per-predicate record behind them.

A result answers "why verified?" and "why not verified?" from structured data alone. There
is no model output here, no chain-of-thought and no prose to parse: every check names the
attribute it read, the value it expected, the value it observed and the observations it
read them from.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from aegis.core.domain import (
    DomainModel,
    EvidenceRef,
    Identifier,
    IncidentRef,
    NonEmptyStr,
    Timestamp,
)
from aegis.core.verification.expectation import Comparator
from aegis.core.verification.observation import ObservedValue

__all__ = [
    "STATUS_PRECEDENCE",
    "CheckOutcome",
    "PredicateCheck",
    "VerificationResult",
    "VerificationStatus",
]


class CheckOutcome(StrEnum):
    """What happened to one predicate."""

    PASS = "PASS"
    FAIL = "FAIL"
    """Evaluated against fresh, trusted evidence and did not hold."""

    MISSING = "MISSING"
    """No usable observation carried this attribute at all."""

    STALE = "STALE"
    """The attribute was observed, but not recently enough to establish current state."""

    CONFLICT = "CONFLICT"
    """Usable observations disagreed about the value, so nothing was established."""


class VerificationStatus(StrEnum):
    """The outcome of a whole verification.

    Exactly one is success. The four failure modes are kept distinct because they call for
    different responses: chase the missing telemetry, wait for fresher data, reconcile the
    sources, or accept that the remediation did not work.
    """

    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    STALE = "STALE"
    MISMATCH = "MISMATCH"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


STATUS_PRECEDENCE: tuple[VerificationStatus, ...] = (
    VerificationStatus.INSUFFICIENT_EVIDENCE,
    VerificationStatus.STALE,
    VerificationStatus.MISMATCH,
    VerificationStatus.FAILED,
)
"""Which failure is reported when several predicates fail differently, most severe first.

Evidential problems outrank evaluation problems: "we could not tell" is a weaker position
than "we checked and it did not hold", and reporting the weaker position keeps the
operator's attention on the missing information. Only the ordering of *reported* failures
depends on this — every entry is equally not-VERIFIED.
"""


class PredicateCheck(DomainModel):
    """The record of evaluating one predicate.

    ``observed`` is ``None`` when nothing usable was found, which is what distinguishes a
    check that failed from one that never ran.
    """

    attribute: NonEmptyStr
    comparator: Comparator
    expected: ObservedValue
    observed: ObservedValue | None = None
    outcome: CheckOutcome
    observation_ids: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
    """Observations this check read, so the value can be traced back to its source."""

    detail: NonEmptyStr
    """Deterministic one-line summary, derived from the fields above."""


class VerificationResult(DomainModel):
    """Whether the enterprise actually reached the expected state.

    Bound to the incident, the action and the resource it was produced for. A verification
    artifact is not globally reusable: the state machine re-checks these bindings before
    letting it resolve anything.
    """

    verification_id: Identifier
    incident_id: IncidentRef
    action_id: Identifier
    action_fingerprint: str
    """SHA-256 of the verified action's canonical JSON, from
    :func:`aegis.core.approval.action_fingerprint`. Shared with the approval subsystem so
    there is exactly one definition of action identity in AEGIS."""

    resource: NonEmptyStr
    """The resource whose state was established. Always the action's target."""

    status: VerificationStatus
    checks: tuple[PredicateCheck, ...] = Field(min_length=1)
    """One entry per predicate, in the expectation's declared order."""

    observations_used: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
    """Every observation that contributed, sorted. Empty when none were usable."""

    evaluated_at: Timestamp
    reason: NonEmptyStr

    @property
    def verified(self) -> bool:
        """Whether this result establishes that the expected state was reached."""
        return self.status is VerificationStatus.VERIFIED
