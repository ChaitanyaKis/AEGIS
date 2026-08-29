"""Memory admission — the only route from a proposal to authoritative history.

The rule this module exists to enforce:

    Only a verified outcome, bound to one incident and one exact action, can establish
    authoritative memory.

Nothing else qualifies. Not a tool that reported success, not an agent that is confident,
not a human who wrote it down, not a verification that returned FAILED, STALE, MISMATCH or
INSUFFICIENT_EVIDENCE, and not a verification belonging to some other incident or action.

Admission is deterministic and total: given the same candidate and the same context it
always reaches the same decision, and every refusal names the check that refused. There is
no model in this path, no threshold, no score and no tie-break.

What admission is not
---------------------

It is not an authorization decision. Admitting a memory grants nobody anything: the result
is a record that retrieval will show to a model as history. Policy, risk, blast radius,
approval, execution, verification and resolution are all decided elsewhere and none of
them reads memory (Part 13).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime

from aegis.core.approval.fingerprint import action_fingerprint
from aegis.core.domain import DomainModel, utc_now
from aegis.memory.errors import MemoryAdmissionRefused
from aegis.memory.models import MemoryCandidate, MemoryProvenance
from aegis.memory.types import (
    REQUIRED_VERIFICATION_STATUS,
    ActionLike,
    MemorySource,
    VerifiedOutcome,
)

__all__ = ["ADMISSION_CHECKS", "AdmissionContext", "MemoryAdmission"]

ADMISSION_CHECKS = (
    "incident.present",
    "action.belongs_to_incident",
    "verification.present",
    "verification.status",
    "verification.incident_binding",
    "verification.action_binding",
    "verification.fingerprint_binding",
    "provenance.evidence",
    "content.corresponds_to_outcome",
)
"""Every check, in the order applied. Named so a refusal is machine-readable and so the
set a test must cover is the set the code runs, not a list someone maintained by hand.
"""


class AdmissionContext(DomainModel):
    """The artifacts admission judges a candidate against.

    Supplied by the caller — in practice the orchestrator, which holds the real incident,
    action and verification for the run that just completed. Memory never fetches these
    itself: it has no route into the control plane and no way to ask whether something is
    true (Part 24). It can only inspect what it was handed.
    """

    model_config = DomainModel.model_config | {"arbitrary_types_allowed": True}

    incident_id: str
    action: object
    """An :class:`~aegis.memory.types.ActionLike`. Typed loosely so this model does not
    import the domain ``Action``; the protocol is checked at admission."""

    verification: object
    """A :class:`~aegis.memory.types.VerifiedOutcome`."""


class MemoryAdmission:
    """Decides whether a candidate may become authoritative memory.

    Args:
        clock: Injected, so admission timestamps are reproducible (Part 26).
        fingerprint: How an action's identity is computed. Defaults to the project's single
            definition, :func:`~aegis.core.approval.fingerprint.action_fingerprint`, which
            the approval and verification subsystems already share. Injectable only so
            tests can prove the binding is actually checked — a caller substituting a
            different definition would be weakening its own check, not escaping one, since
            the fingerprint being compared against comes from the verification artifact.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = utc_now,
        fingerprint: Callable[[ActionLike], str] = action_fingerprint,
    ) -> None:
        self._clock = clock
        self._fingerprint = fingerprint

    def admit(self, candidate: MemoryCandidate, context: AdmissionContext) -> MemoryProvenance:
        """Run every admission check and return the provenance a record may carry.

        Returns:
            The :class:`~aegis.memory.models.MemoryProvenance` derived from the *verified
            artifacts*, not from the candidate. Anything the candidate claimed that the
            artifacts do not support has already been refused; anything it merely asserted
            is discarded rather than copied.

        Raises:
            MemoryAdmissionRefused: naming the first check that refused.
        """
        action = context.action
        verification = context.verification

        # 1. The incident exists in the supplied context, and the candidate is about it.
        if not context.incident_id:
            raise MemoryAdmissionRefused("incident.present", "no incident in context")
        if candidate.incident_id != context.incident_id:
            raise MemoryAdmissionRefused(
                "incident.present",
                f"candidate names incident {candidate.incident_id!r}, context holds "
                f"{context.incident_id!r}",
            )

        # 2. The referenced action belongs to that incident.
        if not isinstance(action, ActionLike):
            raise MemoryAdmissionRefused(
                "action.belongs_to_incident", "context action is not an action"
            )
        if action.incident_id != context.incident_id:
            raise MemoryAdmissionRefused(
                "action.belongs_to_incident",
                f"action {action.action_id!r} belongs to incident "
                f"{action.incident_id!r}, not {context.incident_id!r}",
            )
        if candidate.action_id is not None and candidate.action_id != action.action_id:
            raise MemoryAdmissionRefused(
                "action.belongs_to_incident",
                f"candidate claims action {candidate.action_id!r}, context holds "
                f"{action.action_id!r}",
            )

        # 3. The referenced verification exists.
        if not isinstance(verification, VerifiedOutcome):
            raise MemoryAdmissionRefused(
                "verification.present", "context holds no verification artifact"
            )
        if candidate.verification_id is not None and (
            candidate.verification_id != verification.verification_id
        ):
            raise MemoryAdmissionRefused(
                "verification.present",
                f"candidate claims verification {candidate.verification_id!r}, context "
                f"holds {verification.verification_id!r}",
            )

        # 4. The verification actually established the state.
        status = _status_name(verification.status)
        if status != REQUIRED_VERIFICATION_STATUS:
            raise MemoryAdmissionRefused(
                "verification.status",
                f"verification {verification.verification_id!r} is {status}, and only "
                f"{REQUIRED_VERIFICATION_STATUS} can establish authoritative memory",
            )

        # 5. Verification belongs to the same incident.
        if verification.incident_id != context.incident_id:
            raise MemoryAdmissionRefused(
                "verification.incident_binding",
                f"verification belongs to incident {verification.incident_id!r}, not "
                f"{context.incident_id!r}",
            )

        # 6. Verification belongs to the same action.
        if verification.action_id != action.action_id:
            raise MemoryAdmissionRefused(
                "verification.action_binding",
                f"verification covers action {verification.action_id!r}, not {action.action_id!r}",
            )

        # 7. The fingerprint binds the verification to this exact action, not merely to
        #    one carrying the same id. An id can be reused; a fingerprint cannot.
        expected = self._fingerprint(action)
        if verification.action_fingerprint != expected:
            raise MemoryAdmissionRefused(
                "verification.fingerprint_binding",
                f"verification fingerprint does not match action {action.action_id!r}",
            )

        # 8/9. Provenance and supporting evidence must exist. A verified outcome with no
        #      observation behind it is a contradiction, so this is a refusal rather than
        #      an empty tuple.
        evidence = tuple(verification.observations_used)
        if not evidence:
            raise MemoryAdmissionRefused(
                "provenance.evidence",
                f"verification {verification.verification_id!r} used no observations",
            )
        _require_declared_evidence(candidate.supporting_evidence, evidence)

        # 10. The content must be about the resource the verification established. A memory
        #     claiming a different resource is not a record of this outcome.
        _require_matching_resource(candidate, verification.resource)

        return MemoryProvenance(
            incident_id=context.incident_id,
            agent_id=candidate.agent_id,
            verification_id=verification.verification_id,
            action_id=action.action_id,
            action_fingerprint=verification.action_fingerprint,
            resource=verification.resource,
            evidence_ids=tuple(sorted(evidence)),
            verified_at=verification.evaluated_at,
            source=MemorySource.VERIFIED_OUTCOME,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"


_UNRECOGNISED_STATUS = "<unrecognised>"
"""What an unreadable status compares as. Cannot equal any real status name."""


def _status_name(status: object) -> str:
    """The verification status as a bare name, however it is represented.

    ``StrEnum`` members yield their value and plain strings pass through. Anything else
    yields :data:`_UNRECOGNISED_STATUS` rather than its ``repr`` — deliberately, because an
    object whose ``repr`` happens to read ``VERIFIED`` would otherwise be admitted. Failing
    closed is the whole point: a status this code cannot read is never verified.
    """
    value = getattr(status, "value", status)
    return value if isinstance(value, str) else _UNRECOGNISED_STATUS


def _require_declared_evidence(declared: Sequence[str], established: Sequence[str]) -> None:
    """Every observation the candidate cites must be one the verification actually used.

    A candidate may cite fewer — provenance is taken from the verification regardless — but
    citing an observation the verification never consulted means the candidate is
    describing a different outcome.
    """
    unknown = sorted(set(declared) - set(established))
    if unknown:
        raise MemoryAdmissionRefused(
            "provenance.evidence",
            f"candidate cites evidence the verification did not use: {unknown}",
        )


def _require_matching_resource(candidate: MemoryCandidate, resource: str) -> None:
    """If the candidate names a resource, it must be the verified one.

    Exact match, no substring or prefix logic (Part 9). A candidate that names no resource
    is accepted and takes the verified resource from provenance — it made no claim, so
    there is nothing to contradict.
    """
    claimed = candidate.content.get("resource")
    if claimed is None:
        return
    if not isinstance(claimed, str) or claimed != resource:
        raise MemoryAdmissionRefused(
            "content.corresponds_to_outcome",
            f"candidate content claims resource {claimed!r}, but the verification "
            f"established {resource!r}",
        )
