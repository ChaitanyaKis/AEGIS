"""Organizational memory, labelled for what it is: history, never current state.

Part 13. One label does most of the work here:

    HISTORICAL CONTEXT ONLY

Memory records what was verified about a *past* incident. An operator glancing at a
dashboard must not read "payment-api was rolled back to v4.7" as a statement about
production now -- that question is answered by the enterprise world and by verification, not
by a memory of something that happened last month.

Two things this view refuses to do
----------------------------------

**A revoked memory is never shown as active context.** Revocation is append-only: the
original record stays in the chain and a revocation entry names it. This view resolves that
and reports the record as ``REVOKED``, so a withdrawn conclusion cannot come back through a
dashboard.

**Unverified memory is never shown as authoritative.** Only a record carrying provenance --
the verification that established it -- is labelled authoritative. Everything else is
labelled by its actual status and shown with its provenance missing, which is a visible
absence rather than a silent downgrade.
"""

from __future__ import annotations

from pydantic import Field

from aegis.control_center.capture import ControlCenterInput
from aegis.control_center.models import (
    Completeness,
    Fact,
    Provenance,
    Tri,
    ViewSource,
)
from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp

__all__ = ["HISTORICAL_CONTEXT_LABEL", "MemoryEntryView", "MemoryView", "build_memory"]

HISTORICAL_CONTEXT_LABEL = "HISTORICAL CONTEXT ONLY"
"""The label Part 13 requires, as a constant so a renderer cannot paraphrase it away.

Carried on every entry and asserted by test. A memory view that dropped it would be a view
inviting an operator to read last month's verified rollback as this morning's deployment.
"""


class MemoryEntryView(DomainModel):
    """One memory record, with its provenance and its status resolved.

    ``authoritative`` is derived from the record's *own* status and provenance -- never from
    the fact that the record exists. A record in the store is a record in the store; only
    one with a verification behind it and no revocation against it is authoritative.
    """

    memory_id: Identifier
    label: NonEmptyStr = HISTORICAL_CONTEXT_LABEL
    incident_id: Identifier
    agent_id: Identifier
    memory_type: NonEmptyStr
    status: NonEmptyStr
    summary: NonEmptyStr
    source: NonEmptyStr
    created_at: Timestamp

    action_fingerprint: Fact
    verification_id: Fact
    verified_at: Timestamp | None = None
    age_seconds: float | None = None
    """How old this memory is at capture time. Shown because a verified conclusion from six
    months ago and one from six minutes ago are different kinds of evidence."""

    revoked: Tri = Tri.UNKNOWN
    revoked_by: Fact
    revocation_reason: Fact
    authoritative: Tri = Tri.UNKNOWN
    integrity: Fact
    """Whether this record's own digest matches the chain position it claims. ``UNKNOWN``
    when the chain could not be checked -- never ``VALID`` by default."""

    supporting_evidence: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)

    def __repr__(self) -> str:
        return f"MemoryEntryView({self.memory_id} {self.status} authoritative={self.authoritative})"


class MemoryView(DomainModel):
    """Every memory record this projection was given, with counts an operator can trust."""

    entries: tuple[MemoryEntryView, ...] = Field(default_factory=tuple)
    authoritative_count: int = Field(default=0, ge=0)
    revoked_count: int = Field(default=0, ge=0)
    unverified_count: int = Field(default=0, ge=0)
    """Records with no provenance. Counted separately so "we hold 40 memories" is never
    mistaken for "40 verified conclusions"."""

    label: NonEmptyStr = HISTORICAL_CONTEXT_LABEL
    provenance: Provenance

    def authoritative(self) -> tuple[MemoryEntryView, ...]:
        """Only records that are genuinely authoritative right now.

        Strict: an entry whose authority is ``UNKNOWN`` is excluded. A dashboard that
        showed uncertain memory among the authoritative ones would be making exactly the
        claim this package must not make.
        """
        return tuple(entry for entry in self.entries if entry.authoritative.is_true)

    def __repr__(self) -> str:
        return (
            f"MemoryView({len(self.entries)} records, {self.authoritative_count} authoritative, "
            f"{self.revoked_count} revoked)"
        )


def build_memory(data: ControlCenterInput) -> MemoryView:
    """Project memory records, resolving revocations against the records they name.

    Revocation entries are folded into the records they revoke rather than shown as records
    of their own: an operator asking "what do we know" should see one withdrawn conclusion,
    not a conclusion and a separate note somewhere else saying to ignore it.
    """
    if not data.memory_available:
        return MemoryView(
            provenance=Provenance.unavailable(
                data.captured_at, "the memory store could not be read"
            )
        )

    records = data.memory_records
    revocations = {record.revokes: record for record in records if getattr(record, "revokes", None)}

    entries: list[MemoryEntryView] = []
    for record in records:
        if getattr(record, "revokes", None):
            continue  # folded into the record it withdraws, below
        revocation = revocations.get(record.memory_id)
        provenance = getattr(record, "provenance", None)
        status = str(record.status)
        revoked = revocation is not None or status == "REVOKED"
        entries.append(
            MemoryEntryView(
                memory_id=str(record.memory_id),
                incident_id=str(record.incident_id),
                agent_id=str(record.agent_id),
                memory_type=str(record.memory_type),
                status=status,
                summary=str(record.summary),
                source=str(record.source),
                created_at=record.created_at,
                action_fingerprint=(
                    Fact.observed(provenance.action_fingerprint, str(record.memory_id))
                    if provenance is not None and getattr(provenance, "action_fingerprint", None)
                    else Fact.unknown()
                ),
                verification_id=(
                    Fact.observed(provenance.verification_id, str(record.memory_id))
                    if provenance is not None and getattr(provenance, "verification_id", None)
                    else Fact.unknown()
                ),
                verified_at=getattr(provenance, "verified_at", None),
                age_seconds=max((data.captured_at - record.created_at).total_seconds(), 0.0),
                revoked=Tri.of(revoked),
                revoked_by=(
                    Fact.observed(revocation.memory_id, str(record.memory_id))
                    if revocation is not None
                    else Fact.unknown()
                ),
                revocation_reason=(
                    Fact.observed(revocation.revocation_reason)
                    if revocation is not None and revocation.revocation_reason
                    else Fact.unknown()
                ),
                # Authoritative means: the store marked it so, a verification established
                # it, and nothing has withdrawn it. All three, or the answer is FALSE.
                authoritative=Tri.of(
                    status == "AUTHORITATIVE" and provenance is not None and not revoked
                ),
                integrity=Fact.observed("CHAINED", str(record.digest))
                if getattr(record, "digest", None)
                else Fact.unknown(),
                supporting_evidence=tuple(
                    str(reference) for reference in record.supporting_evidence
                ),
            )
        )

    entries.sort(key=lambda entry: (entry.created_at, entry.memory_id))
    return MemoryView(
        entries=tuple(entries),
        authoritative_count=sum(1 for entry in entries if entry.authoritative.is_true),
        revoked_count=sum(1 for entry in entries if entry.revoked.is_true),
        unverified_count=sum(1 for entry in entries if not entry.verification_id.known),
        provenance=Provenance(
            source=ViewSource.MEMORY,
            as_of=data.captured_at,
            completeness=Completeness.COMPLETE,
        ),
    )
