"""Memory records, candidates, provenance and retrieval results.

The central design decision is here, and it is structural rather than procedural.

A :class:`MemoryCandidate` is what a caller — including an agent — is able to construct.
**It has no status field.** There is no value anyone can pass to it that claims authority,
so "an agent writes authoritative memory" is not a check that can be forgotten or a rule
that can be mis-enforced; it is a sentence that cannot be expressed in the type system.

A :class:`MemoryRecord` is what the store holds. Its ``status`` is assigned during
admission, and the store's only route to AUTHORITATIVE is
:meth:`~aegis.memory.store.MemoryStore.admit`, which takes a candidate. A record built by
hand with ``status=AUTHORITATIVE`` is inert: nothing accepts it, and a validator refuses it
outright unless it carries provenance naming a verified outcome.

Everything is frozen and canonically serializable, following the project's existing
conventions.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import ClassVar

from pydantic import Field, JsonValue, model_validator

from aegis.core.domain import (
    AgentRef,
    DomainModel,
    EvidenceRef,
    Identifier,
    IncidentRef,
    NonEmptyStr,
    Timestamp,
)
from aegis.memory.types import MemorySource, MemoryStatus, MemoryType

__all__ = [
    "MemoryCandidate",
    "MemoryContext",
    "MemoryProvenance",
    "MemoryQuery",
    "MemoryRecord",
    "RetrievedMemory",
]


class MemoryProvenance(DomainModel):
    """Where an authoritative memory came from, in deterministic artifacts only.

    Every field names something the control plane produced and recorded. Deliberately
    absent (``claude.md`` section 12, and Part 5 of this milestone): confidence scores,
    model reasoning, agent assertions and tool success. None of those can establish that
    the enterprise reached a state, so none of them appears here — not even as metadata,
    because a field that exists will eventually be read as if it mattered.
    """

    incident_id: IncidentRef
    agent_id: AgentRef
    """The agent accountable for the action this memory records. Attribution, not
    authority: naming an agent grants nothing."""

    verification_id: Identifier
    action_id: Identifier
    action_fingerprint: str = Field(min_length=64, max_length=64)
    """SHA-256 of the verified action's canonical JSON. Binds this memory to one exact
    action, so a record cannot be re-read as being about a different one."""

    resource: NonEmptyStr
    """The resource whose state the verification established."""

    evidence_ids: tuple[EvidenceRef, ...] = Field(min_length=1)
    """The observations that established the outcome. At least one, always: a verified
    outcome with no supporting observation is a contradiction."""

    verified_at: Timestamp
    """When verification established the outcome — *not* when the memory was written.

    This is the age of the knowledge, and the reason stale memory is visible as stale.
    """

    source: MemorySource = MemorySource.VERIFIED_OUTCOME


class MemoryCandidate(DomainModel):
    """A proposal to remember something. Constructible by anyone; authoritative for nothing.

    This is the only memory type an agent can build, and it has no ``status`` field. There
    is no argument an agent can pass to claim authority — see the module docstring.
    """

    memory_type: MemoryType
    incident_id: IncidentRef
    agent_id: AgentRef
    content: Mapping[str, JsonValue] = Field(default_factory=dict)
    """What is remembered, as structured data.

    Structured rather than prose so retrieval can filter on declared fields, and so that
    nothing here reads as an instruction. Content is never interpreted by this package:
    hostile text stored here stays inert data (Part 15).
    """

    summary: NonEmptyStr
    """One line for a human reading the trail. Never parsed, never matched against."""

    supporting_evidence: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
    verification_id: Identifier | None = None
    action_id: Identifier | None = None
    """What the proposer *claims* established this. Admission checks the claim against the
    real artifacts; a claim is not a binding."""

    source: MemorySource = MemorySource.AGENT_PROPOSAL


class MemoryRecord(DomainModel):
    """One stored memory, with its position in the chain and its integrity digests.

    Produced by :class:`~aegis.memory.store.MemoryStore`. Frozen, like everything else in
    AEGIS: a returned record is a value, and holding one gives no route to stored state.
    """

    memory_id: Identifier
    sequence: int = Field(ge=0)
    """Zero-based position in the log. Covered by the digest, so a record knows where it
    belongs and reordering is detectable."""

    memory_type: MemoryType
    status: MemoryStatus
    incident_id: IncidentRef
    agent_id: AgentRef
    content: Mapping[str, JsonValue] = Field(default_factory=dict)
    summary: NonEmptyStr
    supporting_evidence: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
    provenance: MemoryProvenance | None = None
    """Present exactly when the record is authoritative, or was before revocation."""

    source: MemorySource
    created_at: Timestamp
    revokes: Identifier | None = None
    """For a revocation entry, the memory this withdraws. Revocation is append-only: the
    original record stays in the chain, and this names it."""

    revocation_reason: NonEmptyStr | None = None
    previous_digest: str = Field(min_length=64, max_length=64)
    digest: str = Field(min_length=64, max_length=64)

    @model_validator(mode="after")
    def _authority_requires_provenance(self) -> MemoryRecord:
        """Authoritative memory must name the verification that established it.

        Defence in depth. The real boundary is that the store only admits candidates, but a
        record that claimed authority with no provenance should not be a representable
        value either.
        """
        if self.status is MemoryStatus.AUTHORITATIVE:
            if self.provenance is None:
                raise ValueError(
                    f"{self.memory_id}: AUTHORITATIVE memory requires provenance naming "
                    f"the verification that established it"
                )
            if self.provenance.source is not MemorySource.VERIFIED_OUTCOME:
                raise ValueError(
                    f"{self.memory_id}: AUTHORITATIVE memory requires a VERIFIED_OUTCOME "
                    f"provenance source, not {self.provenance.source}"
                )
            if self.provenance.incident_id != self.incident_id:
                raise ValueError(
                    f"{self.memory_id}: provenance incident {self.provenance.incident_id!r} "
                    f"does not match the record's incident {self.incident_id!r}"
                )
        return self

    @property
    def authoritative(self) -> bool:
        return self.status is MemoryStatus.AUTHORITATIVE

    @property
    def is_revocation(self) -> bool:
        return self.revokes is not None


class MemoryQuery(DomainModel):
    """A deterministic filter over stored memory.

    Exact matching on declared fields only — no substring, prefix, fuzzy or semantic
    matching, and no implicit fallback (Part 9, Part 12). Every field left unset is simply
    not filtered on.
    """

    resource: NonEmptyStr | None = None
    capability: NonEmptyStr | None = None
    incident_id: IncidentRef | None = None
    memory_type: MemoryType | None = None
    agent_id: AgentRef | None = None
    limit: int | None = Field(default=None, ge=1)
    """Cap on returned records, applied after deterministic ordering."""

    exclude_incident: IncidentRef | None = None
    """Drop memory from this incident.

    Used when retrieving history *for* an incident, so its own in-flight record cannot be
    read back as if it were established history.
    """


class RetrievedMemory(DomainModel):
    """One authoritative record, as historical context, with its age made visible.

    A distinct type from :class:`MemoryRecord` on purpose. Retrieval hands back something
    that says plainly what it is: history, with a timestamp, from another incident. It is
    not evidence, and it is not an observation of the world as it is now (Part 13).
    """

    memory_id: Identifier
    memory_type: MemoryType
    incident_id: IncidentRef
    summary: NonEmptyStr
    content: Mapping[str, JsonValue] = Field(default_factory=dict)
    resource: NonEmptyStr
    verified_at: Timestamp
    verification_id: Identifier
    age_seconds: float = Field(ge=0.0)
    """How old the *knowledge* is, from verification to the retrieval clock.

    Reported so a reader can see that history is history. Deliberately not a confidence
    score and not a decay weight: no number here gates anything, because a number that
    gated something would be a security mechanism built out of an estimate (Part 17).
    """

    def as_model_data(self) -> dict[str, JsonValue]:
        """This memory as untrusted JSON data for a model request.

        Every entry is labelled with where it came from and when. It travels in
        ``ModelRequest.data`` and never in the instruction channel (Part 14).
        """
        return {
            "memory_id": self.memory_id,
            "memory_type": self.memory_type.value,
            "from_incident": self.incident_id,
            "resource": self.resource,
            "summary": self.summary,
            "content": dict(self.content),
            "verified_at": self.verified_at.isoformat(),
            "age_seconds": self.age_seconds,
        }


class MemoryContext(DomainModel):
    """What retrieval returns: historical context, and nothing more.

    The name is the contract. This is context for reasoning — it establishes no state,
    satisfies no verification, and grants no permission. Nothing in the control plane
    reads it, and the only place it goes is ``ModelRequest.data``.
    """

    query: MemoryQuery
    records: tuple[RetrievedMemory, ...] = Field(default_factory=tuple)
    retrieved_at: Timestamp

    ADVISORY: ClassVar[str] = "historical context only; establishes no current state"
    """Carried in the model payload so the label travels with the data.

    A class constant rather than a field: it is a fixed label, and a caller able to
    overwrite it could hand a model a payload that described itself as something other
    than history.
    """

    @property
    def empty(self) -> bool:
        return not self.records

    def as_model_data(self) -> dict[str, JsonValue]:
        """The context as untrusted data for ``ModelRequest.data``."""
        return {
            "advisory": self.ADVISORY,
            "retrieved_at": self.retrieved_at.isoformat(),
            "records": [record.as_model_data() for record in self.records],
        }


def age_seconds(verified_at: datetime, now: datetime) -> float:
    """Age of a verified outcome in seconds, never negative.

    A clock that runs backwards produces zero rather than a negative age, so nothing
    downstream has to defend against a memory that appears to come from the future.
    """
    return max((now - verified_at).total_seconds(), 0.0)
