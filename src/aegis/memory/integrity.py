"""The memory hash chain.

Deliberately the same construction as :mod:`aegis.core.audit.records`: a declared payload
model is canonically serialized and hashed, and each record carries the digest of the one
before it. Reusing the shape rather than the code keeps the two logs independent — memory
integrity does not depend on the audit package, and a change to one cannot quietly weaken
the other — while keeping one recognisable idea of what tamper evidence means in AEGIS.

What the chain provides
-----------------------

**Tamper evidence, and only that.** Modifying a record's content, provenance,
verification id, status or position breaks the chain, and :func:`verify_memory_chain`
reports where. Deleting, reordering or inserting a record does the same.

It explicitly does **not** provide external immutability, trusted hardware, remote
attestation or non-repudiation. The digest function lives in this process alongside the
data, so an attacker able to rewrite the whole store can recompute every digest and
rewrite this module too. The chain detects tampering by anything *other* than a
full-process compromise. Nothing here should be described as making memory immutable.

With file persistence the boundary moves but does not disappear: an on-disk log that is
edited out of process *is* detected on load, because the digests no longer chain. An
attacker who rewrites the file and recomputes every digest is not detected, because
nothing external attests to the chain's head.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence

from pydantic import Field, JsonValue

from aegis.core.domain import DomainModel, NonEmptyStr, Timestamp, to_json
from aegis.memory.models import MemoryProvenance, MemoryRecord
from aegis.memory.types import MemorySource, MemoryStatus, MemoryType

__all__ = [
    "MEMORY_GENESIS_DIGEST",
    "MemoryIntegrityReport",
    "memory_digest",
    "verify_memory_chain",
]

MEMORY_GENESIS_DIGEST = "0" * 64
"""The ``previous_digest`` of the first record in any memory chain.

Fixed and documented rather than random, for the same reason as the audit chain: the chain
detects modification, it does not establish identity, and a random root would make two
identical histories serialize differently for no benefit.
"""


class _DigestPayload(DomainModel):
    """Exactly the fields a memory digest covers.

    Declared as a model rather than assembled as a dict so that adding or dropping a
    covered field is a visible code change with a test behind it. Note what is included:
    ``provenance``, ``status``, ``content`` and ``sequence`` are all covered, which is what
    makes altered provenance, silent promotion, edited content and reordering detectable.
    """

    agent_id: NonEmptyStr
    content: Mapping[str, JsonValue]
    created_at: Timestamp
    incident_id: NonEmptyStr
    memory_id: NonEmptyStr
    memory_type: MemoryType
    previous_digest: str
    provenance: MemoryProvenance | None
    revocation_reason: NonEmptyStr | None
    revokes: NonEmptyStr | None
    sequence: int = Field(ge=0)
    namespace: str | None
    source: MemorySource
    status: MemoryStatus
    summary: NonEmptyStr
    supporting_evidence: tuple[NonEmptyStr, ...]


def memory_digest(
    *,
    memory_id: str,
    sequence: int,
    memory_type: MemoryType,
    status: MemoryStatus,
    incident_id: str,
    agent_id: str,
    content: Mapping[str, JsonValue],
    summary: str,
    namespace: str | None,
    supporting_evidence: Sequence[str],
    provenance: MemoryProvenance | None,
    source: MemorySource,
    created_at,
    revokes: str | None,
    revocation_reason: str | None,
    previous_digest: str,
) -> str:
    """The digest of one memory record, as 64 lowercase hex characters.

    A structured document is hashed rather than concatenated strings, so no field value can
    be crafted to imitate a field boundary. Canonicalisation is the project's existing
    :func:`~aegis.core.domain.serialization.to_json` — sorted keys, compact separators,
    UTC ISO-8601 timestamps — so the same record digests identically across processes and
    runs, which is what makes file persistence verifiable at all.
    """
    document = to_json(
        _DigestPayload(
            agent_id=agent_id,
            content=content,
            created_at=created_at,
            incident_id=incident_id,
            memory_id=memory_id,
            memory_type=memory_type,
            previous_digest=previous_digest,
            provenance=provenance,
            revocation_reason=revocation_reason,
            revokes=revokes,
            sequence=sequence,
            namespace=namespace,
            source=source,
            status=status,
            summary=summary,
            supporting_evidence=tuple(supporting_evidence),
        )
    )
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def record_digest(record: MemoryRecord) -> str:
    """Recompute the digest a record should carry, from the record's own fields."""
    return memory_digest(
        memory_id=record.memory_id,
        sequence=record.sequence,
        memory_type=record.memory_type,
        status=record.status,
        incident_id=record.incident_id,
        agent_id=record.agent_id,
        content=record.content,
        summary=record.summary,
        namespace=record.namespace,
        supporting_evidence=record.supporting_evidence,
        provenance=record.provenance,
        source=record.source,
        created_at=record.created_at,
        revokes=record.revokes,
        revocation_reason=record.revocation_reason,
        previous_digest=record.previous_digest,
    )


class MemoryIntegrityReport(DomainModel):
    """The outcome of verifying a memory chain.

    Reports; never repairs. A log that has been tampered with stays tampered with, and the
    report names where the damage starts so the surviving prefix can still be read.
    """

    valid: bool
    checked: int = Field(ge=0)
    first_invalid_index: int | None = None
    reason: NonEmptyStr | None = None

    @property
    def trusted_prefix(self) -> int:
        """How many records from the start are still internally consistent."""
        if self.valid:
            return self.checked
        return self.first_invalid_index or 0


def verify_memory_chain(records: Sequence[MemoryRecord]) -> MemoryIntegrityReport:
    """Check every record's position, link and digest.

    Three independent checks per record, because each catches a different attack:

    * **sequence** — catches deletion and reordering, which can leave digests self-
      consistent while the history is a different history;
    * **previous_digest** — catches insertion and truncation of the link structure;
    * **digest** — catches modification of any covered field, provenance and status
      included.
    """
    previous = MEMORY_GENESIS_DIGEST
    for index, record in enumerate(records):
        if record.sequence != index:
            return MemoryIntegrityReport(
                valid=False,
                checked=index,
                first_invalid_index=index,
                reason=(
                    f"record {record.memory_id!r} claims sequence {record.sequence}, "
                    f"but is at position {index}"
                ),
            )
        if record.previous_digest != previous:
            return MemoryIntegrityReport(
                valid=False,
                checked=index,
                first_invalid_index=index,
                reason=(f"record {record.memory_id!r} does not link to the record before it"),
            )
        expected = record_digest(record)
        if record.digest != expected:
            return MemoryIntegrityReport(
                valid=False,
                checked=index,
                first_invalid_index=index,
                reason=f"record {record.memory_id!r} does not match its digest",
            )
        previous = record.digest
    return MemoryIntegrityReport(valid=True, checked=len(records))
