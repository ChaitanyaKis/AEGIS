"""The memory store: append-only, tamper-evident, and the sole route to authority.

Two API shapes carry the security property:

* :meth:`MemoryStore.append` takes a :class:`~aegis.memory.models.MemoryCandidate` and
  always stores it as ``CANDIDATE``. There is no argument that makes it do anything else.
* :meth:`MemoryStore.admit` takes a candidate *and* the verified artifacts, runs
  :class:`~aegis.memory.admission.MemoryAdmission`, and stores the result as
  ``AUTHORITATIVE``.

Neither method accepts a pre-built :class:`~aegis.memory.models.MemoryRecord`. A caller who
constructs one by hand with ``status=AUTHORITATIVE`` holds a value the store will not take
— there is no method that admits it. That, rather than a check somewhere, is why an agent
cannot write authoritative memory.

Append-only throughout. There is no update and no delete. Revocation appends a revocation
entry naming the original, which stays in the chain: the point of a tamper-evident log is
that history cannot be made to have never happened.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Sequence
from datetime import datetime
from typing import Protocol, runtime_checkable

from aegis.core.domain import utc_now
from aegis.memory.admission import AdmissionContext, MemoryAdmission
from aegis.memory.errors import MemoryIntegrityError, MemoryNotFound
from aegis.memory.integrity import (
    MEMORY_GENESIS_DIGEST,
    MemoryIntegrityReport,
    memory_digest,
    verify_memory_chain,
)
from aegis.memory.models import MemoryCandidate, MemoryProvenance, MemoryQuery, MemoryRecord
from aegis.memory.types import MemorySource, MemoryStatus

__all__ = [
    "InMemoryPersistence",
    "MemoryPersistence",
    "MemoryStore",
]


@runtime_checkable
class MemoryPersistence(Protocol):
    """Where memory records are kept between operations.

    Deliberately minimal, and deliberately append-only: there is no update, no delete and
    no random-access write, so no backend implementing this interface can offer the store a
    way to rewrite history even if it wanted to.

    Implementations must preserve order exactly. The chain's meaning depends on it.
    """

    def load(self) -> Sequence[MemoryRecord]:
        """Every record, in the order it was appended."""
        ...

    def append(self, record: MemoryRecord) -> None:
        """Add one record to the end. Never called with anything but the next record."""
        ...


class InMemoryPersistence:
    """Process-lifetime persistence. **Not durable** — the default, and honest about it.

    Records live in a list that dies with the process. This exists so the store's contract
    can be exercised without a filesystem, and so tests are hermetic. Anything that needs
    to survive a restart wants
    :class:`~aegis.memory.persistence.JsonlMemoryPersistence` instead.
    """

    def __init__(self, records: Iterable[MemoryRecord] = ()) -> None:
        self._records: list[MemoryRecord] = list(records)

    def load(self) -> Sequence[MemoryRecord]:
        return tuple(self._records)

    def append(self, record: MemoryRecord) -> None:
        self._records.append(record)

    def __len__(self) -> int:
        return len(self._records)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(records={len(self._records)})"


class MemoryStore:
    """Append-only, tamper-evident organizational memory.

    Args:
        persistence: Where records are kept. Defaults to
            :class:`InMemoryPersistence`, which is not durable.
        admission: The admission component. Defaults to a standard one.
        clock: Injected, so a run serializes identically every time (Part 26).
        verify_on_load: Check the chain when adopting existing records. On by default:
            silently reading a tampered log would defeat the point of having a chain.

    Raises:
        MemoryIntegrityError: at construction, if persisted records do not verify.
    """

    def __init__(
        self,
        persistence: MemoryPersistence | None = None,
        *,
        admission: MemoryAdmission | None = None,
        clock: Callable[[], datetime] = utc_now,
        verify_on_load: bool = True,
    ) -> None:
        self._persistence = persistence if persistence is not None else InMemoryPersistence()
        self._admission = admission if admission is not None else MemoryAdmission(clock=clock)
        self._clock = clock
        self._records: list[MemoryRecord] = list(self._persistence.load())
        self._by_id: dict[str, MemoryRecord] = {r.memory_id: r for r in self._records}
        self._revoked: set[str] = {
            record.revokes for record in self._records if record.revokes is not None
        }
        if verify_on_load and self._records:
            report = verify_memory_chain(self._records)
            if not report.valid:
                raise MemoryIntegrityError(report.reason or "persisted memory does not verify")

    # --- reading --------------------------------------------------------------------

    def records(self) -> tuple[MemoryRecord, ...]:
        """Every record, in order, as a fresh immutable tuple.

        The internal list is never handed out: a caller can hold, sort or discard what it
        is given without any of that reaching stored history.
        """
        return tuple(self._records)

    def get(self, memory_id: str) -> MemoryRecord:
        """One record by exact id.

        Raises:
            MemoryNotFound: if no record has that id. Exact matching only — no prefix
                fallback, because a near-miss returning *something* is how the wrong
                memory gets read as the right one.
        """
        record = self._by_id.get(memory_id)
        if record is None:
            raise MemoryNotFound(memory_id)
        return record

    def query(self, query: MemoryQuery | None = None) -> tuple[MemoryRecord, ...]:
        """Records matching a deterministic filter, in storage order.

        Only ``AUTHORITATIVE`` records that have not been revoked are returned. Candidates
        and revoked records are in the chain and readable through :meth:`records`, but they
        are never returned as history.
        """
        query = query if query is not None else MemoryQuery()
        matched = [
            record
            for record in self._records
            if self._is_authoritative(record) and self._matches(record, query)
        ]
        if query.limit is not None:
            matched = matched[: query.limit]
        return tuple(matched)

    def _is_authoritative(self, record: MemoryRecord) -> bool:
        """Authoritative *and* not withdrawn.

        Revocation is append-only, so a revoked record still carries
        ``status=AUTHORITATIVE`` in the chain. Standing is the status plus the absence of
        a later revocation, and both are checked here rather than in each caller.
        """
        return record.authoritative and record.memory_id not in self._revoked

    def _matches(self, record: MemoryRecord, query: MemoryQuery) -> bool:
        """Exact-match filtering on declared fields. No fuzzy or substring logic."""
        provenance = record.provenance
        if query.incident_id is not None and record.incident_id != query.incident_id:
            return False
        if query.exclude_incident is not None and record.incident_id == query.exclude_incident:
            return False
        if query.memory_type is not None and record.memory_type is not query.memory_type:
            return False
        if query.agent_id is not None and record.agent_id != query.agent_id:
            return False
        if query.resource is not None:
            resource = provenance.resource if provenance else None
            if resource != query.resource:
                return False
        return not (
            query.capability is not None and record.content.get("capability") != query.capability
        )

    # --- writing --------------------------------------------------------------------

    def append(self, candidate: MemoryCandidate) -> MemoryRecord:
        """Store a proposal as a ``CANDIDATE``. It carries no authority.

        This is the method an agent's memory proposal reaches. There is no parameter that
        makes it store anything else, and it never consults a verification: a candidate is
        a claim, and storing a claim is not endorsing it.
        """
        return self._write(
            memory_type=candidate.memory_type,
            status=MemoryStatus.CANDIDATE,
            incident_id=candidate.incident_id,
            agent_id=candidate.agent_id,
            content=candidate.content,
            summary=candidate.summary,
            supporting_evidence=candidate.supporting_evidence,
            provenance=None,
            source=candidate.source,
        )

    def admit(self, candidate: MemoryCandidate, context: AdmissionContext) -> MemoryRecord:
        """Run admission and, if every check passes, store an ``AUTHORITATIVE`` record.

        The provenance stored is derived from the verified artifacts, not from anything the
        candidate claimed.

        Raises:
            MemoryAdmissionRefused: naming the first check that refused. Nothing is
                written: a refused candidate does not become a stored candidate as a
                consolation, because a partial write is a story about what nearly happened.
        """
        provenance = self._admission.admit(candidate, context)
        return self._write(
            memory_type=candidate.memory_type,
            status=MemoryStatus.AUTHORITATIVE,
            incident_id=candidate.incident_id,
            agent_id=candidate.agent_id,
            content=candidate.content,
            summary=candidate.summary,
            supporting_evidence=provenance.evidence_ids,
            provenance=provenance,
            source=MemorySource.VERIFIED_OUTCOME,
        )

    def revoke(self, memory_id: str, *, reason: str, actor: str) -> MemoryRecord:
        """Withdraw a record by appending a revocation entry that names it.

        The original stays in the chain, unmodified. After this the record is no longer
        returned by :meth:`query`, and the log still shows that it existed and was
        withdrawn — which is the difference between a correction and a cover-up.

        Raises:
            MemoryNotFound: if no record has that id.
        """
        target = self.get(memory_id)
        record = self._write(
            memory_type=target.memory_type,
            status=MemoryStatus.REVOKED,
            incident_id=target.incident_id,
            agent_id=actor,
            content={},
            summary=f"revoked {memory_id}: {reason}",
            supporting_evidence=(),
            provenance=None,
            source=target.source,
            revokes=memory_id,
            revocation_reason=reason,
        )
        self._revoked.add(memory_id)
        return record

    def _write(
        self,
        *,
        memory_type,
        status: MemoryStatus,
        incident_id: str,
        agent_id: str,
        content,
        summary: str,
        supporting_evidence: Sequence[str],
        provenance: MemoryProvenance | None,
        source: MemorySource,
        revokes: str | None = None,
        revocation_reason: str | None = None,
    ) -> MemoryRecord:
        """Build, link and persist one record. The single write path in this class."""
        sequence = len(self._records)
        memory_id = f"mem-{sequence:06d}"
        previous_digest = self._records[-1].digest if self._records else MEMORY_GENESIS_DIGEST
        created_at = self._clock()
        evidence = tuple(supporting_evidence)

        digest = memory_digest(
            memory_id=memory_id,
            sequence=sequence,
            memory_type=memory_type,
            status=status,
            incident_id=incident_id,
            agent_id=agent_id,
            content=content,
            summary=summary,
            supporting_evidence=evidence,
            provenance=provenance,
            source=source,
            created_at=created_at,
            revokes=revokes,
            revocation_reason=revocation_reason,
            previous_digest=previous_digest,
        )
        record = MemoryRecord(
            memory_id=memory_id,
            sequence=sequence,
            memory_type=memory_type,
            status=status,
            incident_id=incident_id,
            agent_id=agent_id,
            content=content,
            summary=summary,
            supporting_evidence=evidence,
            provenance=provenance,
            source=source,
            created_at=created_at,
            revokes=revokes,
            revocation_reason=revocation_reason,
            previous_digest=previous_digest,
            digest=digest,
        )
        self._persistence.append(record)
        self._records.append(record)
        self._by_id[memory_id] = record
        return record

    # --- integrity ------------------------------------------------------------------

    def verify_integrity(self) -> MemoryIntegrityReport:
        """Check the whole chain. See :mod:`aegis.memory.integrity` for its real boundary."""
        return verify_memory_chain(self._records)

    @property
    def head_digest(self) -> str:
        """The digest of the most recent record, or the genesis value when empty."""
        return self._records[-1].digest if self._records else MEMORY_GENESIS_DIGEST

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[MemoryRecord]:
        return iter(tuple(self._records))

    def __repr__(self) -> str:
        return f"{type(self).__name__}(records={len(self._records)})"
