"""Deterministic memory retrieval.

Filtering on declared fields, in storage order, with exact matching. No embeddings, no
vector index, no similarity ranking and no relevance score (Part 12). Two calls with the
same query against the same store return the same records in the same order.

Retrieval creates no authority. It reads records the store already marked authoritative
and wraps them in :class:`~aegis.memory.models.MemoryContext`, whose name is the whole
contract: context for a model to reason with, labelled as history, carrying the time it
was established. Nothing in the deterministic control plane calls this — verification
reads observations, policy reads capabilities and lifecycle, assessment reads the
dependency graph. Memory reaches exactly one destination: ``ModelRequest.data``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from aegis.core.domain import utc_now
from aegis.memory.models import (
    MemoryContext,
    MemoryQuery,
    MemoryRecord,
    RetrievedMemory,
    age_seconds,
)
from aegis.memory.store import MemoryStore

__all__ = ["MemoryRetrieval"]


class MemoryRetrieval:
    """Reads authoritative memory as historical context.

    Args:
        store: The memory store to read. Read-only use: this class calls no write method,
            and holds no route to one that a caller could reach through it.
        clock: Injected, so reported ages are reproducible.
    """

    def __init__(self, store: MemoryStore, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._store = store
        self._clock = clock

    def retrieve(
        self, query: MemoryQuery | None = None, requesting_agent: str | None = None
    ) -> MemoryContext:
        """Authoritative memory matching ``query``, as historical context.

        Revoked and candidate records are never included — that is enforced by the store's
        own filter, not re-implemented here, so there is one definition of what counts as
        authoritative.
        """
        query = query if query is not None else MemoryQuery()
        now = self._clock()
        
        records = []
        for record in self._store.query(query):
            if record.provenance is None:
                continue
            if record.namespace is not None and requesting_agent is not None and record.namespace != requesting_agent:
                continue
            records.append(_as_retrieved(record, now))
            
        return MemoryContext(query=query, records=tuple(records), retrieved_at=now)

    def for_incident(
        self,
        incident_id: str,
        *,
        resource: str | None = None,
        limit: int | None = None,
        requesting_agent: str | None = None,
    ) -> MemoryContext:
        """History relevant to an incident, excluding the incident's own memory.

        The exclusion is the point (Part 16). An incident must not be able to read back
        memory written about itself as though it were established prior knowledge; that is
        how a conclusion becomes its own supporting evidence.
        """
        return self.retrieve(
            MemoryQuery(resource=resource, exclude_incident=incident_id, limit=limit),
            requesting_agent=requesting_agent,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(store={self._store!r})"


def _as_retrieved(record: MemoryRecord, now: datetime) -> RetrievedMemory:
    """Project a stored record into the historical-context view.

    The projection is deliberately lossy: ``status``, digests and chain position do not
    travel. A consumer of retrieved memory has no business reading the chain, and a model
    has no business seeing a field it might mistake for a permission.
    """
    provenance = record.provenance
    assert provenance is not None  # guaranteed by the caller's filter
    return RetrievedMemory(
        memory_id=record.memory_id,
        memory_type=record.memory_type,
        incident_id=record.incident_id,
        summary=record.summary,
        content=record.content,
        resource=provenance.resource,
        verified_at=provenance.verified_at,
        verification_id=provenance.verification_id,
        age_seconds=age_seconds(provenance.verified_at, now),
    )
