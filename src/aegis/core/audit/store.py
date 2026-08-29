"""The append-only audit store.

Authoritative application history (``claude.md`` section 20). Everything material AEGIS
does lands here, and nothing that lands here can be revised: there is no update method, no
delete method, and no way to reach the internal list.

Two kinds of time
-----------------

``AuditEvent.timestamp`` is *semantic* time — when the thing happened. Append order is
*record* time — when AEGIS learned of it. The store preserves append order and never
reorders by timestamp, because the difference between them is itself evidence: an event
recorded late, or out of order relative to its own timestamp, is a fact worth keeping
rather than one to tidy away. Two events sharing a timestamp keep their append order.

In memory only. Persistence is a later milestone; see
:mod:`aegis.core.audit.records` for what the hash chain does and does not guarantee.
"""

from __future__ import annotations

from collections.abc import Mapping

from aegis.core.audit.records import (
    GENESIS_DIGEST,
    AuditRecord,
    IntegrityReport,
    record_digest,
    verify_chain,
)
from aegis.core.domain import AuditEvent

__all__ = ["AuditStore", "DuplicateAuditEventError"]


class DuplicateAuditEventError(Exception):
    """An event id was appended twice.

    Never an overwrite. Two records sharing an id would make the history ambiguous about
    which one actually happened, and silently replacing the first would be exactly the
    revision an append-only log exists to prevent.
    """

    def __init__(self, event_id: str) -> None:
        self.event_id = event_id
        super().__init__(f"audit event already recorded: {event_id!r}")


class AuditStore:
    """An in-memory, append-only, tamper-evident log of audit events.

    The internal list is never exposed: every accessor returns a fresh tuple of frozen
    records, so a caller can hold, sort or discard what it is given without any of that
    reaching stored history.
    """

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self._event_ids: set[str] = set()

    # --- writing --------------------------------------------------------------------

    def append(
        self, event: AuditEvent, *, correlation: Mapping[str, str] | None = None
    ) -> AuditRecord:
        """Record one event at the end of the log.

        Args:
            event: The event. Already frozen, so nothing is copied defensively.
            correlation: Artifact identifiers this event relates to beyond its incident,
                e.g. ``{"action_id": "act-001"}``. Covered by the digest.

        Returns:
            The stored :class:`AuditRecord`, including its chain digests.

        Raises:
            DuplicateAuditEventError: if the event id is already in the log.
        """
        if event.event_id in self._event_ids:
            raise DuplicateAuditEventError(event.event_id)

        sequence = len(self._records)
        previous_digest = self._records[-1].digest if self._records else GENESIS_DIGEST
        resolved = dict(correlation or {})
        record = AuditRecord(
            sequence=sequence,
            event=event,
            correlation=resolved,
            previous_digest=previous_digest,
            digest=record_digest(
                sequence=sequence,
                event=event,
                correlation=resolved,
                previous_digest=previous_digest,
            ),
        )
        self._records.append(record)
        self._event_ids.add(event.event_id)
        return record

    # --- reading --------------------------------------------------------------------

    def records(self) -> tuple[AuditRecord, ...]:
        """Every record in append order, as a fresh tuple."""
        return tuple(self._records)

    def events(self) -> tuple[AuditEvent, ...]:
        """Every event in append order, as a fresh tuple."""
        return tuple(record.event for record in self._records)

    def records_for_incident(self, incident_id: str) -> tuple[AuditRecord, ...]:
        """Records belonging to one incident, in global append order.

        Matching is exact string equality. There is no prefix, substring or fuzzy
        matching, so ``INC-10`` never returns ``INC-100``'s history — an audit query that
        leaks a neighbouring incident's records is a confidentiality failure, not a
        convenience.
        """
        return tuple(record for record in self._records if record.event.incident_id == incident_id)

    def events_for_incident(self, incident_id: str) -> tuple[AuditEvent, ...]:
        """Events belonging to one incident, in global append order. Exact match only."""
        return tuple(record.event for record in self.records_for_incident(incident_id))

    def record_for_event(self, event_id: str) -> AuditRecord | None:
        """The record carrying ``event_id``, or ``None``. Exact match only."""
        for record in self._records:
            if record.event.event_id == event_id:
                return record
        return None

    # --- integrity ------------------------------------------------------------------

    def verify_integrity(self) -> IntegrityReport:
        """Recompute the whole chain and report whether it still holds."""
        return verify_chain(self._records)

    @property
    def head_digest(self) -> str:
        """Digest of the most recent record, or the genesis value for an empty log.

        The single value that commits to the entire history: any change anywhere in the
        log changes it.
        """
        return self._records[-1].digest if self._records else GENESIS_DIGEST

    # --- container protocol ---------------------------------------------------------

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, event_id: object) -> bool:
        return event_id in self._event_ids

    def __repr__(self) -> str:
        return f"{type(self).__name__}({len(self._records)} records)"
