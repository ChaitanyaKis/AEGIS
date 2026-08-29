"""Audit — authoritative, append-only, tamper-evident application history.

Trust zone C (``claude.md`` sections 4, 20). Records what happened, what caused it, what
was decided, what evidence supported it and what state changed — so that the question
"what happened to this incident?" is answered from data, never by asking a model to
reconstruct it.

The store is in memory for this milestone. The hash chain provides tamper *evidence*, not
external immutability or durability; see :mod:`aegis.core.audit.records` for exactly what
it does and does not guarantee.
"""

from aegis.core.audit.events import EVENT_VOCABULARY_VERSION, AuditEventType
from aegis.core.audit.history import IncidentHistory, reconstruct_incident_history
from aegis.core.audit.recorders import APPROVAL_STATUS_EVENTS, AuditRecorder
from aegis.core.audit.records import (
    GENESIS_DIGEST,
    AuditRecord,
    IntegrityReport,
    record_digest,
    verify_chain,
)
from aegis.core.audit.store import AuditStore, DuplicateAuditEventError

__all__ = [
    "APPROVAL_STATUS_EVENTS",
    "EVENT_VOCABULARY_VERSION",
    "GENESIS_DIGEST",
    "AuditEventType",
    "AuditRecord",
    "AuditRecorder",
    "AuditStore",
    "DuplicateAuditEventError",
    "IncidentHistory",
    "IntegrityReport",
    "reconstruct_incident_history",
    "record_digest",
    "verify_chain",
]
