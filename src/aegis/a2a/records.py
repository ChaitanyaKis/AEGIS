"""What is written down about a message, and how the writing is kept honest.

A fourth hash chain, built exactly like the audit chain, the memory chain and the
lifecycle-state chain: SHA-256 over canonical JSON, each record naming the digest of the
one before it. One construction, one set of properties, one thing to review.

Why a chain and not just a table
--------------------------------

The property that matters is **a consumed message stays consumed across a restart**. A
plain table of statuses would give that only as long as nobody edited the table. Three
independent checks close the obvious edits:

* **sequence** — deletion and reordering, which can leave every digest self-consistent;
* **previous_digest** — insertion and truncation of the link structure;
* **digest** — modification of any covered field, ``status`` very much included.

And a fourth, which is the one a cryptographer would not think to add: **status-transition
legality**. A chain can be perfect and still describe an impossible history. Replaying an
old ``ISSUED`` record after a ``CONSUMED`` one is a valid-looking way to make a spent
message fresh again, and it is caught because ``CONSUMED -> ISSUED`` is not a legal edge.

What is *not* written down
--------------------------

The payload. A record carries ``payload_digest``, never payload content. Two reasons, and
both matter: a payload is untrusted material (``claude.md`` section 4, zone A) that already
lives where it belongs and should not be copied into a second durable place; and a digest
is sufficient for every question this chain has to answer, because the envelope's own seal
already binds the payload to the message.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from enum import StrEnum

from pydantic import Field, JsonValue

from aegis.a2a.contracts import MessageStatus, MessageType, TaskType
from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp, to_json

__all__ = [
    "A2A_GENESIS_DIGEST",
    "A2AIntegrityReport",
    "A2ARecordKind",
    "A2AStateRecord",
    "legal_status_transition",
    "payload_digest",
    "record_digest",
    "verify_a2a_chain",
]

A2A_GENESIS_DIGEST = "0" * 64
"""The ``previous_digest`` of the first record.

Fixed and documented, like the audit, memory and lifecycle chains. The chain detects
modification; it does not establish identity, and a fixed genesis makes that plain rather
than implying a secret nobody has.
"""


class A2ARecordKind(StrEnum):
    """What a persisted record describes. Two kinds, and no third.

    A message is brought into existence once and then moves between statuses. There is no
    "amended" record and no "corrected" record, because the chain has no way to express a
    correction — which is the point.
    """

    MESSAGE_ISSUED = "MESSAGE_ISSUED"
    STATUS_CHANGED = "STATUS_CHANGED"


_LEGAL_STATUS_EDGES: frozenset[tuple[MessageStatus, MessageStatus]] = frozenset(
    {
        (MessageStatus.ISSUED, MessageStatus.ACCEPTED),
        (MessageStatus.ISSUED, MessageStatus.CONSUMED),
        (MessageStatus.ISSUED, MessageStatus.REJECTED),
        (MessageStatus.ISSUED, MessageStatus.EXPIRED),
        (MessageStatus.ISSUED, MessageStatus.COMPLETED),
        (MessageStatus.ACCEPTED, MessageStatus.CONSUMED),
        (MessageStatus.ACCEPTED, MessageStatus.COMPLETED),
        (MessageStatus.ACCEPTED, MessageStatus.REJECTED),
        (MessageStatus.CONSUMED, MessageStatus.COMPLETED),
        (MessageStatus.EXPIRED, MessageStatus.REJECTED),
        (MessageStatus.REJECTED, MessageStatus.EXPIRED),
    }
)
"""Every legal status edge, written out one pair at a time.

Deliberately an explicit set of edges rather than a cross product of "from" and "to" sets.
A cross product is how :data:`~aegis.lifecycle.state._LEGAL` was first written in Prompt 13,
and it silently permitted the exact reversal it existed to forbid. The edges that are
*absent* here are the whole security property:

* nothing returns to ``ISSUED`` — a spent message never becomes fresh again;
* ``CONSUMED`` goes only to ``COMPLETED`` — consumption is one-way;
* ``COMPLETED`` goes nowhere at all.
"""


def legal_status_transition(previous: MessageStatus, resulting: MessageStatus) -> bool:
    """Whether a message may move between these two statuses.

    A no-op restatement of the same status is legal: a crash between writing a record and
    acknowledging it can produce a duplicate, and refusing to load such a log would turn a
    harmless retry into an unstartable process.
    """
    return previous is resulting or (previous, resulting) in _LEGAL_STATUS_EDGES


class A2AStateRecord(DomainModel):
    """One durable fact about one message.

    Frozen and closed. Every field below is covered by :func:`record_digest`, so adding a
    field without covering it is a visible change with a test behind it.
    """

    sequence: int = Field(ge=0)
    """Position in the log, from zero. Catches deletion and reordering."""

    previous_digest: NonEmptyStr
    digest: NonEmptyStr
    kind: A2ARecordKind

    message_id: Identifier
    conversation_id: Identifier
    incident_id: Identifier
    sender_agent_id: Identifier
    recipient_agent_id: Identifier
    task_id: Identifier
    task_type: TaskType
    message_type: MessageType
    target_resource: NonEmptyStr | None = None
    evidence_refs: tuple[Identifier, ...] = Field(default_factory=tuple)
    message_sequence: int = Field(ge=1)
    """The message's position in its conversation. Distinct from ``sequence``, which is the
    position of this *record* in the log — one message produces several records."""

    created_at: Timestamp
    expires_at: Timestamp
    payload_digest: NonEmptyStr
    """SHA-256 of the canonical payload. Never the payload itself — see the module docstring."""

    seal: NonEmptyStr
    """The envelope's own seal, so a reloaded ledger can still refuse a resealed forgery."""

    status: MessageStatus
    recorded_at: Timestamp

    @property
    def terminal(self) -> bool:
        return self.status in {MessageStatus.CONSUMED, MessageStatus.COMPLETED}


class _DigestPayload(DomainModel):
    """Exactly the fields the digest covers.

    A declared model rather than an ad-hoc dict, so a field added to
    :class:`A2AStateRecord` without being added here fails a test rather than silently
    escaping the chain.
    """

    conversation_id: str
    created_at: Timestamp
    evidence_refs: tuple[str, ...]
    expires_at: Timestamp
    incident_id: str
    kind: A2ARecordKind
    message_id: str
    message_sequence: int
    message_type: MessageType
    payload_digest: str
    previous_digest: str
    recipient_agent_id: str
    recorded_at: Timestamp
    seal: str
    sender_agent_id: str
    sequence: int
    status: MessageStatus
    target_resource: str | None
    task_id: str
    task_type: TaskType


def record_digest(record: A2AStateRecord) -> str:
    """The digest a record should carry, as 64 lowercase hex characters.

    Canonicalisation is the project's existing :func:`~aegis.core.domain.to_json` — sorted
    keys, compact separators, UTC ISO-8601 — so a record round-trips through a file without
    its integrity check changing. A structured document is hashed rather than concatenated
    strings, so no field value can be crafted to imitate a field boundary.
    """
    document = to_json(
        _DigestPayload(
            conversation_id=record.conversation_id,
            created_at=record.created_at,
            evidence_refs=record.evidence_refs,
            expires_at=record.expires_at,
            incident_id=record.incident_id,
            kind=record.kind,
            message_id=record.message_id,
            message_sequence=record.message_sequence,
            message_type=record.message_type,
            payload_digest=record.payload_digest,
            previous_digest=record.previous_digest,
            recipient_agent_id=record.recipient_agent_id,
            recorded_at=record.recorded_at,
            seal=record.seal,
            sender_agent_id=record.sender_agent_id,
            sequence=record.sequence,
            status=record.status,
            target_resource=record.target_resource,
            task_id=record.task_id,
            task_type=record.task_type,
        )
    )
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def payload_digest(payload: Mapping[str, JsonValue]) -> str:
    """SHA-256 over a canonical payload. What is persisted in place of the payload."""
    document = to_json(_PayloadDocument(payload=dict(payload)))
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


class _PayloadDocument(DomainModel):
    payload: Mapping[str, JsonValue]


class A2AIntegrityReport(DomainModel):
    """The outcome of verifying an A2A chain.

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
        return self.checked if self.valid else (self.first_invalid_index or 0)


def verify_a2a_chain(records: Sequence[A2AStateRecord]) -> A2AIntegrityReport:
    """Check position, link, digest, message identity and status legality for every record.

    Five independent checks. The first three are the ordinary chain properties; the last two
    are what stop a *plausible* history from lying:

    * **identity stability** — a message's bindings may never change between its records,
      so a status record cannot quietly re-point a message at a different sender, recipient,
      conversation, incident or seal;
    * **status legality** — ``CONSUMED`` never returns to ``ISSUED``, which is the exact
      shape of "make a spent message look fresh".
    """
    previous = A2A_GENESIS_DIGEST
    statuses: dict[str, MessageStatus] = {}
    identities: dict[str, tuple] = {}

    for index, record in enumerate(records):

        def fail(reason: str, position: int = index) -> A2AIntegrityReport:
            return A2AIntegrityReport(
                valid=False, checked=position, first_invalid_index=position, reason=reason
            )

        if record.sequence != index:
            return fail(f"record at position {index} claims sequence {record.sequence}")
        if record.previous_digest != previous:
            return fail(f"record {index} does not link to the record before it")
        if record.digest != record_digest(record):
            return fail(f"record {index} does not match its digest")

        identity = (
            record.conversation_id,
            record.incident_id,
            record.sender_agent_id,
            record.recipient_agent_id,
            record.task_id,
            record.task_type,
            record.message_type,
            record.message_sequence,
            record.seal,
            record.payload_digest,
            record.created_at,
            record.expires_at,
        )
        if record.kind is A2ARecordKind.MESSAGE_ISSUED:
            if record.message_id in identities:
                return fail(f"record {index} issues {record.message_id!r} a second time")
            if record.status is not MessageStatus.ISSUED:
                return fail(
                    f"record {index} issues {record.message_id!r} already "
                    f"{record.status}, which is not how a message begins"
                )
            identities[record.message_id] = identity
        else:
            known = identities.get(record.message_id)
            if known is None:
                return fail(
                    f"record {index} changes the status of {record.message_id!r}, "
                    f"which was never issued"
                )
            if known != identity:
                return fail(
                    f"record {index} changes a binding of {record.message_id!r} after issuance"
                )
            was = statuses[record.message_id]
            if not legal_status_transition(was, record.status):
                return fail(
                    f"record {index} moves {record.message_id!r} from {was} to "
                    f"{record.status}, which is not a legal edge"
                )

        statuses[record.message_id] = record.status
        previous = record.digest

    return A2AIntegrityReport(valid=True, checked=len(records))
