"""What has already been said, so that it cannot be said again.

Replay protection and ordering (Parts 5 and 6). The ledger remembers three things and
answers three questions:

* **which message ids exist** — so a captured message cannot be presented twice;
* **which have been consumed** — so a message that already did its work cannot do it again;
* **where each conversation has got to** — so messages arrive in order or not at all.

It is also the *issuer's record*, which is where authenticity comes from. A seal proves a
message was not modified; it proves nothing about origin, because the seal formula is
public. "This ledger issued it" is the fact an attacker cannot manufacture, exactly as
:class:`~aegis.lifecycle.gate.GateRegister` works for lifecycle gates.

No escape hatches
-----------------

There is no ``reset_replay_state``, no ``clear_consumed_messages`` and no public method
that forgets anything (Part 5). A replay window that can be cleared on request is a replay
window an attacker asks to have cleared. Entries are dropped only by
:meth:`prune_expired`, which needs a clock and can only remove conversations whose whole
lifetime has already elapsed — it can never un-consume a message.

Process-restart limitation, stated plainly
------------------------------------------

This state lives **in memory and dies with the process**. A message captured before a
restart would be replayable after one, because the ledger that would have refused it no
longer remembers issuing it. That is acceptable for an in-process transport where a
restart also destroys every conversation partner, and it is *not* acceptable for a network
transport. :class:`LedgerState` names the boundary a durable implementation would have to
satisfy, and nothing in this package pretends the durable one exists.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from aegis.a2a.contracts import (
    MAX_CONVERSATION_SECONDS,
    MAX_MESSAGES_PER_TASK,
    MessageStatus,
    MessageType,
    TaskType,
)
from aegis.a2a.errors import A2APersistenceFailure, A2AStateCorrupt
from aegis.a2a.records import (
    A2A_GENESIS_DIGEST,
    A2AIntegrityReport,
    A2ARecordKind,
    A2AStateRecord,
    record_digest,
    verify_a2a_chain,
)
from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp, utc_now

__all__ = ["ConversationRecord", "LedgerState", "MessageLedger", "MessageRecord"]


class MessageRecord(DomainModel):
    """One message the ledger issued, and what became of it.

    Carries everything a durable record needs, so the in-memory view and the persisted
    view describe the same message rather than two overlapping subsets of one. The payload
    appears only as a digest: untrusted content already lives where it belongs, and a
    ledger is not the place to keep a second copy of it.
    """

    message_id: Identifier
    conversation_id: Identifier
    incident_id: Identifier
    sender_agent_id: Identifier
    recipient_agent_id: Identifier
    task_id: Identifier
    task_type: TaskType
    message_type: MessageType
    target_resource: NonEmptyStr | None = None
    evidence_refs: tuple[Identifier, ...] = ()
    sequence: int
    created_at: Timestamp
    expires_at: Timestamp
    payload_digest: NonEmptyStr
    seal: NonEmptyStr
    status: MessageStatus
    issued_at: Timestamp


class ConversationRecord(DomainModel):
    """One conversation's binding and position."""

    conversation_id: NonEmptyStr
    incident_id: NonEmptyStr
    opened_at: Timestamp
    next_sequence: int
    message_count: int

    def expired(self, now: datetime, lifetime_seconds: float) -> bool:
        return now >= self.opened_at + timedelta(seconds=lifetime_seconds)


@runtime_checkable
class LedgerState(Protocol):
    """The state boundary a durable ledger would implement.

    Declared but deliberately **not implemented durably** in this milestone. Naming the
    boundary is what makes the in-memory limitation visible instead of implicit; a network
    transport would supply an implementation with real persistence, and a comment claiming
    the current one is durable would be a fabricated integration.
    """

    def issued(self, record: MessageRecord) -> None: ...

    def lookup(self, message_id: str) -> MessageRecord | None: ...

    def mark(self, message_id: str, status: MessageStatus) -> None: ...


class MessageLedger:
    """Message identity, ordering and consumption for one process.

    Args:
        clock: Injected, so expiry and pruning are reproducible.
        conversation_lifetime_seconds: How long a conversation stays open.
        max_messages_per_task: Hard ceiling on messages one task may generate.
        persistence: Where durable state lives. Defaults to
            :class:`~aegis.a2a.persistence.InMemoryA2APersistence`, which is **not
            durable** — a caller that needs a consumed message to stay consumed across a
            restart supplies :class:`~aegis.a2a.persistence.JsonlA2APersistence`.

    Construction **loads and verifies** whatever the backend holds. A ledger that cannot
    trust its own history refuses to exist rather than starting as though nothing had been
    consumed, which is the fail-closed reading of "I do not know what happened".

    Raises:
        A2AStateCorrupt: if the persisted chain does not verify.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = utc_now,
        conversation_lifetime_seconds: float = MAX_CONVERSATION_SECONDS,
        max_messages_per_task: int = MAX_MESSAGES_PER_TASK,
        persistence=None,
    ) -> None:
        if conversation_lifetime_seconds <= 0:
            raise ValueError("conversation lifetime must be positive")
        if max_messages_per_task < 1:
            raise ValueError("a task must be allowed at least one message")
        from aegis.a2a.persistence import InMemoryA2APersistence

        self._clock = clock
        self._lifetime = conversation_lifetime_seconds
        self._max_per_task = max_messages_per_task
        self._messages: dict[str, MessageRecord] = {}
        self._conversations: dict[str, ConversationRecord] = {}
        self._task_counts: dict[str, int] = {}
        self._persistence = persistence if persistence is not None else InMemoryA2APersistence()
        self._log: list[A2AStateRecord] = []
        self._head = A2A_GENESIS_DIGEST
        self._restore()

    # --- durability -----------------------------------------------------------------

    @property
    def durable(self) -> bool:
        """Whether this ledger's state survives a restart. Read from the backend, honestly."""
        return bool(getattr(self._persistence, "durable", False))

    @property
    def persisted_records(self) -> int:
        return len(self._log)

    def verify(self) -> A2AIntegrityReport:
        """Verify the durable chain as it currently stands. Reports; never repairs."""
        return verify_a2a_chain(tuple(self._log))

    def _restore(self) -> None:
        """Rebuild in-memory state from the durable log.

        Rebuilt by **replaying** the records in order rather than by trusting a summary.
        A summary is a place for a lie to hide; a replay can only produce a state the
        recorded history actually reaches.
        """
        records = self._persistence.load()
        report = verify_a2a_chain(records)
        if not report.valid:
            raise A2AStateCorrupt(
                f"persisted A2A chain failed at record {report.first_invalid_index}: "
                f"{report.reason} (trusted prefix: {report.trusted_prefix})"
            )
        for record in records:
            self._apply(record)
            self._log.append(record)
            self._head = record.digest

    def _apply(self, record: A2AStateRecord) -> None:
        """Fold one durable record into the in-memory view."""
        if record.kind is A2ARecordKind.MESSAGE_ISSUED:
            message = MessageRecord(
                message_id=record.message_id,
                conversation_id=record.conversation_id,
                incident_id=record.incident_id,
                sender_agent_id=record.sender_agent_id,
                recipient_agent_id=record.recipient_agent_id,
                task_id=record.task_id,
                task_type=record.task_type,
                message_type=record.message_type,
                target_resource=record.target_resource,
                evidence_refs=record.evidence_refs,
                sequence=record.message_sequence,
                created_at=record.created_at,
                expires_at=record.expires_at,
                payload_digest=record.payload_digest,
                seal=record.seal,
                status=record.status,
                issued_at=record.recorded_at,
            )
            self._messages[record.message_id] = message
            self._advance_conversation(message)
            self._task_counts[record.task_id] = self._task_counts.get(record.task_id, 0) + 1
            return
        existing = self._messages.get(record.message_id)
        if existing is not None:
            self._messages[record.message_id] = existing.model_copy(
                update={"status": record.status}
            )

    def _persist(self, message: MessageRecord, kind: A2ARecordKind) -> None:
        """Append one durable record, or refuse.

        The append happens **before** the in-memory view moves on, so a persistence failure
        leaves the ledger exactly as it was rather than one step ahead of its own record.
        A failure raises: it must never be the reason a message is treated as admitted.
        """
        unsealed = A2AStateRecord(
            sequence=len(self._log),
            previous_digest=self._head,
            digest="unsealed",
            kind=kind,
            message_id=message.message_id,
            conversation_id=message.conversation_id,
            incident_id=message.incident_id,
            sender_agent_id=message.sender_agent_id,
            recipient_agent_id=message.recipient_agent_id,
            task_id=message.task_id,
            task_type=message.task_type,
            message_type=message.message_type,
            target_resource=message.target_resource,
            evidence_refs=message.evidence_refs,
            message_sequence=message.sequence,
            created_at=message.created_at,
            expires_at=message.expires_at,
            payload_digest=message.payload_digest,
            seal=message.seal,
            status=message.status,
            recorded_at=message.issued_at,
        )
        record = unsealed.model_copy(update={"digest": record_digest(unsealed)})
        try:
            self._persistence.append(record)
        except A2APersistenceFailure:
            raise
        except Exception as error:
            raise A2APersistenceFailure(f"{type(error).__name__}: {error}") from error
        self._log.append(record)
        self._head = record.digest

    # --- questions ------------------------------------------------------------------

    def known(self, message_id: str) -> bool:
        return message_id in self._messages

    def record_of(self, message_id: str) -> MessageRecord | None:
        return self._messages.get(message_id)

    def status_of(self, message_id: str) -> MessageStatus | None:
        record = self._messages.get(message_id)
        return record.status if record is not None else None

    def consumed(self, message_id: str) -> bool:
        return self.status_of(message_id) in {MessageStatus.CONSUMED, MessageStatus.COMPLETED}

    def conversation(self, conversation_id: str) -> ConversationRecord | None:
        return self._conversations.get(conversation_id)

    def expected_sequence(self, conversation_id: str) -> int:
        """The only sequence number that will be accepted next. One for a new conversation."""
        record = self._conversations.get(conversation_id)
        return record.next_sequence if record is not None else 1

    def task_message_count(self, task_id: str) -> int:
        return self._task_counts.get(task_id, 0)

    def conversation_ids(self) -> tuple[str, ...]:
        """Every conversation the ledger holds, sorted. For reconstruction and audit.

        Read-only, like every other question here. It exists so a reader — the benchmark
        included — can enumerate what happened without reaching into private state,
        which is the kind of shortcut that quietly becomes a dependency.
        """
        return tuple(sorted(self._conversations))

    def messages_for(self, conversation_id: str) -> tuple[MessageRecord, ...]:
        """Every message in one conversation, in sequence order. For reconstruction."""
        return tuple(
            sorted(
                (r for r in self._messages.values() if r.conversation_id == conversation_id),
                key=lambda record: record.sequence,
            )
        )

    # --- state changes ---------------------------------------------------------------

    def issue(self, record: MessageRecord) -> MessageRecord:
        """Register a message this ledger is issuing.

        Raises:
            ValueError: if the id already exists. A duplicate id is a programming error at
                issuance, and quietly overwriting one would erase the replay evidence for
                the message it replaced.
        """
        if record.message_id in self._messages:
            raise ValueError(f"message {record.message_id!r} has already been issued")
        self._persist(record, A2ARecordKind.MESSAGE_ISSUED)
        self._messages[record.message_id] = record
        self._advance_conversation(record)
        self._task_counts[record.task_id] = self._task_counts.get(record.task_id, 0) + 1
        return record

    def _advance_conversation(self, record: MessageRecord) -> None:
        """Move a conversation's position on by one message.

        The only place ``next_sequence`` moves, so restoring from the log and issuing live
        produce the same continuity by the same code rather than by two implementations
        that have to be kept in step.
        """
        conversation = self._conversations.get(record.conversation_id)
        if conversation is None:
            conversation = ConversationRecord(
                conversation_id=record.conversation_id,
                incident_id=record.incident_id,
                opened_at=record.issued_at,
                next_sequence=record.sequence + 1,
                message_count=1,
            )
        else:
            conversation = conversation.model_copy(
                update={
                    "next_sequence": max(conversation.next_sequence, record.sequence + 1),
                    "message_count": conversation.message_count + 1,
                }
            )
        self._conversations[record.conversation_id] = conversation

    def mark(self, message_id: str, status: MessageStatus) -> MessageRecord | None:
        """Move a message to a new status. Consumption is one-way.

        A consumed or completed message stays that way: nothing here can walk it back to
        ISSUED, which is what makes "already consumed" a durable answer rather than a
        temporary one.
        """
        record = self._messages.get(message_id)
        if record is None:
            return None
        if record.status in {MessageStatus.CONSUMED, MessageStatus.COMPLETED} and status not in {
            MessageStatus.CONSUMED,
            MessageStatus.COMPLETED,
        }:
            return record
        updated = record.model_copy(update={"status": status})
        self._persist(updated, A2ARecordKind.STATUS_CHANGED)
        self._messages[message_id] = updated
        return updated

    def conversation_expired(self, conversation_id: str) -> bool:
        record = self._conversations.get(conversation_id)
        if record is None:
            return False
        return record.expired(self._clock(), self._lifetime)

    def task_budget_exhausted(self, task_id: str) -> bool:
        return self._task_counts.get(task_id, 0) >= self._max_per_task

    def prune_expired(self) -> int:
        """Drop conversations whose whole lifetime has elapsed. Returns how many.

        The only removal path, and deliberately a narrow one: it needs the clock to agree
        that the conversation is over, it cannot be aimed at a particular message, and it
        can never un-consume anything — a consumed message inside a pruned conversation is
        gone along with the conversation, not resurrected.
        """
        now = self._clock()
        stale = {
            conversation_id
            for conversation_id, record in self._conversations.items()
            if record.expired(now, self._lifetime)
        }
        if not stale:
            return 0
        for conversation_id in stale:
            del self._conversations[conversation_id]
        self._messages = {
            message_id: record
            for message_id, record in self._messages.items()
            if record.conversation_id not in stale
        }
        return len(stale)

    def __len__(self) -> int:
        return len(self._messages)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({len(self._messages)} messages, "
            f"{len(self._conversations)} conversations)"
        )
