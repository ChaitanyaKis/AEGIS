"""Benchmark control group for durable A2A state.

Everything here exists to *attack* the durability guarantee, so the benchmark can measure
whether restart-safe replay prevention holds rather than assert that it does.

What a "restart" means here
---------------------------

A real one. :func:`prior_session` constructs a genuine broker over a temp file, drives real
messages through it, and then throws it away. The scenario's own broker is built afterwards
over the same file, with new objects and empty memory. Nothing is handed across in Python —
if a guarantee survives, it survived because something was written down.

That is the only honest way to test this inside an in-process benchmark. Faking a restart
by copying state would measure the copy.

None of these can cause an execution. That is the point, and the scenarios that use them
assert it against the world, the executor's records and the persisted log rather than
against anything the ledger reported about itself.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

from aegis.a2a import (
    A2ABroker,
    A2AEnvelope,
    A2APersistenceFailure,
    A2ARecordKind,
    A2AStateCorrupt,
    A2AStateRecord,
    AgentDirectory,
    InMemoryA2ATransport,
    JsonlA2APersistence,
    MessageLedger,
    MessageStatus,
    MessageType,
    record_digest,
    verify_a2a_chain,
)
from aegis.agents.decisions import TaskType
from aegis.evaluation.scenario import A2APersistenceMode

__all__ = [
    "FailingA2APersistence",
    "a2a_consumption_is_durable",
    "build_persistent_broker",
    "persistence_observations",
]


class FailingA2APersistence:
    """A backend that refuses to write. **BENCHMARK CONTROL GROUP.**

    Models a full disk or a read-only mount. It has no power of its own: it cannot admit a
    message, cannot forge a record and holds no control-plane engine. All it does is fail,
    and the property under test is that failing produces no delivery.
    """

    durable = True

    def __init__(self, *, fail_after: int = 0) -> None:
        self._records: list[A2AStateRecord] = []
        self._fail_after = fail_after

    def load(self):
        return tuple(self._records)

    def append(self, record: A2AStateRecord) -> None:
        if len(self._records) >= self._fail_after:
            raise A2APersistenceFailure("the benchmark control refuses every write")
        self._records.append(record)


def _directory(specialists) -> AgentDirectory:
    from aegis.orchestration import DELEGATION_MATRIX

    return AgentDirectory(
        {"commander", *(specialists.ids() if specialists else ())}, DELEGATION_MATRIX
    )


def prior_session(
    path: Path,
    directory: AgentDirectory,
    clock: Callable[[], datetime],
    *,
    incident_id: str,
    conversation_id: str,
    messages: int = 1,
    consume: bool = True,
    resource: str = "service:payment-api",
) -> tuple[A2AEnvelope, ...]:
    """Drive a real broker over ``path`` and then discard it.

    This *is* the previous process. The broker built here is a genuine
    :class:`~aegis.a2a.broker.A2ABroker` with a genuine durable ledger; it issues real
    messages, optionally consumes them, and then goes out of scope. Everything the scenario
    later observes has to come back off the disk.
    """
    broker = A2ABroker(
        directory,
        transport=InMemoryA2ATransport(),
        ledger=MessageLedger(clock=clock, persistence=JsonlA2APersistence(path)),
        clock=clock,
    )
    issued: list[A2AEnvelope] = []
    for index in range(messages):
        envelope = broker.issue(
            accountable_sender="commander",
            recipient_agent_id="diagnostic",
            incident_id=incident_id,
            conversation_id=conversation_id,
            task_id=f"task-prior-{index}",
            task_type=TaskType.DIAGNOSE_SERVICE,
            message_type=MessageType.TASK_REQUEST,
            target_resource=resource,
            payload={"note": "a message from the previous process"},
        )
        if not isinstance(envelope, A2AEnvelope):
            break
        issued.append(envelope)
        broker.send(envelope)
        if consume:
            broker.admit(
                envelope,
                accountable_sender="commander",
                expected_incident_id=incident_id,
                expected_conversation_id=conversation_id,
                expected_task_id=envelope.task_id,
            )
    return tuple(issued)


def build_persistent_broker(
    scenario,
    specialists,
    clock: Callable[[], datetime],
    *,
    incident_id: str,
) -> A2ABroker:
    """The broker a persistence scenario asks for, after whatever happened before it."""
    mode = scenario.a2a_persistence
    directory = _directory(specialists)
    conversation = f"conv-{incident_id}"

    if mode is A2APersistenceMode.WRITE_FAILURE:
        return A2ABroker(
            directory,
            transport=InMemoryA2ATransport(),
            ledger=MessageLedger(clock=clock, persistence=FailingA2APersistence()),
            clock=clock,
        )

    path = Path(tempfile.mkdtemp(prefix="aegis-a2a-")) / "a2a.jsonl"

    if mode in {
        A2APersistenceMode.RESTARTED,
        A2APersistenceMode.SEQUENCE_CONTINUITY,
        A2APersistenceMode.MULTI_CONVERSATION,
        A2APersistenceMode.RESTART_BEFORE_CONSUMPTION,
    }:
        prior_session(
            path,
            directory,
            clock,
            incident_id=incident_id,
            conversation_id=conversation,
            messages=2 if mode is A2APersistenceMode.SEQUENCE_CONTINUITY else 1,
            consume=mode is not A2APersistenceMode.RESTART_BEFORE_CONSUMPTION,
        )
        if mode is A2APersistenceMode.MULTI_CONVERSATION:
            prior_session(
                path,
                directory,
                clock,
                incident_id=incident_id,
                conversation_id="conv-unrelated",
                messages=1,
            )
    elif mode is A2APersistenceMode.CORRUPT_CHAIN:
        _write_corrupt_chain(path, incident_id, conversation, clock)
    elif mode is A2APersistenceMode.TORN_TAIL:
        prior_session(path, directory, clock, incident_id=incident_id, conversation_id=conversation)
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"sequence": 99, "kind": "STATUS')
    elif mode is A2APersistenceMode.CONCURRENT_CORRUPTION:
        # Two writers that each believe they are appending record 0.
        prior_session(path, directory, clock, incident_id=incident_id, conversation_id=conversation)
        second = Path(tempfile.mkdtemp(prefix="aegis-a2a-b-")) / "other.jsonl"
        prior_session(
            second, directory, clock, incident_id=incident_id, conversation_id="conv-other"
        )
        with path.open("a", encoding="utf-8") as handle:
            handle.write(second.read_text(encoding="utf-8"))

    try:
        ledger = MessageLedger(clock=clock, persistence=JsonlA2APersistence(path))
    except A2AStateCorrupt:
        # A real deployment would refuse to start. A benchmark still has to grade a run, so
        # the faithful projection is a process that started and can deliver nothing: every
        # write fails, so every delegation becomes a recorded refusal. What is *not* modelled
        # is a process that starts and quietly ignores the corrupt history — which is the
        # only outcome that would be a security failure.
        ledger = MessageLedger(clock=clock, persistence=FailingA2APersistence())
    return A2ABroker(
        directory,
        transport=InMemoryA2ATransport(),
        ledger=ledger,
        clock=clock,
    )


def _write_corrupt_chain(
    path: Path, incident_id: str, conversation: str, clock: Callable[[], datetime]
) -> None:
    """A record whose digest does not match its contents.

    Written through the real backend so the file is well-formed JSONL — the damage is in
    the *chain*, not in the syntax, which is the harder case to detect and the one a
    tamperer would actually produce.
    """
    now = clock()
    unsealed = A2AStateRecord(
        sequence=0,
        previous_digest="0" * 64,
        digest="placeholder",
        kind=A2ARecordKind.MESSAGE_ISSUED,
        message_id="msg-corrupt0000000000000000",
        conversation_id=conversation,
        incident_id=incident_id,
        sender_agent_id="commander",
        recipient_agent_id="diagnostic",
        task_id="task-corrupt",
        task_type=TaskType.DIAGNOSE_SERVICE,
        message_type=MessageType.TASK_REQUEST,
        target_resource="service:payment-api",
        message_sequence=1,
        created_at=now,
        expires_at=now + timedelta(seconds=60),
        payload_digest="a" * 64,
        seal="b" * 64,
        status=MessageStatus.ISSUED,
        recorded_at=now,
    )
    sealed = unsealed.model_copy(update={"digest": record_digest(unsealed)})
    tampered = sealed.model_copy(update={"status": MessageStatus.CONSUMED})
    JsonlA2APersistence(path).append(tampered)


# --- independent observation ----------------------------------------------------------


def persistence_observations(orchestrator) -> dict:
    """What durability actually did, from the log rather than from the ledger's opinion.

    ``a2a_chain_valid`` is recomputed by :func:`~aegis.a2a.records.verify_a2a_chain` over
    the records the backend hands back — not read from any status the ledger keeps. A ledger
    that lied about its own integrity would still be caught, which is the whole reason the
    check is done here rather than asked for.
    """
    ledger = orchestrator.a2a.ledger
    try:
        records = tuple(ledger._persistence.load())
    except Exception:
        records = ()
    report = verify_a2a_chain(records)
    return {
        "a2a_durable": bool(getattr(ledger, "durable", False)),
        "a2a_persisted_records": len(records),
        "a2a_chain_valid": report.valid,
        "a2a_consumed_records": sum(
            1 for record in records if record.status is MessageStatus.CONSUMED
        ),
    }


def a2a_consumption_is_durable(orchestrator) -> bool:
    """Whether every consumption this run performed is on durable storage.

    Compares the ledger's in-memory consumed set against what the *backend* holds. A
    consumption that exists only in memory is exactly the Prompt 15 weakness, and counting
    them separately is how the benchmark notices it without asking whether it happened.
    """
    ledger = orchestrator.a2a.ledger
    try:
        records = tuple(ledger._persistence.load())
    except Exception:
        return False
    persisted = {
        record.message_id
        for record in records
        if record.status in {MessageStatus.CONSUMED, MessageStatus.COMPLETED}
    }
    live = {
        message_id
        for conversation in ledger.conversation_ids()
        for message in ledger.messages_for(conversation)
        if (message_id := message.message_id)
        and message.status in {MessageStatus.CONSUMED, MessageStatus.COMPLETED}
    }
    return live <= persisted
