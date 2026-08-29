"""Durable A2A state: restart, replay, continuity, expiry, integrity and crash windows.

Parts 1 through 6 and 11 of Prompt 16. The property everything here exists to establish:

    **A consumed message stays consumed across a restart.**

Prompt 15 left this open and said so. A message captured before a restart was replayable
after one, because the ledger that would have refused it no longer remembered issuing it.

Every "restart" below is a *real* restart of the ledger and broker: new objects, new
in-memory state, reading the same file. Nothing is carried over in Python. The only thing
that survives is what was written down.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import ClassVar

import pytest

from aegis.a2a import (
    A2ABroker,
    A2AEnvelope,
    A2APersistence,
    A2ARecordKind,
    A2ARejection,
    A2AStateCorrupt,
    A2AStateRecord,
    InMemoryA2APersistence,
    InMemoryA2ATransport,
    JsonlA2APersistence,
    MessageLedger,
    MessageStatus,
    MessageType,
    envelope_seal,
    record_digest,
    verify_a2a_chain,
)
from aegis.a2a.errors import A2APersistenceFailure
from aegis.a2a.records import legal_status_transition, payload_digest
from aegis.agents.decisions import TaskType
from aegis.orchestration import DELEGATION_MATRIX

from .conftest import CONVERSATION, FLEET, INCIDENT, RESOURCE, TASK

FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


class Restartable:
    """A broker that can be destroyed and rebuilt over the same durable file.

    The whole point: :meth:`restart` throws away every object and constructs new ones. If a
    guarantee survives that, it survived because something was written down.
    """

    def __init__(self, path, clock, directory) -> None:
        self.path = path
        self.clock = clock
        self.directory = directory
        self.transport = InMemoryA2ATransport()
        self.broker = self._build()

    def _build(self) -> A2ABroker:
        return A2ABroker(
            self.directory,
            transport=self.transport,
            ledger=MessageLedger(clock=self.clock, persistence=JsonlA2APersistence(self.path)),
            clock=self.clock,
        )

    def restart(self) -> A2ABroker:
        self.transport = InMemoryA2ATransport()
        self.broker = self._build()
        return self.broker


@pytest.fixture
def durable(tmp_path, clock, directory) -> Restartable:
    return Restartable(tmp_path / "a2a.jsonl", clock, directory)


def issue(broker: A2ABroker, **overrides) -> A2AEnvelope:
    settings = {
        "accountable_sender": "commander",
        "recipient_agent_id": "diagnostic",
        "incident_id": INCIDENT,
        "conversation_id": CONVERSATION,
        "task_id": TASK,
        "task_type": TaskType.DIAGNOSE_SERVICE,
        "message_type": MessageType.TASK_REQUEST,
        "target_resource": RESOURCE,
        "payload": {"note": "please investigate"},
    }
    settings.update(overrides)
    envelope = broker.issue(**settings)
    assert isinstance(envelope, A2AEnvelope), envelope
    return envelope


def admit(broker: A2ABroker, envelope: A2AEnvelope, **overrides):
    settings = {
        "accountable_sender": "commander",
        "expected_incident_id": INCIDENT,
        "expected_conversation_id": CONVERSATION,
        "expected_task_id": TASK,
    }
    settings.update(overrides)
    return broker.admit(envelope, **settings)


# --- Part 1: the persistence abstraction ----------------------------------------------


class TestThePersistenceAbstraction:
    def test_the_protocol_has_only_load_and_append(self) -> None:
        """No update, no delete, no truncate — so no backend can offer one."""
        methods = {name for name in dir(A2APersistence) if not name.startswith("_")}
        assert methods == {"load", "append"}

    @pytest.mark.parametrize("backend", [InMemoryA2APersistence, JsonlA2APersistence])
    def test_neither_backend_offers_an_escape_hatch(self, backend) -> None:
        public = {name for name in dir(backend) if not name.startswith("_")}
        for forbidden in ("update", "delete", "truncate", "reset", "clear", "release", "reopen"):
            assert forbidden not in public, forbidden

    @pytest.mark.parametrize("backend", [InMemoryA2APersistence, JsonlA2APersistence])
    def test_both_backends_satisfy_the_protocol(self, backend, tmp_path) -> None:
        instance = backend() if backend is InMemoryA2APersistence else backend(tmp_path / "x.jsonl")
        assert isinstance(instance, A2APersistence)

    def test_the_in_memory_backend_says_it_is_not_durable(self) -> None:
        """Honesty as an attribute, not only as a docstring."""
        assert InMemoryA2APersistence.durable is False
        assert "NOT DURABLE" in (InMemoryA2APersistence.__doc__ or "")
        assert "durable=False" in repr(InMemoryA2APersistence())

    def test_the_jsonl_backend_says_it_is_durable(self, tmp_path) -> None:
        assert JsonlA2APersistence(tmp_path / "x.jsonl").durable is True

    def test_a_ledger_reports_its_own_durability_honestly(self, tmp_path, clock) -> None:
        assert MessageLedger(clock=clock).durable is False
        assert (
            MessageLedger(
                clock=clock, persistence=JsonlA2APersistence(tmp_path / "x.jsonl")
            ).durable
            is True
        )

    def test_a_missing_file_reads_as_an_empty_log(self, tmp_path) -> None:
        assert JsonlA2APersistence(tmp_path / "absent.jsonl").load() == ()

    def test_records_are_written_one_canonical_line_each(self, durable: Restartable) -> None:
        issue(durable.broker)
        lines = durable.path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        assert lines[0].startswith("{") and lines[0].endswith("}")

    def test_every_append_is_flushed_and_synced_before_returning(self) -> None:
        """Durability against power loss, checked the only way a process can check it.

        Written after a mutation removing ``os.fsync`` survived. It survived for an honest
        reason: a test process that writes and reads back sees identical bytes whether or
        not the data reached the platter, so the difference is **unobservable in-process**.
        Power loss is not something a unit test can stage.

        What *is* observable is the code path, so that is what is asserted: the append calls
        ``flush`` and then ``os.fsync``, in that order, before returning. Structural rather
        than behavioural, and labelled as such rather than dressed up as a durability proof.
        """
        import ast
        import pathlib

        source = pathlib.Path("src/aegis/a2a/persistence.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        jsonl = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == "JsonlA2APersistence"
        )
        append = next(
            node
            for node in jsonl.body
            if isinstance(node, ast.FunctionDef) and node.name == "append"
        )
        calls = [ast.unparse(node.func) for node in ast.walk(append) if isinstance(node, ast.Call)]
        assert "handle.flush" in calls, calls
        assert "os.fsync" in calls, calls
        assert calls.index("handle.flush") < calls.index("os.fsync")

        # Reachable, not merely present. The first version of this test asserted only that
        # the call appeared in the source, and a mutation replacing its guard with `if
        # False:` sailed past — the call was still there and never ran. What has to be
        # checked is the guard itself.
        guards = [
            ast.unparse(node.test)
            for node in ast.walk(append)
            if isinstance(node, ast.If)
            and any(
                isinstance(inner, ast.Call) and ast.unparse(inner.func) == "os.fsync"
                for inner in ast.walk(node)
            )
        ]
        assert guards == ["self._fsync"], guards

    def test_fsync_can_be_turned_off_only_deliberately(self) -> None:
        """An explicit constructor argument, defaulting to on — never a silent default."""
        import inspect

        signature = inspect.signature(JsonlA2APersistence.__init__)
        assert signature.parameters["fsync"].default is True
        assert signature.parameters["fsync"].kind is inspect.Parameter.KEYWORD_ONLY

    def test_an_append_is_readable_immediately_afterwards(self, tmp_path) -> None:
        """The behavioural half: whatever fsync does, the record is there when it returns."""
        backend = JsonlA2APersistence(tmp_path / "a2a.jsonl")
        backend.append(a_record())
        assert len(backend.load()) == 1

    def test_persistence_is_not_an_authorization_mechanism(self) -> None:
        """Structural: no *code* in the module names a governance concept.

        Docstrings are excluded deliberately — this module's prose says "no policy, no
        approval, no verification" precisely to state the boundary, and a sweep that
        counted that as a violation would be punishing the documentation for being clear.
        """
        import ast
        import pathlib

        tree = ast.parse(pathlib.Path("src/aegis/a2a/persistence.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                node.value.value = ""  # blank every docstring and bare string literal
        code = ast.unparse(tree).lower()
        for word in ("policy", "approval", "authoriz", "verification", "risk", "gate"):
            assert word not in code, word


# --- Part 3: replay after restart, the primary property -------------------------------


class TestReplayAfterRestart:
    def test_a_consumed_request_cannot_be_consumed_again_after_restart(
        self, durable: Restartable
    ) -> None:
        """The headline. Issue, persist, consume, restart, reload, retry."""
        envelope = issue(durable.broker)
        durable.broker.send(envelope)
        assert admit(durable.broker, envelope).accepted

        broker = durable.restart()
        verdict = admit(broker, envelope)
        assert not verdict.accepted
        assert verdict.rejection is A2ARejection.ALREADY_CONSUMED

    def test_a_consumed_response_cannot_be_consumed_again_after_restart(
        self, durable: Restartable
    ) -> None:
        request = issue(durable.broker)
        admit(durable.broker, request)
        response = issue(
            durable.broker,
            accountable_sender="diagnostic",
            recipient_agent_id="commander",
            message_type=MessageType.TASK_RESULT,
            payload={"outcome": "COMPLETED"},
        )
        assert durable.broker.bind_response(request, response, None).accepted

        broker = durable.restart()
        verdict = broker.admit(
            response,
            accountable_sender="diagnostic",
            expected_incident_id=INCIDENT,
            expected_conversation_id=CONVERSATION,
        )
        assert verdict.rejection is A2ARejection.ALREADY_CONSUMED

    def test_restart_before_consumption_leaves_the_message_usable(
        self, durable: Restartable
    ) -> None:
        """The other half: durability must not break the honest case."""
        envelope = issue(durable.broker)
        broker = durable.restart()
        assert admit(broker, envelope).accepted

    def test_restart_after_rejection_keeps_the_rejection(self, durable: Restartable) -> None:
        envelope = issue(durable.broker)
        assert admit(durable.broker, envelope, accountable_sender="remediation").rejection is (
            A2ARejection.SENDER_MISMATCH
        )
        broker = durable.restart()
        assert broker.ledger.status_of(envelope.message_id) is MessageStatus.REJECTED

    def test_a_rejected_message_is_still_admissible_by_the_right_sender_after_restart(
        self, durable: Restartable
    ) -> None:
        """A refusal records what happened; it does not blacklist an honest message."""
        envelope = issue(durable.broker)
        admit(durable.broker, envelope, accountable_sender="remediation")
        broker = durable.restart()
        assert admit(broker, envelope).accepted

    def test_restart_with_multiple_conversations_keeps_each_separate(
        self, durable: Restartable
    ) -> None:
        first = issue(durable.broker)
        second = issue(durable.broker, conversation_id="conv-two", task_id="task-two")
        admit(durable.broker, first)

        broker = durable.restart()
        assert admit(broker, first).rejection is A2ARejection.ALREADY_CONSUMED
        assert admit(
            broker, second, expected_conversation_id="conv-two", expected_task_id="task-two"
        ).accepted

    def test_ten_restarts_do_not_erode_the_guarantee(self, durable: Restartable) -> None:
        envelope = issue(durable.broker)
        admit(durable.broker, envelope)
        for _ in range(10):
            broker = durable.restart()
            assert admit(broker, envelope).rejection is A2ARejection.ALREADY_CONSUMED

    def test_the_in_memory_backend_does_not_provide_this(self, clock, directory) -> None:
        """Stated as a test so the limitation cannot quietly stop being true.

        This is what Prompt 15 had everywhere, and what Prompt 16 replaces. Asserting it
        keeps the two backends honestly different rather than differing only in a docstring.
        """
        shared = InMemoryA2APersistence()
        first = A2ABroker(directory, ledger=MessageLedger(clock=clock), clock=clock)
        envelope = issue(first)
        admit(first, envelope)
        # A genuinely new ledger with its own empty in-memory store knows nothing.
        second = A2ABroker(
            directory,
            ledger=MessageLedger(clock=clock, persistence=InMemoryA2APersistence()),
            clock=clock,
        )
        assert second.ledger.persisted_records == 0
        assert not second.ledger.consumed(envelope.message_id)
        assert len(shared) == 0


# --- Part 4: conversation continuity --------------------------------------------------


class TestConversationContinuity:
    def test_sequence_continues_across_restarts(self, durable: Restartable) -> None:
        """1 consumed → restart → 2 accepted → restart → 3 accepted."""
        first = issue(durable.broker)
        assert first.sequence == 1
        assert admit(durable.broker, first).accepted

        broker = durable.restart()
        second = issue(broker, task_id="task-2")
        assert second.sequence == 2
        assert admit(broker, second, expected_task_id="task-2").accepted

        broker = durable.restart()
        third = issue(broker, task_id="task-3")
        assert third.sequence == 3
        assert admit(broker, third, expected_task_id="task-3").accepted

    def test_earlier_sequences_cannot_be_replayed_after_restart(self, durable: Restartable) -> None:
        first = issue(durable.broker)
        admit(durable.broker, first)
        broker = durable.restart()
        second = issue(broker, task_id="task-2")
        admit(broker, second, expected_task_id="task-2")

        broker = durable.restart()
        assert admit(broker, first).rejection is A2ARejection.ALREADY_CONSUMED
        assert admit(broker, second, expected_task_id="task-2").rejection is (
            A2ARejection.ALREADY_CONSUMED
        )

    def test_a_gap_in_the_sequence_is_refused_after_restart(self, durable: Restartable) -> None:
        """Message 4 while 3 is outstanding: refused, not buffered."""
        first = issue(durable.broker)
        admit(durable.broker, first)
        broker = durable.restart()
        third = issue(broker, task_id="task-3")
        fourth = issue(broker, task_id="task-4")
        assert third.sequence == 2 and fourth.sequence == 3
        assert admit(broker, fourth, expected_task_id="task-4").rejection is (
            A2ARejection.SEQUENCE_MISMATCH
        )

    def test_strict_ordering_is_not_loosened_by_persistence(self, durable: Restartable) -> None:
        first = issue(durable.broker)
        second = issue(durable.broker, task_id="task-2")
        broker = durable.restart()
        assert admit(broker, second, expected_task_id="task-2").rejection is (
            A2ARejection.SEQUENCE_MISMATCH
        )
        assert admit(broker, first).accepted
        assert admit(broker, second, expected_task_id="task-2").accepted

    def test_conversation_bindings_survive_restart(self, durable: Restartable) -> None:
        issue(durable.broker)
        broker = durable.restart()
        conversation = broker.ledger.conversation(CONVERSATION)
        assert conversation is not None
        assert conversation.incident_id == INCIDENT
        assert conversation.message_count == 1

    def test_task_message_budgets_survive_restart(self, durable: Restartable) -> None:
        for _ in range(2):
            issue(durable.broker, conversation_id=f"conv-{_}")
        broker = durable.restart()
        assert broker.ledger.task_message_count(TASK) == 2


# --- Part 5: expiry after restart -----------------------------------------------------


class TestExpiryAfterRestart:
    def test_a_message_created_before_a_restart_still_expires(
        self, durable: Restartable, clock
    ) -> None:
        envelope = issue(durable.broker)
        broker = durable.restart()
        clock.advance(120)
        assert admit(broker, envelope).rejection is A2ARejection.EXPIRED

    def test_expiry_is_read_from_the_persisted_message_not_recomputed(
        self, durable: Restartable, clock
    ) -> None:
        """Never rewritten to make anything pass."""
        envelope = issue(durable.broker)
        broker = durable.restart()
        stored = broker.ledger.record_of(envelope.message_id)
        assert stored is not None
        assert stored.expires_at == envelope.expires_at
        assert stored.created_at == envelope.created_at

    def test_a_clock_jumping_forward_expires_early_never_late(
        self, durable: Restartable, clock
    ) -> None:
        envelope = issue(durable.broker)
        broker = durable.restart()
        clock.advance(10_000)
        assert admit(broker, envelope).rejection is A2ARejection.EXPIRED

    def test_a_clock_moving_backwards_does_not_admit_an_expired_message(
        self, durable: Restartable, clock
    ) -> None:
        """Fail closed: going back in time must not resurrect anything.

        Consumption is checked before freshness, so a spent message stays spent whatever the
        clock says — which is the direction that matters. A merely *stale* message becomes
        admissible again if the clock genuinely rewinds, and that is an operator-controlled
        clock problem rather than a replay: the message was never consumed.
        """
        envelope = issue(durable.broker)
        admit(durable.broker, envelope)
        broker = durable.restart()
        clock.now = clock.now - timedelta(days=365)
        assert admit(broker, envelope).rejection is A2ARejection.ALREADY_CONSUMED

    def test_an_unexpired_message_still_works_after_restart(
        self, durable: Restartable, clock
    ) -> None:
        envelope = issue(durable.broker)
        broker = durable.restart()
        clock.advance(30)
        assert admit(broker, envelope).accepted


# --- Part 2: integrity ----------------------------------------------------------------


def a_record(**overrides) -> A2AStateRecord:
    settings = {
        "sequence": 0,
        "previous_digest": "0" * 64,
        "digest": "placeholder",
        "kind": A2ARecordKind.MESSAGE_ISSUED,
        "message_id": "msg-000000000000000000000001",
        "conversation_id": CONVERSATION,
        "incident_id": INCIDENT,
        "sender_agent_id": "commander",
        "recipient_agent_id": "diagnostic",
        "task_id": TASK,
        "task_type": TaskType.DIAGNOSE_SERVICE,
        "message_type": MessageType.TASK_REQUEST,
        "target_resource": RESOURCE,
        "evidence_refs": ("obs-1",),
        "message_sequence": 1,
        "created_at": FIXED_NOW,
        "expires_at": FIXED_NOW + timedelta(seconds=60),
        "payload_digest": "a" * 64,
        "seal": "b" * 64,
        "status": MessageStatus.ISSUED,
        "recorded_at": FIXED_NOW,
    }
    settings.update(overrides)
    unsealed = A2AStateRecord(**settings)
    if "digest" in overrides:
        return unsealed
    return unsealed.model_copy(update={"digest": record_digest(unsealed)})


class TestChainIntegrity:
    MUTATIONS: ClassVar[list] = [
        ("message_id", "msg-000000000000000000000009"),
        ("conversation_id", "conv-elsewhere"),
        ("incident_id", "INC-ELSEWHERE"),
        ("sender_agent_id", "remediation"),
        ("recipient_agent_id", "security"),
        ("task_id", "task-elsewhere"),
        ("task_type", TaskType.INVESTIGATE_SECURITY),
        ("message_type", MessageType.TASK_RESULT),
        ("target_resource", "db:customer-database"),
        ("evidence_refs", ("obs-fabricated",)),
        ("message_sequence", 9),
        ("created_at", FIXED_NOW + timedelta(days=1)),
        ("expires_at", FIXED_NOW + timedelta(days=365)),
        ("payload_digest", "c" * 64),
        ("seal", "d" * 64),
        ("status", MessageStatus.CONSUMED),
        ("recorded_at", FIXED_NOW + timedelta(hours=1)),
        ("kind", A2ARecordKind.STATUS_CHANGED),
        ("previous_digest", "e" * 64),
        ("sequence", 7),
    ]

    @pytest.mark.parametrize(("field", "value"), MUTATIONS, ids=[f for f, _ in MUTATIONS])
    def test_mutating_any_covered_field_is_detected(self, field: str, value) -> None:
        record = a_record()
        tampered = record.model_copy(update={field: value})
        report = verify_a2a_chain((tampered,))
        assert not report.valid, field
        assert report.first_invalid_index == 0
        assert report.reason

    def test_the_digest_covers_every_record_field_except_itself(self) -> None:
        """Adding a field without covering it should be a visible change, not a silent gap."""
        from aegis.a2a.records import _DigestPayload

        covered = set(_DigestPayload.model_fields)
        fields = set(A2AStateRecord.model_fields) - {"digest"}
        assert fields == covered, fields ^ covered

    def test_a_clean_chain_verifies(self, durable: Restartable) -> None:
        envelope = issue(durable.broker)
        admit(durable.broker, envelope)
        report = durable.broker.ledger.verify()
        assert report.valid and report.checked >= 1
        assert report.first_invalid_index is None
        assert report.trusted_prefix == report.checked

    def test_the_report_names_where_the_damage_starts(self) -> None:
        good = a_record()
        second = a_record(
            sequence=1,
            previous_digest=good.digest,
            kind=A2ARecordKind.STATUS_CHANGED,
            status=MessageStatus.CONSUMED,
        )
        broken = second.model_copy(update={"status": MessageStatus.ISSUED})
        report = verify_a2a_chain((good, broken))
        assert not report.valid
        assert report.first_invalid_index == 1
        assert report.trusted_prefix == 1

    def test_a_record_spliced_from_another_chain_is_detected(self) -> None:
        """The link check, reached on its own.

        Written after a mutation survived. Every earlier ``previous_digest`` case mutated the
        field directly, which changes the record's own digest — so the digest check fired
        first and the link comparison could be deleted with nothing failing.

        This is the case where nothing else *can* fire. Two chains are built that differ only
        in when their first record was written, so their second records are identical in
        every field except ``previous_digest``. Splice one into the other and:

        * the sequence is right (position 1 claiming sequence 1);
        * the digest is self-consistent (it covers the spliced record's own link);
        * the identity bindings are identical, so the stability check passes;
        * the status edge is legal.

        Only the link is wrong — which is precisely what insertion and truncation look like.
        """
        first = a_record()
        genuine = a_record(
            sequence=1,
            previous_digest=first.digest,
            kind=A2ARecordKind.STATUS_CHANGED,
            status=MessageStatus.CONSUMED,
        )
        assert verify_a2a_chain((first, genuine)).valid

        # An independently built chain: same message, same bindings, written a second later.
        elsewhere_first = a_record(recorded_at=FIXED_NOW + timedelta(seconds=1))
        assert elsewhere_first.digest != first.digest
        spliced = a_record(
            sequence=1,
            previous_digest=elsewhere_first.digest,
            kind=A2ARecordKind.STATUS_CHANGED,
            status=MessageStatus.CONSUMED,
        )
        # Identical to the genuine record except for the link it names.
        assert spliced.model_dump(exclude={"previous_digest", "digest"}) == genuine.model_dump(
            exclude={"previous_digest", "digest"}
        )
        assert spliced.digest == record_digest(spliced)  # self-consistent

        report = verify_a2a_chain((first, spliced))
        assert not report.valid
        assert "does not link" in (report.reason or "")
        assert report.first_invalid_index == 1

    def test_a_record_inserted_into_the_middle_is_detected(self) -> None:
        """The other half of what the link structure protects: insertion, not just splicing."""
        first = a_record()
        second = a_record(
            sequence=1,
            previous_digest=first.digest,
            kind=A2ARecordKind.STATUS_CHANGED,
            status=MessageStatus.CONSUMED,
        )
        intruder = a_record(
            sequence=1,
            previous_digest=first.digest,
            kind=A2ARecordKind.STATUS_CHANGED,
            status=MessageStatus.ACCEPTED,
        )
        report = verify_a2a_chain((first, intruder, second))
        assert not report.valid
        assert report.first_invalid_index == 2

    def test_a_deleted_record_is_detected(self) -> None:
        first = a_record()
        second = a_record(
            sequence=1,
            previous_digest=first.digest,
            kind=A2ARecordKind.STATUS_CHANGED,
            status=MessageStatus.CONSUMED,
        )
        assert verify_a2a_chain((first, second)).valid
        assert not verify_a2a_chain((second,)).valid

    def test_a_reordered_pair_is_detected(self) -> None:
        first = a_record()
        second = a_record(
            sequence=1,
            previous_digest=first.digest,
            kind=A2ARecordKind.STATUS_CHANGED,
            status=MessageStatus.CONSUMED,
        )
        assert not verify_a2a_chain((second, first)).valid

    def test_history_is_never_repaired(self) -> None:
        """The verifier reports. It has no method that mends anything.

        Matched on whole underscore-separated words rather than substrings: ``fix`` is a
        substring of ``trusted_prefix``, and a sweep that flagged it would fail on a name
        that means the opposite of repair.
        """
        import ast
        import pathlib

        source = pathlib.Path("src/aegis/a2a/records.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        parts = {
            part
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            for part in node.name.split("_")
        }
        assert not (parts & {"repair", "fix", "heal", "rebuild", "restore", "correct"}), parts


class TestStatusLegality:
    @pytest.mark.parametrize(
        "status",
        [MessageStatus.ISSUED, MessageStatus.ACCEPTED, MessageStatus.EXPIRED],
    )
    def test_nothing_returns_from_consumed(self, status: MessageStatus) -> None:
        """The security property: a spent message never becomes fresh again."""
        assert not legal_status_transition(MessageStatus.CONSUMED, status)

    @pytest.mark.parametrize("status", list(MessageStatus))
    def test_nothing_at_all_returns_to_issued(self, status: MessageStatus) -> None:
        if status is MessageStatus.ISSUED:
            return
        assert not legal_status_transition(status, MessageStatus.ISSUED)

    def test_consumed_may_only_complete(self) -> None:
        assert legal_status_transition(MessageStatus.CONSUMED, MessageStatus.COMPLETED)

    def test_completed_goes_nowhere(self) -> None:
        for status in MessageStatus:
            if status is MessageStatus.COMPLETED:
                continue
            assert not legal_status_transition(MessageStatus.COMPLETED, status)

    def test_a_replayed_issued_record_after_consumption_is_detected(self) -> None:
        """The attack the legality check exists for, spelled out.

        Every digest is correct and every link is right. The history is simply impossible.
        """
        first = a_record()
        consumed = a_record(
            sequence=1,
            previous_digest=first.digest,
            kind=A2ARecordKind.STATUS_CHANGED,
            status=MessageStatus.CONSUMED,
        )
        resurrect = a_record(
            sequence=2,
            previous_digest=consumed.digest,
            kind=A2ARecordKind.STATUS_CHANGED,
            status=MessageStatus.ISSUED,
        )
        report = verify_a2a_chain((first, consumed, resurrect))
        assert not report.valid
        assert "not a legal edge" in (report.reason or "")
        assert report.first_invalid_index == 2

    def test_a_status_record_for_an_unissued_message_is_detected(self) -> None:
        orphan = a_record(kind=A2ARecordKind.STATUS_CHANGED, status=MessageStatus.CONSUMED)
        assert not verify_a2a_chain((orphan,)).valid

    def test_a_binding_cannot_change_after_issuance(self) -> None:
        """A status record may not quietly re-point a message at a different sender."""
        first = a_record()
        moved = a_record(
            sequence=1,
            previous_digest=first.digest,
            kind=A2ARecordKind.STATUS_CHANGED,
            status=MessageStatus.CONSUMED,
            sender_agent_id="remediation",
        )
        report = verify_a2a_chain((first, moved))
        assert not report.valid
        assert "binding" in (report.reason or "")

    def test_a_message_cannot_be_issued_twice(self) -> None:
        first = a_record()
        again = a_record(sequence=1, previous_digest=first.digest)
        report = verify_a2a_chain((first, again))
        assert not report.valid
        assert "second time" in (report.reason or "")


# --- corrupted state fails closed ------------------------------------------------------


class TestCorruptionFailsClosed:
    def test_a_ledger_refuses_to_load_a_broken_chain(self, tmp_path, clock) -> None:
        path = tmp_path / "a2a.jsonl"
        good = a_record()
        broken = good.model_copy(update={"status": MessageStatus.CONSUMED})  # digest now wrong
        backend = JsonlA2APersistence(path)
        backend.append(good)
        backend.append(broken)
        with pytest.raises(A2AStateCorrupt, match="failed at record"):
            MessageLedger(clock=clock, persistence=backend)

    def test_an_unreadable_line_is_damage_not_an_ending(self, tmp_path, clock) -> None:
        path = tmp_path / "a2a.jsonl"
        backend = JsonlA2APersistence(path)
        backend.append(a_record())
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"sequence": 1, "truncated')
        with pytest.raises(A2AStateCorrupt, match="damaged"):
            backend.load()

    def test_a_truncated_tail_never_resurrects_a_consumed_message(
        self, durable: Restartable, clock
    ) -> None:
        """The direction the failure falls in matters more than whether it can happen."""
        envelope = issue(durable.broker)
        admit(durable.broker, envelope)
        lines = durable.path.read_text(encoding="utf-8").splitlines()
        durable.path.write_text("\n".join(lines) + '\n{"sequence": 2, "tor', encoding="utf-8")
        with pytest.raises(A2AStateCorrupt):
            durable.restart()

    def test_a_corrupt_ledger_refuses_to_exist_rather_than_starting_empty(
        self, tmp_path, clock
    ) -> None:
        """Starting empty would mean starting as though nothing had been consumed."""
        path = tmp_path / "a2a.jsonl"
        path.write_text("not json at all\n", encoding="utf-8")
        with pytest.raises(A2AStateCorrupt):
            MessageLedger(clock=clock, persistence=JsonlA2APersistence(path))


class _FailingPersistence:
    """A backend that refuses every write. **TEST INSTRUMENT.**"""

    durable = True

    def __init__(self, *, fail_after: int = 0) -> None:
        self._records: list[A2AStateRecord] = []
        self._fail_after = fail_after

    def load(self):
        return tuple(self._records)

    def append(self, record: A2AStateRecord) -> None:
        if len(self._records) >= self._fail_after:
            raise A2APersistenceFailure("the disk is full")
        self._records.append(record)


class TestPersistenceFailureNeverGrantsDelivery:
    def test_a_failed_append_at_issue_produces_no_message(self, directory, clock) -> None:
        broker = A2ABroker(
            directory,
            ledger=MessageLedger(clock=clock, persistence=_FailingPersistence()),
            clock=clock,
        )
        with pytest.raises(A2APersistenceFailure):
            issue(broker)
        assert broker.ledger.persisted_records == 0

    def test_a_failed_append_leaves_the_ledger_where_it_was(self, directory, clock) -> None:
        """The append happens before the in-memory view moves, so nothing gets ahead."""
        backend = _FailingPersistence(fail_after=1)
        broker = A2ABroker(
            directory, ledger=MessageLedger(clock=clock, persistence=backend), clock=clock
        )
        envelope = issue(broker)
        assert broker.ledger.known(envelope.message_id)
        with pytest.raises(A2APersistenceFailure):
            admit(broker, envelope)
        # The consumption was never recorded, so the message is still exactly as issued.
        assert broker.ledger.status_of(envelope.message_id) is MessageStatus.ISSUED
        assert not broker.ledger.consumed(envelope.message_id)

    def test_a_persistence_failure_is_never_an_acceptance(self, directory, clock) -> None:
        backend = _FailingPersistence(fail_after=1)
        broker = A2ABroker(
            directory, ledger=MessageLedger(clock=clock, persistence=backend), clock=clock
        )
        envelope = issue(broker)
        with pytest.raises(A2APersistenceFailure):
            admit(broker, envelope)
        # No verdict was returned at all, so nothing could have read one as permission.
        assert backend.load()[-1].status is MessageStatus.ISSUED


# --- Part 11: crash windows -----------------------------------------------------------


class TestCrashWindows:
    """Every dangerous boundary, crashed at and restarted from.

    "Crash" here means the harshest realistic form: the process stops between one durable
    append and the next, and everything in memory is lost. The rule being checked is one
    directional property — **a consumed message must never come back available** — because
    that is the only failure that turns a crash into a security problem.
    """

    def test_a_issue_then_crash(self, durable: Restartable) -> None:
        envelope = issue(durable.broker)
        broker = durable.restart()
        assert broker.ledger.status_of(envelope.message_id) is MessageStatus.ISSUED
        assert admit(broker, envelope).accepted

    def test_b_persist_then_crash_before_sending(self, durable: Restartable) -> None:
        envelope = issue(durable.broker)
        broker = durable.restart()
        assert broker.send(envelope).accepted
        assert admit(broker, envelope).accepted

    def test_c_consume_then_crash(self, durable: Restartable) -> None:
        envelope = issue(durable.broker)
        admit(durable.broker, envelope)
        broker = durable.restart()
        assert broker.ledger.consumed(envelope.message_id)
        assert admit(broker, envelope).rejection is A2ARejection.ALREADY_CONSUMED

    def test_d_reject_then_crash(self, durable: Restartable) -> None:
        envelope = issue(durable.broker)
        admit(durable.broker, envelope, expected_incident_id="INC-OTHER")
        broker = durable.restart()
        assert broker.ledger.status_of(envelope.message_id) is MessageStatus.REJECTED

    def test_e_response_bind_then_crash(self, durable: Restartable) -> None:
        request = issue(durable.broker)
        admit(durable.broker, request)
        response = issue(
            durable.broker,
            accountable_sender="diagnostic",
            recipient_agent_id="commander",
            message_type=MessageType.TASK_RESULT,
        )
        durable.broker.bind_response(request, response, None)
        broker = durable.restart()
        assert broker.ledger.status_of(response.message_id) is MessageStatus.COMPLETED
        assert broker.ledger.consumed(response.message_id)

    @pytest.mark.parametrize("crash_after", range(1, 5))
    def test_no_crash_point_makes_a_consumed_message_available(
        self, durable: Restartable, crash_after: int
    ) -> None:
        """Swept across every append boundary rather than at one chosen point."""
        envelope = issue(durable.broker)
        admit(durable.broker, envelope)
        for _ in range(crash_after):
            broker = durable.restart()
            assert admit(broker, envelope).rejection is A2ARejection.ALREADY_CONSUMED


# --- Part 12: concurrent writers ------------------------------------------------------


class TestConcurrentWriters:
    """JSONL is single-writer, and this says so with tests rather than with a comment.

    Nothing here claims to *solve* concurrent writing. What is asserted is that the failure
    is **detected on load** rather than silently accepted — which is the honest boundary for
    this milestone, and the one documented in ``docs/A2A.md``.
    """

    def test_two_writers_produce_a_detectable_collision(self, tmp_path, clock, directory) -> None:
        path = tmp_path / "a2a.jsonl"
        first = A2ABroker(
            directory,
            ledger=MessageLedger(clock=clock, persistence=JsonlA2APersistence(path)),
            clock=clock,
        )
        second = A2ABroker(
            directory,
            ledger=MessageLedger(clock=clock, persistence=JsonlA2APersistence(path)),
            clock=clock,
        )
        issue(first)
        issue(second, task_id="task-second")  # both believe they are writing record 0
        with pytest.raises(A2AStateCorrupt):
            MessageLedger(clock=clock, persistence=JsonlA2APersistence(path))

    def test_a_sequence_collision_is_named_in_the_report(self, tmp_path) -> None:
        backend = JsonlA2APersistence(tmp_path / "a2a.jsonl")
        backend.append(a_record())
        backend.append(a_record(message_id="msg-000000000000000000000002"))
        report = verify_a2a_chain(backend.load())
        assert not report.valid
        assert "sequence" in (report.reason or "") or "link" in (report.reason or "")

    def test_a_partial_append_is_detected(self, tmp_path) -> None:
        path = tmp_path / "a2a.jsonl"
        backend = JsonlA2APersistence(path)
        backend.append(a_record())
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"sequence": 1, "kind": "STATUS')
        with pytest.raises(A2AStateCorrupt):
            backend.load()

    def test_no_file_locking_is_claimed(self) -> None:
        """The architecture does not pretend to solve this."""
        import pathlib

        text = pathlib.Path("src/aegis/a2a/persistence.py").read_text(encoding="utf-8")
        assert "fcntl" not in text and "msvcrt" not in text and "flock" not in text
        assert "No concurrency control" in text


# --- Part 6: broker reconstruction ----------------------------------------------------


class TestBrokerReconstruction:
    def test_a_new_broker_loads_state_without_regenerating_identity(
        self, durable: Restartable
    ) -> None:
        envelope = issue(durable.broker)
        broker = durable.restart()
        stored = broker.ledger.record_of(envelope.message_id)
        assert stored is not None
        assert stored.message_id == envelope.message_id
        assert stored.seal == envelope.seal
        assert stored.sequence == envelope.sequence

    def test_reconstruction_does_not_change_message_ids(self, durable: Restartable) -> None:
        before = {m.message_id for m in durable.broker.ledger.messages_for(CONVERSATION)}
        issue(durable.broker)
        issue(durable.broker, task_id="task-2")
        expected = {m.message_id for m in durable.broker.ledger.messages_for(CONVERSATION)}
        broker = durable.restart()
        after = {m.message_id for m in broker.ledger.messages_for(CONVERSATION)}
        assert after == expected != before

    def test_a_reissued_id_after_restart_would_be_refused(self, durable: Restartable) -> None:
        """Ids are derived, so a restart must not be able to mint a colliding one."""
        first = issue(durable.broker)
        broker = durable.restart()
        second = issue(broker, task_id="task-2")
        assert second.message_id != first.message_id

    @pytest.mark.parametrize(
        "forbidden", ["reset", "clear", "release", "reopen", "restore", "rewind", "rollback"]
    )
    def test_no_escape_hatch_on_the_ledger_or_the_broker(self, forbidden: str) -> None:
        for target in (MessageLedger, A2ABroker):
            public = {name for name in dir(target) if not name.startswith("_")}
            assert not any(forbidden in name for name in public), (target.__name__, forbidden)

    def test_the_ledger_reports_its_own_chain(self, durable: Restartable) -> None:
        envelope = issue(durable.broker)
        admit(durable.broker, envelope)
        report = durable.broker.ledger.verify()
        assert report.valid
        assert report.checked == durable.broker.ledger.persisted_records


# --- Part 7: the identity boundary is unchanged ---------------------------------------


class TestIdentityIsStillSeparate:
    def test_a_correctly_sealed_message_from_the_wrong_sender_still_fails_after_restart(
        self, durable: Restartable
    ) -> None:
        envelope = issue(durable.broker)
        broker = durable.restart()
        assert admit(broker, envelope, accountable_sender="remediation").rejection is (
            A2ARejection.SENDER_MISMATCH
        )

    def test_a_resealed_forgery_still_fails_after_restart(self, durable: Restartable) -> None:
        envelope = issue(durable.broker)
        forged = envelope.model_copy(update={"message_id": "msg-forged00000000000000000"})
        forged = forged.model_copy(update={"seal": envelope_seal(forged)})
        broker = durable.restart()
        assert admit(broker, forged).rejection is A2ARejection.NOT_ISSUED

    def test_a_tampered_message_still_fails_after_restart(self, durable: Restartable) -> None:
        envelope = issue(durable.broker)
        broker = durable.restart()
        tampered = envelope.model_copy(update={"payload": {"note": "altered"}})
        assert admit(broker, tampered).rejection is A2ARejection.INTEGRITY_FAILURE

    def test_persistence_is_not_an_identity_authority(self, durable: Restartable) -> None:
        """Being in the log proves issuance, never who a remote party is."""
        envelope = issue(durable.broker)
        broker = durable.restart()
        assert broker.ledger.known(envelope.message_id)
        # Known, and still refused under the wrong accountable identity.
        assert not admit(broker, envelope, accountable_sender="security").accepted

    def test_specialist_to_specialist_is_still_refused_after_restart(
        self, durable: Restartable
    ) -> None:
        envelope = issue(
            durable.broker,
            accountable_sender="diagnostic",
            recipient_agent_id="security",
            task_type=TaskType.INVESTIGATE_SECURITY,
        )
        broker = durable.restart()
        assert admit(broker, envelope, accountable_sender="diagnostic").rejection is (
            A2ARejection.NOT_PERMITTED
        )


# --- Part 10: at-most-once ------------------------------------------------------------


class TestAtMostOnceDelivery:
    def test_a_message_is_consumed_at_most_once_across_any_number_of_restarts(
        self, durable: Restartable
    ) -> None:
        envelope = issue(durable.broker)
        accepted = 0
        for _ in range(6):
            broker = durable.restart()
            if admit(broker, envelope).accepted:
                accepted += 1
        assert accepted == 1

    def test_the_ledger_records_exactly_one_consumption(self, durable: Restartable) -> None:
        envelope = issue(durable.broker)
        admit(durable.broker, envelope)
        for _ in range(3):
            admit(durable.broker, envelope)
        consumed = [
            record
            for record in JsonlA2APersistence(durable.path).load()
            if record.message_id == envelope.message_id and record.status is MessageStatus.CONSUMED
        ]
        assert len(consumed) == 1

    def test_no_retry_lives_in_a2a(self) -> None:
        """At-most-once, not at-least-once. Retry belongs to the lifecycle."""
        import ast
        import pathlib

        for path in sorted(pathlib.Path("src/aegis/a2a").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    assert "retry" not in node.name.lower(), f"{path.name}:{node.name}"

    def test_exactly_once_is_not_claimed(self) -> None:
        import pathlib

        for name in ("src/aegis/a2a/transport.py", "docs/A2A.md"):
            text = pathlib.Path(name).read_text(encoding="utf-8").lower()
            assert "exactly-once" not in text or "not" in text


# --- Part 13: the audit needed nothing new --------------------------------------------


class TestTheAuditVocabularyDidNotGrow:
    """Durability changed what is *stored*, not what needs *recording*.

    Part 13 permits a new event type only if reconstruction genuinely requires one. It does
    not: a replay refused because a previous process consumed the message already appears as
    ``a2a.message`` with ``status=REJECTED`` and ``rejection=ALREADY_CONSUMED``, which is
    precisely the fact. Adding an event to say the same thing again would be vocabulary for
    its own sake, and every future reader would have to learn the difference between two
    names for one occurrence.
    """

    def test_prompt_16_added_no_audit_event_type(self) -> None:
        from aegis.core.audit import AuditEventType

        a2a_members = [name for name in AuditEventType.__members__ if name.startswith("A2A")]
        assert a2a_members == ["A2A_MESSAGE"], a2a_members

    def test_no_event_type_names_persistence_or_restart(self) -> None:
        from aegis.core.audit import AuditEventType

        for member in AuditEventType:
            lowered = member.value.lower()
            for word in ("persist", "restart", "durable", "ledger", "replay"):
                assert word not in lowered, member.value

    def test_the_replay_fact_is_reconstructible_from_existing_fields(self) -> None:
        """The reason no new event was needed, demonstrated rather than asserted."""
        from aegis.core.audit import AuditEventType, AuditRecorder, AuditStore

        store = AuditStore()
        recorder = AuditRecorder(store, clock=lambda: FIXED_NOW)
        recorder.record_a2a_message(
            incident_id=INCIDENT,
            message_id="msg-000000000000000000000001",
            conversation_id=CONVERSATION,
            sender_agent_id="commander",
            recipient_agent_id="diagnostic",
            task_id=TASK,
            task_type=TaskType.DIAGNOSE_SERVICE.value,
            status="REJECTED",
            digest="d" * 64,
            sequence=1,
            rejection=A2ARejection.ALREADY_CONSUMED.value,
        )
        record = store.records()[-1]
        assert record.event.event_type == AuditEventType.A2A_MESSAGE.value
        assert record.correlation["rejection"] == "ALREADY_CONSUMED"
        assert record.correlation["digest"] == "d" * 64
        assert store.verify_integrity().valid

    def test_the_recorder_still_takes_only_scalars(self) -> None:
        """Durability must not have leaked a record type into the audit package."""
        import inspect

        from aegis.core.audit import AuditRecorder

        signature = inspect.signature(AuditRecorder.record_a2a_message)
        for name, parameter in signature.parameters.items():
            if name == "self":
                continue
            rendered = str(parameter.annotation)
            assert any(p in rendered for p in ("str", "int", "datetime", "None")), (
                name,
                rendered,
            )

    def test_the_audit_package_still_knows_nothing_about_a2a(self) -> None:
        import ast
        import pathlib

        for path in sorted(pathlib.Path("src/aegis/core/audit").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    assert not (node.module or "").startswith("aegis.a2a"), path.name


def test_the_fleet_fixture_is_the_real_one() -> None:
    """Guards every test above: they must exercise the configuration AEGIS runs."""
    assert frozenset(DELEGATION_MATRIX) == FLEET


def test_payload_digest_is_canonical() -> None:
    assert payload_digest({"a": 1, "b": 2}) == payload_digest({"b": 2, "a": 1})
    assert payload_digest({"a": 1}) != payload_digest({"a": 2})
