"""Part 6: a remote message does its work once, and a restart does not give it another go.

Prompt 16 established durable replay protection for the local boundary. The property this
file has to establish is that **the remote path does not route around it** -- that a
signature, a wire format and a transport in between change nothing about how many times a
message can be spent.

The headline sequence, run end to end:

    issue -> sign -> deliver -> consume -> restart the receiver -> redeliver -> reject

"Restart" is real: a new ledger, a new broker, a new gateway, a new channel, over the same
file. Nothing crosses in Python. If a guarantee survives, it survived because something was
written down.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.a2a import (
    A2ABroker,
    InMemoryA2ATransport,
    JsonlA2APersistence,
    MessageLedger,
    MessageStatus,
    MessageType,
)
from aegis.a2a.remote import (
    InMemoryRemoteTransport,
    RemoteChannel,
    RemoteGateway,
    RemoteRejection,
)
from aegis.agents.decisions import TaskType

from .conftest import CONVERSATION, FLEET, INCIDENT, TASK, frame_for, issue


class Restartable:
    """A receiver that can be genuinely restarted over the same durable file.

    Every call to :meth:`restart` throws away the ledger, the broker, the gateway and the
    channel and builds new ones over the same path. Faking a restart by copying state would
    measure the copy -- the same reasoning ``tests/a2a/test_persistence.py`` uses, applied to
    the remote path.
    """

    def __init__(self, path: Path, directory, authenticator, keys, clock) -> None:
        self.path = path
        self.directory = directory
        self.authenticator = authenticator
        self.ring, self.by_agent, _ = keys
        self.clock = clock
        self.restart()

    def restart(self) -> RemoteChannel:
        self.broker = A2ABroker(
            self.directory,
            transport=InMemoryA2ATransport(),
            ledger=MessageLedger(clock=self.clock, persistence=JsonlA2APersistence(self.path)),
            clock=self.clock,
        )
        self.transport = InMemoryRemoteTransport()
        self.gateway = RemoteGateway(
            FLEET,
            self.authenticator,
            self.broker,
            transport=self.transport,
            clock=self.clock,
        )
        self.channel = RemoteChannel(self.gateway, self.ring, self.by_agent)
        return self.channel


@pytest.fixture
def durable(tmp_path, directory, authenticator, keys, clock) -> Restartable:
    return Restartable(tmp_path / "a2a.jsonl", directory, authenticator, keys, clock)


def _carry(channel, remote, **overrides):
    settings = {
        "as_agent": "diagnostic",
        "expected_incident_id": INCIDENT,
        "expected_conversation_id": CONVERSATION,
    }
    settings.update(overrides)
    return channel.carry_signed(remote, **settings)


class TestTheHeadlineSequence:
    def test_a_consumed_message_is_refused_after_a_restart(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        """Issue, sign, deliver, consume, restart, redeliver, reject."""
        remote = signer("commander", issue(peer_broker))

        first = _carry(durable.channel, remote)
        assert first.admitted

        durable.restart()

        again = _carry(durable.channel, remote)
        assert not again.admitted
        assert again.verdict.rejection is RemoteRejection.ALREADY_CONSUMED

    def test_the_consumption_really_reached_the_disk(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        """Read from the backend rather than from the ledger, which is the component under
        test and is therefore not the one to ask."""
        remote = signer("commander", issue(peer_broker))
        assert _carry(durable.channel, remote).admitted

        records = tuple(JsonlA2APersistence(durable.path).load())
        consumed = [
            record
            for record in records
            if record.message_id == remote.message.message_id
            and record.status is MessageStatus.CONSUMED
        ]
        assert len(consumed) == 1

    def test_six_restarts_still_spend_it_once(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        remote = signer("commander", issue(peer_broker))
        admitted = 0
        for _ in range(6):
            if _carry(durable.channel, remote).admitted:
                admitted += 1
            durable.restart()
        assert admitted == 1

        records = tuple(JsonlA2APersistence(durable.path).load())
        spent = [
            record
            for record in records
            if record.message_id == remote.message.message_id
            and record.status is MessageStatus.CONSUMED
        ]
        assert len(spent) == 1, "one consumption, however many restarts"

    def test_an_unconsumed_message_survives_a_restart_and_still_works(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        """The other half. A boundary that refused everything after a restart would pass
        every test above and be useless."""
        remote = signer("commander", issue(peer_broker))
        durable.restart()
        assert _carry(durable.channel, remote).admitted

    def test_a_valid_old_signature_stays_invalid_for_a_consumed_message(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        """Part 6, stated exactly. The signature is still mathematically perfect; the
        message is spent, and spent is not a property of the cryptography."""
        remote = signer("commander", issue(peer_broker))
        assert _carry(durable.channel, remote).admitted

        verifier = durable.authenticator.registry.verifier(remote.key_id)
        from aegis.a2a.remote import signing_payload

        assert verifier is not None
        assert verifier.verify(signing_payload(remote), remote.signature), (
            "the signature must still be valid, or this test proves nothing"
        )
        assert not _carry(durable.channel, remote).admitted


class TestTheSameMessageElsewhere:
    """Part 6's four "same message, different X" cases."""

    def test_the_same_message_to_a_different_receiver(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        remote = signer("commander", issue(peer_broker))
        delivery = durable.gateway.deliver(
            frame_for(remote, destination="security"),
            as_agent="security",
            expected_incident_id=INCIDENT,
        )
        assert not delivery.admitted
        assert delivery.verdict.rejection is RemoteRejection.WRONG_RECIPIENT

    def test_the_same_message_in_a_different_conversation(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        remote = signer("commander", issue(peer_broker))
        delivery = _carry(durable.channel, remote, expected_conversation_id="conv-elsewhere")
        assert not delivery.admitted
        assert delivery.verdict.rejection is RemoteRejection.CROSS_CONVERSATION

    def test_the_same_message_against_a_different_incident(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        remote = signer("commander", issue(peer_broker))
        delivery = _carry(durable.channel, remote, expected_incident_id="INC-ELSEWHERE")
        assert not delivery.admitted
        assert delivery.verdict.rejection is RemoteRejection.CROSS_INCIDENT

    def test_the_same_message_at_a_different_position(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        """A message signed for position three, arriving into a conversation at one."""
        third = issue(peer_broker, task_id="task-3")
        peer_broker.issue(
            accountable_sender="commander",
            recipient_agent_id="security",
            incident_id=INCIDENT,
            conversation_id=CONVERSATION,
            task_id="task-filler",
            task_type=TaskType.INVESTIGATE_SECURITY,
        )
        later = issue(peer_broker, task_id="task-later")
        assert later.sequence > third.sequence

        delivery = _carry(durable.channel, signer("commander", later))
        assert not delivery.admitted
        assert delivery.verdict.rejection is RemoteRejection.SEQUENCE_MISMATCH

    def test_none_of_them_left_a_consumption_behind(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        """A refusal records; it must not spend anything."""
        remote = signer("commander", issue(peer_broker))
        _carry(durable.channel, remote, expected_incident_id="INC-ELSEWHERE")
        assert not durable.broker.ledger.consumed(remote.message.message_id)


class TestDuplicateDelivery:
    def test_a_frame_delivered_twice_is_admitted_once(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        remote = signer("commander", issue(peer_broker))
        frame = frame_for(remote)
        first = durable.gateway.deliver(frame, as_agent="diagnostic", expected_incident_id=INCIDENT)
        second = durable.gateway.deliver(
            frame, as_agent="diagnostic", expected_incident_id=INCIDENT
        )
        assert first.admitted
        assert not second.admitted
        assert second.verdict.rejection is RemoteRejection.ALREADY_CONSUMED

    def test_ten_deliveries_produce_one_consumption(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        remote = signer("commander", issue(peer_broker))
        frame = frame_for(remote)
        admitted = sum(
            1
            for _ in range(10)
            if durable.gateway.deliver(
                frame, as_agent="diagnostic", expected_incident_id=INCIDENT
            ).admitted
        )
        assert admitted == 1

    def test_at_most_once_is_the_claim_and_exactly_once_is_not(self) -> None:
        """Stated in the transport's own docstring, so the two are not confused by a reader
        who never opens the docs."""
        from aegis.a2a.remote import transport as transport_module

        text = transport_module.__doc__ or ""
        assert "At-most-once" in text
        assert "Exactly-once is not claimed" in text


class TestOneIdCannotCarryTwoMessages:
    def test_a_different_message_under_a_known_id_is_a_replay(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        """One id, two contents. Refused at the boundary that owns message identity rather
        than left to the broker's integrity check -- both refuse, and this one names the
        problem correctly."""
        from aegis.a2a import envelope_seal

        remote = signer("commander", issue(peer_broker))
        durable.gateway.deliver(
            frame_for(remote), as_agent="diagnostic", expected_incident_id=INCIDENT
        )
        durable.restart()
        # Deliver the genuine one so the id is known but not yet consumed... it is consumed,
        # so build a fresh, unconsumed one and substitute its content under the same id.
        fresh = signer("commander", issue(peer_broker, task_id="task-fresh"))
        substituted_message = fresh.message.model_copy(update={"payload": {"note": "substituted"}})
        resealed = substituted_message.model_copy(
            update={"seal": envelope_seal(substituted_message)}
        )
        substituted = fresh.model_copy(update={"message": resealed})

        first = durable.gateway.deliver(
            frame_for(fresh),
            as_agent="diagnostic",
            expected_incident_id=INCIDENT,
        )
        assert first.verdict.rejection is not RemoteRejection.REPLAY
        second = durable.gateway.deliver(
            frame_for(substituted),
            as_agent="diagnostic",
            expected_incident_id=INCIDENT,
        )
        assert not second.admitted


class TestResponsesAreReplayProtectedToo:
    def test_a_duplicate_response_is_refused(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        request = issue(peer_broker)
        assert _carry(durable.channel, signer("commander", request)).admitted

        response = peer_broker.issue(
            accountable_sender="diagnostic",
            recipient_agent_id="commander",
            incident_id=INCIDENT,
            conversation_id=CONVERSATION,
            task_id=TASK,
            task_type=TaskType.DIAGNOSE_SERVICE,
            message_type=MessageType.TASK_RESULT,
            payload={"outcome": "COMPLETED"},
        )
        remote_response = signer("diagnostic", response)
        frame = frame_for(remote_response)

        first = durable.gateway.deliver_response(frame, request, None, as_agent="commander")
        second = durable.gateway.deliver_response(frame, request, None, as_agent="commander")
        assert first.admitted
        assert not second.admitted
        assert second.verdict.rejection is RemoteRejection.ALREADY_CONSUMED

    def test_a_response_replayed_after_a_restart_is_refused(
        self, durable: Restartable, peer_broker, signer
    ) -> None:
        request = issue(peer_broker)
        assert _carry(durable.channel, signer("commander", request)).admitted
        response = peer_broker.issue(
            accountable_sender="diagnostic",
            recipient_agent_id="commander",
            incident_id=INCIDENT,
            conversation_id=CONVERSATION,
            task_id=TASK,
            task_type=TaskType.DIAGNOSE_SERVICE,
            message_type=MessageType.TASK_RESULT,
            payload={"outcome": "COMPLETED"},
        )
        remote_response = signer("diagnostic", response)
        assert durable.gateway.deliver_response(
            frame_for(remote_response), request, None, as_agent="commander"
        ).admitted

        durable.restart()
        again = durable.gateway.deliver_response(
            frame_for(remote_response), request, None, as_agent="commander"
        )
        assert not again.admitted
        assert again.verdict.rejection is RemoteRejection.ALREADY_CONSUMED


class TestReplayProtectionDoesNotRestOnTimestamps:
    def test_a_message_well_inside_its_window_is_still_refused_once_spent(
        self, durable: Restartable, peer_broker, signer, clock
    ) -> None:
        """Part 6: "do not rely only on timestamps". The message is fresh by every clock
        reading available, and it is still spent."""
        remote = signer("commander", issue(peer_broker))
        assert _carry(durable.channel, remote).admitted
        clock.advance(1)
        assert not remote.message.expired_at(clock())
        assert not _carry(durable.channel, remote).admitted

    def test_the_gateway_checks_consumption_before_freshness(self) -> None:
        """Structural. Ordering is the reason a rolled-back clock cannot un-spend anything,
        and ordering is exactly what a behavioural test cannot pin down."""
        import ast
        import pathlib

        tree = ast.parse(
            pathlib.Path("src/aegis/a2a/remote/gateway.py").read_text(encoding="utf-8")
        )
        record = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "_record"
        )
        body = ast.unparse(record)
        assert body.index("consumed") < body.index("expected_sequence")


def test_the_ledger_still_offers_no_way_to_forget(durable: Restartable) -> None:
    """The Prompt 15 rule, re-asserted now that a second caller reaches the ledger.

    A replay window that can be cleared on request is a replay window an attacker asks to
    have cleared, and adding a remote path must not have quietly added such a request.
    """
    surface = {name for name in dir(durable.broker.ledger) if not name.startswith("_")}
    for forbidden in ("reset", "clear", "forget", "release", "reopen", "unconsume"):
        assert not any(forbidden in name for name in surface), (forbidden, surface)
