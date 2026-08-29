"""Part 16: a party on the wire with six powers and no key.

Modify, duplicate, reorder, drop, replay, redirect -- and nothing else, because everything
else requires a key it does not have. The required outcomes:

    modification -> rejected
    redirection  -> rejected
    replay       -> rejected
    duplication  -> at-most-once
    reordering   -> rejected, per the documented ordering rule
    drop         -> bounded failure

**No intermediary action may produce execution**, and the last test in this file sweeps
every attack to say so from the world's own state rather than from any verdict.
"""

from __future__ import annotations

import json

import pytest

from aegis.a2a.remote import (
    InMemoryRemoteTransport,
    RemoteChannel,
    RemoteRejection,
    decode_envelope,
    encode_envelope,
    signing_payload,
)
from aegis.evaluation.remote_stage import MaliciousIntermediary
from aegis.evaluation.scenario import RemoteMode

from .conftest import CONVERSATION, INCIDENT, frame_for, issue

ATTACKS = [
    RemoteMode.TAMPERED_FRAME,
    RemoteMode.REBUILT_FRAME,
    RemoteMode.TRUNCATED_FRAME,
    RemoteMode.OVERSIZED_FRAME,
    RemoteMode.MALFORMED_FRAME,
    RemoteMode.STRIPPED_SIGNATURE,
    RemoteMode.DOWNGRADED_FRAME,
    RemoteMode.KEY_CONFUSION,
    RemoteMode.CROSS_INCIDENT_FRAME,
    RemoteMode.CROSS_CONVERSATION_FRAME,
]
"""Every attack that rewrites a frame's body. Each must be refused, and the sweep at the
bottom asserts none of them ever produced an admission."""


def _relayed(channel, gateway, mode: RemoteMode) -> tuple[RemoteChannel, MaliciousIntermediary]:
    relay = MaliciousIntermediary(mode)
    gateway.transport = InMemoryRemoteTransport(relay=relay)
    return RemoteChannel(gateway, channel.key_ring, channel.keys_by_agent), relay


def _carry(channel, peer_broker, **issue_overrides):
    return channel.carry(
        issue(peer_broker, **issue_overrides),
        signed_by="commander",
        as_agent="diagnostic",
        expected_incident_id=INCIDENT,
        expected_conversation_id=CONVERSATION,
    )


class TestTheIntermediaryHoldsNoKey:
    def test_it_cannot_sign(self) -> None:
        """The whole premise. An intermediary that could sign would not be an intermediary,
        it would be a peer -- and every result in this file would be about something else."""
        relay = MaliciousIntermediary(RemoteMode.TAMPERED_FRAME)
        assert not hasattr(relay, "sign")
        assert not hasattr(relay, "key_ring")
        surface = {name for name in dir(relay) if not name.startswith("_")}
        assert surface == {"mode", "seen", "tampered"}

    def test_it_can_only_change_bytes_in_flight(self, channel, gateway, peer_broker) -> None:
        _, relay = _relayed(channel, gateway, RemoteMode.TAMPERED_FRAME)
        assert relay.seen == 0
        _carry(_relayed(channel, gateway, RemoteMode.TAMPERED_FRAME)[0], peer_broker)


class TestModificationIsRejected:
    def test_one_flipped_character(self, channel, gateway, peer_broker) -> None:
        """Refused either as unparseable or as unsigned, depending on where the flipped
        character lands. Both are correct answers to "this is not the message that was
        signed", and pinning one would be asserting a coincidence of layout."""
        relayed, _ = _relayed(channel, gateway, RemoteMode.TAMPERED_FRAME)
        delivery = _carry(relayed, peer_broker)
        assert not delivery.admitted
        assert delivery.verdict.rejection in {
            RemoteRejection.MALFORMED_FRAME,
            RemoteRejection.SIGNATURE_INVALID,
        }

    def test_a_convincing_rewrite_is_still_rejected(self, channel, gateway, peer_broker) -> None:
        """The strong form. Every hash inside the message agrees with itself, the JSON is
        impeccable, and only the signature was computed over different bytes. A boundary
        that checked hashes alone would accept this."""
        relayed, _ = _relayed(channel, gateway, RemoteMode.REBUILT_FRAME)
        delivery = _carry(relayed, peer_broker)
        assert not delivery.admitted
        assert delivery.verdict.rejection is RemoteRejection.SIGNATURE_INVALID

    def test_the_rewrite_really_did_produce_a_valid_seal(
        self, peer_broker, signer, registry
    ) -> None:
        """Proving the control group is as strong as it claims. If the rewrite broke the
        inner seal, the test above would be measuring the seal and not the signature."""
        from aegis.a2a import envelope_seal
        from aegis.evaluation.remote_stage import MaliciousIntermediary

        relay = MaliciousIntermediary(RemoteMode.REBUILT_FRAME)
        original = frame_for(signer("commander", issue(peer_broker)))
        rewritten = relay(original)[0]
        envelope = decode_envelope(rewritten.body)
        assert envelope is not None
        assert envelope_seal(envelope.message) == envelope.message.seal, "seal intact"
        assert dict(envelope.message.payload) != dict(
            decode_envelope(original.body).message.payload
        ), "payload really changed"
        verifier = registry.verifier(envelope.key_id)
        assert verifier is not None
        assert not verifier.verify(signing_payload(envelope), envelope.signature)

    @pytest.mark.parametrize(
        ("mode", "expected"),
        [
            (RemoteMode.TRUNCATED_FRAME, RemoteRejection.MALFORMED_FRAME),
            (RemoteMode.OVERSIZED_FRAME, RemoteRejection.OVERSIZED_FRAME),
            (RemoteMode.MALFORMED_FRAME, RemoteRejection.MALFORMED_FRAME),
            (RemoteMode.STRIPPED_SIGNATURE, RemoteRejection.MALFORMED_FRAME),
            (RemoteMode.DOWNGRADED_FRAME, RemoteRejection.UNSUPPORTED_PROTOCOL_VERSION),
            # Only one commander key is registered in this fixture, so naming a second one
            # is an unknown key rather than a wrong one. The case where *both* keys are
            # registered and valid -- the harder one -- is ``test_rotation.py`` case 4.
            (RemoteMode.KEY_CONFUSION, RemoteRejection.UNKNOWN_KEY),
            (RemoteMode.CROSS_INCIDENT_FRAME, RemoteRejection.SIGNATURE_INVALID),
            (RemoteMode.CROSS_CONVERSATION_FRAME, RemoteRejection.SIGNATURE_INVALID),
        ],
    )
    def test_each_body_attack_has_its_own_refusal(
        self, channel, gateway, peer_broker, mode, expected
    ) -> None:
        relayed, _ = _relayed(channel, gateway, mode)
        delivery = _carry(relayed, peer_broker)
        assert not delivery.admitted
        assert delivery.verdict.rejection is expected


class TestRedirectionIsRejected:
    def test_a_readdressed_frame_never_reaches_the_intended_recipient(
        self, channel, gateway, peer_broker
    ) -> None:
        relayed, _ = _relayed(channel, gateway, RemoteMode.REDIRECTED_FRAME)
        delivery = _carry(relayed, peer_broker)
        assert not delivery.admitted

    def test_the_unintended_recipient_refuses_it(self, gateway, peer_broker, signer) -> None:
        """The address on the outside is unsigned; the recipient inside is not. So a relay
        may move bytes and never a message."""
        remote = signer("commander", issue(peer_broker))
        delivery = gateway.deliver(
            frame_for(remote, destination="security"),
            as_agent="security",
            expected_incident_id=INCIDENT,
        )
        assert delivery.authenticated, "it really is from the commander"
        assert not delivery.admitted
        assert delivery.verdict.rejection is RemoteRejection.WRONG_RECIPIENT

    def test_readdressing_does_not_break_the_signature(
        self, gateway, peer_broker, signer, registry
    ) -> None:
        """Which is exactly why the recipient check cannot be left to the cryptography. The
        frame's metadata is unsigned on purpose -- it changes between hops -- so something
        else has to compare the signed recipient, and that something is the gateway."""
        remote = signer("commander", issue(peer_broker))
        redirected = frame_for(remote, destination="security")
        envelope = decode_envelope(redirected.body)
        assert envelope is not None
        verifier = registry.verifier(envelope.key_id)
        assert verifier is not None
        assert verifier.verify(signing_payload(envelope), envelope.signature)


class TestDuplicationIsAtMostOnce:
    def test_the_second_copy_is_refused(self, channel, gateway, peer_broker) -> None:
        relayed, _ = _relayed(channel, gateway, RemoteMode.DUPLICATED_FRAME)
        delivery = _carry(relayed, peer_broker)
        assert delivery.admitted, "the first copy does its work"
        refusals = [rejection for _, rejection in gateway.transport.rejected]
        assert RemoteRejection.ALREADY_CONSUMED in refusals

    def test_the_duplicate_genuinely_reached_the_boundary(
        self, channel, gateway, peer_broker
    ) -> None:
        """Not merely ignored. A duplicate that sat unexamined would make "at-most-once"
        true because nothing ever tried, which is the kind of green result that means
        nothing."""
        relayed, _ = _relayed(channel, gateway, RemoteMode.DUPLICATED_FRAME)
        _carry(relayed, peer_broker)
        assert len(gateway.transport.carried) == 2
        assert gateway.transport.rejected, "the second copy was judged, not dropped"

    def test_the_message_is_consumed_exactly_once(
        self, channel, gateway, peer_broker, receiver_broker
    ) -> None:
        from aegis.a2a import MessageStatus

        relayed, _ = _relayed(channel, gateway, RemoteMode.DUPLICATED_FRAME)
        delivery = _carry(relayed, peer_broker)
        assert delivery.envelope is not None
        record = receiver_broker.ledger.record_of(delivery.envelope.message_id)
        assert record is not None
        assert record.status is MessageStatus.CONSUMED


class TestReplayIsRejected:
    def test_an_earlier_frame_re_sent_is_refused(self, channel, gateway, peer_broker) -> None:
        """The first frame to a destination is genuine -- there is nothing yet to replay.
        Every later delivery carries it again, and every later copy loses."""
        relayed, _ = _relayed(channel, gateway, RemoteMode.REPLAYED_FRAME)
        first = _carry(relayed, peer_broker, task_id="task-1")
        assert first.admitted
        second = _carry(relayed, peer_broker, task_id="task-2")
        refusals = [rejection for _, rejection in gateway.transport.rejected]
        assert refusals, "the replayed copy reached the boundary and was judged"
        assert not second.admitted or RemoteRejection.ALREADY_CONSUMED in refusals

    def test_the_replayed_copy_is_never_consumed_twice(
        self, channel, gateway, peer_broker, receiver_broker
    ) -> None:
        from aegis.a2a import MessageStatus

        relayed, _ = _relayed(channel, gateway, RemoteMode.REPLAYED_FRAME)
        first = _carry(relayed, peer_broker, task_id="task-1")
        _carry(relayed, peer_broker, task_id="task-2")
        assert first.envelope is not None
        spent = [
            record
            for conversation in receiver_broker.ledger.conversation_ids()
            for record in receiver_broker.ledger.messages_for(conversation)
            if record.message_id == first.envelope.message_id
            and record.status is MessageStatus.CONSUMED
        ]
        assert len(spent) == 1


class TestDropIsBoundedFailure:
    def test_a_swallowed_frame_produces_no_delivery(self, channel, gateway, peer_broker) -> None:
        relayed, _ = _relayed(channel, gateway, RemoteMode.DROPPED_FRAME)
        delivery = _carry(relayed, peer_broker)
        assert not delivery.admitted
        assert delivery.verdict.rejection is RemoteRejection.TRANSPORT_FAILURE

    def test_a_dropped_frame_is_not_an_empty_message(self, channel, gateway, peer_broker) -> None:
        """Part 12. A message that was lost and a message that said nothing are different
        facts, and a boundary rendering them identically would let a dropped frame look
        like a specialist with no findings."""
        relayed, _ = _relayed(channel, gateway, RemoteMode.DROPPED_FRAME)
        delivery = _carry(relayed, peer_broker)
        assert delivery.envelope is None
        assert delivery.local is None
        assert delivery.verdict.rejection is not None


class TestReorderingFollowsTheDocumentedRule:
    def test_an_out_of_order_frame_is_refused_not_buffered(
        self, channel, gateway, peer_broker
    ) -> None:
        """The documented rule is strict ordering: a message arriving while a predecessor
        is outstanding is refused rather than held. Not loosened for the wire."""
        relayed, _ = _relayed(channel, gateway, RemoteMode.REORDERED_FRAME)
        first = _carry(relayed, peer_broker, task_id="task-1")
        assert not first.admitted
        assert first.verdict.rejection is RemoteRejection.TRANSPORT_FAILURE

        second = _carry(relayed, peer_broker, task_id="task-2")
        assert not second.admitted
        refusals = [rejection for _, rejection in gateway.transport.rejected]
        assert RemoteRejection.SEQUENCE_MISMATCH in refusals, (
            "the late frame arrived and lost to the ordering rule, not to the cryptography"
        )

    def test_the_rule_is_written_down(self) -> None:
        from aegis.a2a.remote import transport as transport_module

        text = transport_module.__doc__ or ""
        assert "Nor is ordered delivery" in text


class TestNoIntermediaryActionProducesExecution:
    @pytest.mark.parametrize("mode", ATTACKS)
    def test_nothing_is_admitted(self, channel, gateway, peer_broker, mode) -> None:
        relayed, _ = _relayed(channel, gateway, mode)
        assert not _carry(relayed, peer_broker).admitted, mode

    @pytest.mark.parametrize("mode", ATTACKS)
    def test_nothing_is_consumed(
        self, channel, gateway, peer_broker, receiver_broker, mode
    ) -> None:
        """From the ledger, which the intermediary cannot reach, rather than from the
        verdict, which is what the boundary said about itself."""
        relayed, _ = _relayed(channel, gateway, mode)
        _carry(relayed, peer_broker)
        consumed = [
            record
            for conversation in receiver_broker.ledger.conversation_ids()
            for record in receiver_broker.ledger.messages_for(conversation)
            if record.status.value in {"CONSUMED", "COMPLETED"}
        ]
        assert consumed == [], mode

    @pytest.mark.parametrize("mode", ATTACKS)
    def test_a_rewritten_body_never_verifies(self, peer_broker, signer, registry, mode) -> None:
        """Independent of the boundary entirely: take what the relay produced and check it
        with the evaluator's own cryptography."""
        relay = MaliciousIntermediary(mode)
        produced = relay(frame_for(signer("commander", issue(peer_broker))))
        assert len(produced) == 1
        envelope = decode_envelope(produced[0].body)
        if envelope is None:
            return  # unparseable is already a refusal
        verifier = registry.verifier(envelope.key_id)
        if verifier is None:
            return  # an unknown key is already a refusal
        assert not verifier.verify(signing_payload(envelope), envelope.signature), mode


def test_the_intermediary_lives_in_the_benchmark_not_the_product() -> None:
    """Attack code belongs with the control groups. A network does not tamper -- an
    attacker does, and an attacker is not a method on a transport."""
    import pathlib

    for path in sorted(pathlib.Path("src/aegis/a2a").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert "MaliciousIntermediary" not in text, path.name


def test_stripping_a_field_is_a_parse_failure_not_a_default(peer_broker, signer) -> None:
    """Checked directly, so the relay's behaviour and the schema's agree."""
    remote = signer("commander", issue(peer_broker))
    document = json.loads(encode_envelope(remote))
    del document["signature"]
    assert decode_envelope(json.dumps(document)) is None
