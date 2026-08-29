"""Parts 4 and 5: what the signature covers, and what a hash cannot buy.

The centrepiece is :class:`TestEverySecurityRelevantFieldIsSigned`, which is written so that
**adding a security-relevant field without signing it is a test failure**. That is the Part 4
requirement stated exactly, and it is the difference between a signature scheme that stays
correct and one that was correct on the day it was written.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.a2a import A2AEnvelope, MessageType, envelope_seal
from aegis.a2a.records import payload_digest
from aegis.a2a.remote import (
    MAX_REMOTE_FRAME_BYTES,
    SIGNED_FIELDS,
    UNSIGNED_BY_DESIGN,
    RemoteEnvelope,
    RemoteFrame,
    decode_envelope,
    encode_envelope,
    frame_digest,
    signing_payload,
)
from aegis.a2a.remote.envelope import _SigningPayload

from .conftest import frame_for, issue


class TestEverySecurityRelevantFieldIsSigned:
    def test_the_declared_list_and_the_signing_model_agree(self) -> None:
        """Two declarations of the same thing, asserted equal so they cannot drift."""
        assert set(SIGNED_FIELDS) == set(_SigningPayload.model_fields)

    def test_the_list_is_sorted(self) -> None:
        """So a diff that adds a field is obvious rather than buried."""
        assert list(SIGNED_FIELDS) == sorted(SIGNED_FIELDS)

    def test_every_wrapper_field_is_covered_or_justified(self) -> None:
        uncovered = set(RemoteEnvelope.model_fields) - set(SIGNED_FIELDS) - UNSIGNED_BY_DESIGN
        assert uncovered == set(), (
            f"{uncovered} is on the remote envelope, is not signed, and is not on the "
            f"justified exception list"
        )

    def test_every_inner_field_is_covered_or_justified(self) -> None:
        uncovered = set(A2AEnvelope.model_fields) - set(SIGNED_FIELDS) - UNSIGNED_BY_DESIGN
        assert uncovered == set(), (
            f"{uncovered} is on the inner envelope, is not signed, and is not on the "
            f"justified exception list"
        )

    def test_the_exception_list_is_short_and_named(self) -> None:
        """Three fields, each with a stated reason. A fourth joining quietly is the risk
        this assertion exists for."""
        assert {"signature", "payload", "message"} == UNSIGNED_BY_DESIGN

    def test_the_part_4_minimum_is_a_subset(self) -> None:
        required = {
            "protocol_version",
            "message_id",
            "conversation_id",
            "sequence",
            "sender_agent_id",
            "recipient_agent_id",
            "incident_id",
            "task_type",
            "message_type",
            "created_at",
            "expires_at",
            "payload_digest",
            "key_id",
            "algorithm",
        }
        assert required <= set(SIGNED_FIELDS)

    def test_the_payload_is_covered_through_its_digest(self, peer_broker, signer) -> None:
        """``payload`` is on the exception list only because ``payload_digest`` is signed
        *and* recomputed. A digest nobody recomputes is a claim wearing a hash's clothes."""
        remote = signer("commander", issue(peer_broker))
        assert remote.payload_digest == payload_digest(remote.message.payload)
        assert "payload_digest" in SIGNED_FIELDS


class TestChangingAnySignedFieldBreaksTheSignature:
    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("conversation_id", "conv-elsewhere"),
            ("incident_id", "INC-ELSEWHERE"),
            ("sender_agent_id", "remediation"),
            ("recipient_agent_id", "security"),
            ("task_id", "task-elsewhere"),
            ("sequence", 7),
            ("message_id", "msg-elsewhere000000000000"),
        ],
    )
    def test_a_rebound_inner_message_no_longer_verifies(
        self, peer_broker, signer, registry, field: str, value
    ) -> None:
        """Resealed, so the *inner* integrity check passes and only the signature is left
        to catch it. A control that broke the seal would prove the seal works."""
        remote = signer("commander", issue(peer_broker))
        changed = remote.message.model_copy(update={field: value})
        resealed = changed.model_copy(update={"seal": envelope_seal(changed)})
        tampered = remote.model_copy(update={"message": resealed})

        verifier = registry.verifier(remote.key_id)
        assert verifier is not None
        assert verifier.verify(signing_payload(remote), remote.signature)
        assert not verifier.verify(signing_payload(tampered), tampered.signature)

    @pytest.mark.parametrize("field", ["protocol_version", "key_id", "payload_digest"])
    def test_a_changed_wrapper_field_no_longer_verifies(
        self, peer_broker, signer, registry, field: str
    ) -> None:
        remote = signer("commander", issue(peer_broker))
        replacement = {
            "protocol_version": "aegis.a2a/1",
            "key_id": "key-security-1",
            "payload_digest": "0" * 64,
        }[field]
        tampered = remote.model_copy(update={field: replacement})
        verifier = registry.verifier(remote.key_id)
        assert verifier is not None
        assert not verifier.verify(signing_payload(tampered), tampered.signature)

    def test_the_algorithm_itself_is_signed(self, peer_broker, signer, registry) -> None:
        """Otherwise a downgrade would be a one-field edit nothing noticed."""
        from aegis.a2a.remote import KeyAlgorithm

        remote = signer("commander", issue(peer_broker))
        other = (
            KeyAlgorithm.ED25519
            if remote.algorithm is KeyAlgorithm.HMAC_SHA256
            else KeyAlgorithm.HMAC_SHA256
        )
        tampered = remote.model_copy(update={"algorithm": other})
        verifier = registry.verifier(remote.key_id)
        assert verifier is not None
        assert not verifier.verify(signing_payload(tampered), tampered.signature)

    def test_a_changed_payload_changes_the_signing_payload(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        changed = remote.message.model_copy(update={"payload": {"note": "rewritten"}})
        rebuilt = remote.model_copy(
            update={"message": changed, "payload_digest": payload_digest(changed.payload)}
        )
        assert signing_payload(rebuilt) != signing_payload(remote)


class TestTheSigningPayloadIsCanonical:
    def test_it_is_deterministic(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        assert signing_payload(remote) == signing_payload(remote)

    def test_it_is_a_structured_document_not_a_concatenation(self, peer_broker, signer) -> None:
        """A structured document means no field value can be crafted to imitate a field
        boundary, which a concatenated string would allow."""
        remote = signer("commander", issue(peer_broker))
        payload = signing_payload(remote).decode("utf-8")
        assert payload.startswith("{") and payload.endswith("}")
        for field in SIGNED_FIELDS:
            assert f'"{field}"' in payload, field

    def test_the_signature_is_not_part_of_what_it_signs(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        assert remote.signature not in signing_payload(remote).decode("utf-8")

    def test_one_function_serves_signer_and_verifier(self, peer_broker, signer, registry) -> None:
        """A separate "build the verification payload" routine is how a scheme ends up
        verifying something subtly different from what it signed."""
        remote = signer("commander", issue(peer_broker))
        verifier = registry.verifier(remote.key_id)
        assert verifier is not None
        assert verifier.verify(signing_payload(remote), remote.signature)


class TestTheRemoteEnvelopeIsClosed:
    @pytest.mark.parametrize(
        "field",
        [
            "policy",
            "decision",
            "approval",
            "authorization",
            "risk",
            "blast_radius",
            "verification",
            "lifecycle",
            "gate",
            "authorized",
            "approved",
            "trusted",
        ],
    )
    def test_no_authority_field_can_be_carried(self, peer_broker, signer, field: str) -> None:
        """A *signed* claim of approval is still a claim, and this schema gives it nowhere
        to sit."""
        remote = signer("commander", issue(peer_broker))
        with pytest.raises(ValidationError):
            RemoteEnvelope(**{**remote.model_dump(), field: "ALLOW"})

    def test_it_is_frozen(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        with pytest.raises(ValueError):
            remote.signature = "rewritten"

    def test_a_missing_signature_cannot_be_constructed(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        fields = remote.model_dump()
        del fields["signature"]
        with pytest.raises(ValidationError):
            RemoteEnvelope(**fields)

    def test_the_digest_must_be_a_full_sha256(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        with pytest.raises(ValidationError):
            RemoteEnvelope(**{**remote.model_dump(), "payload_digest": "short"})

    def test_an_oversized_signature_cannot_be_constructed(self, peer_broker, signer) -> None:
        from aegis.a2a.remote import MAX_SIGNATURE_HEX

        remote = signer("commander", issue(peer_broker))
        with pytest.raises(ValidationError):
            RemoteEnvelope(**{**remote.model_dump(), "signature": "a" * (MAX_SIGNATURE_HEX + 1)})

    def test_a_whitespace_padded_key_id_cannot_be_constructed(self, peer_broker, signer) -> None:
        """The Prompt 15 rule, unchanged: identifiers are matched, never repaired."""
        remote = signer("commander", issue(peer_broker))
        with pytest.raises(ValidationError):
            RemoteEnvelope(**{**remote.model_dump(), "key_id": " key-commander-1"})


class TestTheFrameIsUnsignedAndKnownToBe:
    def test_frame_metadata_is_not_covered_by_the_signature(self, peer_broker, signer) -> None:
        """Part 4: mutable transport metadata legitimately changes between hops, so signing
        it would make every relay a tamper."""
        remote = signer("commander", issue(peer_broker))
        one = frame_for(remote)
        two = one.forwarded("relay-a").forwarded("relay-b")
        assert two.hop_count == 2
        assert two.body == one.body

    def test_readdressing_a_frame_does_not_change_the_body(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        redirected = frame_for(remote, destination="security")
        assert decode_envelope(redirected.body) is not None
        assert decode_envelope(redirected.body).message.recipient_agent_id == "diagnostic"

    def test_a_frame_carries_no_authority_field(self) -> None:
        assert set(RemoteFrame.model_fields) == {
            "destination",
            "body",
            "hop_count",
            "received_at",
            "route",
        }

    def test_hops_are_bounded(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        with pytest.raises(ValidationError):
            frame_for(remote).model_copy(update={"hop_count": 99}).model_validate(
                {**frame_for(remote).model_dump(), "hop_count": 99}
            )

    def test_a_frame_digest_names_a_frame_without_reproducing_it(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        digest = frame_digest(frame_for(remote))
        assert len(digest) == 64
        assert remote.message.message_id not in digest


class TestEncodingAndDecoding:
    def test_a_message_round_trips(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        assert decode_envelope(encode_envelope(remote)) == remote

    def test_encoding_is_canonical(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        assert encode_envelope(remote) == encode_envelope(remote)
        assert " " not in encode_envelope(remote).split('"note"')[0][:40]

    @pytest.mark.parametrize(
        "body",
        [
            "",
            "{",
            "not json",
            "[]",
            '{"protocol_version": "aegis.a2a/2"}',
            "null",
        ],
    )
    def test_a_malformed_body_decodes_to_none(self, body: str) -> None:
        """``None`` rather than an exception, and never a partially populated object: the
        *shape* of a malformed frame must not select which code path runs next."""
        assert decode_envelope(body) is None

    def test_a_truncated_body_decodes_to_none(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        body = encode_envelope(remote)
        assert decode_envelope(body[: len(body) // 2]) is None

    def test_an_oversized_body_is_refused_before_parsing(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        body = encode_envelope(remote) + "x" * MAX_REMOTE_FRAME_BYTES
        assert decode_envelope(body) is None

    def test_a_body_with_an_unknown_field_decodes_to_none(self, peer_broker, signer) -> None:
        """Closed schema. A message arriving with an extra field is a validation error, not
        a message with something extra in it."""
        import json

        remote = signer("commander", issue(peer_broker))
        document = json.loads(encode_envelope(remote))
        document["authorized"] = True
        assert decode_envelope(json.dumps(document)) is None


class TestAValidHashIsNotAnAuthenticatedSender:
    """Part 5, first of three. The seal is computed by a public formula, so anything that
    can build a message can produce a perfect one."""

    def test_a_hand_built_message_can_have_a_perfect_seal(self, peer_broker) -> None:
        envelope = issue(peer_broker)
        assert envelope_seal(envelope) == envelope.seal

    def test_a_perfect_seal_does_not_verify_as_a_signature(
        self, peer_broker, registry, signer
    ) -> None:
        """The whole reason the remote envelope exists."""
        envelope = issue(peer_broker)
        forged = RemoteEnvelope(
            protocol_version=signer("commander", envelope).protocol_version,
            key_id="key-commander-1",
            algorithm=signer("commander", envelope).algorithm,
            payload_digest=payload_digest(envelope.payload),
            signature=envelope.seal,  # a perfectly good hash, used as a signature
            message=envelope,
        )
        verifier = registry.verifier("key-commander-1")
        assert verifier is not None
        assert not verifier.verify(signing_payload(forged), forged.signature)

    def test_the_seal_and_the_signature_are_different_values(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        assert remote.signature != remote.message.seal


def test_a_response_envelope_signs_the_same_way(peer_broker, signer, registry) -> None:
    """No second scheme for replies: one signing payload, one verification path."""
    request = issue(peer_broker)
    response = peer_broker.issue(
        accountable_sender="diagnostic",
        recipient_agent_id="commander",
        incident_id=request.incident_id,
        conversation_id=request.conversation_id,
        task_id=request.task_id,
        task_type=request.task_type,
        message_type=MessageType.TASK_RESULT,
        payload={"outcome": "COMPLETED"},
    )
    assert isinstance(response, A2AEnvelope)
    remote = signer("diagnostic", response)
    verifier = registry.verifier(remote.key_id)
    assert verifier is not None
    assert verifier.verify(signing_payload(remote), remote.signature)
