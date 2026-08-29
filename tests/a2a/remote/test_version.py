"""Part 9: protocol versioning, and the four downgrade attacks.

A downgrade works by getting the wrong interpreter to run. The defence is that there is only
one interpreter, it is selected by exact membership rather than by comparison, and the
version it selects on is itself signed.
"""

from __future__ import annotations

import json

import pytest

from aegis.a2a.remote import (
    LEGACY_PROTOCOL_VERSION,
    REMOTE_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    RemoteAgentIdentity,
    RemoteAgentRegistry,
    RemoteAuthenticator,
    RemoteRejection,
    decode_envelope,
    encode_envelope,
)

from .conftest import issue


class TestTheSupportedSet:
    def test_this_build_speaks_exactly_one_version(self) -> None:
        assert {REMOTE_PROTOCOL_VERSION} == SUPPORTED_PROTOCOL_VERSIONS

    def test_the_legacy_version_is_named_and_not_supported(self) -> None:
        """A version constant that exists but is refused is worth more than one that does
        not exist: it gives "v2 sender, v1 receiver" a name and a rejection code instead of
        leaving it a scenario nobody wrote."""
        assert LEGACY_PROTOCOL_VERSION not in SUPPORTED_PROTOCOL_VERSIONS
        assert LEGACY_PROTOCOL_VERSION != REMOTE_PROTOCOL_VERSION

    def test_support_is_membership_not_comparison(self) -> None:
        """Ordering invites "v1 is lower, so it is older, so we can probably handle it",
        which is a downgrade written as politeness."""
        assert isinstance(SUPPORTED_PROTOCOL_VERSIONS, frozenset)

    def test_the_supported_set_is_immutable(self) -> None:
        with pytest.raises(AttributeError):
            SUPPORTED_PROTOCOL_VERSIONS.add("aegis.a2a/99")


class TestTheFourDowngradeAttacks:
    def test_a_v2_sender_meeting_a_receiver_that_wants_v1(
        self, authenticator, peer_broker, signer
    ) -> None:
        """The sender speaks the version it was configured for; the receiver does not
        silently meet it halfway."""
        remote = signer("commander", issue(peer_broker), protocol_version="aegis.a2a/99")
        verdict = authenticator.authenticate(remote)
        assert verdict.rejection is RemoteRejection.UNSUPPORTED_PROTOCOL_VERSION

    def test_an_attacker_rewriting_v2_to_v1_is_refused(
        self, authenticator, peer_broker, signer
    ) -> None:
        remote = signer("commander", issue(peer_broker))
        downgraded = remote.model_copy(update={"protocol_version": LEGACY_PROTOCOL_VERSION})
        assert (
            authenticator.authenticate(downgraded).rejection
            is RemoteRejection.UNSUPPORTED_PROTOCOL_VERSION
        )

    def test_the_rewrite_would_also_break_the_signature(
        self, registry, peer_broker, signer
    ) -> None:
        """Two independent defences, and the version check simply runs first. Worth proving
        separately: if the version check were removed the signature would still catch it,
        and if the signature check were removed the version check would."""
        from aegis.a2a.remote import signing_payload

        remote = signer("commander", issue(peer_broker))
        downgraded = remote.model_copy(update={"protocol_version": LEGACY_PROTOCOL_VERSION})
        verifier = registry.verifier(remote.key_id)
        assert verifier is not None
        assert not verifier.verify(signing_payload(downgraded), downgraded.signature)

    @pytest.mark.parametrize(
        "field", ["signature", "key_id", "algorithm", "protocol_version", "payload_digest"]
    )
    def test_an_attacker_stripping_a_security_field_produces_no_message(
        self, peer_broker, signer, field: str
    ) -> None:
        """Every one of them is required, so a body without it is a parse failure rather
        than a message with a default. There is no version of this schema in which a missing
        signature means "unsigned"."""
        remote = signer("commander", issue(peer_broker))
        document = json.loads(encode_envelope(remote))
        del document[field]
        assert decode_envelope(json.dumps(document)) is None

    def test_an_attacker_removing_the_signature_is_refused_at_the_gateway(
        self, gateway, peer_broker, signer
    ) -> None:
        from .conftest import INCIDENT, frame_for

        remote = signer("commander", issue(peer_broker))
        document = json.loads(encode_envelope(remote))
        del document["signature"]
        frame = frame_for(remote).model_copy(update={"body": json.dumps(document)})
        delivery = gateway.deliver(frame, as_agent="diagnostic", expected_incident_id=INCIDENT)
        assert not delivery.admitted
        assert delivery.verdict.rejection is RemoteRejection.MALFORMED_FRAME

    def test_an_empty_signature_cannot_be_constructed(self, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        document = json.loads(encode_envelope(remote))
        document["signature"] = ""
        assert decode_envelope(json.dumps(document)) is None


class TestTheRegistryOwnsWhichVersionsAnIdentityMaySpeak:
    def test_a_supported_version_the_registry_does_not_list_is_refused(
        self, keys, peer_broker, signer, clock
    ) -> None:
        """Part 13. A peer cannot widen its own version support by claiming a version."""
        _, _, identities = keys
        narrowed = tuple(
            i.model_copy(update={"protocol_versions": (LEGACY_PROTOCOL_VERSION,)})
            if i.agent_id == "commander"
            else i
            for i in identities
        )
        authenticator = RemoteAuthenticator(RemoteAgentRegistry(narrowed, clock=clock), clock=clock)
        remote = signer("commander", issue(peer_broker))
        assert authenticator.authenticate(remote).rejection is RemoteRejection.VERSION_NOT_PERMITTED

    def test_an_identity_listing_the_version_is_accepted(
        self, authenticator, peer_broker, signer
    ) -> None:
        assert authenticator.authenticate(signer("commander", issue(peer_broker))).authenticated

    def test_versions_are_matched_exactly_not_by_prefix(self, keys, clock) -> None:
        _, _, identities = keys
        identity: RemoteAgentIdentity = identities[0]
        assert identity.speaks(REMOTE_PROTOCOL_VERSION)
        assert not identity.speaks(REMOTE_PROTOCOL_VERSION[:-1])
        assert not identity.speaks(REMOTE_PROTOCOL_VERSION + "9")
        assert not identity.speaks(REMOTE_PROTOCOL_VERSION.upper())


class TestVersionIsCheckedFirst:
    def test_an_unsupported_version_is_refused_before_the_key_is_looked_up(
        self, authenticator, peer_broker, algorithm
    ) -> None:
        """Interpretation is version-specific, so nothing about the message is interpreted
        until the version is known to be one this build understands. Demonstrated with a
        message that is *also* signed by an unregistered key: the version answer wins."""
        from aegis.a2a.remote import provider_for, sign_remote

        stray, _ = provider_for(algorithm).generate("key-nobody", seed=b"stray")
        remote = sign_remote(issue(peer_broker), key=stray, protocol_version="aegis.a2a/99")
        assert (
            authenticator.authenticate(remote).rejection
            is RemoteRejection.UNSUPPORTED_PROTOCOL_VERSION
        )

    def test_an_overlong_version_string_cannot_be_constructed(self, peer_broker, signer) -> None:
        from pydantic import ValidationError

        from aegis.a2a.remote import RemoteEnvelope

        remote = signer("commander", issue(peer_broker))
        with pytest.raises(ValidationError):
            RemoteEnvelope(**{**remote.model_dump(), "protocol_version": "v" * 200})

    def test_an_empty_version_cannot_be_constructed(self, peer_broker, signer) -> None:
        from pydantic import ValidationError

        from aegis.a2a.remote import RemoteEnvelope

        remote = signer("commander", issue(peer_broker))
        with pytest.raises(ValidationError):
            RemoteEnvelope(**{**remote.model_dump(), "protocol_version": ""})
