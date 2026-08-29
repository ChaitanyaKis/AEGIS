"""Part 8: key rotation, and the policy this build documents for revoked keys.

The five required cases, plus the two that make the policy honest.

The documented policy, stated once here and once in ``docs/A2A.md``
-------------------------------------------------------------------

**A revoked key admits nothing, whenever it claims to have signed.** Historical
*verification* survives -- a revocation records a timestamp rather than deleting anything,
so "was this key valid last Tuesday?" stays answerable and an old signature stays
mathematically checkable forever. Historical *admission* does not, and cannot: a peer
holding a stolen key controls every timestamp in its own message, so honouring
"but I signed this before you revoked me" would hand the thief the exact excuse revocation
exists to remove.

That is a choice, not an inevitability, and it is written down as one.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from aegis.a2a.remote import (
    REMOTE_PROTOCOL_VERSION,
    IdentityStatus,
    RemoteAgentIdentity,
    RemoteAgentRegistry,
    RemoteAuthenticator,
    RemoteRejection,
    provider_for,
    sign_remote,
    signing_payload,
)

from .conftest import FIXED_NOW, issue


@pytest.fixture
def rotation(keys, algorithm, clock):
    """Key A active, key B active, both genuinely the Commander's.

    Two live keys before anything is revoked, so the rotation cases below differ from the
    single-key ones by *what was revoked* rather than by what exists.
    """
    ring, by_agent, identities = keys
    provider = provider_for(algorithm)
    key_b, verifier_b = provider.generate("key-commander-2", seed=b"commander-b")
    ring.add(key_b)
    identities = (
        *identities,
        RemoteAgentIdentity(
            agent_id="commander",
            key_id="key-commander-2",
            algorithm=algorithm,
            verification_key=verifier_b.material,
            protocol_versions=(REMOTE_PROTOCOL_VERSION,),
            created_at=FIXED_NOW - timedelta(hours=1),
            expires_at=FIXED_NOW + timedelta(days=30),
        ),
    )
    registry = RemoteAgentRegistry(identities, clock=clock)
    return {
        "registry": registry,
        "authenticator": RemoteAuthenticator(registry, clock=clock),
        "key_a": ring.signer(by_agent["commander"]),
        "key_b": key_b,
    }


class TestTheFiveRequiredCases:
    def test_1_a_message_signed_by_a_before_revocation_is_documented_as_inadmissible(
        self, rotation, peer_broker, clock
    ) -> None:
        """Part 8, case one, answered by the documented policy.

        The message was genuinely signed while key A was active. It remains *verifiable*
        forever -- the signature still checks out, and the registry still knows the key was
        valid then. It is not *admissible*, because a thief with A could back-date freely.
        """
        signed_while_active = sign_remote(issue(peer_broker), key=rotation["key_a"])
        verifier = rotation["registry"].verifier("key-commander-1")
        assert verifier is not None
        assert verifier.verify(
            signing_payload(signed_while_active), signed_while_active.signature
        ), "the signature must still verify, or this test proves nothing"

        rotation["registry"].revoke("key-commander-1", at=clock())
        verdict = rotation["authenticator"].authenticate(signed_while_active)
        assert verdict.rejection is RemoteRejection.IDENTITY_REVOKED

    def test_2_a_message_signed_by_a_after_revocation_is_rejected(
        self, rotation, peer_broker, clock
    ) -> None:
        rotation["registry"].revoke("key-commander-1", at=clock() - timedelta(minutes=1))
        remote = sign_remote(issue(peer_broker), key=rotation["key_a"])
        assert (
            rotation["authenticator"].authenticate(remote).rejection
            is RemoteRejection.IDENTITY_REVOKED
        )

    def test_3_a_message_signed_by_b_is_accepted(self, rotation, peer_broker, clock) -> None:
        """The half that makes the other four mean something. Enforcement that refused the
        replacement key too would be an outage with a security justification."""
        rotation["registry"].revoke("key-commander-1", at=clock() - timedelta(minutes=1))
        remote = sign_remote(issue(peer_broker), key=rotation["key_b"])
        verdict = rotation["authenticator"].authenticate(remote)
        assert verdict.authenticated
        assert verdict.agent_id == "commander"
        assert verdict.key_id == "key-commander-2"

    def test_4_a_message_claiming_b_but_signed_by_a_is_rejected(
        self, rotation, peer_broker
    ) -> None:
        """The key id is a signed field, so this cannot be assembled without breaking the
        signature. Enforced by what was signed rather than by a comparison somebody could
        delete."""
        remote = sign_remote(issue(peer_broker), key=rotation["key_a"])
        claiming_b = remote.model_copy(update={"key_id": "key-commander-2"})
        assert (
            rotation["authenticator"].authenticate(claiming_b).rejection
            is RemoteRejection.SIGNATURE_INVALID
        )

    def test_5_a_revoked_key_cannot_be_reactivated_by_a_message(
        self, rotation, peer_broker, clock
    ) -> None:
        """No message, however well signed, reaches a method that could do this -- because
        no such method exists and the authenticator calls neither of the two that change
        the registry."""
        rotation["registry"].revoke("key-commander-1", at=clock() - timedelta(minutes=1))
        for _ in range(3):
            rotation["authenticator"].authenticate(
                sign_remote(issue(peer_broker, task_id=f"t-{_}"), key=rotation["key_a"])
            )
        assert rotation["registry"].status("commander", "key-commander-1") is IdentityStatus.REVOKED


class TestAThiefCannotBackDate:
    """The single most important consequence of the documented policy, and it needed its
    own test: a mutation that judged revocation against the *message's* ``created_at``
    survived the whole suite until this existed.

    A peer holding a stolen key controls every timestamp it writes. If admission honoured
    "I signed this before you revoked me", the thief would simply say so.
    """

    def test_a_message_dated_before_the_revocation_is_still_refused(
        self, rotation, peer_broker, clock
    ) -> None:
        # Signed an hour ago by the peer's reckoning; the key was revoked ten minutes ago.
        # Judged against the receiver's clock, this is refused. Judged against the
        # message's own, it would sail through.
        old_clock = clock.now
        clock.now = old_clock - timedelta(hours=1)
        back_dated = sign_remote(issue(peer_broker), key=rotation["key_a"])
        clock.now = old_clock

        rotation["registry"].revoke("key-commander-1", at=old_clock - timedelta(minutes=10))

        assert back_dated.message.created_at < old_clock - timedelta(minutes=10), (
            "the message really is dated before the revocation, or this proves nothing"
        )
        verdict = rotation["authenticator"].authenticate(back_dated)
        assert verdict.rejection is RemoteRejection.IDENTITY_REVOKED

    def test_the_registry_would_have_called_that_moment_active(self, rotation, clock) -> None:
        """The other half, stated explicitly: history *does* say the key was fine then.
        Admission simply does not consult history."""
        rotation["registry"].revoke("key-commander-1", at=clock() - timedelta(minutes=10))
        assert (
            rotation["registry"].historical_status(
                "commander", "key-commander-1", clock() - timedelta(hours=1)
            )
            is IdentityStatus.ACTIVE
        )

    def test_a_message_dated_before_an_expiry_is_refused_too(
        self, keys, peer_broker, signer, clock
    ) -> None:
        """The same reasoning for expiry, which a thief can back-date just as easily."""
        _, _, identities = keys
        old_clock = clock.now
        clock.now = old_clock - timedelta(days=10)
        back_dated = signer("commander", issue(peer_broker))
        clock.now = old_clock

        expired = tuple(
            _shorten(identity, old_clock) if identity.agent_id == "commander" else identity
            for identity in identities
        )
        authenticator = RemoteAuthenticator(RemoteAgentRegistry(expired, clock=clock), clock=clock)
        assert authenticator.authenticate(back_dated).rejection is RemoteRejection.IDENTITY_EXPIRED


def _shorten(identity: RemoteAgentIdentity, now) -> RemoteAgentIdentity:
    """The same identity with a window that closed yesterday."""
    return identity.model_copy(
        update={
            "created_at": now - timedelta(days=30),
            "expires_at": now - timedelta(days=1),
        }
    )


class TestBothKeysLiveAtOnce:
    def test_a_and_b_both_authenticate_before_any_revocation(self, rotation, peer_broker) -> None:
        """The overlap window a real rotation needs: a peer mid-rollout signs with either."""
        for name, key in (
            ("key-commander-1", rotation["key_a"]),
            ("key-commander-2", rotation["key_b"]),
        ):
            remote = sign_remote(issue(peer_broker, task_id=f"task-{name}"), key=key)
            verdict = rotation["authenticator"].authenticate(remote)
            assert verdict.authenticated
            assert verdict.key_id == name

    def test_revoking_one_does_not_touch_the_other(self, rotation, clock) -> None:
        rotation["registry"].revoke("key-commander-1", at=clock() - timedelta(minutes=1))
        assert rotation["registry"].status("commander", "key-commander-1") is IdentityStatus.REVOKED
        assert rotation["registry"].status("commander", "key-commander-2") is IdentityStatus.ACTIVE

    def test_active_keys_reports_the_rollout_state(self, rotation, clock) -> None:
        assert rotation["registry"].active_keys_for("commander") == (
            "key-commander-1",
            "key-commander-2",
        )
        rotation["registry"].revoke("key-commander-1", at=clock() - timedelta(minutes=1))
        assert rotation["registry"].active_keys_for("commander") == ("key-commander-2",)


class TestHistoryIsNotRewritten:
    def test_the_old_record_is_still_there_after_revocation(self, rotation, clock) -> None:
        """A rotation history with the old keys deleted is not a history."""
        rotation["registry"].revoke("key-commander-1", at=clock())
        identity = rotation["registry"].identity("key-commander-1")
        assert identity is not None
        assert identity.revoked_at == clock()

    def test_historical_verification_survives(self, rotation, clock) -> None:
        rotation["registry"].revoke("key-commander-1", at=clock())
        assert (
            rotation["registry"].historical_status(
                "commander", "key-commander-1", clock() - timedelta(days=1)
            )
            is IdentityStatus.ACTIVE
        )

    def test_an_old_signature_still_verifies_mathematically(
        self, rotation, peer_broker, clock
    ) -> None:
        """Revocation is an authorization fact, not a mathematical one. Conflating them
        would make an audit of a compromise impossible."""
        remote = sign_remote(issue(peer_broker), key=rotation["key_a"])
        rotation["registry"].revoke("key-commander-1", at=clock())
        verifier = rotation["registry"].verifier("key-commander-1")
        assert verifier is not None
        assert verifier.verify(signing_payload(remote), remote.signature)

    def test_but_verifiable_is_not_admissible(self, rotation, peer_broker, clock) -> None:
        """The two halves of the documented policy, side by side in one test so nobody can
        quote half of it."""
        remote = sign_remote(issue(peer_broker), key=rotation["key_a"])
        rotation["registry"].revoke("key-commander-1", at=clock())
        verifier = rotation["registry"].verifier("key-commander-1")
        assert verifier is not None
        assert verifier.verify(signing_payload(remote), remote.signature)
        assert not rotation["authenticator"].authenticate(remote).authenticated


class TestTheRotationDocsSayWhatTheCodeDoes:
    def test_the_policy_is_written_down(self) -> None:
        """A documented policy that lives only in a test is not documented."""
        import pathlib

        doc = pathlib.Path("docs/A2A.md").read_text(encoding="utf-8").lower()
        assert "revoked key admits nothing" in doc
        assert "historical" in doc

    def test_the_registry_docstring_states_the_reasoning(self) -> None:
        text = RemoteAgentRegistry.historical_status.__doc__ or ""
        assert "revoked key admits nothing" in text.lower()
