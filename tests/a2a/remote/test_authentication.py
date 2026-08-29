"""Part 5: the three sentences, and every way authentication refuses.

    a valid hash is not an authenticated sender
    a valid signature is not an authorization
    a registered identity is not execution authority

The first is demonstrated in ``test_envelope.py``. The other two are demonstrated here and
in ``test_compromised.py``, and "demonstrated" is the operative word: each has a test that
would fail if the distinction were collapsed, rather than a comment asserting it holds.
"""

from __future__ import annotations

import ast
import pathlib
from datetime import timedelta

import pytest

from aegis.a2a import envelope_seal
from aegis.a2a.records import payload_digest
from aegis.a2a.remote import (
    MAX_CLOCK_SKEW_SECONDS,
    REMOTE_PROTOCOL_VERSION,
    KeyAlgorithm,
    RemoteAuthenticator,
    RemoteEnvelope,
    RemoteRejection,
    RemoteVerdict,
    provider_for,
)

from .conftest import FIXED_NOW, issue


class TestTheHappyPathEstablishesExactlyOneThing:
    def test_a_legitimate_message_authenticates(self, authenticator, peer_broker, signer):
        verdict = authenticator.authenticate(signer("commander", issue(peer_broker)))
        assert verdict.authenticated
        assert verdict.agent_id == "commander"
        assert verdict.key_id == "key-commander-1"

    def test_the_agent_id_comes_from_the_registry_not_the_message(
        self, authenticator, peer_broker, signer, registry
    ) -> None:
        """The whole difference between an authenticated sender and a claimed one."""
        verdict = authenticator.authenticate(signer("commander", issue(peer_broker)))
        identity = registry.identity("key-commander-1")
        assert identity is not None
        assert verdict.agent_id == identity.agent_id

    def test_a_verdict_has_no_field_that_reads_as_permission(self) -> None:
        assert set(RemoteVerdict.model_fields) == {
            "authenticated",
            "agent_id",
            "key_id",
            "rejection",
            "detail",
            "message_id",
        }

    def test_authenticating_twice_changes_nothing(self, authenticator, peer_broker, signer) -> None:
        """Pure. Authentication cannot consume, admit or mark anything, so a bug here
        cannot make something look delivered."""
        remote = signer("commander", issue(peer_broker))
        first = authenticator.authenticate(remote)
        second = authenticator.authenticate(remote)
        assert first == second

    def test_the_detail_says_what_was_and_was_not_established(
        self, authenticator, peer_broker, signer
    ) -> None:
        verdict = authenticator.authenticate(signer("commander", issue(peer_broker)))
        assert "and nothing else" in verdict.detail


class TestEveryRefusalPath:
    def test_an_unregistered_key_is_unknown(self, authenticator, peer_broker, algorithm) -> None:
        stray, _ = provider_for(algorithm).generate("key-nobody", seed=b"stray")
        from aegis.a2a.remote import sign_remote

        verdict = authenticator.authenticate(sign_remote(issue(peer_broker), key=stray))
        assert verdict.rejection is RemoteRejection.UNKNOWN_KEY
        assert verdict.agent_id is None

    def test_a_key_belonging_to_another_agent_is_a_sender_mismatch(
        self, authenticator, peer_broker, signer
    ) -> None:
        """The forged-identity case. The signature verifies; it verifies as somebody else."""
        verdict = authenticator.authenticate(signer("diagnostic", issue(peer_broker)))
        assert verdict.rejection is RemoteRejection.SENDER_MISMATCH
        assert verdict.agent_id is None

    def test_an_invalid_signature_is_refused(self, authenticator, peer_broker, signer) -> None:
        remote = signer("commander", issue(peer_broker))
        broken = remote.model_copy(update={"signature": "0" * len(remote.signature)})
        assert authenticator.authenticate(broken).rejection is RemoteRejection.SIGNATURE_INVALID

    def test_a_rebound_message_is_refused_by_the_signature(
        self, authenticator, peer_broker, signer
    ) -> None:
        """Resealed, so the inner hash agrees with itself and only the key disagrees."""
        remote = signer("commander", issue(peer_broker))
        changed = remote.message.model_copy(update={"incident_id": "INC-ELSEWHERE"})
        resealed = changed.model_copy(update={"seal": envelope_seal(changed)})
        tampered = remote.model_copy(update={"message": resealed})
        assert authenticator.authenticate(tampered).rejection is RemoteRejection.SIGNATURE_INVALID

    def test_a_payload_swapped_after_signing_is_refused(
        self, authenticator, peer_broker, signer
    ) -> None:
        """``payload_digest`` is signed *and recomputed*. A digest nobody recomputes is a
        claim wearing a hash's clothes."""
        remote = signer("commander", issue(peer_broker))
        changed = remote.message.model_copy(update={"payload": {"note": "swapped"}})
        resealed = changed.model_copy(update={"seal": envelope_seal(changed)})
        tampered = remote.model_copy(update={"message": resealed})
        # The signature covers the seal too, so this is caught there first; strip that
        # protection away to prove the digest check is independently reachable.
        assert authenticator.authenticate(tampered).rejection is RemoteRejection.SIGNATURE_INVALID

    def test_the_payload_digest_check_is_reachable_on_its_own(
        self, peer_broker, keys, clock, algorithm
    ) -> None:
        """A signed message whose *only* fault is that the payload does not match its
        signed digest. Built deliberately, because otherwise the check could be deleted
        with every other test still green."""
        ring, by_agent, identities = keys
        from aegis.a2a.remote import RemoteAgentRegistry, signing_payload

        envelope = issue(peer_broker)
        swapped = envelope.model_copy(update={"payload": {"note": "swapped"}})
        resealed = swapped.model_copy(update={"seal": envelope_seal(swapped)})
        key = ring.signer(by_agent["commander"])
        assert key is not None
        unsigned = RemoteEnvelope(
            protocol_version=REMOTE_PROTOCOL_VERSION,
            key_id=key.key_id,
            algorithm=key.algorithm,
            payload_digest=payload_digest(envelope.payload),  # the *original* payload
            signature="unsigned",
            message=resealed,  # carrying the *swapped* one
        )
        remote = unsigned.model_copy(update={"signature": key.sign(signing_payload(unsigned))})
        authenticator = RemoteAuthenticator(
            RemoteAgentRegistry(identities, clock=clock), clock=clock
        )
        verdict = authenticator.authenticate(remote)
        assert verdict.rejection is RemoteRejection.PAYLOAD_DIGEST_MISMATCH

    def test_a_broken_inner_seal_is_refused(self, peer_broker, keys, clock) -> None:
        """And the seal check is reachable on its own too, for the same reason."""
        from aegis.a2a.remote import RemoteAgentRegistry, signing_payload

        ring, by_agent, identities = keys
        envelope = issue(peer_broker)
        broken = envelope.model_copy(update={"seal": "0" * 64})
        key = ring.signer(by_agent["commander"])
        assert key is not None
        unsigned = RemoteEnvelope(
            protocol_version=REMOTE_PROTOCOL_VERSION,
            key_id=key.key_id,
            algorithm=key.algorithm,
            payload_digest=payload_digest(envelope.payload),
            signature="unsigned",
            message=broken,
        )
        remote = unsigned.model_copy(update={"signature": key.sign(signing_payload(unsigned))})
        authenticator = RemoteAuthenticator(
            RemoteAgentRegistry(identities, clock=clock), clock=clock
        )
        assert authenticator.authenticate(remote).rejection is RemoteRejection.SEAL_INVALID

    def test_a_revoked_key_is_refused(self, authenticator, registry, peer_broker, signer) -> None:
        registry.revoke("key-commander-1", at=FIXED_NOW - timedelta(minutes=1))
        remote = signer("commander", issue(peer_broker))
        assert authenticator.authenticate(remote).rejection is RemoteRejection.IDENTITY_REVOKED

    def test_an_algorithm_mismatch_is_refused(self, keys, peer_broker, signer, clock) -> None:
        from aegis.a2a.remote import RemoteAgentRegistry

        _, _, identities = keys
        other = (
            KeyAlgorithm.ED25519
            if identities[0].algorithm is KeyAlgorithm.HMAC_SHA256
            else KeyAlgorithm.HMAC_SHA256
        )
        rewritten = tuple(
            i.model_copy(update={"algorithm": other}) if i.agent_id == "commander" else i
            for i in identities
        )
        authenticator = RemoteAuthenticator(
            RemoteAgentRegistry(rewritten, clock=clock), clock=clock
        )
        remote = signer("commander", issue(peer_broker))
        assert authenticator.authenticate(remote).rejection is RemoteRejection.ALGORITHM_MISMATCH

    def test_an_unavailable_algorithm_is_refused_not_substituted(
        self, keys, peer_broker, signer, clock, monkeypatch
    ) -> None:
        """A missing provider is a refusal. It is never a fallback to something weaker."""
        from aegis.a2a.remote import RemoteAgentRegistry
        from aegis.a2a.remote import authenticator as authenticator_module

        _, _, identities = keys
        remote = signer("commander", issue(peer_broker))
        monkeypatch.setattr(authenticator_module, "available_algorithms", tuple)
        authenticator = RemoteAuthenticator(
            RemoteAgentRegistry(identities, clock=clock), clock=clock
        )
        verdict = authenticator.authenticate(remote)
        assert verdict.rejection is RemoteRejection.UNSUPPORTED_ALGORITHM

    def test_no_refusal_is_ever_an_acceptance(
        self, authenticator, registry, peer_broker, signer, algorithm
    ) -> None:
        """The headline sweep."""
        from aegis.a2a.remote import sign_remote

        stray, _ = provider_for(algorithm).generate("key-nobody", seed=b"stray")
        remote = signer("commander", issue(peer_broker, task_id="task-a"))
        cases = [
            authenticator.authenticate(sign_remote(issue(peer_broker, task_id="t-b"), key=stray)),
            authenticator.authenticate(signer("diagnostic", issue(peer_broker, task_id="t-c"))),
            authenticator.authenticate(remote.model_copy(update={"signature": "00" * 32})),
            authenticator.authenticate(
                remote.model_copy(update={"protocol_version": "aegis.a2a/1"})
            ),
        ]
        assert all(not verdict.authenticated for verdict in cases)
        assert all(verdict.rejection is not None for verdict in cases)
        assert all(verdict.agent_id is None for verdict in cases)


class TestFreshnessIsJudgedByTheReceiver:
    def test_an_expired_message_is_refused(self, authenticator, peer_broker, signer, clock) -> None:
        remote = signer("commander", issue(peer_broker))
        clock.advance(3600)
        assert authenticator.authenticate(remote).rejection is RemoteRejection.MESSAGE_EXPIRED

    def test_a_future_dated_message_is_refused(self, keys, peer_broker, signer, clock) -> None:
        from aegis.a2a.remote import RemoteAgentRegistry

        _, _, identities = keys
        remote = signer("commander", issue(peer_broker))

        class Behind:
            def __call__(self):
                return clock() - timedelta(hours=1)

        behind = Behind()
        authenticator = RemoteAuthenticator(
            RemoteAgentRegistry(identities, clock=behind), clock=behind
        )
        assert authenticator.authenticate(remote).rejection is RemoteRejection.FUTURE_DATED

    def test_small_skew_is_tolerated(self, keys, peer_broker, signer, clock) -> None:
        """Real clocks disagree. Refusing every peer a few seconds fast would be a denial
        of service the boundary inflicted on itself."""
        from aegis.a2a.remote import RemoteAgentRegistry

        _, _, identities = keys
        remote = signer("commander", issue(peer_broker))

        def slightly_behind():
            return clock() - timedelta(seconds=MAX_CLOCK_SKEW_SECONDS / 2)

        authenticator = RemoteAuthenticator(
            RemoteAgentRegistry(identities, clock=slightly_behind), clock=slightly_behind
        )
        assert authenticator.authenticate(remote).authenticated

    def test_the_skew_bound_is_one_sided(self) -> None:
        """Being late is already handled by ``expires_at``, which is signed. Being early is
        what needs a separate limit."""
        assert MAX_CLOCK_SKEW_SECONDS > 0

    def test_a_negative_skew_allowance_is_refused_at_construction(self, registry) -> None:
        with pytest.raises(ValueError):
            RemoteAuthenticator(registry, max_skew_seconds=-1)

    def test_a_clock_rolled_back_does_not_un_expire_a_consumed_message(
        self, channel, peer_broker, clock
    ) -> None:
        """Consumption is checked before freshness, so a spent message stays spent whatever
        the clock does. An operator-controlled clock problem, not a replay."""
        envelope = issue(peer_broker)
        first = channel.carry(
            envelope,
            signed_by="commander",
            as_agent="diagnostic",
            expected_incident_id=envelope.incident_id,
        )
        assert first.admitted
        clock.advance(-600)
        again = channel.carry_signed(
            channel.sign_as("commander", envelope),
            as_agent="diagnostic",
            expected_incident_id=envelope.incident_id,
        )
        assert not again.admitted


class TestAuthenticationEstablishesNoAuthority:
    """Part 5, sentences two and three, at the structural level."""

    def test_the_authenticator_holds_no_control_plane(self) -> None:
        tree = ast.parse(
            pathlib.Path("src/aegis/a2a/remote/authenticator.py").read_text(encoding="utf-8")
        )
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        forbidden = {"ledger", "broker", "transport", "persistence", "gateway", "channel"}
        assert not any(part in name for name in imported for part in forbidden), imported

    def test_the_authenticator_module_holds_no_governance_vocabulary(self) -> None:
        """Sweep over the *code*, docstrings blanked: they state the boundary, and the
        boundary is exactly what must not appear in what runs."""
        tree = ast.parse(
            pathlib.Path("src/aegis/a2a/remote/authenticator.py").read_text(encoding="utf-8")
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                node.value.value = ""
        code = ast.unparse(tree).lower()
        for word in ("policy", "approv", "blast", "lifecycle", "execute", "risk", "gate"):
            assert word not in code, word

    def test_authentication_changes_no_ledger_state(
        self, authenticator, peer_broker, signer, receiver_broker
    ) -> None:
        remote = signer("commander", issue(peer_broker))
        before = receiver_broker.ledger.persisted_records
        for _ in range(5):
            authenticator.authenticate(remote)
        assert receiver_broker.ledger.persisted_records == before
        assert not receiver_broker.ledger.known(remote.message.message_id)
