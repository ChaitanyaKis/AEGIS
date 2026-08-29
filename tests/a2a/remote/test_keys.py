"""Part 3: signing, verifying, and the things a key must never do.

The properties here are the ones a signature scheme is worth nothing without: a signature
belongs to exactly one key and exactly one message, an unsupported algorithm is refused
rather than substituted, and key material never leaves the object holding it.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from aegis.a2a.remote import (
    MAX_SIGNATURE_HEX,
    HmacKeyProvider,
    KeyAlgorithm,
    KeyProvider,
    KeyRing,
    SigningKey,
    UnsupportedAlgorithm,
    VerifyingKey,
    available_algorithms,
    looks_like_a_signature,
    provider_for,
)

from .conftest import issue as issue_message

MESSAGE = b"the exact bytes that were signed"
OTHER = b"the exact bytes that were not"


class TestTheAlgorithmVocabularyIsClosed:
    def test_there_is_no_none_algorithm(self) -> None:
        """An algorithm that does not authenticate is a downgrade with a spelling."""
        names = {member.name for member in KeyAlgorithm}
        assert "NONE" not in names
        assert not any("none" in member.value.lower() for member in KeyAlgorithm)

    def test_an_unknown_algorithm_is_not_constructible(self) -> None:
        with pytest.raises(ValueError):
            KeyAlgorithm("MD5")

    def test_hmac_is_always_available(self) -> None:
        """The standard-library algorithm, so the benchmark needs no third-party package."""
        assert KeyAlgorithm.HMAC_SHA256 in available_algorithms()

    def test_availability_is_reported_rather_than_assumed(self) -> None:
        from aegis.a2a.remote import ED25519_AVAILABLE

        assert (KeyAlgorithm.ED25519 in available_algorithms()) is ED25519_AVAILABLE

    def test_an_unhandled_algorithm_raises_where_material_is_requested(self) -> None:
        """And nowhere else: a message naming it produces a verdict, never an exception."""

        class Fake(str):
            pass

        with pytest.raises(UnsupportedAlgorithm):
            provider_for(Fake("Curve-Nonexistent"))


class TestSignaturesBindOneKeyToOneMessage:
    def test_a_signature_verifies_for_the_message_it_signed(self, algorithm) -> None:
        signer, verifier = provider_for(algorithm).generate("k1", seed=b"a")
        assert verifier.verify(MESSAGE, signer.sign(MESSAGE))

    def test_a_signature_does_not_verify_for_another_message(self, algorithm) -> None:
        signer, verifier = provider_for(algorithm).generate("k1", seed=b"a")
        assert not verifier.verify(OTHER, signer.sign(MESSAGE))

    def test_a_signature_from_key_a_does_not_validate_as_key_b(self, algorithm) -> None:
        """The Part 3 requirement, at the primitive level."""
        provider = provider_for(algorithm)
        signer_a, _ = provider.generate("k-a", seed=b"a")
        _, verifier_b = provider.generate("k-b", seed=b"b")
        assert not verifier_b.verify(MESSAGE, signer_a.sign(MESSAGE))

    def test_one_flipped_byte_breaks_it(self, algorithm) -> None:
        signer, verifier = provider_for(algorithm).generate("k1", seed=b"a")
        signature = signer.sign(MESSAGE)
        broken = ("0" if signature[0] != "0" else "1") + signature[1:]
        assert not verifier.verify(MESSAGE, broken)

    def test_signing_is_deterministic_for_a_seeded_key(self, algorithm) -> None:
        """So a failing run reproduces. Not a security property; a debuggability one."""
        provider = provider_for(algorithm)
        first, _ = provider.generate("k1", seed=b"seed")
        second, _ = provider.generate("k1", seed=b"seed")
        assert first.sign(MESSAGE) == second.sign(MESSAGE)

    def test_different_seeds_produce_different_keys(self, algorithm) -> None:
        provider = provider_for(algorithm)
        _, one = provider.generate("k1", seed=b"one")
        _, two = provider.generate("k1", seed=b"two")
        assert one.material != two.material

    def test_an_unseeded_key_is_not_reproducible(self, algorithm) -> None:
        """Randomness where randomness belongs: real key generation, not the fixtures."""
        provider = provider_for(algorithm)
        _, one = provider.generate("k1")
        _, two = provider.generate("k1")
        assert one.material != two.material


class TestVerificationNeverRaises:
    """A hostile signature must be ``False``, not an exception.

    A verifier that raised on one malformed shape and returned ``False`` on another would
    let the *form* of a forgery choose which code path runs next.
    """

    @pytest.mark.parametrize(
        "signature",
        [
            "",
            "not hex at all",
            "zz",
            "0",
            "00" * 200,
            "f" * (MAX_SIGNATURE_HEX + 10),
        ],
    )
    def test_a_malformed_signature_is_false(self, algorithm, signature: str) -> None:
        _, verifier = provider_for(algorithm).generate("k1", seed=b"a")
        assert verifier.verify(MESSAGE, signature) is False

    def test_an_absurdly_long_signature_is_refused_by_length_first(self, algorithm) -> None:
        _, verifier = provider_for(algorithm).generate("k1", seed=b"a")
        assert not verifier.verify(MESSAGE, "a" * (MAX_SIGNATURE_HEX + 1))

    def test_the_length_bound_refuses_plausible_hex_too(self, algorithm) -> None:
        """Discriminating, because the obvious version above is refused for a different
        reason: an odd number of characters is not a byte string, so parity catches it and
        the length bound never runs.

        This one is even-length, entirely hex, and simply too long -- so the bound is the
        only thing that can refuse it. Without this, dropping the bound changed no verdict
        anywhere and the check could have been deleted unnoticed.
        """
        oversized = "ab" * (MAX_SIGNATURE_HEX // 2 + 1)
        assert len(oversized) % 2 == 0
        assert all(character in "0123456789abcdef" for character in oversized)
        assert len(oversized) > MAX_SIGNATURE_HEX
        assert not looks_like_a_signature(oversized)

        _, verifier = provider_for(algorithm).generate("k1", seed=b"a")
        assert not verifier.verify(MESSAGE, oversized)

    def test_a_correctly_sized_hex_signature_reaches_the_comparison(self, algorithm) -> None:
        """The other half: the bound must not refuse a real signature."""
        signer, verifier = provider_for(algorithm).generate("k1", seed=b"a")
        signature = signer.sign(MESSAGE)
        assert looks_like_a_signature(signature)
        assert verifier.verify(MESSAGE, signature)

    @pytest.mark.parametrize(
        "signature",
        [
            "\u00fc" * 8,
            "\u7b7e\u540d",
            "\x00\x01",
            "sig\nnewline",
            "\u200b" * 4,
        ],
    )
    def test_a_non_ascii_signature_is_false_not_an_exception(
        self, algorithm, signature: str
    ) -> None:
        """Written after a mutation survived. ``hmac.compare_digest`` raises on non-ASCII
        text, so removing the length-and-emptiness guard turned a hostile signature into an
        exception in the middle of judging a message -- and nothing in the suite noticed,
        because every test signature happened to be hex.

        A message being judged must always end in a verdict. An exception there is a
        message nothing decided about, somewhere that assumed something had.
        """
        _, verifier = provider_for(algorithm).generate("k1", seed=b"a")
        assert verifier.verify(MESSAGE, signature) is False

    def test_a_non_ascii_signature_is_refused_at_the_boundary_too(
        self, authenticator, peer_broker, signer
    ) -> None:
        """End to end, because a verdict is what the boundary owes its caller."""
        from aegis.a2a.remote import RemoteRejection

        remote = signer("commander", issue_message(peer_broker))
        hostile = remote.model_copy(update={"signature": "ü" * 16})
        verdict = authenticator.authenticate(hostile)
        assert verdict.rejection is RemoteRejection.SIGNATURE_INVALID

    def test_unreadable_registered_material_verifies_nothing(self, algorithm) -> None:
        """Corrupt registry material must not crash a boundary mid-judgement."""
        verifier = provider_for(algorithm).verifier("k1", "zzzz")
        assert verifier.verify(MESSAGE, "00" * 32) is False


class TestTheComparisonIsConstantTime:
    def test_the_hmac_provider_uses_compare_digest(self) -> None:
        """Structural, because timing is not observable from a unit test.

        A ``==`` here would leak how much of a forged tag was correct. The assertion is on
        the source rather than on behaviour precisely because the behaviour is the thing a
        test cannot see.
        """
        source = pathlib.Path("src/aegis/a2a/remote/keys.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        # The concrete key, not the Protocol's stub -- a stub containing ``...`` would pass
        # any assertion about what it does not contain.
        key_class = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == "_HmacKey"
        )
        verify = next(
            node
            for node in key_class.body
            if isinstance(node, ast.FunctionDef) and node.name == "verify"
        )
        calls = {
            node.func.attr
            for node in ast.walk(verify)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert "compare_digest" in calls
        comparisons = [node for node in ast.walk(verify) if isinstance(node, ast.Compare)]
        assert all(not any(isinstance(op, ast.Eq) for op in node.ops) for node in comparisons), (
            "the signature comparison must not use =="
        )


class TestKeyMaterialStaysWhereItIs:
    def test_a_key_ring_never_renders_material(self, keys) -> None:
        ring, by_agent, _ = keys
        rendered = repr(ring)
        for key_id in by_agent.values():
            signer = ring.signer(key_id)
            assert signer is not None
            assert repr(signer).count("=") <= 2, repr(signer)
        assert "material" not in rendered

    def test_a_signing_key_repr_carries_no_secret(self, algorithm) -> None:
        signer, verifier = provider_for(algorithm).generate("k1", seed=b"a")
        assert verifier.material not in repr(signer)
        assert verifier.material not in repr(verifier)

    def test_a_signing_key_protocol_has_no_export_method(self) -> None:
        """A ``SigningKey`` that could export itself is one somebody will export."""
        surface = {name for name in dir(SigningKey) if not name.startswith("_")}
        assert surface == {"algorithm", "key_id", "sign"}

    def test_a_verifying_key_cannot_sign(self, algorithm) -> None:
        """True for Ed25519 by construction. For a symmetric MAC it is not, and the
        docstrings say so rather than the type pretending otherwise."""
        _, verifier = provider_for(algorithm).generate("k1", seed=b"a")
        if algorithm is KeyAlgorithm.ED25519:
            assert not hasattr(verifier, "sign")
        else:
            assert hasattr(verifier, "sign"), "a symmetric key signs; the docs must say so"


class TestTheKeyRing:
    def test_a_key_id_is_matched_exactly(self, keys) -> None:
        ring, _, _ = keys
        assert ring.signer("key-commander-1") is not None
        assert ring.signer("key-commander-1 ") is None
        assert ring.signer("KEY-COMMANDER-1") is None

    def test_a_duplicate_key_id_is_refused(self, algorithm) -> None:
        """Overwriting would silently change which key an agent signs with."""
        ring = KeyRing()
        provider = provider_for(algorithm)
        first, _ = provider.generate("k1", seed=b"a")
        second, _ = provider.generate("k1", seed=b"b")
        ring.add(first)
        with pytest.raises(ValueError, match="already held"):
            ring.add(second)

    def test_a_key_ring_offers_no_removal(self) -> None:
        surface = {name for name in dir(KeyRing) if not name.startswith("_")}
        assert surface == {"add", "key_ids", "signer"}

    def test_an_empty_ring_signs_for_nobody(self) -> None:
        assert KeyRing().signer("anything") is None


class TestAnAgentWithNoKeySignsNothing:
    """Written after a mutation survived. ``sign_as`` falling back to *any* held key was
    invisible to the whole suite, because every agent in every fixture had one.

    A fallback there would be this process impersonating one of its own agents, which is
    exactly what the package exists to make impossible.
    """

    def test_an_unknown_agent_gets_no_signature(self, channel, peer_broker) -> None:
        from .conftest import issue

        assert channel.sign_as("nobody-at-all", issue(peer_broker)) is None

    def test_an_agent_whose_key_is_missing_gets_no_signature(self, channel, peer_broker) -> None:
        from .conftest import issue

        channel.keys_by_agent["ghost"] = "key-that-was-never-added"
        assert channel.sign_as("ghost", issue(peer_broker)) is None

    def test_signs_for_reports_the_same_answer(self, channel) -> None:
        assert channel.signs_for("commander")
        assert not channel.signs_for("nobody-at-all")

    def test_carrying_for_an_agent_with_no_key_is_a_refusal(self, channel, peer_broker) -> None:
        from .conftest import INCIDENT, issue

        delivery = channel.carry(
            issue(peer_broker),
            signed_by="nobody-at-all",
            as_agent="diagnostic",
            expected_incident_id=INCIDENT,
        )
        assert not delivery.authenticated
        assert not delivery.admitted
        assert delivery.verdict.rejection is not None

    def test_it_did_not_borrow_another_agents_key(self, channel, peer_broker) -> None:
        """The discriminating assertion: nothing was sent at all, rather than something
        sent under a borrowed identity."""
        from .conftest import INCIDENT, issue

        channel.carry(
            issue(peer_broker),
            signed_by="nobody-at-all",
            as_agent="diagnostic",
            expected_incident_id=INCIDENT,
        )
        assert channel.transport.sent == ()
        assert channel.transport.carried == ()


class TestTheProvidersSatisfyTheProtocol:
    def test_hmac(self) -> None:
        assert isinstance(HmacKeyProvider(), KeyProvider)

    def test_every_available_provider(self, algorithm) -> None:
        provider = provider_for(algorithm)
        assert isinstance(provider, KeyProvider)
        assert provider.algorithm is algorithm

    def test_generated_keys_satisfy_their_protocols(self, algorithm) -> None:
        signer, verifier = provider_for(algorithm).generate("k1", seed=b"a")
        assert isinstance(signer, SigningKey)
        assert isinstance(verifier, VerifyingKey)
        assert signer.key_id == verifier.key_id == "k1"
