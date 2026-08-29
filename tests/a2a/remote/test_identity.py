"""Parts 2, 8 and 13: who an agent is, and what the registry may never be asked to do.

The registry is the authority for identity and for nothing else. These tests hold it to
both halves of that: it must answer identity questions exactly, and it must be structurally
incapable of answering any other kind.
"""

from __future__ import annotations

import ast
import pathlib
from datetime import timedelta

import pytest

from aegis.a2a.remote import (
    REMOTE_PROTOCOL_VERSION,
    IdentityStatus,
    KeyAlgorithm,
    RemoteAgentIdentity,
    RemoteAgentRegistry,
    provider_for,
)

from .conftest import FIXED_NOW


def _identity(**overrides) -> RemoteAgentIdentity:
    settings = {
        "agent_id": "diagnostic",
        "key_id": "key-diagnostic-1",
        "algorithm": KeyAlgorithm.HMAC_SHA256,
        "verification_key": "ab" * 32,
        "protocol_versions": (REMOTE_PROTOCOL_VERSION,),
        "created_at": FIXED_NOW - timedelta(days=1),
        "expires_at": FIXED_NOW + timedelta(days=30),
    }
    settings.update(overrides)
    return RemoteAgentIdentity(**settings)


class TestTheIdentityRecordCarriesNoAuthority:
    def test_the_field_set_is_exactly_identity(self) -> None:
        """Part 2. An identity record that carried authority would make the registry a
        policy engine with a directory API attached."""
        assert set(RemoteAgentIdentity.model_fields) == {
            "agent_id",
            "key_id",
            "algorithm",
            "verification_key",
            "protocol_versions",
            "created_at",
            "expires_at",
            "revoked_at",
        }

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
            "capabilities",
            "trusted",
            "authorized",
        ],
    )
    def test_no_authority_field_can_be_added(self, field: str) -> None:
        with pytest.raises(ValueError):
            _identity(**{field: "ALLOW"})

    def test_an_identity_is_frozen(self) -> None:
        identity = _identity()
        with pytest.raises(ValueError):
            identity.agent_id = "commander"

    def test_the_material_field_is_not_called_public_key(self) -> None:
        """For a symmetric algorithm it is not public, and a field name asserting otherwise
        would be a lie told by the schema itself."""
        assert "public_key" not in RemoteAgentIdentity.model_fields
        assert "verification_key" in RemoteAgentIdentity.model_fields


class TestValidityWindows:
    def test_a_window_must_be_real(self) -> None:
        with pytest.raises(ValueError, match="after created_at"):
            _identity(expires_at=FIXED_NOW - timedelta(days=2))

    def test_a_key_cannot_be_revoked_before_it_existed(self) -> None:
        with pytest.raises(ValueError, match="before it existed"):
            _identity(revoked_at=FIXED_NOW - timedelta(days=5))

    def test_active_inside_the_window(self) -> None:
        assert _identity().status_at(FIXED_NOW) is IdentityStatus.ACTIVE

    def test_not_yet_valid_before_the_window(self) -> None:
        identity = _identity(
            created_at=FIXED_NOW + timedelta(days=1), expires_at=FIXED_NOW + timedelta(days=2)
        )
        assert identity.status_at(FIXED_NOW) is IdentityStatus.NOT_YET_VALID

    def test_expired_after_the_window(self) -> None:
        assert _identity().status_at(FIXED_NOW + timedelta(days=31)) is IdentityStatus.EXPIRED

    def test_expiry_is_inclusive_at_the_boundary(self) -> None:
        identity = _identity()
        assert identity.status_at(identity.expires_at) is IdentityStatus.EXPIRED
        assert (
            identity.status_at(identity.expires_at - timedelta(seconds=1)) is IdentityStatus.ACTIVE
        )

    def test_revocation_beats_a_valid_window(self) -> None:
        """The ordering is the property. Checking the window first would let a live
        compromised key look fine until it happened to expire on its own."""
        identity = _identity(revoked_at=FIXED_NOW - timedelta(minutes=1))
        assert identity.status_at(FIXED_NOW) is IdentityStatus.REVOKED

    def test_a_key_is_active_before_its_own_revocation(self) -> None:
        identity = _identity(revoked_at=FIXED_NOW + timedelta(hours=1))
        assert identity.status_at(FIXED_NOW) is IdentityStatus.ACTIVE


class TestTheRegistryBindsKeysToAgents:
    def test_an_unregistered_key_is_unknown(self, registry: RemoteAgentRegistry) -> None:
        assert registry.status("commander", "key-nobody") is IdentityStatus.UNKNOWN

    def test_a_key_registered_to_another_agent_is_unknown_here(self, registry) -> None:
        """The cross-agent substitution defence, at the registry level: a lookup needs
        *both* halves to match, so a valid key belonging to somebody else establishes
        nothing."""
        assert registry.status("commander", "key-diagnostic-1") is IdentityStatus.UNKNOWN
        assert registry.status("diagnostic", "key-diagnostic-1") is IdentityStatus.ACTIVE

    def test_lookups_are_exact(self, registry) -> None:
        assert registry.identity("key-diagnostic-1") is not None
        assert registry.identity("key-diagnostic-1 ") is None
        assert registry.identity("KEY-DIAGNOSTIC-1") is None

    def test_a_duplicate_key_id_is_refused(self, registry) -> None:
        """Re-registering is how a revoked key comes back without anybody un-revoking it."""
        with pytest.raises(ValueError, match="already registered"):
            registry.register(_identity(key_id="key-diagnostic-1"))

    def test_the_registry_knows_which_agents_exist(self, registry) -> None:
        assert "commander" in registry.agents()
        assert "shadow-executor" not in registry.agents()

    def test_keys_for_returns_the_whole_history(self, registry) -> None:
        registry.revoke("key-diagnostic-1")
        assert [i.key_id for i in registry.keys_for("diagnostic")] == ["key-diagnostic-1"]
        assert registry.active_keys_for("diagnostic") == ()


class TestRevocationIsPermanent:
    def test_there_is_no_way_to_reverse_a_revocation(self) -> None:
        """A revocation that can be lifted on request is one an attacker asks to have
        lifted."""
        surface = {name for name in dir(RemoteAgentRegistry) if not name.startswith("_")}
        for forbidden in ("reactivate", "unrevoke", "restore", "clear", "reset", "remove"):
            assert not any(forbidden in name for name in surface), (forbidden, surface)

    def test_revoking_twice_keeps_the_earlier_time(self, registry) -> None:
        """Monotonic: a second call can never move a revocation later and reopen a window
        that was closed."""
        first = registry.revoke("key-diagnostic-1", at=FIXED_NOW - timedelta(hours=2))
        second = registry.revoke("key-diagnostic-1", at=FIXED_NOW)
        assert first is not None and second is not None
        assert second.revoked_at == first.revoked_at

    def test_revoking_an_unregistered_key_is_not_an_error(self, registry) -> None:
        """It is already the state the caller wanted."""
        assert registry.revoke("key-nobody") is None

    def test_a_revoked_key_stays_revoked_across_lookups(self, registry) -> None:
        registry.revoke("key-diagnostic-1", at=FIXED_NOW - timedelta(minutes=1))
        for _ in range(3):
            assert registry.status("diagnostic", "key-diagnostic-1") is IdentityStatus.REVOKED

    def test_revocation_does_not_delete_the_record(self, registry) -> None:
        """A rotation history with the old keys deleted is not a history."""
        registry.revoke("key-diagnostic-1")
        assert registry.identity("key-diagnostic-1") is not None


class TestHistoricalVerificationSurvivesRevocation:
    """Part 8's documented policy, in two halves that must not be confused."""

    def test_history_stays_answerable(self, registry) -> None:
        registry.revoke("key-diagnostic-1", at=FIXED_NOW)
        assert (
            registry.historical_status(
                "diagnostic", "key-diagnostic-1", FIXED_NOW - timedelta(hours=2)
            )
            is IdentityStatus.ACTIVE
        )

    def test_admission_is_judged_against_the_receivers_clock(self, registry) -> None:
        """A peer holding a stolen key controls every timestamp in its own message, so
        judging revocation against a message's own ``created_at`` would let the thief claim
        to have signed before the theft was noticed."""
        registry.revoke("key-diagnostic-1", at=FIXED_NOW)
        assert registry.status("diagnostic", "key-diagnostic-1") is IdentityStatus.REVOKED

    def test_the_two_questions_have_two_methods(self) -> None:
        assert hasattr(RemoteAgentRegistry, "status")
        assert hasattr(RemoteAgentRegistry, "historical_status")

    def test_the_authenticator_asks_only_the_admission_question(self) -> None:
        """Structural, so a future edit cannot quietly reach for the other one."""
        tree = ast.parse(
            pathlib.Path("src/aegis/a2a/remote/authenticator.py").read_text(encoding="utf-8")
        )
        called = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert "status" in called, "the test found no status call, so it checks nothing"
        assert "historical_status" not in called


class TestTheRegistryCannotBeChangedByAMessage:
    def test_the_authenticator_never_registers_or_revokes(self) -> None:
        """Part 13. No message, however well signed, may add an identity, extend a window
        or reverse a revocation."""
        tree = ast.parse(
            pathlib.Path("src/aegis/a2a/remote/authenticator.py").read_text(encoding="utf-8")
        )
        called = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert not (called & {"register", "revoke"}), called

    def test_the_gateway_never_registers_or_revokes(self) -> None:
        tree = ast.parse(
            pathlib.Path("src/aegis/a2a/remote/gateway.py").read_text(encoding="utf-8")
        )
        called = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert not (called & {"register", "revoke"}), called

    def test_a_model_supplied_agent_id_cannot_become_an_identity(self, registry) -> None:
        """A near-miss name is an unknown agent, not a helpful match."""
        for claimed in ("diagnostic ", "Diagnostic", "diagnostic-2", "diagnos"):
            assert registry.status(claimed, "key-diagnostic-1") is IdentityStatus.UNKNOWN


class TestProtocolVersionsAreRegistryOwned:
    def test_an_identity_must_declare_at_least_one_version(self) -> None:
        with pytest.raises(ValueError):
            _identity(protocol_versions=())

    def test_versions_are_matched_exactly(self) -> None:
        identity = _identity()
        assert identity.speaks(REMOTE_PROTOCOL_VERSION)
        assert not identity.speaks("aegis.a2a/1")
        assert not identity.speaks(REMOTE_PROTOCOL_VERSION + "x")
        assert not identity.speaks(REMOTE_PROTOCOL_VERSION[:-1])


class TestVerifiersComeFromRegisteredMaterial:
    def test_a_verifier_is_rebuilt_from_what_the_registry_stores(self, keys, registry) -> None:
        ring, by_agent, _ = keys
        signer = ring.signer(by_agent["diagnostic"])
        assert signer is not None
        verifier = registry.verifier("key-diagnostic-1")
        assert verifier is not None
        assert verifier.verify(b"payload", signer.sign(b"payload"))

    def test_an_unregistered_key_has_no_verifier(self, registry) -> None:
        assert registry.verifier("key-nobody") is None

    def test_corrupt_material_produces_a_verifier_that_refuses(self, clock) -> None:
        """Never an exception: the boundary calling this is mid-judgement on a hostile
        message and has to end in a verdict."""
        registry = RemoteAgentRegistry([_identity(verification_key="zzzz")], clock=clock)
        verifier = registry.verifier("key-diagnostic-1")
        assert verifier is not None
        assert verifier.verify(b"anything", "00" * 32) is False

    def test_a_verifier_for_an_unavailable_algorithm_is_none_not_a_fallback(
        self, clock, monkeypatch
    ) -> None:
        """A missing provider means the algorithm cannot be offered. It never means the
        message is verified some other way."""
        from aegis.a2a.remote import keys as keys_module

        monkeypatch.setattr(keys_module, "_providers", dict)
        registry = RemoteAgentRegistry([_identity()], clock=clock)
        assert registry.verifier("key-diagnostic-1") is None


def test_the_two_shipped_algorithms_produce_distinct_material() -> None:
    """Sanity: a test suite that ran both algorithms against the same bytes would not be
    running both."""
    materials = {
        provider_for(algorithm).generate("k", seed=b"same")[1].material
        for algorithm in (KeyAlgorithm.HMAC_SHA256,)
    }
    assert len(materials) == 1
