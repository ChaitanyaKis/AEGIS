"""Who a remote agent actually is, established cryptographically rather than declared.

Part 2 and Part 13. The local boundary (:mod:`aegis.a2a.identity`) answers "is the declared
sender the agent that actually sent this?" by comparing against the application's wiring,
which works because the sender and the receiver are the same process. A remote sender is
not in this process, so there is no wiring to compare against and something has to take its
place. That something is a signature over a registered key.

    declared sender      (in the message -- **not evidence**)
    signature over the signed fields, under key_id
    registry entry for (agent_id, key_id)
                    |
                    v
    the sender is the agent the *registry* binds that key to

A message saying ``sender_agent_id = "security"`` does not make the sender security. Only
a valid signature under a key the registry binds to ``security`` does, and even then it
makes the sender security and nothing more -- see :mod:`aegis.a2a.remote.threats` on why
that sentence has to end there.

What an identity record holds, and what it must never hold
----------------------------------------------------------

Key material, validity dates, an algorithm, a status. **No policy, no risk, no approval, no
lifecycle state and no execution authority.** An identity record that carried authority
would make the registry a policy engine with a directory API attached, and every question
about what a remote agent may *do* would start being answered in the wrong place. A test
asserts the field set, so this stays true by failure rather than by memory.

The registry cannot be changed by a message
-------------------------------------------

:meth:`RemoteAgentRegistry.register` and :meth:`RemoteAgentRegistry.revoke` are operator
operations. :mod:`aegis.a2a.remote.authenticator` calls neither -- structurally, asserted
by test -- so no message, however well signed, can add an identity, extend a validity
window or reverse a revocation. There is no ``reactivate``, no ``unrevoke`` and no
``clear``: a revocation that can be lifted on request is a revocation an attacker asks to
have lifted.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime
from enum import StrEnum

from pydantic import Field, model_validator

from aegis.a2a.remote.keys import KeyAlgorithm, VerifyingKey, provider_for
from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp, utc_now

__all__ = ["IdentityStatus", "RemoteAgentIdentity", "RemoteAgentRegistry"]


class IdentityStatus(StrEnum):
    """Whether a key may authenticate anything right now.

    The four Part 2 names, plus one the calendar forces. A key whose validity window has
    not opened yet is not *expired*; recording it as expired would put a false word in an
    audit record and send whoever reads it looking for a rotation that never happened.

    Only :attr:`ACTIVE` permits authentication. Every other member fails closed, and there
    is no member that means "probably fine".
    """

    UNKNOWN = "UNKNOWN"
    """No registry entry binds this key to this agent. The default answer, and a refusal."""

    ACTIVE = "ACTIVE"
    NOT_YET_VALID = "NOT_YET_VALID"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class RemoteAgentIdentity(DomainModel):
    """One key, bound to one agent, valid over one window.

    Frozen and closed. A rotation is a *new record*, never an edit to this one: editing an
    identity in place would erase the evidence of what the old key was allowed to do, which
    is exactly what an audit of a compromise needs.
    """

    agent_id: Identifier
    key_id: Identifier
    algorithm: KeyAlgorithm
    verification_key: NonEmptyStr = Field(max_length=4096)
    """The material a verifier is rebuilt from.

    Deliberately **not** called ``public_key``. For Ed25519 it genuinely is a public key;
    for ``HMAC_SHA256`` it is shared secret material, and a
    field name asserting otherwise would be a lie told by the schema itself. The name is
    accurate for both, which is the only name that can be.
    """

    protocol_versions: tuple[NonEmptyStr, ...] = Field(min_length=1)
    """Which protocol versions this identity may speak. The registry is authoritative
    (Part 13), so a peer cannot widen its own version support by claiming a version."""

    created_at: Timestamp
    expires_at: Timestamp
    revoked_at: Timestamp | None = None

    @model_validator(mode="after")
    def _window_is_real(self) -> RemoteAgentIdentity:
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        if self.revoked_at is not None and self.revoked_at < self.created_at:
            raise ValueError("a key cannot be revoked before it existed")
        return self

    def status_at(self, when: datetime) -> IdentityStatus:
        """This identity's status at a given instant. Never :attr:`IdentityStatus.UNKNOWN`.

        Precedence is revocation first, and that ordering is the whole point: a key revoked
        inside its validity window is ``REVOKED``, not ``ACTIVE``. Checking the window first
        and revocation second would make a live compromised key look fine until it happened
        to expire on its own.
        """
        if self.revoked_at is not None and when >= self.revoked_at:
            return IdentityStatus.REVOKED
        if when < self.created_at:
            return IdentityStatus.NOT_YET_VALID
        if when >= self.expires_at:
            return IdentityStatus.EXPIRED
        return IdentityStatus.ACTIVE

    def speaks(self, protocol_version: str) -> bool:
        """Whether this identity may use that protocol version. Exact match, never a prefix."""
        return protocol_version in self.protocol_versions

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({self.agent_id} key={self.key_id} "
            f"{self.algorithm} revoked={self.revoked_at is not None})"
        )


class RemoteAgentRegistry:
    """The authoritative record of which keys belong to which remote agents.

    Args:
        identities: The entries to start with.
        clock: Injected, so status is reproducible.

    Two lookups, and the difference between them matters. :meth:`status` takes an
    ``agent_id`` **and** a ``key_id`` and answers ``UNKNOWN`` unless the registry binds that
    exact pair -- so a valid signature under a key belonging to some *other* agent
    establishes nothing. :meth:`verifier` takes a key id alone and is only ever reached
    after that pair has already matched.
    """

    def __init__(
        self,
        identities: Iterable[RemoteAgentIdentity] = (),
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._clock = clock
        self._identities: dict[str, RemoteAgentIdentity] = {}
        for identity in identities:
            self.register(identity)

    # --- operator operations ---------------------------------------------------------

    def register(self, identity: RemoteAgentIdentity) -> RemoteAgentIdentity:
        """Add one identity.

        Raises:
            ValueError: if that key id is already registered. Re-registering would let a
                new record silently replace an old one, which is how a revoked key comes
                back to life without anybody having to un-revoke it.
        """
        if identity.key_id in self._identities:
            raise ValueError(f"key {identity.key_id!r} is already registered")
        self._identities[identity.key_id] = identity
        return identity

    def revoke(self, key_id: str, *, at: datetime | None = None) -> RemoteAgentIdentity | None:
        """Withdraw a key's authority to authenticate anything, permanently.

        Monotonic: revoking an already-revoked key keeps the **earlier** timestamp, so a
        second call can never move a revocation later and open a window that was closed.
        There is no inverse operation anywhere in this class.

        Returns:
            The revoked identity, or ``None`` if no such key is registered. ``None`` rather
            than an exception because revoking a key that was never registered is already
            the state the caller wanted.
        """
        identity = self._identities.get(key_id)
        if identity is None:
            return None
        when = at if at is not None else self._clock()
        if identity.revoked_at is not None:
            when = min(identity.revoked_at, when)
        revoked = identity.model_copy(update={"revoked_at": when})
        self._identities[key_id] = revoked
        return revoked

    # --- read-only questions ---------------------------------------------------------

    def identity(self, key_id: str) -> RemoteAgentIdentity | None:
        """The entry for this exact key id, or ``None``. No normalisation, no fuzzy match."""
        return self._identities.get(key_id)

    def status(self, agent_id: str, key_id: str, *, at: datetime | None = None) -> IdentityStatus:
        """Whether this key may authenticate this agent, now.

        ``at`` defaults to the injected clock and exists for tests. It is deliberately
        **not** wired to anything a message carries: a peer holding a stolen key controls
        every timestamp in its own message, so judging revocation against the message's own
        ``created_at`` would let the thief simply claim to have signed before the theft was
        noticed. Admission is judged against the receiver's clock, always.
        """
        identity = self._identities.get(key_id)
        if identity is None or identity.agent_id != agent_id:
            return IdentityStatus.UNKNOWN
        return identity.status_at(at if at is not None else self._clock())

    def historical_status(self, agent_id: str, key_id: str, when: datetime) -> IdentityStatus:
        """What the status *was* at some past instant. For audit reconstruction only.

        Part 8 asks whether historical verification survives revocation. It does: a
        revocation records a timestamp rather than deleting anything, so "was this key valid
        last Tuesday?" stays answerable forever and the signature on an old message stays
        mathematically checkable.

        What that emphatically does **not** buy is admission. A revoked key admits nothing,
        whenever it claims to have signed -- see :meth:`status`. The two questions have two
        methods so that no caller can reach for the wrong one by accident, and a structural
        test asserts the authenticator calls only :meth:`status`.
        """
        identity = self._identities.get(key_id)
        if identity is None or identity.agent_id != agent_id:
            return IdentityStatus.UNKNOWN
        return identity.status_at(when)

    def verifier(self, key_id: str) -> VerifyingKey | None:
        """A verifying key rebuilt from the registered material, or ``None``.

        ``None`` when the key is unregistered or its algorithm has no provider in this
        deployment. Both are refusals at the boundary; neither is an exception, because a
        message being judged must always end in a verdict.
        """
        identity = self._identities.get(key_id)
        if identity is None:
            return None
        try:
            provider = provider_for(identity.algorithm)
        except Exception:
            return None
        return provider.verifier(identity.key_id, identity.verification_key)

    def keys_for(self, agent_id: str) -> tuple[RemoteAgentIdentity, ...]:
        """Every key registered to one agent, by key id. Includes revoked and expired ones,
        because a rotation history with the old keys deleted is not a history."""
        return tuple(
            sorted(
                (i for i in self._identities.values() if i.agent_id == agent_id),
                key=lambda identity: identity.key_id,
            )
        )

    def active_keys_for(self, agent_id: str, *, at: datetime | None = None) -> tuple[str, ...]:
        """Key ids that could authenticate this agent right now. Sorted."""
        when = at if at is not None else self._clock()
        return tuple(
            identity.key_id
            for identity in self.keys_for(agent_id)
            if identity.status_at(when) is IdentityStatus.ACTIVE
        )

    def agents(self) -> frozenset[str]:
        """Every agent id the registry knows about."""
        return frozenset(identity.agent_id for identity in self._identities.values())

    def __len__(self) -> int:
        return len(self._identities)

    def __repr__(self) -> str:
        revoked = sum(1 for i in self._identities.values() if i.revoked_at is not None)
        return f"{type(self).__name__}({len(self._identities)} keys, {revoked} revoked)"
