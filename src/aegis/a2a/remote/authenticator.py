"""Who sent this? -- and nothing else.

Part 5. This module answers exactly one question and is deliberately unable to answer any
other. It holds no ledger, no broker, no transport, no policy engine and no executor; it
cannot import them, and a structural test asserts that it does not. It changes no state:
:meth:`RemoteAuthenticator.authenticate` is a pure function of a message, a registry and a
clock, so authenticating a message twice cannot consume anything, and a bug here cannot
mark something delivered.

The three sentences this module exists to keep apart
----------------------------------------------------

    a valid hash is not an authenticated sender
    a valid signature is not an authorization
    a registered identity is not execution authority

The first is why :class:`~aegis.a2a.remote.envelope.RemoteEnvelope` exists at all: the
inner envelope's seal is computed by a public formula, so anything that can build a message
can produce a perfect one. The second and third are why this module returns a
:class:`~aegis.a2a.remote.verdicts.RemoteVerdict` carrying an ``agent_id`` and no authority
of any kind. A compromised peer with genuine key material authenticates perfectly on every
malicious message it sends, and that is the *correct* answer -- the message really did come
from that agent. What the agent may do about it was never this module's question.

The order of checks, and why it is this order
---------------------------------------------

1. **protocol version** -- before anything is interpreted, because interpretation is
   version-specific and a downgrade works by getting the wrong interpreter to run;
2. **registry entry for the key** -- the key determines the identity, so this is where the
   sender is actually established;
3. **permitted version, algorithm agreement, provider availability** -- all cheap, all
   before any cryptography;
4. **identity status** -- revoked first, so a live compromised key is refused rather than
   waiting to expire on its own;
5. **signature** -- the expensive check, once everything cheap agrees;
6. **declared sender against the established one** -- the message's own claim, checked last
   because it is the least trustworthy thing in the message;
7. **payload digest and inner seal** -- integrity of what the signature covered by
   reference;
8. **freshness** -- against the *receiver's* clock, never the message's own timestamps.

Every one of them fails closed, and every one returns a verdict rather than raising.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from aegis.a2a.contracts import envelope_seal
from aegis.a2a.records import payload_digest
from aegis.a2a.remote.envelope import (
    SUPPORTED_PROTOCOL_VERSIONS,
    RemoteEnvelope,
    signing_payload,
)
from aegis.a2a.remote.identity import IdentityStatus, RemoteAgentRegistry
from aegis.a2a.remote.keys import available_algorithms
from aegis.a2a.remote.verdicts import RemoteRejection, RemoteVerdict
from aegis.core.domain import utc_now

__all__ = ["MAX_CLOCK_SKEW_SECONDS", "RemoteAuthenticator"]

MAX_CLOCK_SKEW_SECONDS = 30.0
"""How far ahead of the receiver's clock a message may claim to have been created.

Real clocks disagree, and refusing every message from a peer thirty seconds fast would be a
denial of service the boundary inflicted on itself. Refusing one dated an hour ahead is a
different matter: a message from the future is either a badly broken peer or an attempt to
manufacture a validity window that has not opened yet.

The bound is one-sided on purpose. Being *late* is already handled by ``expires_at``, which
is signed; being early is what needs a separate limit.
"""

_STATUS_REJECTIONS = {
    IdentityStatus.UNKNOWN: RemoteRejection.UNKNOWN_AGENT,
    IdentityStatus.NOT_YET_VALID: RemoteRejection.IDENTITY_NOT_YET_VALID,
    IdentityStatus.EXPIRED: RemoteRejection.IDENTITY_EXPIRED,
    IdentityStatus.REVOKED: RemoteRejection.IDENTITY_REVOKED,
}
"""Every non-``ACTIVE`` status and the refusal it produces.

A mapping rather than a chain of ``if``s so that adding a status without deciding what it
refuses is a ``KeyError`` at the boundary rather than a silent fall-through into acceptance.
"""


class RemoteAuthenticator:
    """Establishes the sender of a remote message. Establishes nothing else.

    Args:
        registry: The authoritative binding of keys to agents. Read only -- this class calls
            no method that changes it, and a structural test asserts as much, so no message
            can register an identity or reverse a revocation.
        clock: Injected, so status and freshness are reproducible.
        max_skew_seconds: How far into the future a message may be dated.
    """

    def __init__(
        self,
        registry: RemoteAgentRegistry,
        *,
        clock: Callable[[], datetime] = utc_now,
        max_skew_seconds: float = MAX_CLOCK_SKEW_SECONDS,
    ) -> None:
        if max_skew_seconds < 0:
            raise ValueError("clock skew allowance cannot be negative")
        self.registry = registry
        self._clock = clock
        self._skew = max_skew_seconds

    def authenticate(self, envelope: RemoteEnvelope) -> RemoteVerdict:
        """Decide who sent this message, or why that cannot be established.

        Returns:
            A verdict whose ``agent_id`` -- when set -- comes from the **registry entry the
            verified key belongs to**, never from the message's own ``sender_agent_id``.
            That is the whole difference between an authenticated sender and a claimed one.
        """
        message_id = envelope.message.message_id
        now = self._clock()

        def refuse(rejection: RemoteRejection, detail: str) -> RemoteVerdict:
            return RemoteVerdict.refuse(
                rejection, detail, message_id=message_id, key_id=envelope.key_id
            )

        # 1. protocol version, before anything is interpreted
        if envelope.protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
            return refuse(
                RemoteRejection.UNSUPPORTED_PROTOCOL_VERSION,
                f"protocol {envelope.protocol_version!r} is not supported; supported: "
                f"{', '.join(sorted(SUPPORTED_PROTOCOL_VERSIONS))}",
            )

        # 2. the key determines the identity. The declared sender is checked against it
        #    later; it is never used to find the entry, because a lookup keyed on the
        #    attacker's own claim is not a lookup.
        identity = self.registry.identity(envelope.key_id)
        if identity is None:
            return refuse(
                RemoteRejection.UNKNOWN_KEY,
                f"key {envelope.key_id!r} is not registered to any agent",
            )

        # 3. what this identity is permitted to speak, and with what
        if not identity.speaks(envelope.protocol_version):
            return refuse(
                RemoteRejection.VERSION_NOT_PERMITTED,
                f"{identity.agent_id} is not registered for {envelope.protocol_version!r}; "
                f"registered: {', '.join(identity.protocol_versions)}",
            )
        if envelope.algorithm is not identity.algorithm:
            return refuse(
                RemoteRejection.ALGORITHM_MISMATCH,
                f"message names {envelope.algorithm} but key {envelope.key_id!r} is "
                f"registered as {identity.algorithm}; no algorithm is ever substituted",
            )
        if envelope.algorithm not in available_algorithms():
            return refuse(
                RemoteRejection.UNSUPPORTED_ALGORITHM,
                f"no provider in this deployment handles {envelope.algorithm}; a missing "
                f"provider is a refusal, never a fallback to something weaker",
            )

        # 4. status, revocation first
        status = self.registry.status(identity.agent_id, envelope.key_id, at=now)
        if status is not IdentityStatus.ACTIVE:
            return refuse(
                _STATUS_REJECTIONS[status],
                f"key {envelope.key_id!r} for {identity.agent_id} is {status} at {now.isoformat()}",
            )

        # 5. the signature itself
        verifier = self.registry.verifier(envelope.key_id)
        if verifier is None:
            return refuse(
                RemoteRejection.UNSUPPORTED_ALGORITHM,
                f"no verifier could be built for key {envelope.key_id!r}",
            )
        if not verifier.verify(signing_payload(envelope), envelope.signature):
            return refuse(
                RemoteRejection.SIGNATURE_INVALID,
                f"the signature does not verify under key {envelope.key_id!r}",
            )

        # 6. the message's own claim, checked against what the key established
        if envelope.message.sender_agent_id != identity.agent_id:
            return refuse(
                RemoteRejection.SENDER_MISMATCH,
                f"message declares sender {envelope.message.sender_agent_id!r} but key "
                f"{envelope.key_id!r} authenticates {identity.agent_id!r}",
            )

        # 7. what the signature covered by reference
        if payload_digest(envelope.message.payload) != envelope.payload_digest:
            return refuse(
                RemoteRejection.PAYLOAD_DIGEST_MISMATCH,
                "the signed payload digest does not match the payload actually carried",
            )
        if envelope_seal(envelope.message) != envelope.message.seal:
            return refuse(
                RemoteRejection.SEAL_INVALID,
                "the inner envelope's seal does not match it",
            )

        # 8. freshness, against the receiver's clock
        if envelope.message.expired_at(now):
            return refuse(
                RemoteRejection.MESSAGE_EXPIRED,
                f"message expired at {envelope.message.expires_at.isoformat()}",
            )
        if envelope.message.created_at > now + timedelta(seconds=self._skew):
            return refuse(
                RemoteRejection.FUTURE_DATED,
                f"message is dated {envelope.message.created_at.isoformat()}, more than "
                f"{self._skew}s ahead of this receiver",
            )

        return RemoteVerdict.accept(
            agent_id=identity.agent_id,
            key_id=envelope.key_id,
            message_id=message_id,
            detail=(
                f"{identity.agent_id} authenticated under key {envelope.key_id} "
                f"({identity.algorithm}); this establishes the sender and nothing else"
            ),
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.registry!r}, skew={self._skew}s)"
