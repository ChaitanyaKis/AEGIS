"""How a remote message can be refused, and what an *acceptance* is careful not to mean.

Same rule as :mod:`aegis.a2a.verdicts`: a refusal is a returned value, not an exception.
Every member of :class:`RemoteRejection` fails closed, there is no partial acceptance, and
there is no member meaning "allow anyway".

The one sentence this module exists to enforce
----------------------------------------------

    An authenticated message is a message whose author is known.

:class:`RemoteVerdict` has an ``agent_id`` field and no authority field of any kind, because
those are different questions with different answers in different modules. There is nothing
here a caller could read as permission, and a test asserts the field set so it stays that
way.
"""

from __future__ import annotations

from enum import StrEnum

from aegis.a2a.verdicts import A2ARejection
from aegis.core.domain import DomainModel, NonEmptyStr

__all__ = ["RemoteRejection", "RemoteVerdict"]


class RemoteRejection(StrEnum):
    """Every way a remote message can be refused. Closed, and every member fails closed.

    Grouped by the layer that answers it (:mod:`aegis.a2a.remote.threats`). The grouping is
    not decoration: it is how a reader can tell at a glance that an authentication failure
    and an authorization failure are different things, arriving from different code, with
    different consequences.
    """

    # --- protocol (Part 9) ---
    UNSUPPORTED_PROTOCOL_VERSION = "UNSUPPORTED_PROTOCOL_VERSION"
    """The version is not in the supported set. Includes every downgrade attempt."""

    MALFORMED_FRAME = "MALFORMED_FRAME"
    """The frame did not parse: truncated, oversized, not JSON, or missing a signed field."""

    OVERSIZED_FRAME = "OVERSIZED_FRAME"

    # --- identity (Parts 2, 13) ---
    UNKNOWN_AGENT = "UNKNOWN_AGENT"
    """No registry entry binds any key to that agent id."""

    UNKNOWN_KEY = "UNKNOWN_KEY"
    """No registry entry binds *this* key to *this* agent. A key belonging to some other
    agent is unknown here, which is the cross-agent substitution defence."""

    IDENTITY_NOT_YET_VALID = "IDENTITY_NOT_YET_VALID"
    IDENTITY_EXPIRED = "IDENTITY_EXPIRED"
    IDENTITY_REVOKED = "IDENTITY_REVOKED"
    """The key was withdrawn. Refused even when the signature is mathematically perfect --
    which is the entire point of revocation."""

    VERSION_NOT_PERMITTED = "VERSION_NOT_PERMITTED"
    """The registry does not list that protocol version for this identity."""

    # --- cryptography (Parts 3, 4) ---
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    """No provider in this deployment handles it. Never a fallback to a weaker one."""

    ALGORITHM_MISMATCH = "ALGORITHM_MISMATCH"
    """The message names one algorithm and the registered identity another."""

    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    PAYLOAD_DIGEST_MISMATCH = "PAYLOAD_DIGEST_MISMATCH"
    """The signed digest does not match the payload actually carried."""

    SEAL_INVALID = "SEAL_INVALID"
    """The inner envelope's own seal does not match it."""

    # --- binding (Parts 4, 14) ---
    SENDER_MISMATCH = "SENDER_MISMATCH"
    """The key authenticates one agent and the message declares another as its sender."""

    WRONG_RECIPIENT = "WRONG_RECIPIENT"
    """Signed for somebody else. The frame's address is not consulted."""

    CROSS_CONVERSATION = "CROSS_CONVERSATION"
    CROSS_INCIDENT = "CROSS_INCIDENT"
    SEQUENCE_MISMATCH = "SEQUENCE_MISMATCH"
    """Signed for a position other than the next one in this conversation.

    Checked here as well as locally, and not because the local check is doubted. A remote
    peer's messages are recorded on arrival, and a record written at the wrong position
    would let the *recording* step create the continuity the check is supposed to verify.
    """

    RESPONSE_BINDING_MISMATCH = "RESPONSE_BINDING_MISMATCH"
    """A response that is not bound to the request it claims to answer."""

    # --- freshness (Part 7) ---
    MESSAGE_EXPIRED = "MESSAGE_EXPIRED"
    FUTURE_DATED = "FUTURE_DATED"
    """Created further ahead of the receiver's clock than the permitted skew."""

    # --- replay (Part 6) ---
    REPLAY = "REPLAY"
    """This message id has been admitted here before. Durable across a restart."""

    ALREADY_CONSUMED = "ALREADY_CONSUMED"

    # --- transport (Part 12) ---
    TRANSPORT_FAILURE = "TRANSPORT_FAILURE"
    TRANSPORT_TIMEOUT = "TRANSPORT_TIMEOUT"
    PEER_UNAVAILABLE = "PEER_UNAVAILABLE"

    # --- the local boundary, unchanged (Parts 6, 10) ---
    LOCAL_REFUSAL = "LOCAL_REFUSAL"
    """The existing local broker refused it after authentication succeeded.

    Kept as one member with the local reason in ``detail`` rather than mirrored into
    twenty. Every Prompt 15 and 16 guarantee still applies to an authenticated message, and
    duplicating the local vocabulary here would create a second copy to drift out of step
    with the first.
    """

    STATE_UNAVAILABLE = "STATE_UNAVAILABLE"
    """Durable A2A state could not be read or written. A refusal, never a delivery."""


class RemoteVerdict(DomainModel):
    """Whether a remote message may proceed to the local boundary, and who sent it.

    ``authenticated=True`` means exactly one thing: **a key the registry binds to
    ``agent_id`` signed these bytes, and the key was active when the receiver checked.**

    It does not mean the message was delivered, that the recipient will act, that the
    content is true, or that anything at all is permitted. A compromised peer holding valid
    key material produces ``authenticated=True`` on every malicious message it sends, and
    that is the correct answer to the question authentication asks.

    There is no ``authorized``, no ``approved``, no ``allow``, no ``risk`` and no ``gate``
    field -- not because a check strips them, but because there is nothing here to read.
    """

    authenticated: bool
    agent_id: NonEmptyStr | None = None
    """The cryptographically established sender. ``None`` on every refusal.

    Populated *only* from the registry entry the verified key belongs to -- never from the
    message's own ``sender_agent_id``, which is the field an attacker controls.
    """

    key_id: NonEmptyStr | None = None
    rejection: RemoteRejection | None = None
    detail: NonEmptyStr
    message_id: NonEmptyStr | None = None

    @classmethod
    def accept(cls, *, agent_id: str, key_id: str, message_id: str, detail: str) -> RemoteVerdict:
        return cls(
            authenticated=True,
            agent_id=agent_id,
            key_id=key_id,
            message_id=message_id,
            detail=detail,
        )

    @classmethod
    def refuse(
        cls,
        rejection: RemoteRejection,
        detail: str,
        *,
        message_id: str | None = None,
        key_id: str | None = None,
    ) -> RemoteVerdict:
        """A refusal. ``agent_id`` is never set: nothing was established."""
        return cls(
            authenticated=False,
            rejection=rejection,
            detail=detail,
            message_id=message_id,
            key_id=key_id,
        )

    @classmethod
    def from_local(cls, rejection: A2ARejection, detail: str, message_id: str) -> RemoteVerdict:
        """A local refusal, carried out through the remote vocabulary without duplicating it."""
        return cls.refuse(
            RemoteRejection.LOCAL_REFUSAL,
            f"{rejection}: {detail}",
            message_id=message_id,
        )

    def __repr__(self) -> str:
        state = (
            f"AUTHENTICATED:{self.agent_id}" if self.authenticated else f"REFUSED:{self.rejection}"
        )
        return f"{type(self).__name__}({state} {self.detail!r})"
