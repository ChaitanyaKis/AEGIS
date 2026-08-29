"""The authenticated remote envelope, and exactly which fields its signature covers.

Part 4 and Part 9. A :class:`~aegis.a2a.contracts.A2AEnvelope` is already sealed, but a seal
is a public formula: anything that can build a message can compute one, so it proves
integrity and says nothing about origin. :class:`RemoteEnvelope` wraps that message in the
one thing a hash cannot supply -- a signature under a key the receiver's registry binds to a
named agent.

    A2AEnvelope        what the message says          (sealed: integrity)
    RemoteEnvelope     who signed it, and with what   (signed: authenticity)
    RemoteFrame        how it is being carried        (unsigned: routing)

Wrapping rather than duplicating. Every local guarantee -- closed schema, no authority
field, bounded payload, sequence, expiry -- is the same object it always was, so the remote
path cannot drift away from the local one by having its own copy of the contract.

What is signed, and what deliberately is not
--------------------------------------------

:data:`SIGNED_FIELDS` names all eighteen covered fields, and :class:`_SigningPayload`
declares them as a model so the two cannot disagree. A test asserts that every field on
either envelope is either covered or on the short, justified exception list -- so adding a
security-relevant field without signing it is a **test failure**, not an oversight
somebody notices later.

Two exceptions, both deliberate:

``signature``
    A signature cannot cover itself.
``payload``
    Covered by :attr:`RemoteEnvelope.payload_digest`, which *is* signed and which the
    authenticator recomputes from the actual payload. Signing a digest rather than the
    bytes keeps the signing payload small and bounded; recomputing it is what stops the
    digest from being a claim rather than a fact.

And what is on the frame -- hop count, arrival time, the address it is being carried to --
is **not signed at all**, because it legitimately changes between hops. That is exactly why
:attr:`~aegis.a2a.contracts.A2AEnvelope.recipient_agent_id` is signed *inside* the message:
an intermediary may readdress the frame all it likes, and the receiver compares its own
identity against the signed recipient rather than against the label on the outside.
"""

from __future__ import annotations

import hashlib

from pydantic import Field

from aegis.a2a.contracts import A2AEnvelope, ExactId, MessageType, TaskType
from aegis.a2a.records import payload_digest
from aegis.a2a.remote.keys import MAX_SIGNATURE_HEX, KeyAlgorithm, SigningKey
from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp, to_json

__all__ = [
    "LEGACY_PROTOCOL_VERSION",
    "MAX_REMOTE_FRAME_BYTES",
    "REMOTE_PROTOCOL_VERSION",
    "SIGNED_FIELDS",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "UNSIGNED_BY_DESIGN",
    "RemoteEnvelope",
    "RemoteFrame",
    "decode_envelope",
    "encode_envelope",
    "frame_digest",
    "sign_remote",
    "signing_payload",
]

REMOTE_PROTOCOL_VERSION = "aegis.a2a/2"
"""The one version this build speaks. Version 2 because version 1 is the *local* protocol,
which has no signature at all -- and the whole downgrade defence is that they are not
interchangeable."""

LEGACY_PROTOCOL_VERSION = "aegis.a2a/1"
"""Named so a downgrade attempt is testable, and **not** in the supported set.

A version constant that exists but is refused is worth more than one that does not exist:
it makes "v2 sender, v1 receiver" a case with a name and a rejection code, instead of a
scenario nobody wrote because nobody had a string for it.
"""

SUPPORTED_PROTOCOL_VERSIONS: frozenset[str] = frozenset({REMOTE_PROTOCOL_VERSION})
"""Every version this build will accept. Membership, never a comparison.

Deliberately a set rather than ``>=`` on a parsed number. Ordering invites "well, v1 is
lower, so it is *older*, so we can probably handle it", which is a downgrade written as
politeness. A version is supported or it is refused.
"""

MAX_REMOTE_FRAME_BYTES = 128 * 1024
"""Largest frame the boundary will parse.

Checked on the raw text **before** parsing, because a parser is exactly what an oversized
frame is aimed at. The local payload bounds still apply underneath and are checked again by
the local broker; this is the outer bound that stops the outer parser being the victim.
"""

SIGNED_FIELDS: tuple[str, ...] = (
    "algorithm",
    "conversation_id",
    "created_at",
    "evidence_refs",
    "expires_at",
    "incident_id",
    "key_id",
    "message_id",
    "message_type",
    "payload_digest",
    "protocol_version",
    "recipient_agent_id",
    "seal",
    "sender_agent_id",
    "sequence",
    "target_resource",
    "task_id",
    "task_type",
)
"""Every field the signature covers. Sorted, so a diff that adds one is obvious.

A superset of the fourteen Part 4 requires: ``seal``, ``task_id``, ``target_resource`` and
``evidence_refs`` are covered too. They are security-relevant bindings, and a signature that
left them out would authenticate a message about a *different resource* just as happily.
"""

UNSIGNED_BY_DESIGN: frozenset[str] = frozenset({"signature", "payload", "message"})
"""The only fields allowed to be outside the signature, each for a stated reason.

``signature`` cannot cover itself; ``payload`` is covered through ``payload_digest``;
``message`` is the wrapper's handle on the inner envelope, whose own fields are covered
individually. A test uses this set to prove no *fourth* field ever quietly joins it.
"""


class _SigningPayload(DomainModel):
    """Exactly the fields the signature covers.

    A declared model rather than an ad-hoc dict, for the same reason
    :class:`~aegis.a2a.contracts._SealPayload` is one: a field added to an envelope without
    being added here fails a test instead of silently escaping the signature. Canonical JSON
    means no field value can be crafted to imitate a field boundary, which a concatenated
    string would allow.
    """

    algorithm: KeyAlgorithm
    conversation_id: str
    created_at: Timestamp
    evidence_refs: tuple[str, ...]
    expires_at: Timestamp
    incident_id: str
    key_id: str
    message_id: str
    message_type: MessageType
    payload_digest: str
    protocol_version: str
    recipient_agent_id: str
    seal: str
    sender_agent_id: str
    sequence: int
    target_resource: str | None
    task_id: str
    task_type: TaskType


class RemoteEnvelope(DomainModel):
    """One A2A message, authenticated for a peer that is not in this process.

    Frozen and closed, like everything else that crosses a boundary. There is no field here
    for policy, approval, risk, verification or a gate -- for the same reason there is none
    on the inner envelope, and it is worth saying twice: a *signed* claim of approval is
    still a claim, and this schema gives it nowhere to sit.
    """

    protocol_version: NonEmptyStr = Field(max_length=64)
    key_id: ExactId
    algorithm: KeyAlgorithm
    payload_digest: NonEmptyStr = Field(min_length=64, max_length=64)
    """SHA-256 over the inner payload. Signed, and recomputed by the authenticator -- a
    digest nobody recomputes is a claim wearing a hash's clothes."""

    signature: NonEmptyStr = Field(max_length=MAX_SIGNATURE_HEX)
    message: A2AEnvelope

    @property
    def sender_agent_id(self) -> str:
        """Who the message *says* sent it. Not evidence -- see :mod:`aegis.a2a.remote.identity`."""
        return self.message.sender_agent_id

    @property
    def recipient_agent_id(self) -> str:
        """Who the message is signed *for*. The frame's address is not consulted."""
        return self.message.recipient_agent_id

    @property
    def message_id(self) -> str:
        return self.message.message_id

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({self.protocol_version} {self.algorithm} "
            f"key={self.key_id} {self.message!r})"
        )


def signing_payload(envelope: RemoteEnvelope) -> bytes:
    """The exact bytes a signature is computed over.

    One function used by both the signer and the verifier, so the two cannot disagree about
    what was signed. A separate "build the verification payload" routine is how a signature
    scheme ends up verifying something subtly different from what it signed.
    """
    message = envelope.message
    document = to_json(
        _SigningPayload(
            algorithm=envelope.algorithm,
            conversation_id=message.conversation_id,
            created_at=message.created_at,
            evidence_refs=message.evidence_refs,
            expires_at=message.expires_at,
            incident_id=message.incident_id,
            key_id=envelope.key_id,
            message_id=message.message_id,
            message_type=message.message_type,
            payload_digest=envelope.payload_digest,
            protocol_version=envelope.protocol_version,
            recipient_agent_id=message.recipient_agent_id,
            seal=message.seal,
            sender_agent_id=message.sender_agent_id,
            sequence=message.sequence,
            target_resource=message.target_resource,
            task_id=message.task_id,
            task_type=message.task_type,
        )
    )
    return document.encode("utf-8")


def sign_remote(
    message: A2AEnvelope,
    *,
    key: SigningKey,
    protocol_version: str = REMOTE_PROTOCOL_VERSION,
) -> RemoteEnvelope:
    """Wrap a locally issued message and sign it.

    The algorithm comes from the *key*, never from an argument. A caller able to name an
    algorithm independently of the key it is holding is a caller able to claim Ed25519 while
    signing with something else, and the mismatch would then have to be caught rather than
    being impossible.
    """
    unsigned = RemoteEnvelope(
        protocol_version=protocol_version,
        key_id=key.key_id,
        algorithm=key.algorithm,
        payload_digest=payload_digest(message.payload),
        signature="unsigned",
        message=message,
    )
    return unsigned.model_copy(update={"signature": key.sign(signing_payload(unsigned))})


# --- the wire ---------------------------------------------------------------------------


class RemoteFrame(DomainModel):
    """What a transport actually carries. **Unsigned, and known to be unsigned.**

    A frame is the envelope's outside: an address, a hop count, an arrival time and a body
    of canonical JSON. None of it is covered by the signature, because all of it legitimately
    changes between hops (Part 4).

    That is safe only because nothing trusts it. The address is a routing hint; the receiver
    compares its own identity against the **signed** recipient inside the body. An
    intermediary that readdresses a frame has changed a hint, not a destination -- which is
    what makes redirection detectable rather than effective.
    """

    destination: NonEmptyStr = Field(max_length=256)
    """Where the transport is carrying this. A hint. Never an authorization to deliver."""

    body: str = Field(max_length=MAX_REMOTE_FRAME_BYTES)
    """Canonical JSON of a :class:`RemoteEnvelope`, as text. Text rather than an object so a
    tamper, a truncation and a malformed frame are all genuinely representable."""

    hop_count: int = Field(default=0, ge=0, le=16)
    received_at: Timestamp | None = None
    route: tuple[Identifier, ...] = ()
    """Which relays handled this frame. Diagnostic only, and unsigned -- a route a peer
    could write is a route a peer could invent."""

    @property
    def size(self) -> int:
        return len(self.body.encode("utf-8"))

    def forwarded(self, by: str) -> RemoteFrame:
        """The same body, one hop further along. Mutating metadata, never the body."""
        return self.model_copy(update={"hop_count": self.hop_count + 1, "route": (*self.route, by)})

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(to={self.destination!r}, {self.size} bytes, "
            f"hops={self.hop_count})"
        )


def encode_envelope(envelope: RemoteEnvelope) -> str:
    """Serialize to canonical JSON -- the project's one serializer, not a second format."""
    return to_json(envelope)


def decode_envelope(raw: str) -> RemoteEnvelope | None:
    """Parse a frame body, or ``None``.

    ``None`` rather than an exception, and rather than a partially populated object. A
    caller has to unpack the ``None`` and turn it into a refusal, which is exactly what
    :mod:`aegis.a2a.remote.gateway` does. Every failure -- truncated, oversized, not JSON,
    missing a required field, carrying an unknown one -- collapses to the same answer, so
    the *shape* of a malformed frame cannot select which code path runs next.

    An oversized body is refused **before** parsing. Checking afterwards would mean having
    already paid the cost the bound exists to avoid.
    """
    if not raw or len(raw.encode("utf-8")) > MAX_REMOTE_FRAME_BYTES:
        return None
    try:
        from aegis.core.domain import from_json

        return from_json(RemoteEnvelope, raw)
    except Exception:
        return None


def frame_digest(frame: RemoteFrame) -> str:
    """SHA-256 over a frame's body. An identifier for audit, never a security check.

    Worth being blunt about: this digest proves nothing on its own. It exists so a rejected
    frame can be named in an audit record without reproducing a byte of what it contained.
    """
    return hashlib.sha256(frame.body.encode("utf-8")).hexdigest()
