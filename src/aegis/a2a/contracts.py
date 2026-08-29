"""What an agent may say to another agent, and what it structurally cannot say.

The whole of Prompt 15 rests on one sentence:

    **Agents may communicate. Agents may not transfer authority.**

A2A is a transport and identity boundary, not a second control plane. An envelope routes a
bounded task to a named recipient and binds itself to one incident, one conversation and
one position in that conversation. It carries no policy decision, no approval, no
authorization, no risk, no blast radius, no verification result and no lifecycle gate —
and it carries none of them because there is **no field for them**, not because a check
rejects them later.

Three properties do the work, the same three that make
:mod:`aegis.agents.decisions` safe:

* **Closed schema.** ``extra="forbid"`` everywhere. A message that tries to arrive with
  ``policy="ALLOW"`` is not a message with a policy decision in it — it is a validation
  error.
* **Closed vocabularies.** Message type, task type and message status are enums with no
  "other" member. There is no free-form command field.
* **No authority anywhere.** Nothing here can express permission. A specialist writing
  "policy already approved this" has written prose into ``payload``, which is data.

Identifiers are matched, never repaired
---------------------------------------

:data:`ExactId` deliberately *rejects* a value with surrounding whitespace instead of
stripping it, which is what the ordinary ``Identifier`` alias does. ``"diagnostic "`` from
a model is not a typo to be helpfully corrected; it is an identifier that does not exist,
and normalising it would mean a model-supplied string had been edited into a valid identity
on its way through the boundary (Part 3).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated

from pydantic import BeforeValidator, Field, JsonValue, StringConstraints, model_validator

from aegis.agents.decisions import TaskType
from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp, to_json

__all__ = [
    "DEFAULT_MESSAGE_TTL_SECONDS",
    "FORBIDDEN_ENVELOPE_FIELDS",
    "MAX_CONVERSATION_SECONDS",
    "MAX_EVIDENCE_REFS",
    "MAX_MESSAGES_PER_TASK",
    "MAX_PAYLOAD_BYTES",
    "MAX_RESOURCE_LENGTH",
    "MAX_RESPONSE_BYTES",
    "A2AEnvelope",
    "ExactId",
    "MessageStatus",
    "MessageType",
    "TaskType",
    "envelope_seal",
    "payload_size",
]

# --- bounds (Part 7) ------------------------------------------------------------------

MAX_PAYLOAD_BYTES = 16 * 1024
"""Largest task payload, measured on canonical JSON.

A delegated task needs an incident payload and a handful of references. Anything
approaching this is either a runaway or an attempt to exhaust whatever reads it, and both
are refused **before** a specialist model is asked — checking afterwards would mean having
already paid the cost the limit exists to avoid.
"""

MAX_RESPONSE_BYTES = 32 * 1024
"""Largest response payload. Larger than a request because a finding carries prose."""

MAX_EVIDENCE_REFS = 128
"""How many observation ids one message may cite.

A ceiling on growth, not a uniqueness rule. References legitimately repeat: a Commander
accumulates them across steps and the same observation is often cited by several. Rejecting
duplicates would turn ordinary accumulation into a hard failure while protecting nothing —
citing one observation twice says exactly what citing it once says.

Sized with headroom above what a long real investigation produces, because a bound that a
legitimate run trips is an outage the bound inflicted.
"""

MAX_RESOURCE_LENGTH = 256
"""Longest target resource. Matches the domain ``Identifier`` bound."""

MAX_MESSAGES_PER_TASK = 4
"""Messages one task may generate: a request, a result, and room for a refusal.

Not a round number for its own sake. A task that has produced four messages is not making
progress, and an unbounded conversation is an unbounded loop with extra steps.
"""

MAX_CONVERSATION_SECONDS = 300.0
"""How long a conversation may stay open before every message in it is stale."""

DEFAULT_MESSAGE_TTL_SECONDS = 60.0
"""How long one message stays usable. Shorter than the conversation on purpose."""


# --- identifiers ----------------------------------------------------------------------


def _reject_normalisation(value: object) -> object:
    """Refuse a string that would change under normalisation.

    Runs *before* the string constraints, so it sees what actually arrived. The domain
    ``Identifier`` alias strips whitespace, which is right for values AEGIS constructs and
    wrong for values a model supplies: silently turning ``"diagnostic "`` into a real agent
    id is exactly the kind of helpfulness that becomes an identity bug.
    """
    if isinstance(value, str) and value != value.strip():
        raise ValueError(
            "identifier has surrounding whitespace; A2A identifiers are matched exactly "
            "and never normalised"
        )
    return value


type ExactId = Annotated[
    str,
    BeforeValidator(_reject_normalisation),
    StringConstraints(
        strip_whitespace=False,
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    ),
]
"""An identifier that must already be exactly right. See :func:`_reject_normalisation`."""


# --- vocabularies ---------------------------------------------------------------------


class MessageType(StrEnum):
    """The complete set of things one agent may send another.

    Three members, and none of them is "instruction". A request asks for a declared kind of
    work; a result returns a typed finding; a refusal explains why nothing happened. There
    is no message that carries a command, because there is no member for one.
    """

    TASK_REQUEST = "TASK_REQUEST"
    TASK_RESULT = "TASK_RESULT"
    TASK_REJECTED = "TASK_REJECTED"


class MessageStatus(StrEnum):
    """Where one message has got to. Recorded; never consulted as permission."""

    ISSUED = "ISSUED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    COMPLETED = "COMPLETED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"
    """Spent. A consumed message is never usable again, whatever its seal says."""


FORBIDDEN_ENVELOPE_FIELDS = frozenset(
    {
        "policy",
        "policy_decision",
        "decision",
        "approval",
        "authorization",
        "execution_authorization",
        "risk",
        "blast_radius",
        "verification",
        "verification_result",
        "lifecycle",
        "lifecycle_gate",
        "gate",
        "execute",
        "authorized",
        "approved",
    }
)
"""Names an envelope may never carry, listed so the guarantee is greppable.

Enforced structurally by ``extra="forbid"`` rather than by this set — the constant exists
so a test can assert that each one really is rejected, and so that a reader can see at a
glance what "A2A cannot transfer authority" means concretely (Part 13).
"""


# --- the envelope ---------------------------------------------------------------------


class A2AEnvelope(DomainModel):
    """One message between two agents.

    Frozen, closed, and sealed. Everything needed to route the message and bind it to one
    exact place in one exact conversation, and nothing else.

    ``payload`` is **untrusted data** (``claude.md`` section 4, zone A) whichever agent
    wrote it. It travels to a model through ``ModelRequest.data`` and nowhere else; there is
    no path from here to a system instruction, because ``ModelRequest`` has no instruction
    field to reach.
    """

    message_id: ExactId
    conversation_id: ExactId
    incident_id: ExactId
    sender_agent_id: ExactId
    recipient_agent_id: ExactId
    task_id: ExactId
    message_type: MessageType
    task_type: TaskType
    target_resource: NonEmptyStr | None = Field(default=None, max_length=MAX_RESOURCE_LENGTH)
    evidence_refs: tuple[Identifier, ...] = Field(default_factory=tuple)
    payload: Mapping[str, JsonValue] = Field(default_factory=dict)
    sequence: int = Field(ge=1)
    """Position in the conversation, from one. Zero is not a position (Part 6)."""

    created_at: Timestamp
    expires_at: Timestamp
    seal: NonEmptyStr
    """SHA-256 over every field above. Integrity, not authenticity — see :func:`envelope_seal`."""

    @model_validator(mode="after")
    def _within_bounds(self) -> A2AEnvelope:
        """Bounds a message can never be outside, checked at construction.

        Deliberately here rather than only in the broker: a message that violates a bound
        should not be *constructible*, so no code path anywhere can hold one and be tempted
        to pass it along.
        """
        if self.sender_agent_id == self.recipient_agent_id:
            raise ValueError("an agent may not send a message to itself")
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        if len(self.evidence_refs) > MAX_EVIDENCE_REFS:
            raise ValueError(
                f"{len(self.evidence_refs)} evidence references exceeds the "
                f"{MAX_EVIDENCE_REFS} limit"
            )
        return self

    @property
    def payload_bytes(self) -> int:
        return payload_size(self.payload)

    def expired_at(self, now) -> bool:
        """Whether this message is stale. A message with no future is not a message."""
        return now >= self.expires_at

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({self.message_type} {self.sender_agent_id}"
            f"->{self.recipient_agent_id} seq={self.sequence} id={self.message_id!r})"
        )


def payload_size(payload: Mapping[str, JsonValue]) -> int:
    """Size of a payload in bytes, measured on its canonical JSON.

    Canonical rather than ``len(str(...))`` so the number is the same one the seal is
    computed over, and so a payload cannot be smaller by being written differently.
    """
    return len(_PayloadDocument(payload=dict(payload)).model_dump_json().encode("utf-8"))


class _PayloadDocument(DomainModel):
    """Wrapper giving a bare payload a canonical serialization."""

    payload: Mapping[str, JsonValue]


class _SealPayload(DomainModel):
    """Exactly the fields the seal covers.

    A declared model rather than an ad-hoc dict, so adding an envelope field without
    sealing it is a visible code change with a test behind it (Part 4).
    """

    conversation_id: str
    created_at: Timestamp
    evidence_refs: tuple[str, ...]
    expires_at: Timestamp
    incident_id: str
    message_id: str
    message_type: MessageType
    payload: Mapping[str, JsonValue]
    recipient_agent_id: str
    sender_agent_id: str
    sequence: int
    target_resource: str | None
    task_id: str
    task_type: TaskType


def envelope_seal(envelope: A2AEnvelope) -> str:
    """The deterministic seal over every binding an envelope carries.

    SHA-256 over canonical JSON, exactly as the audit chain, the memory chain, the lifecycle
    state chain and the lifecycle gate do it. One construction, one set of properties, one
    thing to review — a fourth hash scheme would be a fourth thing to get subtly wrong.

    **Integrity, not authentication.** The formula is in this file; anything running in this
    process can compute it, so a perfect seal proves only that the message was not modified
    after it was built. It proves nothing about *who* built it. Identity comes from the
    authoritative agent record at the transport boundary
    (:mod:`aegis.a2a.identity`), and a hand-built envelope with a flawless seal is still
    rejected there because the sender it declares is not the agent that actually sent it.
    """
    document = to_json(
        _SealPayload(
            conversation_id=envelope.conversation_id,
            created_at=envelope.created_at,
            evidence_refs=envelope.evidence_refs,
            expires_at=envelope.expires_at,
            incident_id=envelope.incident_id,
            message_id=envelope.message_id,
            message_type=envelope.message_type,
            payload=dict(envelope.payload),
            recipient_agent_id=envelope.recipient_agent_id,
            sender_agent_id=envelope.sender_agent_id,
            sequence=envelope.sequence,
            target_resource=envelope.target_resource,
            task_id=envelope.task_id,
            task_type=envelope.task_type,
        )
    )
    return hashlib.sha256(document.encode("utf-8")).hexdigest()
