"""How an A2A message can be refused, and what a refusal is.

A refusal is a **returned value**, not an exception. The caller has to route it into a
delegation result and an audit record, and a returned refusal is harder to ignore than a
raised one is to swallow — the same reasoning that makes
:class:`~aegis.lifecycle.coordinator.GateIssue` a value.

Every reason below fails closed. There is no reason that means "allow anyway", no partial
acceptance, and no field on :class:`A2AVerdict` that a caller could mistake for permission:
``accepted`` means "this message may be delivered to its recipient", and delivering a
message is not authorizing anything.
"""

from __future__ import annotations

from enum import StrEnum

from aegis.core.domain import DomainModel, NonEmptyStr

__all__ = ["A2ARejection", "A2AVerdict"]


class A2ARejection(StrEnum):
    """Every way a message can be refused. Closed, and every member fails closed."""

    # --- identity (Part 2) ---
    SENDER_MISMATCH = "SENDER_MISMATCH"
    """The declared sender is not the agent that actually sent it."""

    UNKNOWN_SENDER = "UNKNOWN_SENDER"
    UNKNOWN_RECIPIENT = "UNKNOWN_RECIPIENT"

    # --- authorization to communicate (Part 3) ---
    NOT_PERMITTED = "NOT_PERMITTED"
    """The delegation matrix has no edge from this sender to this recipient."""

    UNKNOWN_TASK = "UNKNOWN_TASK"
    """The recipient does not handle that task type."""

    # --- integrity (Part 4) ---
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    """The seal does not match the message. Something changed after issuance."""

    NOT_ISSUED = "NOT_ISSUED"
    """No broker issued this message. A perfect seal is not an origin."""

    # --- replay and ordering (Parts 5, 6) ---
    REPLAY = "REPLAY"
    """This message id has been seen before."""

    ALREADY_CONSUMED = "ALREADY_CONSUMED"
    EXPIRED = "EXPIRED"
    CONVERSATION_EXPIRED = "CONVERSATION_EXPIRED"
    SEQUENCE_MISMATCH = "SEQUENCE_MISMATCH"
    INCIDENT_MISMATCH = "INCIDENT_MISMATCH"
    CONVERSATION_MISMATCH = "CONVERSATION_MISMATCH"
    TASK_MISMATCH = "TASK_MISMATCH"

    # --- bounds (Part 7) ---
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    TOO_MANY_MESSAGES = "TOO_MANY_MESSAGES"

    # --- delivery and response (Parts 9, 11) ---
    RECIPIENT_UNAVAILABLE = "RECIPIENT_UNAVAILABLE"
    MALFORMED = "MALFORMED"
    TIMEOUT = "TIMEOUT"
    RECIPIENT_REFUSED = "RECIPIENT_REFUSED"
    RESPONSE_IDENTITY_MISMATCH = "RESPONSE_IDENTITY_MISMATCH"
    """A response claims to come from an agent other than the one that produced it."""

    RESPONSE_BINDING_MISMATCH = "RESPONSE_BINDING_MISMATCH"
    """A response's finding is bound to a different incident than the message."""


class A2AVerdict(DomainModel):
    """Whether one message may be delivered, and why not when it may not.

    ``accepted=True`` means exactly one thing: this message is well-formed, sealed, in
    sequence, unexpired, unreplayed, from the agent it claims, to an agent permitted to
    receive it. It does **not** mean the recipient will do anything, and it means nothing at
    all about whether any action is allowed. There is no field here that a caller could read
    as authorization, because there is nothing here to read.
    """

    accepted: bool
    rejection: A2ARejection | None = None
    detail: NonEmptyStr
    message_id: NonEmptyStr | None = None

    @classmethod
    def accept(cls, message_id: str, detail: str) -> A2AVerdict:
        return cls(accepted=True, detail=detail, message_id=message_id)

    @classmethod
    def refuse(
        cls, rejection: A2ARejection, detail: str, message_id: str | None = None
    ) -> A2AVerdict:
        return cls(accepted=False, rejection=rejection, detail=detail, message_id=message_id)

    def __repr__(self) -> str:
        state = "ACCEPTED" if self.accepted else f"REFUSED:{self.rejection}"
        return f"{type(self).__name__}({state} {self.detail!r})"
