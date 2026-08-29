"""Every message between agents, and not one byte of key material.

Part 14. The view shows identity, routing, status and -- for remote messages -- the key id,
algorithm and protocol version that authenticated them.

What it never shows
-------------------

Private keys, HMAC secrets, API keys, credentials, or the payload of any message. That is
not enforced by remembering to leave them out: this view is built from
:class:`~aegis.a2a.ledger.MessageRecord` and audit correlations, and **neither holds any**.
A ledger record carries a ``payload_digest`` rather than a payload; an audit correlation
carries a key *id* rather than a key. A test sweeps every rendered field against the live
key material to prove it, because "we did not include it" is worth less than "it is not
reachable from here".

Status is reported in five separate fields
------------------------------------------

Authentication, identity, integrity, replay and consumption are five different questions
with five different answers, and a message can pass four and fail the fifth. Collapsing them
into one "OK" badge would hide exactly the case an operator needs: a message that
authenticated perfectly and was then refused on a binding -- the signature of a compromised
peer.
"""

from __future__ import annotations

from pydantic import Field

from aegis.control_center.capture import ControlCenterInput
from aegis.control_center.models import (
    Completeness,
    Fact,
    Provenance,
    Tri,
    ViewSource,
)
from aegis.core.audit.events import AuditEventType
from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp

__all__ = ["A2AMessageView", "A2AView", "build_a2a"]

FORBIDDEN_FIELDS = frozenset(
    {
        "payload",
        "signature",
        "secret",
        "private_key",
        "verification_key",
        "material",
        "api_key",
        "credential",
        "token",
    }
)
"""Names this view must never carry, listed so the guarantee is greppable and testable.

Enforced by the view's own closed schema rather than by this set -- the constant exists so a
test can assert each one really is absent, the same discipline
:data:`~aegis.a2a.contracts.FORBIDDEN_ENVELOPE_FIELDS` follows.
"""


class A2AMessageView(DomainModel):
    """One message, with its five statuses kept apart.

    Frozen and closed. There is no payload field, no signature field and no key material
    field, so a renderer cannot display one by reaching for it.
    """

    message_id: Identifier
    conversation_id: Identifier
    incident_id: Identifier
    sender: Identifier
    recipient: Identifier
    task_id: Identifier
    task_type: NonEmptyStr
    message_type: NonEmptyStr
    sequence: int = Field(ge=0)
    created_at: Timestamp
    expires_at: Timestamp | None = None

    consumption: Fact
    """The ledger's recorded status: ISSUED, ACCEPTED, CONSUMED, COMPLETED, REJECTED,
    EXPIRED."""

    consumed: Tri = Tri.UNKNOWN
    integrity: Fact
    """The message's seal, as a digest. Integrity, not authenticity -- the seal formula is
    public, so it proves the message was not modified and nothing about who wrote it."""

    replayed: Tri = Tri.UNKNOWN
    """Whether the ledger holds this id more than once as consumed. ``UNKNOWN`` when the
    ledger was unreadable."""

    rejection: Fact
    """Why the transport refused it, when it did."""

    # --- remote only ---
    remote: Tri = Tri.UNKNOWN
    authentication: Fact
    """AUTHENTICATED or REFUSED, from the ``remote.authentication`` event. ``UNKNOWN`` for a
    local message: local A2A has no authentication step, and reporting one would invent it."""

    identity_established: Fact
    """The agent the signature established. Distinct from ``sender``, which is what the
    message *declared* -- and the two disagreeing is the interesting case."""

    key_id: Fact
    algorithm: Fact
    protocol_version: Fact

    def __repr__(self) -> str:
        return (
            f"A2AMessageView({self.message_id} {self.sender}->{self.recipient} "
            f"{self.consumption.value})"
        )


class A2AView(DomainModel):
    """Every message this incident produced, with counts and provenance."""

    messages: tuple[A2AMessageView, ...] = Field(default_factory=tuple)
    issued: int = Field(default=0, ge=0)
    consumed: int = Field(default=0, ge=0)
    rejected: int = Field(default=0, ge=0)
    authenticated: int = Field(default=0, ge=0)
    authentication_failures: int = Field(default=0, ge=0)
    provenance: Provenance

    def of_conversation(self, conversation_id: str) -> tuple[A2AMessageView, ...]:
        return tuple(
            message for message in self.messages if message.conversation_id == conversation_id
        )

    def __repr__(self) -> str:
        return (
            f"A2AView({len(self.messages)} messages, {self.consumed} consumed, "
            f"{self.rejected} rejected)"
        )


def build_a2a(data: ControlCenterInput) -> A2AView:
    """Project the ledger's records, enriched with what the audit trail says about them.

    Two sources, joined on message id, and each stays responsible for what it knows: the
    ledger owns routing, ordering and consumption; the audit trail owns authentication and
    refusal. Neither is asked a question the other should answer.

    Cross-incident records are dropped before anything is counted (Part 18).
    """
    if not data.a2a_available:
        return A2AView(
            provenance=Provenance.unavailable(data.captured_at, "the A2A ledger could not be read")
        )

    authentications = _authentication_index(data)
    rejections = _rejection_index(data)
    consumed_counts = _consumption_counts(data)

    views: list[A2AMessageView] = []
    for record in data.a2a_messages:
        if str(record.incident_id) != data.incident_id:
            continue
        message_id = str(record.message_id)
        authentication = authentications.get(message_id)
        status = str(record.status)
        views.append(
            A2AMessageView(
                message_id=message_id,
                conversation_id=str(record.conversation_id),
                incident_id=str(record.incident_id),
                sender=str(record.sender_agent_id),
                recipient=str(record.recipient_agent_id),
                task_id=str(record.task_id),
                task_type=str(record.task_type),
                message_type=str(record.message_type),
                sequence=record.sequence,
                created_at=record.created_at,
                expires_at=record.expires_at,
                consumption=Fact.observed(status, message_id),
                consumed=Tri.of(status in {"CONSUMED", "COMPLETED"}),
                # The seal is a digest, and a digest identifies a message without
                # reproducing a byte of it. That is the whole reason it is safe to show.
                integrity=Fact.observed(record.seal[:16], message_id),
                replayed=Tri.of(consumed_counts.get(message_id, 0) > 1),
                rejection=(
                    Fact.observed(rejections[message_id], message_id)
                    if message_id in rejections
                    else Fact.unknown()
                ),
                remote=Tri.of(data.remote_enabled),
                authentication=(
                    Fact.observed(authentication["status"], message_id)
                    if authentication
                    else Fact.unknown()
                ),
                identity_established=(
                    Fact.observed(authentication["agent"], message_id)
                    if authentication and authentication.get("agent")
                    else Fact.unknown()
                ),
                key_id=(
                    Fact.observed(authentication["key_id"], message_id)
                    if authentication and authentication.get("key_id")
                    else Fact.unknown()
                ),
                algorithm=(
                    Fact.observed(authentication["algorithm"], message_id)
                    if authentication and authentication.get("algorithm")
                    else Fact.unknown()
                ),
                protocol_version=(
                    Fact.observed(authentication["protocol_version"], message_id)
                    if authentication and authentication.get("protocol_version")
                    else Fact.unknown()
                ),
            )
        )

    views.sort(key=lambda view: (view.conversation_id, view.sequence, view.message_id))
    return A2AView(
        messages=tuple(views),
        issued=len(views),
        consumed=sum(1 for view in views if view.consumed.is_true),
        rejected=sum(1 for view in views if view.consumption.value == "REJECTED"),
        authenticated=sum(1 for view in views if view.authentication.value == "AUTHENTICATED"),
        authentication_failures=sum(
            1
            for view in views
            if view.authentication.known and view.authentication.value != "AUTHENTICATED"
        ),
        provenance=Provenance(
            source=ViewSource.A2A_LEDGER,
            as_of=data.captured_at,
            completeness=(Completeness.COMPLETE if data.audit_available else Completeness.PARTIAL),
            detail=(
                None
                if data.audit_available
                else "the ledger was read but the audit trail was not; authentication is UNKNOWN"
            ),
        ),
    )


def _incident_records(data: ControlCenterInput):
    return tuple(
        record
        for record in data.audit_records
        if record.event.incident_id in (None, data.incident_id)
    )


def _authentication_index(data: ControlCenterInput) -> dict[str, dict[str, str]]:
    """Authentication outcomes by message id, from ``remote.authentication`` events.

    Carries the key *id*, never key material. The recorder has no parameter that could hold
    a secret, which is asserted in ``tests/a2a/remote/test_structure.py``.
    """
    if not data.audit_available:
        return {}
    index: dict[str, dict[str, str]] = {}
    for record in _incident_records(data):
        if record.event.event_type != AuditEventType.REMOTE_AUTHENTICATION.value:
            continue
        message_id = record.correlation.get("message_id")
        if not message_id:
            continue
        index[message_id] = {
            "status": record.correlation.get("status", "UNKNOWN"),
            "agent": record.correlation.get("authenticated_agent_id", ""),
            "key_id": record.correlation.get("key_id", ""),
            "algorithm": record.correlation.get("algorithm", ""),
            "protocol_version": record.correlation.get("protocol_version", ""),
        }
    return index


def _rejection_index(data: ControlCenterInput) -> dict[str, str]:
    """Why each refused message was refused, from ``a2a.message`` events."""
    if not data.audit_available:
        return {}
    index: dict[str, str] = {}
    for record in _incident_records(data):
        if record.event.event_type != AuditEventType.A2A_MESSAGE.value:
            continue
        rejection = record.correlation.get("rejection")
        message_id = record.correlation.get("message_id")
        if rejection and message_id:
            index.setdefault(message_id, rejection)
    return index


def _consumption_counts(data: ControlCenterInput) -> dict[str, int]:
    """How many times each message id appears as consumed in the ledger.

    More than once is a replay, and counting records is how that is detected -- never by
    asking the ledger whether a replay occurred, which is the component the count exists to
    check.
    """
    counts: dict[str, int] = {}
    for record in data.a2a_messages:
        if str(record.status) in {"CONSUMED", "COMPLETED"}:
            key = str(record.message_id)
            counts[key] = counts.get(key, 0) + 1
    return counts
