"""The enforcement point: everything a message must satisfy before a recipient sees it.

    issue → seal → send → admit → deliver → respond

The broker is where the A2A guarantees actually live. It issues messages bound to the
*accountable* sender rather than the declared one, and it admits an incoming message only
after every binding it carries has been checked against something the sender could not
influence.

What it checks, and in what order
---------------------------------

Order matters, and it is cheapest-and-most-fundamental first:

1. **integrity** — the seal matches, so the fields below are the fields that were issued;
2. **origin** — this broker's ledger issued this message; a public seal formula is not an
   origin (:mod:`aegis.a2a.ledger`);
3. **identity** — the declared sender is the accountable agent, and both ends exist;
4. **permission to communicate** — the injected matrix has this edge;
5. **binding** — incident, conversation and task are the ones the message claims;
6. **freshness** — not expired, conversation not expired;
7. **ordering** — exactly the next sequence number;
8. **replay** — not seen before as delivered, not already consumed;
9. **bounds** — payload size, evidence count, messages per task.

Every one of them fails closed, and a failure is a returned
:class:`~aegis.a2a.verdicts.A2AVerdict`, never a partial acceptance.

What it does not do
-------------------

It never decides whether an action is permitted. It has no policy engine, no approval
engine, no assessment pipeline, no verification engine and no executor — it cannot import
them. Admitting a message means "this message may be delivered", which is a statement about
a message and not about the world. A specialist whose message was admitted has been allowed
to *speak*, and speaking has never been authorization in AEGIS.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta

from pydantic import JsonValue, ValidationError

from aegis.a2a.contracts import (
    DEFAULT_MESSAGE_TTL_SECONDS,
    MAX_EVIDENCE_REFS,
    MAX_PAYLOAD_BYTES,
    MAX_RESPONSE_BYTES,
    A2AEnvelope,
    MessageStatus,
    MessageType,
    TaskType,
    envelope_seal,
    payload_size,
)
from aegis.a2a.identity import AgentDirectory
from aegis.a2a.ledger import MessageLedger, MessageRecord
from aegis.a2a.records import payload_digest
from aegis.a2a.transport import A2ATransport, InMemoryA2ATransport, TransportError
from aegis.a2a.verdicts import A2ARejection, A2AVerdict
from aegis.agents.findings import AgentFinding
from aegis.core.domain import utc_now

__all__ = ["A2ABroker", "A2ADelivery"]


class A2ADelivery:
    """One admitted message and the verdict that admitted it.

    Not a domain contract: it pairs a frozen envelope with a frozen verdict for the caller's
    convenience and holds no state of its own.
    """

    __slots__ = ("envelope", "verdict")

    def __init__(self, envelope: A2AEnvelope, verdict: A2AVerdict) -> None:
        self.envelope = envelope
        self.verdict = verdict

    @property
    def accepted(self) -> bool:
        return self.verdict.accepted

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.envelope!r}, {self.verdict!r})"


class A2ABroker:
    """Issues, seals, sends and admits A2A messages.

    Args:
        directory: Authoritative agent identities and the permitted communication edges.
        transport: How messages move. Local and in-memory unless a caller supplies another.
        ledger: Message identity, ordering and consumption state.
        clock: Injected, so expiry and issuance are reproducible.
        message_ttl_seconds: How long an issued message stays usable.
        max_payload_bytes / max_response_bytes: Hard size bounds, checked before a
            recipient — or a recipient's model — ever sees the payload.
    """

    def __init__(
        self,
        directory: AgentDirectory,
        *,
        transport: A2ATransport | None = None,
        ledger: MessageLedger | None = None,
        clock: Callable[[], datetime] = utc_now,
        message_ttl_seconds: float = DEFAULT_MESSAGE_TTL_SECONDS,
        max_payload_bytes: int = MAX_PAYLOAD_BYTES,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        if message_ttl_seconds <= 0:
            raise ValueError("message_ttl_seconds must be positive")
        self.directory = directory
        self.transport = transport if transport is not None else InMemoryA2ATransport()
        self.ledger = ledger if ledger is not None else MessageLedger(clock=clock)
        self._clock = clock
        self._ttl = message_ttl_seconds
        self._max_payload = max_payload_bytes
        self._max_response = max_response_bytes
        self._issued_counter = 0

    # --- issuing --------------------------------------------------------------------

    def issue(
        self,
        *,
        accountable_sender: str,
        recipient_agent_id: str,
        incident_id: str,
        conversation_id: str,
        task_id: str,
        task_type: TaskType,
        message_type: MessageType = MessageType.TASK_REQUEST,
        target_resource: str | None = None,
        evidence_refs: Sequence[str] = (),
        payload: Mapping[str, JsonValue] | None = None,
    ) -> A2AEnvelope | A2AVerdict:
        """Build and register one sealed message.

        ``accountable_sender`` is the authoritative identity, taken from the application's
        wiring. It becomes ``sender_agent_id``, so a message cannot be *issued* under a
        borrowed identity in the first place — :meth:`admit` then re-checks the same
        equality for messages that arrived by some other route.

        Returns:
            The envelope, or an :class:`A2AVerdict` explaining why none could be built.
            A refusal is a value here too: a caller that has to unpack a union cannot
            accidentally treat a failure as a message.
        """
        body = dict(payload or {})
        size = payload_size(body)
        limit = self._max_response if message_type is MessageType.TASK_RESULT else self._max_payload
        if size > limit:
            return A2AVerdict.refuse(
                A2ARejection.PAYLOAD_TOO_LARGE,
                f"payload is {size} bytes, over the {limit}-byte limit; refused unsent",
            )
        if len(evidence_refs) > MAX_EVIDENCE_REFS:
            return A2AVerdict.refuse(
                A2ARejection.PAYLOAD_TOO_LARGE,
                f"{len(evidence_refs)} evidence references exceeds the {MAX_EVIDENCE_REFS} limit",
            )
        if self.ledger.task_budget_exhausted(task_id):
            return A2AVerdict.refuse(
                A2ARejection.TOO_MANY_MESSAGES,
                f"task {task_id!r} has already produced its message budget",
            )

        now = self._clock()
        sequence = self.ledger.expected_sequence(conversation_id)
        self._issued_counter += 1
        message_id = self._message_id(conversation_id, sequence, task_id)
        try:
            unsealed = A2AEnvelope(
                message_id=message_id,
                conversation_id=conversation_id,
                incident_id=incident_id,
                sender_agent_id=accountable_sender,
                recipient_agent_id=recipient_agent_id,
                task_id=task_id,
                message_type=message_type,
                task_type=task_type,
                target_resource=target_resource,
                evidence_refs=tuple(evidence_refs),
                payload=body,
                sequence=sequence,
                created_at=now,
                expires_at=now + timedelta(seconds=self._ttl),
                seal="unsealed",
            )
        except ValidationError as error:
            return A2AVerdict.refuse(
                A2ARejection.MALFORMED, f"message could not be constructed: {error}"
            )
        envelope = unsealed.model_copy(update={"seal": envelope_seal(unsealed)})
        self.ledger.issue(
            MessageRecord(
                message_id=envelope.message_id,
                conversation_id=envelope.conversation_id,
                incident_id=envelope.incident_id,
                sender_agent_id=envelope.sender_agent_id,
                recipient_agent_id=envelope.recipient_agent_id,
                task_id=envelope.task_id,
                task_type=envelope.task_type,
                message_type=envelope.message_type,
                target_resource=envelope.target_resource,
                evidence_refs=envelope.evidence_refs,
                sequence=envelope.sequence,
                created_at=envelope.created_at,
                expires_at=envelope.expires_at,
                payload_digest=payload_digest(envelope.payload),
                seal=envelope.seal,
                status=MessageStatus.ISSUED,
                issued_at=now,
            )
        )
        return envelope

    def _message_id(self, conversation_id: str, sequence: int, task_id: str) -> str:
        """A deterministic id: same conversation, same position, same task, same id.

        Derived rather than random so a run is byte-reproducible. It is an identifier, not a
        secret, and nothing anywhere treats knowing one as evidence of anything.
        """
        seed = f"{conversation_id}|{sequence}|{task_id}|{self._issued_counter}"
        return f"msg-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:24]}"

    # --- sending --------------------------------------------------------------------

    def send(self, envelope: A2AEnvelope) -> A2AVerdict:
        """Hand an issued message to the transport."""
        try:
            self.transport.send(envelope)
        except TransportError as error:
            self.ledger.mark(envelope.message_id, MessageStatus.REJECTED)
            return A2AVerdict.refuse(
                A2ARejection.RECIPIENT_UNAVAILABLE, str(error), envelope.message_id
            )
        return A2AVerdict.accept(envelope.message_id, "delivered to the recipient inbox")

    # --- admitting ------------------------------------------------------------------

    def admit(
        self,
        envelope: A2AEnvelope,
        *,
        accountable_sender: str,
        expected_incident_id: str,
        expected_conversation_id: str | None = None,
        expected_task_id: str | None = None,
        recipient_handles: TaskType | None = None,
    ) -> A2AVerdict:
        """Decide whether one message may be delivered to its recipient.

        Args:
            envelope: The message, exactly as it arrived.
            accountable_sender: Who actually sent it, from the wiring. Never from the
                message.
            expected_incident_id: The incident the caller is actually working on.
            expected_conversation_id: The conversation the caller is actually in.
            expected_task_id: The task the caller actually dispatched.
            recipient_handles: The task type the recipient really handles, if the caller
                knows it. ``None`` skips only that check; every other one still runs.

        Accepting marks the message consumed, so the same message can never be admitted
        twice — the check and the state change happen together rather than being two steps
        a caller could perform out of order.
        """
        message_id = envelope.message_id

        def refuse(rejection: A2ARejection, detail: str) -> A2AVerdict:
            self.ledger.mark(message_id, MessageStatus.REJECTED)
            return A2AVerdict.refuse(rejection, detail, message_id)

        # 1. integrity, before anything below is trusted to say what it says
        if envelope_seal(envelope) != envelope.seal:
            return refuse(
                A2ARejection.INTEGRITY_FAILURE,
                "the seal does not match the message; it was modified after issuance",
            )

        # 2. origin: a valid seal is not proof this broker issued anything
        record = self.ledger.record_of(message_id)
        if record is None:
            return refuse(
                A2ARejection.NOT_ISSUED,
                f"no message {message_id!r} was issued by this broker; a correct seal is "
                f"integrity, not origin",
            )
        if record.seal != envelope.seal:
            return refuse(
                A2ARejection.INTEGRITY_FAILURE,
                "the message does not match the one this broker issued under that id",
            )

        # 3. replay and consumption, before any work is done on the message's behalf
        if self.ledger.consumed(message_id):
            return refuse(
                A2ARejection.ALREADY_CONSUMED,
                f"message {message_id!r} has already been consumed",
            )

        # 4. identity: the declared sender against the agent actually sending
        if not self.directory.binds(envelope.sender_agent_id, accountable_sender):
            return refuse(
                A2ARejection.SENDER_MISMATCH,
                f"message declares sender {envelope.sender_agent_id!r} but the accountable "
                f"agent is {accountable_sender!r}",
            )
        if not self.directory.knows(envelope.sender_agent_id):
            return refuse(
                A2ARejection.UNKNOWN_SENDER,
                f"sender {envelope.sender_agent_id!r} is not registered",
            )
        if not self.directory.knows(envelope.recipient_agent_id):
            return refuse(
                A2ARejection.UNKNOWN_RECIPIENT,
                f"recipient {envelope.recipient_agent_id!r} is not registered; known: "
                f"{', '.join(sorted(self.directory.agents)) or 'none'}",
            )

        # 5. permission to communicate at all
        if not self.directory.permits(envelope.sender_agent_id, envelope.recipient_agent_id):
            return refuse(
                A2ARejection.NOT_PERMITTED,
                f"{envelope.sender_agent_id} may not send to {envelope.recipient_agent_id}; "
                f"permitted: "
                f"{', '.join(self.directory.recipients_for(envelope.sender_agent_id)) or 'none'}",
            )

        # 6. task: the recipient must actually handle it
        if recipient_handles is not None and envelope.task_type is not recipient_handles:
            return refuse(
                A2ARejection.UNKNOWN_TASK,
                f"{envelope.recipient_agent_id} handles {recipient_handles}, not "
                f"{envelope.task_type}",
            )

        # 7. bindings against what the caller is genuinely doing
        if envelope.incident_id != expected_incident_id:
            return refuse(
                A2ARejection.INCIDENT_MISMATCH,
                f"message is bound to incident {envelope.incident_id!r}, not "
                f"{expected_incident_id!r}",
            )
        if (
            expected_conversation_id is not None
            and envelope.conversation_id != expected_conversation_id
        ):
            return refuse(
                A2ARejection.CONVERSATION_MISMATCH,
                f"message belongs to conversation {envelope.conversation_id!r}, not "
                f"{expected_conversation_id!r}",
            )
        if expected_task_id is not None and envelope.task_id != expected_task_id:
            return refuse(
                A2ARejection.TASK_MISMATCH,
                f"message belongs to task {envelope.task_id!r}, not {expected_task_id!r}",
            )
        if record.incident_id != envelope.incident_id or record.conversation_id != (
            envelope.conversation_id
        ):
            return refuse(
                A2ARejection.CONVERSATION_MISMATCH,
                "the message's bindings do not match the ones it was issued with",
            )

        # 8. freshness
        now = self._clock()
        if envelope.expired_at(now):
            self.ledger.mark(message_id, MessageStatus.EXPIRED)
            return A2AVerdict.refuse(
                A2ARejection.EXPIRED,
                f"message expired at {envelope.expires_at.isoformat()}",
                message_id,
            )
        if self.ledger.conversation_expired(envelope.conversation_id):
            return refuse(
                A2ARejection.CONVERSATION_EXPIRED,
                f"conversation {envelope.conversation_id!r} is no longer open",
            )

        # 9. ordering: exactly the position this message was issued at, and no other
        if envelope.sequence != record.sequence:
            return refuse(
                A2ARejection.SEQUENCE_MISMATCH,
                f"message claims sequence {envelope.sequence}, was issued at {record.sequence}",
            )
        preceding = [
            other
            for other in self.ledger.messages_for(envelope.conversation_id)
            if other.sequence < envelope.sequence
        ]
        unfinished = [
            other.sequence
            for other in preceding
            if other.status
            not in {MessageStatus.CONSUMED, MessageStatus.COMPLETED, MessageStatus.REJECTED}
        ]
        if unfinished:
            return refuse(
                A2ARejection.SEQUENCE_MISMATCH,
                f"sequence {envelope.sequence} arrived while {sorted(unfinished)} are "
                f"still outstanding; messages are not silently reordered",
            )

        # 10. bounds, last because they are the most expensive to measure
        size = envelope.payload_bytes
        limit = (
            self._max_response
            if envelope.message_type is MessageType.TASK_RESULT
            else self._max_payload
        )
        if size > limit:
            return refuse(
                A2ARejection.PAYLOAD_TOO_LARGE,
                f"payload is {size} bytes, over the {limit}-byte limit; refused before "
                f"any recipient saw it",
            )

        self.ledger.mark(message_id, MessageStatus.CONSUMED)
        self.transport.acknowledge(message_id)
        return A2AVerdict.accept(
            message_id, f"admitted {envelope.message_type} at seq {envelope.sequence}"
        )

    def reject(self, envelope: A2AEnvelope, verdict: A2AVerdict) -> A2AVerdict:
        """Record a refusal on the transport as well as the ledger."""
        self.transport.reject(envelope.message_id, verdict)
        return verdict

    # --- responses ------------------------------------------------------------------

    def bind_response(
        self, request: A2AEnvelope, response: A2AEnvelope, finding: AgentFinding | None
    ) -> A2AVerdict:
        """Check that a response really came from the agent it claims, about the right thing.

        Part 9. Two equalities the transport must not let a specialist escape:

        * ``response.sender_agent_id == finding.agent_id`` — a specialist cannot return a
          finding attributed to a different specialist;
        * ``response.incident_id == finding.incident_id`` — a finding cannot be about some
          other incident.

        A response with no finding is fine and common: a failed or refused task produces a
        typed failure, not a hollow finding.
        """
        if response.conversation_id != request.conversation_id:
            return A2AVerdict.refuse(
                A2ARejection.CONVERSATION_MISMATCH,
                "the response belongs to a different conversation than the request",
                response.message_id,
            )
        if response.task_id != request.task_id:
            return A2AVerdict.refuse(
                A2ARejection.TASK_MISMATCH,
                "the response belongs to a different task than the request",
                response.message_id,
            )
        if response.sender_agent_id != request.recipient_agent_id:
            return A2AVerdict.refuse(
                A2ARejection.RESPONSE_IDENTITY_MISMATCH,
                f"the response claims sender {response.sender_agent_id!r} but the request "
                f"went to {request.recipient_agent_id!r}",
                response.message_id,
            )
        if finding is not None:
            if finding.agent_id != response.sender_agent_id:
                return A2AVerdict.refuse(
                    A2ARejection.RESPONSE_IDENTITY_MISMATCH,
                    f"finding claims agent {finding.agent_id!r} in a message sent by "
                    f"{response.sender_agent_id!r}",
                    response.message_id,
                )
            if finding.incident_id != response.incident_id:
                return A2AVerdict.refuse(
                    A2ARejection.RESPONSE_BINDING_MISMATCH,
                    f"finding is bound to incident {finding.incident_id!r} in a message "
                    f"about {response.incident_id!r}",
                    response.message_id,
                )
        self.ledger.mark(response.message_id, MessageStatus.COMPLETED)
        return A2AVerdict.accept(response.message_id, "response bound to its request")

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.directory!r}, {self.ledger!r})"
