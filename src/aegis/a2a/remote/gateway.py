"""Where a remote message meets the boundary that already existed.

The composition point, and the most important file in this milestone. Everything else here
answers *who sent this*; this module takes that answer and hands it to the machinery from
Prompts 15 and 16 **as the accountable sender**.

    RemoteFrame
        |  decode           bounded, and a failure is a refusal, never an empty message
        v
    RemoteEnvelope
        |  authenticate     who sent this -- and nothing else
        v
    agent_id (cryptographic)
        |  address          signed recipient against an agent this process really hosts
        |  bind             incident, conversation, position
        |  replay           durable, from Prompt 16
        v
    A2ABroker.admit(envelope, accountable_sender=agent_id, ...)
        |
        v
    the existing control plane, entirely unchanged

The line that matters is ``accountable_sender=agent_id``. In Prompt 15 that argument came
from the application's wiring, because sender and receiver shared a process. For a remote
peer there is no shared wiring, so the signature takes its place -- and every check the
local broker already performs then runs unchanged against an identity the sender could not
choose. Authentication *supplies* the accountable identity. It does not replace a single
check, weaken one, or add one of its own.

Two facts a caller must not be able to confuse
----------------------------------------------

``hosted_agents`` is **wiring**: the agent ids this process actually runs. ``as_agent`` is
which of them a particular delivery is for, and it must be one of them. The message's own
``recipient_agent_id`` is then compared against that -- so a frame readdressed by an
intermediary is refused, because the address on the outside was never what was consulted.

What this module is careful not to become
-----------------------------------------

An authorization layer. It holds no policy engine, no approval provider, no risk
assessment, no blast radius, no lifecycle gate, no breaker and no executor, and the A2A
package cannot import any of them. A message that arrives here perfectly signed, from an
identity in excellent standing, has earned exactly one thing: the right to be *considered*
by the same control plane that considers every local message. A compromised remote
specialist gets the same answer a compromised local one gets, which is the property Part 15
exists to prove.
"""

from __future__ import annotations

from collections.abc import Callable, Set
from datetime import datetime

from aegis.a2a.broker import A2ABroker
from aegis.a2a.contracts import A2AEnvelope, MessageStatus, TaskType
from aegis.a2a.errors import A2AError
from aegis.a2a.ledger import MessageRecord
from aegis.a2a.remote.authenticator import RemoteAuthenticator
from aegis.a2a.remote.envelope import (
    MAX_REMOTE_FRAME_BYTES,
    RemoteEnvelope,
    RemoteFrame,
    decode_envelope,
    encode_envelope,
    frame_digest,
)
from aegis.a2a.remote.transport import (
    InMemoryRemoteTransport,
    RemoteTransport,
    RemoteTransportError,
)
from aegis.a2a.remote.verdicts import RemoteRejection, RemoteVerdict
from aegis.agents.findings import AgentFinding
from aegis.core.domain import utc_now

__all__ = ["RemoteDelivery", "RemoteGateway"]


class RemoteDelivery:
    """One remote message and every verdict it collected on the way in.

    Not a domain contract: it pairs frozen values for the caller's convenience and holds no
    state. Both verdicts are kept deliberately -- a caller can see that authentication
    succeeded *and* that the local boundary refused it, which is the shape of a compromised
    peer and is exactly the distinction a single boolean would destroy.
    """

    __slots__ = ("authentication", "envelope", "local", "verdict")

    def __init__(
        self,
        verdict: RemoteVerdict,
        envelope: A2AEnvelope | None,
        local=None,
        *,
        authentication: RemoteVerdict | None = None,
    ) -> None:
        self.verdict = verdict
        """The outcome: whatever refused the message, or the acceptance that did not."""

        self.authentication = authentication if authentication is not None else verdict
        """What the *authenticator* said, kept even when something later refused.

        Separate from :attr:`verdict` on purpose. A message can authenticate perfectly and
        then be refused by the local boundary -- that is the exact shape of a compromised
        peer, and folding the two into one field would erase the distinction this class
        exists to preserve. When nothing reached the authenticator, the two are the same
        object and the refusal speaks for both.
        """

        self.envelope = envelope
        self.local = local

    @property
    def authenticated(self) -> bool:
        """Whether the sender was established. **Not** whether anything was permitted.

        Read from :attr:`authentication`, so a message the local boundary refused still
        reports the sender it genuinely proved.
        """
        return self.authentication.authenticated

    @property
    def admitted(self) -> bool:
        """Whether the local boundary accepted the message for delivery.

        Still not authorization. An admitted message is a message a specialist may read; a
        finding it produces goes through policy, approval, the gate and verification exactly
        as every other finding does.
        """
        return self.local is not None and self.local.accepted

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(authenticated={self.authenticated}, "
            f"admitted={self.admitted}, {self.verdict!r})"
        )


class RemoteGateway:
    """Admits remote messages by composing authentication with the local boundary.

    Args:
        hosted_agents: The agent ids this process actually runs. Wiring, not a claim: a
            delivery for an agent absent from this set is refused, because a frame cannot
            be delivered to an agent that is not here.
        authenticator: Establishes the sender. Read-only over the registry.
        broker: The real local broker. Never replaced, never bypassed, never subclassed --
            every Prompt 15 and 16 guarantee applies to a remote message because the same
            object enforces it.
        transport: How frames move. Local and in-memory unless a caller supplies another.
        clock: Injected, so freshness and recording are reproducible.
    """

    def __init__(
        self,
        hosted_agents: Set[str],
        authenticator: RemoteAuthenticator,
        broker: A2ABroker,
        *,
        transport: RemoteTransport | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if not hosted_agents:
            raise ValueError("a gateway must host at least one agent")
        self.hosted_agents = frozenset(hosted_agents)
        self.authenticator = authenticator
        self.broker = broker
        self.transport = transport if transport is not None else InMemoryRemoteTransport()
        self._clock = clock

    # --- sending ---------------------------------------------------------------------

    def dispatch(self, envelope: RemoteEnvelope) -> RemoteVerdict:
        """Put one signed message on the transport.

        A transport failure is a **refusal**, carrying which failure it was. It is never a
        silent success and never an empty delivery: the caller has to unpack a verdict, and
        a verdict that says ``TRANSPORT_FAILURE`` cannot be mistaken for a message that
        arrived and said nothing.
        """
        frame = RemoteFrame(
            destination=envelope.message.recipient_agent_id, body=encode_envelope(envelope)
        )
        try:
            self.transport.send(frame)
        except RemoteTransportError as error:
            return RemoteVerdict.refuse(
                RemoteRejection.TRANSPORT_FAILURE,
                f"the frame could not be carried: {error}",
                message_id=envelope.message.message_id,
                key_id=envelope.key_id,
            )
        return RemoteVerdict.accept(
            agent_id=envelope.message.sender_agent_id,
            key_id=envelope.key_id,
            message_id=envelope.message.message_id,
            detail="frame handed to the transport; handing over is not acceptance",
        )

    # --- receiving -------------------------------------------------------------------

    def deliver(
        self,
        frame: RemoteFrame,
        *,
        as_agent: str,
        expected_incident_id: str,
        expected_conversation_id: str | None = None,
        recipient_handles: TaskType | None = None,
    ) -> RemoteDelivery:
        """Take one frame off the wire and decide whether it may reach ``as_agent``.

        Args:
            frame: Exactly as it arrived, unsigned metadata and all.
            as_agent: Which hosted agent this delivery is for. From the application's own
                registry of running agents -- never from the frame, and never from the
                message.
            expected_incident_id: The incident this receiver is genuinely working on.
            expected_conversation_id: The conversation it is genuinely in, when it knows.
            recipient_handles: The task type this receiver really handles, when known.

        Every refusal path marks the frame rejected on the transport, so a refused frame
        cannot sit in an inbox waiting to be tried again by something less careful.
        """
        reference = frame_digest(frame)

        def refuse(rejection: RemoteRejection, detail: str, message_id: str | None = None):
            verdict = RemoteVerdict.refuse(rejection, detail, message_id=message_id)
            self.transport.reject(reference, verdict)
            return RemoteDelivery(verdict, None)

        if as_agent not in self.hosted_agents:
            return refuse(
                RemoteRejection.WRONG_RECIPIENT,
                f"this process does not host {as_agent!r}; hosted: "
                f"{', '.join(sorted(self.hosted_agents))}",
            )

        # 1. bounds, before the parser is asked to do anything
        if frame.size > MAX_REMOTE_FRAME_BYTES:
            return refuse(
                RemoteRejection.OVERSIZED_FRAME,
                f"frame is {frame.size} bytes, over the {MAX_REMOTE_FRAME_BYTES}-byte "
                f"limit; refused before parsing",
            )
        envelope = decode_envelope(frame.body)
        if envelope is None:
            return refuse(
                RemoteRejection.MALFORMED_FRAME,
                "the frame body is not a well-formed remote envelope; truncated, altered, "
                "or missing a required field",
            )

        # 2. who sent this
        verdict = self.authenticator.authenticate(envelope)
        if not verdict.authenticated or verdict.agent_id is None:
            self.transport.reject(reference, verdict)
            return RemoteDelivery(verdict, None)
        message = envelope.message
        message_id = message.message_id

        def refuse_after_authenticating(rejection: RemoteRejection, detail: str):
            """A refusal that happened *after* the sender was established.

            Keeps the authentication verdict, so a caller can still see who sent the
            message it is refusing -- which is exactly what an operator needs when the
            answer is "a peer you trust sent something it may not send".
            """
            refusal = RemoteVerdict.refuse(rejection, detail, message_id=message_id)
            self.transport.reject(reference, refusal)
            return RemoteDelivery(refusal, None, authentication=verdict)

        # 3. addressing, against the *signed* recipient. The frame's destination is a hint
        #    an intermediary can rewrite, so it is never what this is compared with.
        if message.recipient_agent_id != as_agent:
            return refuse_after_authenticating(
                RemoteRejection.WRONG_RECIPIENT,
                f"message is signed for {message.recipient_agent_id!r}; this delivery is "
                f"for {as_agent!r}",
            )

        # 4. bindings, against what this receiver is genuinely doing
        if message.incident_id != expected_incident_id:
            return refuse_after_authenticating(
                RemoteRejection.CROSS_INCIDENT,
                f"message is bound to incident {message.incident_id!r}, not "
                f"{expected_incident_id!r}",
            )
        if expected_conversation_id is not None and (
            message.conversation_id != expected_conversation_id
        ):
            return refuse_after_authenticating(
                RemoteRejection.CROSS_CONVERSATION,
                f"message belongs to conversation {message.conversation_id!r}, not "
                f"{expected_conversation_id!r}",
            )

        # 5. replay and recording, in that order
        recorded = self._record(envelope, verdict.agent_id, message)
        if recorded is not None:
            return refuse_after_authenticating(recorded[0], recorded[1])

        try:
            local = self.broker.admit(
                message,
                accountable_sender=verdict.agent_id,
                expected_incident_id=expected_incident_id,
                expected_conversation_id=message.conversation_id,
                expected_task_id=message.task_id,
                recipient_handles=recipient_handles,
            )
        except A2AError as error:
            return refuse_after_authenticating(
                RemoteRejection.STATE_UNAVAILABLE,
                f"A2A state is unusable: {type(error).__name__}: {error}",
            )
        if not local.accepted:
            local_verdict = RemoteVerdict.from_local(local.rejection, local.detail, message_id)
            self.transport.reject(reference, local_verdict)
            return RemoteDelivery(local_verdict, None, local, authentication=verdict)

        self.transport.acknowledge(reference)
        return RemoteDelivery(verdict, message, local)

    def deliver_response(
        self,
        frame: RemoteFrame,
        request: A2AEnvelope,
        finding: AgentFinding | None,
        *,
        as_agent: str,
    ) -> RemoteDelivery:
        """Take a remote peer's answer and bind it to the request it claims to answer.

        Part 14. A response is *bound*, never *admitted*: the local design has always
        treated the two differently, and mirroring that here is what keeps one set of rules.
        The delegation matrix says a specialist may send to nobody, which is correct for
        delegation and would be wrong for a reply, so a reply does not go through the check
        that enforces it.

        Four equalities a remote peer must not escape, on top of the signature:

        * the **authenticated** agent is the one the request was sent to;
        * the response is addressed to this receiver;
        * it is bound to the request's incident and conversation;
        * :meth:`~aegis.a2a.broker.A2ABroker.bind_response` agrees about task, sender and
          the finding's own attribution.
        """
        reference = frame_digest(frame)

        def refuse(rejection: RemoteRejection, detail: str, message_id: str | None = None):
            verdict = RemoteVerdict.refuse(rejection, detail, message_id=message_id)
            self.transport.reject(reference, verdict)
            return RemoteDelivery(verdict, None)

        if as_agent not in self.hosted_agents:
            return refuse(
                RemoteRejection.WRONG_RECIPIENT, f"this process does not host {as_agent!r}"
            )
        if frame.size > MAX_REMOTE_FRAME_BYTES:
            return refuse(RemoteRejection.OVERSIZED_FRAME, f"frame is {frame.size} bytes")
        envelope = decode_envelope(frame.body)
        if envelope is None:
            return refuse(
                RemoteRejection.MALFORMED_FRAME,
                "the frame body is not a well-formed remote envelope",
            )

        verdict = self.authenticator.authenticate(envelope)
        if not verdict.authenticated or verdict.agent_id is None:
            self.transport.reject(reference, verdict)
            return RemoteDelivery(verdict, None)

        response = envelope.message
        message_id = response.message_id

        def refuse_after_authenticating(rejection: RemoteRejection, detail: str):
            """A refusal after the responder was established. Keeps who it was."""
            refusal = RemoteVerdict.refuse(rejection, detail, message_id=message_id)
            self.transport.reject(reference, refusal)
            return RemoteDelivery(refusal, None, authentication=verdict)

        if verdict.agent_id != request.recipient_agent_id:
            return refuse_after_authenticating(
                RemoteRejection.RESPONSE_BINDING_MISMATCH,
                f"the response is authenticated as {verdict.agent_id!r} but the request "
                f"went to {request.recipient_agent_id!r}",
            )
        if response.recipient_agent_id != as_agent:
            return refuse_after_authenticating(
                RemoteRejection.WRONG_RECIPIENT,
                f"the response is signed for {response.recipient_agent_id!r}, not {as_agent!r}",
            )
        if response.incident_id != request.incident_id:
            return refuse_after_authenticating(
                RemoteRejection.CROSS_INCIDENT,
                f"the response is bound to incident {response.incident_id!r}, not "
                f"{request.incident_id!r}",
            )
        if response.conversation_id != request.conversation_id:
            return refuse_after_authenticating(
                RemoteRejection.CROSS_CONVERSATION,
                "the response belongs to a different conversation than the request",
            )

        recorded = self._record(envelope, verdict.agent_id, response)
        if recorded is not None:
            return refuse_after_authenticating(recorded[0], recorded[1])
        try:
            local = self.broker.bind_response(request, response, finding)
        except A2AError as error:
            return refuse_after_authenticating(
                RemoteRejection.STATE_UNAVAILABLE,
                f"A2A state is unusable: {type(error).__name__}: {error}",
            )
        if not local.accepted:
            local_verdict = RemoteVerdict.from_local(local.rejection, local.detail, message_id)
            self.transport.reject(reference, local_verdict)
            return RemoteDelivery(local_verdict, None, local, authentication=verdict)

        self.transport.acknowledge(reference)
        return RemoteDelivery(verdict, response, local)

    # --- internals -------------------------------------------------------------------

    def _record(
        self, envelope: RemoteEnvelope, agent_id: str, message: A2AEnvelope
    ) -> tuple[RemoteRejection, str] | None:
        """Replay-check an arriving message, then write it into this receiver's own ledger.

        Returns a refusal, or ``None`` when the message may proceed.

        Three cases, and the reasoning for each:

        **Already consumed.** The durable answer, and the whole of the replay defence.
        Since Prompt 16 the ledger is backed by an append-only log, so a redelivery after the
        receiver was restarted meets a record that was written to disk rather than a set
        that died with the process.

        **Known, and the same message.** The receiver already holds this record -- either it
        issued the message itself (an in-process link, where sender and receiver share a
        ledger) or it received and refused it earlier. Neither is a replay of *work done*,
        and Prompt 16 settled that a refusal records without blacklisting, so the message is
        judged again by the local boundary rather than short-circuited here.

        **Known, and a different message.** One id, two contents. That is a substitution
        attempt, and it is refused here rather than left to the broker's integrity check --
        both refuse, and refusing at the boundary that owns message identity is the one that
        names the problem correctly.
        """
        ledger = self.broker.ledger
        if ledger.consumed(message.message_id):
            return (
                RemoteRejection.ALREADY_CONSUMED,
                f"message {message.message_id!r} has already been consumed here",
            )
        known = ledger.record_of(message.message_id)
        if known is not None:
            if known.seal != message.seal:
                return (
                    RemoteRejection.REPLAY,
                    f"message id {message.message_id!r} is already bound to a different "
                    f"message here; one id, two contents",
                )
            return None

        # A genuinely new arrival must land at the next position in its conversation.
        # Checked here rather than earlier because writing the record is what *creates*
        # the continuity the check exists to verify -- and checked only on this branch,
        # because a message this ledger issued itself has already advanced the position it
        # would be compared against.
        expected_sequence = ledger.expected_sequence(message.conversation_id)
        if message.sequence != expected_sequence:
            return (
                RemoteRejection.SEQUENCE_MISMATCH,
                f"message claims position {message.sequence}; conversation "
                f"{message.conversation_id!r} is at {expected_sequence}",
            )
        try:
            self._record_inbound(envelope, agent_id, message)
        except A2AError as error:
            return (
                RemoteRejection.STATE_UNAVAILABLE,
                f"A2A state is unusable: {type(error).__name__}: {error}; a persistence "
                f"failure is a refusal, never a delivery",
            )
        return None

    def _record_inbound(
        self, envelope: RemoteEnvelope, agent_id: str, message: A2AEnvelope
    ) -> None:
        """Write an arriving message into this receiver's own durable ledger.

        The receiver records what it accepted. Without this the local broker would refuse
        every genuinely remote message as ``NOT_ISSUED`` -- correctly, since it issued none
        of them -- and the replay, ordering and durability machinery would have nothing to
        work on.

        ``sender_agent_id`` is the **authenticated** identity rather than the field in the
        message. The two have already been compared, so they agree; recording the
        authenticated one anyway means the durable record says what was *established*, not
        what was *claimed*, and a future reader of the log gets the stronger fact.
        """
        self.broker.ledger.issue(
            MessageRecord(
                message_id=message.message_id,
                conversation_id=message.conversation_id,
                incident_id=message.incident_id,
                sender_agent_id=agent_id,
                recipient_agent_id=message.recipient_agent_id,
                task_id=message.task_id,
                task_type=message.task_type,
                message_type=message.message_type,
                target_resource=message.target_resource,
                evidence_refs=message.evidence_refs,
                sequence=message.sequence,
                created_at=message.created_at,
                expires_at=message.expires_at,
                payload_digest=envelope.payload_digest,
                seal=message.seal,
                status=MessageStatus.ISSUED,
                issued_at=self._clock(),
            )
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(hosts={', '.join(sorted(self.hosted_agents))}, "
            f"{self.authenticator!r}, {self.transport!r})"
        )
