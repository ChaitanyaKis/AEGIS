"""The one seam the orchestrator sees: sign, carry, authenticate, admit.

Everything else in this package is a layer. This is the object an application holds. It
signs an outbound message on behalf of a local agent, puts it on the transport, takes it off
again and hands it to :class:`~aegis.a2a.remote.gateway.RemoteGateway` -- so a caller
switching from local to remote delegation changes *which object it delegates through* and
nothing else.

Signing is bound to wiring, never to a claim
--------------------------------------------

:meth:`RemoteChannel.sign_as` takes an agent id from the application's own wiring and looks
up that agent's key in a mapping the application built. A model that decided to be
``remediation`` reaches this method as the string ``commander``, because the string comes
from the orchestrator's own record of which agent it is -- exactly as
``accountable_sender`` always has. An agent with no key signs nothing: there is no default
key, no shared key and no fallback, because each of those is a way for one agent to sign as
another.

Why this is not a distributed system
------------------------------------

Sender and receiver are the same process. What is genuinely exercised is the *security
boundary*: the message is serialized to a wire format, carried by a transport that can lose,
delay, duplicate, reorder or corrupt it, parsed back from text, verified against a registry,
and only then handed to the local broker under the identity the signature established. What
is **not** exercised is a network, a remote machine, or a peer AEGIS does not control --
and no part of this package claims otherwise.
"""

from __future__ import annotations

from collections.abc import Mapping

from aegis.a2a.contracts import A2AEnvelope, TaskType
from aegis.a2a.remote.envelope import (
    REMOTE_PROTOCOL_VERSION,
    RemoteEnvelope,
    RemoteFrame,
    encode_envelope,
    frame_digest,
    sign_remote,
)
from aegis.a2a.remote.gateway import RemoteDelivery, RemoteGateway
from aegis.a2a.remote.keys import KeyRing
from aegis.a2a.remote.verdicts import RemoteRejection, RemoteVerdict
from aegis.agents.findings import AgentFinding

__all__ = ["RemoteChannel"]


class RemoteChannel:
    """Signs, carries and delivers A2A messages across the remote boundary.

    Args:
        gateway: The receiving side. Holds the authenticator, the registry and the real
            local broker.
        key_ring: The signing keys this process legitimately holds.
        keys_by_agent: Which key id each local agent signs with. Built by the application
            from its own wiring; an agent absent from it cannot sign at all.
        protocol_version: What outbound messages declare. Explicit so a test can produce a
            downgrade without reaching into private state.
    """

    def __init__(
        self,
        gateway: RemoteGateway,
        key_ring: KeyRing,
        keys_by_agent: Mapping[str, str],
        *,
        protocol_version: str = REMOTE_PROTOCOL_VERSION,
    ) -> None:
        self.gateway = gateway
        self.key_ring = key_ring
        self.keys_by_agent = dict(keys_by_agent)
        self.protocol_version = protocol_version

    @property
    def transport(self):
        return self.gateway.transport

    def signs_for(self, agent_id: str) -> bool:
        """Whether this process can sign as that agent. Exact match, never a scan."""
        key_id = self.keys_by_agent.get(agent_id)
        return key_id is not None and self.key_ring.signer(key_id) is not None

    def sign_as(self, agent_id: str, envelope: A2AEnvelope) -> RemoteEnvelope | None:
        """Sign one message on behalf of a local agent, or ``None`` if it holds no key.

        ``None`` rather than a helpful fallback. An agent with no key must produce no
        message; picking some other key would be this process impersonating one of its own
        agents, which is the thing the whole package exists to make impossible.
        """
        key_id = self.keys_by_agent.get(agent_id)
        if key_id is None:
            return None
        signer = self.key_ring.signer(key_id)
        if signer is None:
            return None
        return sign_remote(envelope, key=signer, protocol_version=self.protocol_version)

    # --- the round trip ---------------------------------------------------------------

    def carry(
        self,
        envelope: A2AEnvelope,
        *,
        signed_by: str,
        as_agent: str,
        expected_incident_id: str,
        expected_conversation_id: str | None = None,
        recipient_handles: TaskType | None = None,
    ) -> RemoteDelivery:
        """Sign a message, put it on the wire, take it off, and deliver it.

        Args:
            envelope: The locally issued message.
            signed_by: Which local agent is sending. From the wiring.
            as_agent: Which hosted agent is receiving. From the wiring.

        Every failure between here and the recipient is a refusal carrying its own reason.
        A frame that never arrives produces ``TRANSPORT_FAILURE``, not an empty delivery: a
        message that was lost and a message that said nothing are different facts, and a
        boundary that rendered them identically would let a dropped frame look like a
        specialist with no findings.
        """
        remote = self.sign_as(signed_by, envelope)
        if remote is None:
            return RemoteDelivery(
                RemoteVerdict.refuse(
                    RemoteRejection.UNKNOWN_KEY,
                    f"{signed_by!r} holds no signing key in this process; an agent that "
                    f"cannot sign sends nothing",
                    message_id=envelope.message_id,
                ),
                None,
            )
        return self.carry_signed(
            remote,
            as_agent=as_agent,
            expected_incident_id=expected_incident_id,
            expected_conversation_id=expected_conversation_id,
            recipient_handles=recipient_handles,
        )

    def carry_signed(
        self,
        remote: RemoteEnvelope,
        *,
        as_agent: str,
        expected_incident_id: str,
        expected_conversation_id: str | None = None,
        recipient_handles: TaskType | None = None,
    ) -> RemoteDelivery:
        """The round trip for a message that is already signed.

        Separate from :meth:`carry` so a test -- or a benchmark control group -- can present
        a message it built itself, including one signed by the wrong key or claiming the
        wrong version. The boundary must hold for messages it did not help construct, and a
        method that only ever accepted its own output could not demonstrate that.
        """
        sent = self.gateway.dispatch(remote)
        if not sent.authenticated:
            return RemoteDelivery(sent, None)
        frame = self._collect(remote)
        if frame is None:
            return RemoteDelivery(
                RemoteVerdict.refuse(
                    RemoteRejection.TRANSPORT_FAILURE,
                    "the frame was handed to the transport and never arrived",
                    message_id=remote.message.message_id,
                    key_id=remote.key_id,
                ),
                None,
            )
        delivery = self.gateway.deliver(
            frame,
            as_agent=as_agent,
            expected_incident_id=expected_incident_id,
            expected_conversation_id=expected_conversation_id,
            recipient_handles=recipient_handles,
        )
        self._drain(
            remote.message.recipient_agent_id,
            lambda extra: self.gateway.deliver(
                extra,
                as_agent=as_agent,
                expected_incident_id=expected_incident_id,
                expected_conversation_id=expected_conversation_id,
                recipient_handles=recipient_handles,
            ),
        )
        return delivery

    def carry_response(
        self,
        envelope: A2AEnvelope,
        request: A2AEnvelope,
        finding: AgentFinding | None,
        *,
        signed_by: str,
        as_agent: str,
    ) -> RemoteDelivery:
        """Sign a specialist's answer, carry it back, and bind it to its request."""
        remote = self.sign_as(signed_by, envelope)
        if remote is None:
            return RemoteDelivery(
                RemoteVerdict.refuse(
                    RemoteRejection.UNKNOWN_KEY,
                    f"{signed_by!r} holds no signing key in this process",
                    message_id=envelope.message_id,
                ),
                None,
            )
        sent = self.gateway.dispatch(remote)
        if not sent.authenticated:
            return RemoteDelivery(sent, None)
        frame = self._collect(remote)
        if frame is None:
            return RemoteDelivery(
                RemoteVerdict.refuse(
                    RemoteRejection.TRANSPORT_FAILURE,
                    "the response was handed to the transport and never arrived",
                    message_id=envelope.message_id,
                    key_id=remote.key_id,
                ),
                None,
            )
        delivery = self.gateway.deliver_response(frame, request, finding, as_agent=as_agent)
        self._drain(
            envelope.recipient_agent_id,
            lambda extra: self.gateway.deliver_response(extra, request, finding, as_agent=as_agent),
        )
        return delivery

    def _collect(self, remote: RemoteEnvelope) -> RemoteFrame | None:
        """Take the frame carrying this message off the transport, if one arrived.

        Matched by body digest where possible, because a receiver awaiting a correlated
        reply legitimately knows which frame it is waiting for -- that is what a request id
        is *for*, and every RPC transport does it.

        When no frame matches, the oldest waiting frame is taken instead. That case is the
        interesting one: it is what happens when an intermediary rewrote the body, and a
        receiver has no way to know what it *should* have received. Skipping it would put
        the attack's detection in the transport, where it does not belong, instead of in
        the boundary that has to actually catch it.
        """
        waiting = self.gateway.transport.receive(remote.message.recipient_agent_id)
        if not waiting:
            return None
        wanted = frame_digest(
            RemoteFrame(destination=remote.message.recipient_agent_id, body=encode_envelope(remote))
        )
        for frame in waiting:
            if frame_digest(frame) == wanted:
                return frame
        return waiting[0]

    def _drain(self, destination: str, judge) -> int:
        """Judge every frame still waiting at a destination, and return how many.

        A receiver processes its inbox; it does not take one frame and walk away. Without
        this, a duplicated or replayed frame would sit unexamined and "at-most-once" would
        hold *trivially* -- true because nothing ever tried, which is the kind of green
        result that means nothing. Draining makes the second copy genuinely meet the
        boundary, and the boundary genuinely refuse it.

        Called only *after* the awaited frame has been delivered, so the copy that arrives
        first is the one that does the work and every later copy is the one that is spent.
        Results are deliberately discarded here: what happened to them is recorded on the
        transport and in the durable ledger, which is where an evaluator should read it
        from rather than from a return value this method invented.
        """
        judged = 0
        for frame in self.gateway.transport.receive(destination):
            judge(frame)
            judged += 1
        return judged

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({self.protocol_version}, "
            f"signs for {', '.join(sorted(self.keys_by_agent)) or 'nobody'})"
        )
