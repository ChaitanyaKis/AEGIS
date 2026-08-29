"""Moving messages, and nothing else.

    Agent -> A2ATransport -> Remote Agent

The transport is the seam a future network implementation would replace. It knows how to
carry an envelope from one place to another and how to report that it could not. It knows
nothing about policy, approval, risk, verification or lifecycle — not as a matter of
discipline but because it holds none of them and this package cannot import them.

Governance sits **above** the transport (the broker validates before handing anything over)
and **below** it (the control plane governs whatever a finding eventually becomes). The
transport itself is the thin part in the middle, deliberately.

Local only, stated plainly
--------------------------

:class:`InMemoryA2ATransport` is a dictionary and a list. There is no socket, no
serialization to a wire, no retry policy, no peer discovery and no remote anything. A
network transport would implement :class:`A2ATransport` and would additionally have to
solve durable replay state, authenticated peer identity, wire integrity and partial
delivery — none of which is solved here, and none of which this milestone claims.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from aegis.a2a.contracts import A2AEnvelope
from aegis.a2a.verdicts import A2ARejection, A2AVerdict

__all__ = ["A2ATransport", "InMemoryA2ATransport", "TransportError"]


class TransportError(Exception):
    """The message could not be moved. Never a partial success, never a default."""


@runtime_checkable
class A2ATransport(Protocol):
    """The four operations any transport must offer.

    Send, receive, acknowledge, reject. Nothing about permission appears in this protocol,
    and nothing should: a transport that could approve a message would be a control plane
    with a delivery API attached.
    """

    def send(self, envelope: A2AEnvelope) -> None:
        """Hand a message to the recipient's inbox, or raise :class:`TransportError`."""
        ...

    def receive(self, recipient_agent_id: str) -> tuple[A2AEnvelope, ...]:
        """Every message waiting for this exact recipient, in arrival order."""
        ...

    def acknowledge(self, message_id: str) -> None:
        """Record that a message was taken and is no longer pending."""
        ...

    def reject(self, message_id: str, verdict: A2AVerdict) -> None:
        """Record that a message was refused, and why."""
        ...


class InMemoryA2ATransport:
    """A local, deterministic transport. **CONTROLLED SIMULATION.**

    In-process only: a dictionary of inboxes and a log of what happened. Reproducible, with
    no clock of its own, no randomness and no I/O.

    Args:
        unavailable: Recipient ids that cannot be reached, so the unavailable-recipient
            path is testable without breaking anything. Empty in ordinary use.
    """

    def __init__(self, *, unavailable: frozenset[str] = frozenset()) -> None:
        self._inboxes: dict[str, list[A2AEnvelope]] = {}
        self._delivered: list[str] = []
        self._acknowledged: list[str] = []
        self._rejected: list[tuple[str, A2ARejection | None]] = []
        self._unavailable = frozenset(unavailable)

    def send(self, envelope: A2AEnvelope) -> None:
        if envelope.recipient_agent_id in self._unavailable:
            raise TransportError(f"recipient {envelope.recipient_agent_id!r} is unavailable")
        self._inboxes.setdefault(envelope.recipient_agent_id, []).append(envelope)
        self._delivered.append(envelope.message_id)

    def receive(self, recipient_agent_id: str) -> tuple[A2AEnvelope, ...]:
        """Messages waiting for this exact recipient. Exact key, never a prefix or a scan."""
        return tuple(self._inboxes.get(recipient_agent_id, ()))

    def acknowledge(self, message_id: str) -> None:
        self._acknowledged.append(message_id)
        for inbox in self._inboxes.values():
            for index, envelope in enumerate(inbox):
                if envelope.message_id == message_id:
                    del inbox[index]
                    return

    def reject(self, message_id: str, verdict: A2AVerdict) -> None:
        self._rejected.append((message_id, verdict.rejection))
        for inbox in self._inboxes.values():
            for index, envelope in enumerate(inbox):
                if envelope.message_id == message_id:
                    del inbox[index]
                    return

    # --- inspection, for tests and reconstruction ------------------------------------

    @property
    def delivered(self) -> tuple[str, ...]:
        return tuple(self._delivered)

    @property
    def acknowledged(self) -> tuple[str, ...]:
        return tuple(self._acknowledged)

    @property
    def rejected(self) -> tuple[tuple[str, A2ARejection | None], ...]:
        return tuple(self._rejected)

    def pending(self) -> int:
        return sum(len(inbox) for inbox in self._inboxes.values())

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(delivered={len(self._delivered)}, "
            f"pending={self.pending()}, rejected={len(self._rejected)})"
        )
