"""Carrying frames between peers, deterministically, with no network anywhere.

Part 10 and Part 11. Four operations -- send, receive, acknowledge, reject -- and no fifth.
There is no ``authorize``, no ``approve``, no ``execute``, no ``verify_action``, no
``resolve_incident``, no ``issue_gate`` and no ``change_risk``, and there is a structural
test over the protocol *and* over every implementation in this module, because Prompt 16
learned the hard way that a protocol constrains what a caller may rely on and not what a
class may grow.

**CONTROLLED SIMULATION.** :class:`InMemoryRemoteTransport` is dictionaries and lists. The
A2A package structurally cannot import ``socket``, ``httpx``, ``requests``, ``urllib`` or
``aiohttp`` -- a test asserts it -- so "no real network protocol yet" is not a promise, it
is a property of the source tree. What this class simulates is what a network *does to
messages*: delay, duplication, reordering, loss, timeouts, unreachable peers.

Why the transport is allowed to be hostile
------------------------------------------

Everything a network can do to a frame, this class can do to a frame, including handing the
receiver something an adversary rewrote (:attr:`InMemoryRemoteTransport.relay`). That is not
a weakness in the simulation, it is the point of it: the boundary above must hold for
*every* behaviour a transport can exhibit, so a transport that could only behave well would
prove nothing. Nothing the transport does can produce an authenticated message, because it
holds no key; nothing it does can produce an authorized action, because it holds no
control-plane engine and cannot import one.

Delivery semantics, stated exactly
----------------------------------

**At-most-once.** A frame is admitted once, or refused, expired, lost or replayed -- never
consumed twice. Duplication at the transport is expected and handled: the second copy meets
the same durable ledger the first one did (Prompt 16) and is refused.

**Exactly-once is not claimed and is not implemented.** Nor is ordered delivery: reordering
is a fault this class can inject, and the local broker's strict sequencing refuses an
out-of-order message rather than buffering it. There is no retry here -- retry is the
Commander deciding to delegate again, costing a step from the same bounded budget every
other decision costs one from.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from enum import StrEnum
from typing import Protocol, runtime_checkable

from aegis.a2a.remote.envelope import RemoteFrame, frame_digest
from aegis.a2a.remote.verdicts import RemoteVerdict

__all__ = [
    "InMemoryRemoteTransport",
    "RemoteFault",
    "RemoteTransport",
    "RemoteTransportError",
]


class RemoteTransportError(Exception):
    """A frame could not be carried. Never a partial success, never a default.

    Deliberately **not** a subclass of :class:`~aegis.a2a.errors.A2AError`. An A2A error
    means durable state is unusable and the process must not continue as though it were; a
    transport error means one message did not arrive, which is an ordinary event on any
    network and is answered by the lifecycle, not by refusing to run.
    """


class RemoteFault(StrEnum):
    """What the simulated network does to a frame. Deterministic, never random.

    Only genuine *network conditions* live here. Adversarial rewriting -- tampering,
    truncation, redirection, downgrade -- is not a property of a network, it is the act of
    an attacker, and it arrives through :attr:`InMemoryRemoteTransport.relay` from the
    benchmark's control group rather than shipping in the product as a method somebody
    could call.
    """

    NONE = "NONE"

    DELAY = "DELAY"
    """The frame arrives, one receive later than it should."""

    DUPLICATE = "DUPLICATE"
    """The frame arrives twice. Expected on a real network, and refused the second time."""

    REORDER = "REORDER"
    """Frames arrive in the opposite order to the one they were sent in."""

    LOSS = "LOSS"
    """The frame never arrives, and the sender is told so."""

    TIMEOUT = "TIMEOUT"
    PEER_UNAVAILABLE = "PEER_UNAVAILABLE"


@runtime_checkable
class RemoteTransport(Protocol):
    """The four operations any remote transport must offer, and the only four.

    A transport moves frames and reports that it could not. Nothing about permission appears
    here, and nothing should: a transport that could approve a message would be a control
    plane with a delivery API attached.
    """

    def send(self, frame: RemoteFrame) -> None:
        """Carry one frame, or raise :class:`RemoteTransportError`."""
        ...

    def receive(self, destination: str) -> tuple[RemoteFrame, ...]:
        """Every frame waiting at this exact destination, in arrival order."""
        ...

    def acknowledge(self, frame_ref: str) -> None:
        """Record that a frame was taken and is no longer pending."""
        ...

    def reject(self, frame_ref: str, verdict: RemoteVerdict) -> None:
        """Record that a frame was refused, and why."""
        ...


class InMemoryRemoteTransport:
    """A deterministic simulation of a network. **CONTROLLED SIMULATION.**

    Args:
        fault: Which network condition to simulate. One condition per transport, so a
            scenario tests one thing.
        unavailable: Destinations that cannot be reached at all.
        relay: An optional hook standing where an intermediary would stand. It receives the
            frame the sender produced and returns the frames the receiver will see -- none,
            one, several, or something it rewrote entirely. It is a single, reviewable seam
            rather than a set of tamper methods on the transport, and it is supplied by the
            benchmark's control group, never by the product.

    Reproducible: no clock of its own, no randomness, no I/O.
    """

    def __init__(
        self,
        *,
        fault: RemoteFault = RemoteFault.NONE,
        unavailable: frozenset[str] = frozenset(),
        relay: Callable[[RemoteFrame], Sequence[RemoteFrame]] | None = None,
    ) -> None:
        self._fault = fault
        self._unavailable = frozenset(unavailable)
        self._relay = relay
        self._inboxes: dict[str, list[RemoteFrame]] = {}
        self._held: list[RemoteFrame] = []
        self._carried: list[RemoteFrame] = []
        self._sent: list[str] = []
        self._delivered: list[str] = []
        self._acknowledged: list[str] = []
        self._rejected: list[tuple[str, object]] = []
        self._dropped: list[str] = []

    # --- the four operations ----------------------------------------------------------

    def send(self, frame: RemoteFrame) -> None:
        """Carry one frame, applying whichever single fault this transport simulates.

        Raises:
            RemoteTransportError: on loss, timeout or an unreachable peer. A transport that
                dropped a frame and returned normally would be telling the sender a message
                arrived when it did not, and every layer above would be reasoning from a
                lie. Silence is a worse failure mode than an error.
        """
        self._sent.append(frame_digest(frame))
        if frame.destination in self._unavailable:
            raise RemoteTransportError(f"peer {frame.destination!r} is unreachable")
        if self._fault is RemoteFault.PEER_UNAVAILABLE:
            raise RemoteTransportError(f"peer {frame.destination!r} did not answer")
        if self._fault is RemoteFault.TIMEOUT:
            raise RemoteTransportError("the peer did not respond within the deadline")
        if self._fault is RemoteFault.LOSS:
            self._dropped.append(frame_digest(frame))
            raise RemoteTransportError("delivery could not be confirmed; the frame is lost")

        for delivered in self._through_relay(frame):
            self._carried.append(delivered)
            self._deliver(delivered)

    def _through_relay(self, frame: RemoteFrame) -> tuple[RemoteFrame, ...]:
        """Whatever stands between the sender and the receiver, if anything does.

        A relay that returns nothing has dropped the frame; one that returns several has
        duplicated it; one that returns a different frame has rewritten it. None of that is
        trusted, and none of it needs to be -- the frame's body is signed and the receiver
        checks the signature against its own registry.
        """
        if self._relay is None:
            return (frame,)
        return tuple(self._relay(frame))

    def _deliver(self, frame: RemoteFrame) -> None:
        inbox = self._inboxes.setdefault(frame.destination, [])
        if self._fault is RemoteFault.DELAY:
            # Held until the next send or receive: arrives, late. Not lost.
            self._held.append(frame)
            return
        if self._fault is RemoteFault.REORDER:
            inbox.insert(0, frame)
        else:
            inbox.append(frame)
        self._delivered.append(frame_digest(frame))
        if self._fault is RemoteFault.DUPLICATE:
            inbox.append(frame)
            self._delivered.append(frame_digest(frame))

    def receive(self, destination: str) -> tuple[RemoteFrame, ...]:
        """Frames waiting at this exact destination. Exact key, never a prefix or a scan.

        A delayed frame is released here, which is what "late" means: it becomes visible on
        a later call than it would have been, and the receiver has no way to tell a late
        frame from a punctual one -- exactly as on a real network.
        """
        if self._held:
            for frame in self._held:
                self._inboxes.setdefault(frame.destination, []).append(frame)
                self._delivered.append(frame_digest(frame))
            self._held.clear()
        return tuple(self._inboxes.get(destination, ()))

    def acknowledge(self, frame_ref: str) -> None:
        """Record that a frame was taken, and remove one copy of it from its inbox."""
        self._acknowledged.append(frame_ref)
        self._remove(frame_ref)

    def reject(self, frame_ref: str, verdict: RemoteVerdict) -> None:
        """Record that a frame was refused, and remove one copy of it from its inbox."""
        self._rejected.append((frame_ref, verdict.rejection))
        self._remove(frame_ref)

    def _remove(self, frame_ref: str) -> None:
        for inbox in self._inboxes.values():
            for index, frame in enumerate(inbox):
                if frame_digest(frame) == frame_ref:
                    del inbox[index]
                    return

    # --- inspection, for tests and reconstruction --------------------------------------

    @property
    def fault(self) -> RemoteFault:
        return self._fault

    @property
    def sent(self) -> tuple[str, ...]:
        return tuple(self._sent)

    @property
    def carried(self) -> tuple[RemoteFrame, ...]:
        """Every frame that actually reached the receiving side, exactly as it reached it.

        The frames *after* any relay, so a tampered frame appears here in its tampered
        form. Kept so a reader -- the benchmark's oracle very much included -- can verify
        signatures independently instead of asking the boundary whether it verified them.
        Inspection only: nothing in the delivery path reads this.
        """
        return tuple(self._carried)

    @property
    def delivered(self) -> tuple[str, ...]:
        return tuple(self._delivered)

    @property
    def acknowledged(self) -> tuple[str, ...]:
        return tuple(self._acknowledged)

    @property
    def dropped(self) -> tuple[str, ...]:
        return tuple(self._dropped)

    @property
    def rejected(self) -> tuple[tuple[str, object], ...]:
        return tuple(self._rejected)

    def pending(self) -> int:
        return sum(len(inbox) for inbox in self._inboxes.values()) + len(self._held)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(fault={self._fault}, sent={len(self._sent)}, "
            f"pending={self.pending()}, rejected={len(self._rejected)})"
        )
