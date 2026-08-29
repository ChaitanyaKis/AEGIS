"""Fixtures for the remote-boundary suite: real keys, a real registry, a real broker.

Nothing is mocked that matters. The directory holds the same five agent ids and the same
delegation matrix the orchestrator uses, the broker is the real one, and the authenticator
is the real one. A test that passes here is a test about the configuration AEGIS runs.

Both algorithms, wherever both exist
------------------------------------

Every property that depends on cryptography is parametrised over
:func:`~aegis.a2a.remote.keys.available_algorithms`, so it is proven for the symmetric MAC
the benchmark pins **and** for genuine Ed25519 signatures wherever ``cryptography`` is
installed. When it is not, the Ed25519 parameter simply does not exist -- which is the
honest behaviour, and is asserted by a test rather than assumed.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from aegis.a2a import (
    A2ABroker,
    A2AEnvelope,
    AgentDirectory,
    InMemoryA2ATransport,
    MessageLedger,
    MessageType,
)
from aegis.a2a.remote import (
    REMOTE_PROTOCOL_VERSION,
    InMemoryRemoteTransport,
    KeyAlgorithm,
    KeyRing,
    RemoteAgentIdentity,
    RemoteAgentRegistry,
    RemoteAuthenticator,
    RemoteChannel,
    RemoteEnvelope,
    RemoteFrame,
    RemoteGateway,
    available_algorithms,
    encode_envelope,
    provider_for,
    sign_remote,
)
from aegis.agents.decisions import TaskType

from ..conftest import CONVERSATION, FIXED_NOW, FLEET, INCIDENT, RESOURCE, TASK, MovableClock

__all__ = [
    "CONVERSATION",
    "FIXED_NOW",
    "FLEET",
    "INCIDENT",
    "RESOURCE",
    "TASK",
    "MovableClock",
    "frame_for",
    "issue",
]


@pytest.fixture(params=[a.value for a in available_algorithms()])
def algorithm(request) -> KeyAlgorithm:
    """Every algorithm this deployment can actually handle.

    Parametrised by *value* so a skipped Ed25519 deployment produces a shorter run rather
    than a broken one. The list is read from the provider registry, never hard-coded: a
    test suite that claimed to cover an algorithm the deployment cannot load would be
    asserting a capability nobody has.
    """
    return KeyAlgorithm(request.param)


@pytest.fixture
def keys(algorithm: KeyAlgorithm):
    """A key ring and a registry entry for every agent in the fleet.

    Seeds are fixed, so a failing test reproduces. **Deriving a key from a printable seed
    is a test fixture, not key management**, and nothing in AEGIS does it outside tests and
    the deterministic benchmark.
    """
    provider = provider_for(algorithm)
    ring = KeyRing()
    identities = []
    by_agent = {}
    for agent_id in sorted(FLEET):
        key_id = f"key-{agent_id}-1"
        signer, verifier = provider.generate(key_id, seed=f"seed-{agent_id}".encode())
        ring.add(signer)
        by_agent[agent_id] = key_id
        identities.append(
            RemoteAgentIdentity(
                agent_id=agent_id,
                key_id=key_id,
                algorithm=algorithm,
                verification_key=verifier.material,
                protocol_versions=(REMOTE_PROTOCOL_VERSION,),
                created_at=FIXED_NOW - timedelta(days=1),
                expires_at=FIXED_NOW + timedelta(days=30),
            )
        )
    return ring, by_agent, tuple(identities)


@pytest.fixture
def registry(keys, clock) -> RemoteAgentRegistry:
    _, _, identities = keys
    return RemoteAgentRegistry(identities, clock=clock)


@pytest.fixture
def authenticator(registry, clock) -> RemoteAuthenticator:
    return RemoteAuthenticator(registry, clock=clock)


@pytest.fixture
def peer_broker(directory: AgentDirectory, clock) -> A2ABroker:
    """The *sending* side's broker, with its own ledger.

    Separate from the receiver's on purpose. A single shared broker would make every
    message look like one this process issued, and the interesting case -- a message that
    genuinely arrived from somewhere else -- would never be exercised.
    """
    return A2ABroker(
        directory,
        transport=InMemoryA2ATransport(),
        ledger=MessageLedger(clock=clock),
        clock=clock,
    )


@pytest.fixture
def receiver_broker(directory: AgentDirectory, clock) -> A2ABroker:
    """The *receiving* side's broker. Knows nothing about what the peer issued."""
    return A2ABroker(
        directory,
        transport=InMemoryA2ATransport(),
        ledger=MessageLedger(clock=clock),
        clock=clock,
    )


@pytest.fixture
def remote_transport() -> InMemoryRemoteTransport:
    return InMemoryRemoteTransport()


@pytest.fixture
def gateway(authenticator, receiver_broker, remote_transport, clock) -> RemoteGateway:
    return RemoteGateway(
        FLEET, authenticator, receiver_broker, transport=remote_transport, clock=clock
    )


@pytest.fixture
def channel(gateway, keys) -> RemoteChannel:
    ring, by_agent, _ = keys
    return RemoteChannel(gateway, ring, by_agent)


@pytest.fixture
def signer(keys):
    """A callable that signs a message as a named agent, using that agent's own key."""
    ring, by_agent, _ = keys

    def sign(agent_id: str, envelope: A2AEnvelope, **overrides) -> RemoteEnvelope:
        key = ring.signer(by_agent[agent_id])
        assert key is not None, agent_id
        return sign_remote(envelope, key=key, **overrides)

    return sign


def issue(broker: A2ABroker, **overrides) -> A2AEnvelope:
    """One ordinary Commander-to-Diagnostic request, unless overridden."""
    settings = {
        "accountable_sender": "commander",
        "recipient_agent_id": "diagnostic",
        "incident_id": INCIDENT,
        "conversation_id": CONVERSATION,
        "task_id": TASK,
        "task_type": TaskType.DIAGNOSE_SERVICE,
        "message_type": MessageType.TASK_REQUEST,
        "target_resource": RESOURCE,
        "payload": {"note": "please investigate"},
    }
    settings.update(overrides)
    envelope = broker.issue(**settings)
    assert isinstance(envelope, A2AEnvelope), envelope
    return envelope


def frame_for(remote: RemoteEnvelope, *, destination: str | None = None) -> RemoteFrame:
    """The frame a transport would carry for this message.

    ``destination`` overrides the address without touching the body, which is exactly the
    power an intermediary has: the outside of an envelope, and nothing inside it.
    """
    return RemoteFrame(
        destination=destination or remote.message.recipient_agent_id,
        body=encode_envelope(remote),
    )
