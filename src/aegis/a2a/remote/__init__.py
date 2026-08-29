"""The remote A2A security boundary (Prompt 17).

    AEGIS provides an authenticated, integrity-protected, replay-resistant remote A2A
    security boundary in a deterministic offline transport simulation.

That sentence is the claim, and every word in it is load-bearing. **"Deterministic offline
transport simulation"** is not a hedge: there is no socket, no TLS, no DNS, no credential
and no remote machine anywhere in AEGIS, and the A2A package structurally cannot import the
libraries that would provide them.

What this package is for
------------------------

Building and proving the security boundary that has to exist *before* a network transport
could ever be trusted. The layers, and the order they run in:

    transport        carries frames; decides nothing
    envelope         signed fields, protocol version, wire format
    identity         which keys the registry binds to which agents
    authenticator    who sent this -- and nothing else
    gateway          addressing, binding, replay, then the existing local broker
    (unchanged)      policy, risk, approval, lifecycle gate, execution, verification

Authentication answers ``who sent this?``. It does **not** answer ``is this allowed?``.
Those are different questions, they are answered in different packages, and this package
cannot import the one that answers the second. A remote agent AEGIS can identify with
certainty has exactly the authority its capability grants give it, which for every
specialist is none.

Three sentences the tests demonstrate rather than assert
--------------------------------------------------------

    a valid hash is not an authenticated sender
    a valid signature is not an authorization
    a registered identity is not execution authority

Not claimed
-----------

Real internet transport, TLS, cloud-to-cloud federation, distributed consensus, Byzantine
fault tolerance, secure multi-process shared state, production key management, HSM-backed
identity, remote attestation. See ``docs/A2A.md``.
"""

from aegis.a2a.remote.authenticator import MAX_CLOCK_SKEW_SECONDS, RemoteAuthenticator
from aegis.a2a.remote.channel import RemoteChannel
from aegis.a2a.remote.ed25519 import ED25519_AVAILABLE, Ed25519KeyProvider, ed25519_provider
from aegis.a2a.remote.envelope import (
    LEGACY_PROTOCOL_VERSION,
    MAX_REMOTE_FRAME_BYTES,
    REMOTE_PROTOCOL_VERSION,
    SIGNED_FIELDS,
    SUPPORTED_PROTOCOL_VERSIONS,
    UNSIGNED_BY_DESIGN,
    RemoteEnvelope,
    RemoteFrame,
    decode_envelope,
    encode_envelope,
    frame_digest,
    sign_remote,
    signing_payload,
)
from aegis.a2a.remote.errors import RemoteA2AError, UnsupportedAlgorithm
from aegis.a2a.remote.gateway import RemoteDelivery, RemoteGateway
from aegis.a2a.remote.identity import IdentityStatus, RemoteAgentIdentity, RemoteAgentRegistry
from aegis.a2a.remote.keys import (
    MAX_SIGNATURE_HEX,
    HmacKeyProvider,
    KeyAlgorithm,
    KeyProvider,
    KeyRing,
    SigningKey,
    UnusableKey,
    VerifyingKey,
    available_algorithms,
    looks_like_a_signature,
    provider_for,
)
from aegis.a2a.remote.threats import REMOTE_THREATS, SecurityLayer, ThreatClass
from aegis.a2a.remote.transport import (
    InMemoryRemoteTransport,
    RemoteFault,
    RemoteTransport,
    RemoteTransportError,
)
from aegis.a2a.remote.verdicts import RemoteRejection, RemoteVerdict

__all__ = [
    "ED25519_AVAILABLE",
    "LEGACY_PROTOCOL_VERSION",
    "MAX_CLOCK_SKEW_SECONDS",
    "MAX_REMOTE_FRAME_BYTES",
    "MAX_SIGNATURE_HEX",
    "REMOTE_PROTOCOL_VERSION",
    "REMOTE_THREATS",
    "SIGNED_FIELDS",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "UNSIGNED_BY_DESIGN",
    "Ed25519KeyProvider",
    "HmacKeyProvider",
    "IdentityStatus",
    "InMemoryRemoteTransport",
    "KeyAlgorithm",
    "KeyProvider",
    "KeyRing",
    "RemoteA2AError",
    "RemoteAgentIdentity",
    "RemoteAgentRegistry",
    "RemoteAuthenticator",
    "RemoteChannel",
    "RemoteDelivery",
    "RemoteEnvelope",
    "RemoteFault",
    "RemoteFrame",
    "RemoteGateway",
    "RemoteRejection",
    "RemoteTransport",
    "RemoteTransportError",
    "RemoteVerdict",
    "SecurityLayer",
    "SigningKey",
    "ThreatClass",
    "UnsupportedAlgorithm",
    "UnusableKey",
    "VerifyingKey",
    "available_algorithms",
    "decode_envelope",
    "ed25519_provider",
    "encode_envelope",
    "frame_digest",
    "looks_like_a_signature",
    "provider_for",
    "sign_remote",
    "signing_payload",
]
