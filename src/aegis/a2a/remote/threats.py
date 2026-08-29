"""The remote A2A threat model, written down as data so coverage can be asserted.

Part 1. A threat model in prose is a threat model nobody can test. Every threat below is a
member of a closed enum, every member names the layer that answers it, and a test walks the
enum and fails if a member has no test bound to it. That turns "we thought about these
thirty things" into "these thirty things each have a test", which is a different claim.

The six layers, kept separate on purpose
----------------------------------------

The single most important thing this milestone gets right is not collapsing these:

``AUTHENTICATION``
    *Who sent this?* Cryptographic evidence that the sender controls a registered identity.
``INTEGRITY``
    *Is this the message that was signed?* Nothing changed in flight.
``FRESHNESS``
    *Is this message still current?* Expiry, clock skew, future-dating.
``REPLAY``
    *Has this exact message already done its work?* Durable, from Prompt 16.
``AUTHORIZATION``
    *Is the proposed action permitted?* Policy, risk, blast radius, approval. **Not here.**
``EXECUTION``
    *May this actually change production?* Lifecycle gate, breaker, executor. **Not here.**

An authenticated message is a message whose author is known. It is not a permitted action,
not an approval, not a verification and not a gate. A remote agent that AEGIS can identify
with certainty still has exactly the authority its capability grants say it has, which for
every specialist is none. Collapsing authentication into authorization is the single
mistake that would make all of this worse than useless — it would turn a solved identity
problem into an unsolved authority problem.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["REMOTE_THREATS", "SecurityLayer", "ThreatClass"]


class SecurityLayer(StrEnum):
    """Which layer answers a threat. Six, and they are not interchangeable."""

    AUTHENTICATION = "AUTHENTICATION"
    INTEGRITY = "INTEGRITY"
    FRESHNESS = "FRESHNESS"
    REPLAY = "REPLAY"
    AUTHORIZATION = "AUTHORIZATION"
    EXECUTION = "EXECUTION"


class ThreatClass(StrEnum):
    """Every remote threat this milestone claims to address.

    Closed, so "is that covered?" is a membership question rather than an opinion. A threat
    that is *not* addressed does not get a quiet member here — it goes in the not-claimed
    list in ``docs/A2A.md`` where a reader will actually see it.
    """

    UNKNOWN_REMOTE_AGENT = "UNKNOWN_REMOTE_AGENT"
    FORGED_AGENT_IDENTITY = "FORGED_AGENT_IDENTITY"
    STOLEN_IDENTITY_MATERIAL = "STOLEN_IDENTITY_MATERIAL"
    MESSAGE_TAMPERING = "MESSAGE_TAMPERING"
    MESSAGE_REPLAY = "MESSAGE_REPLAY"
    CROSS_CONVERSATION_REPLAY = "CROSS_CONVERSATION_REPLAY"
    CROSS_INCIDENT_REPLAY = "CROSS_INCIDENT_REPLAY"
    CROSS_RECIPIENT_DELIVERY = "CROSS_RECIPIENT_DELIVERY"
    CROSS_AGENT_SUBSTITUTION = "CROSS_AGENT_SUBSTITUTION"
    EXPIRED_MESSAGE = "EXPIRED_MESSAGE"
    FUTURE_DATED_MESSAGE = "FUTURE_DATED_MESSAGE"
    CLOCK_SKEW = "CLOCK_SKEW"
    DUPLICATE_DELIVERY = "DUPLICATE_DELIVERY"
    REORDERED_DELIVERY = "REORDERED_DELIVERY"
    TRUNCATED_MESSAGE = "TRUNCATED_MESSAGE"
    OVERSIZED_MESSAGE = "OVERSIZED_MESSAGE"
    MALFORMED_ENVELOPE = "MALFORMED_ENVELOPE"
    UNSUPPORTED_PROTOCOL_VERSION = "UNSUPPORTED_PROTOCOL_VERSION"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    DOWNGRADE_ATTEMPT = "DOWNGRADE_ATTEMPT"
    KEY_ROTATION = "KEY_ROTATION"
    REVOKED_IDENTITY = "REVOKED_IDENTITY"
    REVOKED_KEY = "REVOKED_KEY"
    COMPROMISED_PEER = "COMPROMISED_PEER"
    MALICIOUS_INTERMEDIARY = "MALICIOUS_INTERMEDIARY"
    DUPLICATE_REQUEST = "DUPLICATE_REQUEST"
    DUPLICATE_RESPONSE = "DUPLICATE_RESPONSE"
    CONVERSATION_CONFUSION = "CONVERSATION_CONFUSION"
    RESPONSE_SUBSTITUTION = "RESPONSE_SUBSTITUTION"
    CLAIMED_AUTHORITY = "CLAIMED_AUTHORITY"
    """A remote agent asserting an authority it does not possess.

    The one threat on this list that **authentication cannot touch**, and the reason the
    layer mapping below exists. A perfectly authenticated specialist claiming "policy has
    approved this" is answered by ``AUTHORIZATION``, not by a better signature. Filing it
    under ``AUTHENTICATION`` would be the exact collapse this module exists to prevent.
    """


REMOTE_THREATS: dict[ThreatClass, SecurityLayer] = {
    ThreatClass.UNKNOWN_REMOTE_AGENT: SecurityLayer.AUTHENTICATION,
    ThreatClass.FORGED_AGENT_IDENTITY: SecurityLayer.AUTHENTICATION,
    ThreatClass.STOLEN_IDENTITY_MATERIAL: SecurityLayer.AUTHENTICATION,
    ThreatClass.MESSAGE_TAMPERING: SecurityLayer.INTEGRITY,
    ThreatClass.MESSAGE_REPLAY: SecurityLayer.REPLAY,
    ThreatClass.CROSS_CONVERSATION_REPLAY: SecurityLayer.REPLAY,
    ThreatClass.CROSS_INCIDENT_REPLAY: SecurityLayer.REPLAY,
    ThreatClass.CROSS_RECIPIENT_DELIVERY: SecurityLayer.INTEGRITY,
    ThreatClass.CROSS_AGENT_SUBSTITUTION: SecurityLayer.AUTHENTICATION,
    ThreatClass.EXPIRED_MESSAGE: SecurityLayer.FRESHNESS,
    ThreatClass.FUTURE_DATED_MESSAGE: SecurityLayer.FRESHNESS,
    ThreatClass.CLOCK_SKEW: SecurityLayer.FRESHNESS,
    ThreatClass.DUPLICATE_DELIVERY: SecurityLayer.REPLAY,
    ThreatClass.REORDERED_DELIVERY: SecurityLayer.REPLAY,
    ThreatClass.TRUNCATED_MESSAGE: SecurityLayer.INTEGRITY,
    ThreatClass.OVERSIZED_MESSAGE: SecurityLayer.INTEGRITY,
    ThreatClass.MALFORMED_ENVELOPE: SecurityLayer.INTEGRITY,
    ThreatClass.UNSUPPORTED_PROTOCOL_VERSION: SecurityLayer.AUTHENTICATION,
    ThreatClass.UNSUPPORTED_ALGORITHM: SecurityLayer.AUTHENTICATION,
    ThreatClass.DOWNGRADE_ATTEMPT: SecurityLayer.AUTHENTICATION,
    ThreatClass.KEY_ROTATION: SecurityLayer.AUTHENTICATION,
    ThreatClass.REVOKED_IDENTITY: SecurityLayer.AUTHENTICATION,
    ThreatClass.REVOKED_KEY: SecurityLayer.AUTHENTICATION,
    ThreatClass.COMPROMISED_PEER: SecurityLayer.AUTHORIZATION,
    ThreatClass.MALICIOUS_INTERMEDIARY: SecurityLayer.INTEGRITY,
    ThreatClass.DUPLICATE_REQUEST: SecurityLayer.REPLAY,
    ThreatClass.DUPLICATE_RESPONSE: SecurityLayer.REPLAY,
    ThreatClass.CONVERSATION_CONFUSION: SecurityLayer.REPLAY,
    ThreatClass.RESPONSE_SUBSTITUTION: SecurityLayer.AUTHENTICATION,
    ThreatClass.CLAIMED_AUTHORITY: SecurityLayer.AUTHORIZATION,
}
"""Which layer answers each threat. Complete by construction — a test asserts every
:class:`ThreatClass` member appears exactly once as a key.

Two entries are worth reading twice. ``COMPROMISED_PEER`` and ``CLAIMED_AUTHORITY`` map to
``AUTHORIZATION``, not to ``AUTHENTICATION``: a compromised remote agent may hold perfectly
valid key material and sign perfectly valid messages, and no amount of cryptography makes
its *content* true. What stops it is the control plane it was never inside.
"""
