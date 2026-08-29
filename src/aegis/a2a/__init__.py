"""Governed agent-to-agent communication (Prompt 15).

    AGENTS MAY COMMUNICATE. AGENTS MAY NOT TRANSFER AUTHORITY.

A transport and identity boundary, not a second control plane. This package routes bounded
tasks between named agents, binds every message to one incident and one position in one
conversation, and refuses anything it cannot account for. It decides nothing about whether
an action is permitted, because it holds nothing that could decide that.

**Local semantics only.** The transport here is in-process and deterministic. There is no
network code, no serialization to a wire, no remote peer and no distributed deployment.
:class:`~aegis.a2a.transport.A2ATransport` names the boundary a future network transport
would have to implement; until one exists and has been tested, AEGIS supports governed
*local* A2A and nothing more.

Dependency rules, asserted structurally by test:

* no module here imports policy, approval, assessment, verification, enterprise,
  orchestration or memory;
* no module here imports Google or any provider SDK;
* no module here uses ``eval``, ``exec``, ``subprocess``, ``importlib`` or dynamic import.

The delegation matrix is *injected* rather than imported, which is why enforcing the
existing policy does not require importing the package that declares it.
"""

from aegis.a2a.broker import A2ABroker, A2ADelivery
from aegis.a2a.contracts import (
    DEFAULT_MESSAGE_TTL_SECONDS,
    FORBIDDEN_ENVELOPE_FIELDS,
    MAX_CONVERSATION_SECONDS,
    MAX_EVIDENCE_REFS,
    MAX_MESSAGES_PER_TASK,
    MAX_PAYLOAD_BYTES,
    MAX_RESOURCE_LENGTH,
    MAX_RESPONSE_BYTES,
    A2AEnvelope,
    MessageStatus,
    MessageType,
    envelope_seal,
    payload_size,
)
from aegis.a2a.errors import A2AError, A2APersistenceFailure, A2AStateCorrupt
from aegis.a2a.identity import AgentDirectory
from aegis.a2a.ledger import ConversationRecord, LedgerState, MessageLedger, MessageRecord
from aegis.a2a.persistence import (
    A2APersistence,
    InMemoryA2APersistence,
    JsonlA2APersistence,
)
from aegis.a2a.records import (
    A2A_GENESIS_DIGEST,
    A2AIntegrityReport,
    A2ARecordKind,
    A2AStateRecord,
    legal_status_transition,
    payload_digest,
    record_digest,
    verify_a2a_chain,
)
from aegis.a2a.transport import A2ATransport, InMemoryA2ATransport, TransportError
from aegis.a2a.verdicts import A2ARejection, A2AVerdict

__all__ = [
    "A2A_GENESIS_DIGEST",
    "DEFAULT_MESSAGE_TTL_SECONDS",
    "FORBIDDEN_ENVELOPE_FIELDS",
    "MAX_CONVERSATION_SECONDS",
    "MAX_EVIDENCE_REFS",
    "MAX_MESSAGES_PER_TASK",
    "MAX_PAYLOAD_BYTES",
    "MAX_RESOURCE_LENGTH",
    "MAX_RESPONSE_BYTES",
    "A2ABroker",
    "A2ADelivery",
    "A2AEnvelope",
    "A2AError",
    "A2AIntegrityReport",
    "A2APersistence",
    "A2APersistenceFailure",
    "A2ARecordKind",
    "A2ARejection",
    "A2AStateCorrupt",
    "A2AStateRecord",
    "A2ATransport",
    "A2AVerdict",
    "AgentDirectory",
    "ConversationRecord",
    "InMemoryA2APersistence",
    "InMemoryA2ATransport",
    "JsonlA2APersistence",
    "LedgerState",
    "MessageLedger",
    "MessageRecord",
    "MessageStatus",
    "MessageType",
    "TransportError",
    "envelope_seal",
    "legal_status_transition",
    "payload_digest",
    "payload_size",
    "record_digest",
    "verify_a2a_chain",
]
