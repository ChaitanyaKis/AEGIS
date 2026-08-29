"""Persistent organizational memory (``claude.md`` section 12).

    MEMORY IS CONTEXT, NOT AUTHORITY.

Memory records what the enterprise was actually established to have done — verified
outcomes, verified root causes, remediation results, operational patterns — so an agent
can reason with history instead of starting cold every time.

It decides nothing. Risk, blast radius, policy, approval, execution, verification and
resolution are all determined by the deterministic control plane, and not one of them reads
this package. The dependency arrow points only inward: memory knows about domain contracts
and about the *shape* of a verification artifact, and nothing in the control plane knows
memory exists.

Three properties carry the security of this subsystem:

**Authority comes from verified artifacts, never from claims.** Only a ``VERIFIED``
verification, bound to one incident and one exact action by fingerprint, can make a memory
authoritative. A tool that reported success, an agent that is confident and a human who
wrote it down are all recorded as what they are and none of them can be promoted.

**Agents cannot claim authority.** :class:`~aegis.memory.models.MemoryCandidate` — the only
memory type a caller constructs — has no status field, and the store has no method that
accepts a pre-built record. The boundary is structural rather than procedural.

**History is history.** Retrieved memory carries the time it was verified and travels only
in ``ModelRequest.data``. Current observation always wins: nothing here can override what
the enterprise is doing now, because nothing in the verification path consults it.
"""

from aegis.memory.admission import ADMISSION_CHECKS, AdmissionContext, MemoryAdmission
from aegis.memory.errors import (
    MemoryAdmissionRefused,
    MemoryError,
    MemoryIntegrityError,
    MemoryNotFound,
    UnknownMemoryRecord,
)
from aegis.memory.integrity import (
    MEMORY_GENESIS_DIGEST,
    MemoryIntegrityReport,
    memory_digest,
    verify_memory_chain,
)
from aegis.memory.models import (
    MemoryCandidate,
    MemoryContext,
    MemoryProvenance,
    MemoryQuery,
    MemoryRecord,
    RetrievedMemory,
)
from aegis.memory.persistence import JsonlMemoryPersistence
from aegis.memory.retrieval import MemoryRetrieval
from aegis.memory.store import InMemoryPersistence, MemoryPersistence, MemoryStore
from aegis.memory.types import (
    REQUIRED_VERIFICATION_STATUS,
    ActionLike,
    MemorySource,
    MemoryStatus,
    MemoryType,
    VerifiedOutcome,
)

__all__ = [
    "ADMISSION_CHECKS",
    "MEMORY_GENESIS_DIGEST",
    "REQUIRED_VERIFICATION_STATUS",
    "ActionLike",
    "AdmissionContext",
    "InMemoryPersistence",
    "JsonlMemoryPersistence",
    "MemoryAdmission",
    "MemoryAdmissionRefused",
    "MemoryCandidate",
    "MemoryContext",
    "MemoryError",
    "MemoryIntegrityError",
    "MemoryIntegrityReport",
    "MemoryNotFound",
    "MemoryPersistence",
    "MemoryProvenance",
    "MemoryQuery",
    "MemoryRecord",
    "MemoryRetrieval",
    "MemorySource",
    "MemoryStatus",
    "MemoryStore",
    "MemoryType",
    "RetrievedMemory",
    "UnknownMemoryRecord",
    "VerifiedOutcome",
    "memory_digest",
    "verify_memory_chain",
]
