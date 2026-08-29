"""Evidence — a provenance-carrying pointer to an observed fact."""

from __future__ import annotations

from pydantic import Field

from aegis.core.domain.base import DomainModel, Identifier, NonEmptyStr, Timestamp
from aegis.core.domain.enums import EvidenceType

__all__ = ["Evidence"]


class Evidence(DomainModel):
    """A single provenance-carrying observation.

    Evidence is how AEGIS distinguishes an assertion from a fact (``claude.md``
    sections 11, 12, 17). It never contains a conclusion — it points at the artifact a
    conclusion was drawn from, so that any later component (verification, memory, audit,
    evaluation) can re-derive or challenge that conclusion.

    ``confidence`` is a declared confidence in ``[0.0, 1.0]`` supplied by whoever
    recorded the evidence. It carries no authority: it is an input to deterministic
    components, never a substitute for verification.
    """

    evidence_id: Identifier
    source: NonEmptyStr
    """Where the observation came from, e.g. ``telemetry.payment-api`` or ``agent:diagnostic``."""

    reference: NonEmptyStr
    """Opaque pointer to the underlying artifact (log id, metric query, deployment id)."""

    timestamp: Timestamp
    """When the observation was made, not when the Evidence object was constructed."""

    type: EvidenceType
    confidence: float = Field(ge=0.0, le=1.0)
