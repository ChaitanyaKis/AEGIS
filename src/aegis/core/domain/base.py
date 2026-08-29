"""Shared base model and scalar types for the AEGIS domain contracts.

Design decisions that the rest of the domain depends on:

Immutability
    Every domain model is frozen. Domain objects are values, not mutable records:
    a state change produces a *new* object, which is what makes
    ``state_before`` / ``state_after`` audit records (``claude.md`` section 20) honest
    and what keeps the audit log append-only at the application level.
    Use :meth:`pydantic.BaseModel.model_copy` with ``update=`` to derive a new value.

Closed schemas
    ``extra="forbid"``. An unknown field in an incoming payload is a contract violation,
    not something to silently absorb — untrusted input (``claude.md`` section 4, zone A)
    must never smuggle fields past the control plane.

Timezone-aware, UTC-normalised timestamps
    Naive datetimes are rejected. All timestamps normalise to UTC so serialization is
    deterministic and audit ordering is unambiguous.

Reference vs. embedding
    Values owned by an aggregate are embedded (``Incident.evidence``). Relations that
    cross aggregates are referenced by identifier (``Incident.assigned_agents``,
    ``Action.capability``). This keeps a single source of truth for every object.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, StringConstraints

__all__ = [
    "AgentRef",
    "CapabilityRef",
    "DomainModel",
    "EvidenceRef",
    "Identifier",
    "IncidentRef",
    "NonEmptyStr",
    "Timestamp",
    "utc_now",
]


def _require_utc(value: datetime) -> datetime:
    """Reject naive datetimes and normalise aware ones to UTC."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


type NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
"""A required free-text or opaque-reference string that may not be blank."""

type Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    ),
]
"""An AEGIS identifier.

Deliberately narrow: identifiers appear in audit records, policy references and
evaluation fixtures, so whitespace and free-form punctuation are rejected at the
boundary. Dots, colons, slashes and hyphens are permitted for namespaced ids such as
``telemetry.read``, ``service:payment-api`` or ``INC-2026-0001``.
"""

type Timestamp = Annotated[datetime, AfterValidator(_require_utc)]
"""A timezone-aware instant, normalised to UTC."""

# Semantic aliases for cross-aggregate references. They are all `Identifier` at
# runtime; the distinct names document *what* is being referenced.
type AgentRef = Identifier
type CapabilityRef = Identifier
type IncidentRef = Identifier
type EvidenceRef = Identifier


def utc_now() -> datetime:
    """Current instant in UTC. The single clock helper for domain construction."""
    return datetime.now(UTC)


class DomainModel(BaseModel):
    """Base class for every AEGIS domain contract."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )
