"""Observations — what the enterprise actually looks like.

An observation is not a tool return value. That distinction is the whole point of this
package (``claude.md`` section 11):

* A **tool result** says what happened when the control plane asked for something. It is
  execution metadata. ``HTTP 200`` means the request was accepted, not that the service
  recovered.
* An **observation** says what an independent source measured about a resource. It is the
  only thing that can establish enterprise truth.

Provenance comes from the existing :class:`~aegis.core.domain.evidence.Evidence` contract
rather than a parallel one: every observation is evidence-backed by construction, so
source, timestamp, reference and type are always present and always audit-ready. The
observation adds the two things ``Evidence`` deliberately does not carry — which resource
was looked at, and what values came back.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, Field

from aegis.core.domain import DomainModel, Evidence, EvidenceType, Identifier, NonEmptyStr

__all__ = ["OBSERVABLE_EVIDENCE_TYPES", "Observation", "ObservedValue"]

type ObservedValue = float | str
"""A measured value: numeric for quantities, string for categorical state.

Deliberately narrow. Verification compares values; it does not interpret them, so there
is nothing here that a predicate cannot evaluate exactly.
"""

OBSERVABLE_EVIDENCE_TYPES: frozenset[EvidenceType] = frozenset(
    {
        EvidenceType.TELEMETRY,
        EvidenceType.LOG,
        EvidenceType.DEPLOYMENT,
        EvidenceType.DEPENDENCY,
        EvidenceType.CUSTOMER_IMPACT,
        EvidenceType.SECURITY_EVENT,
    }
)
"""Evidence types that can establish enterprise state. An allowlist, not a denylist.

Notable exclusions, each deliberate:

* ``TOOL_RESULT`` — execution metadata, never enterprise truth (section 11). This is the
  rule that stops "the rollback call returned success" from resolving an incident.
* ``AGENT_FINDING`` — trust zone B. An agent's conclusion is a proposal, not a fact.
* ``HUMAN_INPUT`` — a person reporting a service looks fine is not a measurement.
* ``MEMORY`` — historical organisational knowledge says nothing about the state right now.
* ``VERIFICATION`` — a previous verification result cannot be its own evidence.
"""


def _sorted_values(value: Mapping[str, ObservedValue]) -> dict[str, ObservedValue]:
    """Normalise attribute keys to sorted order for deterministic serialization."""
    return dict(sorted(value.items()))


_Values = Annotated[Mapping[str, ObservedValue], AfterValidator(_sorted_values)]


class Observation(DomainModel):
    """One measurement of one resource, carrying its own provenance.

    Attributes are free-form names (``health``, ``error_rate``, ``deployment``) mapped to
    measured values. The engine never interprets an attribute name — it only matches the
    names a predicate asks for, so a new enterprise signal needs no new model.
    """

    evidence: Evidence
    """Provenance: id, source, reference, timestamp, type and declared confidence."""

    resource: NonEmptyStr
    """The resource that was observed, e.g. ``service:payment-api``.

    Matched by exact string equality against an action's target. An observation of a
    dependent service is additional context; it never stands in for the target itself.
    """

    values: _Values = Field(min_length=1)
    """Measured attribute values. At least one, normalised to sorted key order."""

    @property
    def observation_id(self) -> Identifier:
        """Identity of this observation, which is its evidence's identity."""
        return self.evidence.evidence_id

    @property
    def observed_at(self) -> datetime:
        """When the measurement was taken — not when this object was built."""
        return self.evidence.timestamp

    @property
    def source(self) -> str:
        """Where the measurement came from, e.g. ``telemetry.payment-api``."""
        return self.evidence.source

    @property
    def is_observable(self) -> bool:
        """Whether this evidence type can establish enterprise state at all."""
        return self.evidence.type in OBSERVABLE_EVIDENCE_TYPES
