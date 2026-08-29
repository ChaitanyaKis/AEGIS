"""What a specialist concludes, and what that conclusion is worth.

A finding says:

    "Agent X concluded Y from evidence Z."

It does **not** say:

    "The enterprise is in state Y."

That distinction is the whole contract. A finding is advisory input to the Commander's
reasoning and to a human reading the audit trail. It is never authorization, never proof
of enterprise state, and never evidence that a remediation worked — the verification
engine refuses ``EvidenceType.AGENT_FINDING`` precisely so that an agent cannot conclude
its own success (``claude.md`` sections 4, 11).

Provenance is preserved, not summarised away. ``supporting_evidence`` holds the observation
ids the specialist actually read, so the Commander — and anyone auditing later — can tell a
direct measurement from an agent's interpretation of one.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from aegis.agents.decisions import CommanderProposal
from aegis.core.domain import (
    AgentRef,
    DomainModel,
    EvidenceRef,
    Identifier,
    IncidentRef,
    NonEmptyStr,
    Timestamp,
)

__all__ = ["AgentFinding", "FindingType"]


class FindingType(StrEnum):
    """The kind of conclusion a specialist reached. One per specialist role."""

    TECHNICAL_DIAGNOSIS = "TECHNICAL_DIAGNOSIS"
    SECURITY_ASSESSMENT = "SECURITY_ASSESSMENT"
    BUSINESS_IMPACT = "BUSINESS_IMPACT"
    REMEDIATION_PROPOSAL = "REMEDIATION_PROPOSAL"


class AgentFinding(DomainModel):
    """One specialist's conclusion about one incident.

    ``confidence`` is the specialist's own declared certainty. Like
    :class:`~aegis.core.domain.evidence.Evidence`'s, it carries no authority: no
    deterministic component reads it, and a confident finding is exactly as
    non-authoritative as a hesitant one.
    """

    finding_id: Identifier
    incident_id: IncidentRef
    agent_id: AgentRef
    finding_type: FindingType
    summary: NonEmptyStr
    """The specialist's conclusion, in its own words. Recorded and shown; never parsed."""

    confidence: float = Field(ge=0.0, le=1.0)
    supporting_evidence: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
    """Observation ids actually read. References, never contents — a summary of telemetry
    is not telemetry, and the control plane keeps working from the observations."""

    recommended_next_step: NonEmptyStr
    """What the specialist thinks should happen next. A recommendation, not a decision."""

    created_at: Timestamp
    proposal: CommanderProposal | None = None
    """A remediation, when the specialist is permitted to propose one.

    Present only on a REMEDIATION_PROPOSAL finding, and only from an agent whose declared
    proposal authority covers the capability. Even then it is a proposal: it carries no
    risk and no blast radius, and it reaches the enterprise only through assessment,
    policy, approval and execution.
    """

    @model_validator(mode="after")
    def _only_remediation_findings_propose(self) -> AgentFinding:
        if self.proposal is not None and self.finding_type is not FindingType.REMEDIATION_PROPOSAL:
            raise ValueError(f"a {self.finding_type} finding must not carry a proposal")
        return self
