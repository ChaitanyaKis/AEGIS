"""The forensic export: one incident, canonically, with its integrity verdict attached.

Part 23. An export is what somebody reads months later, in an investigation, without the
system that produced it. Three properties matter and each is enforced rather than intended.

**Deterministic.** Two exports of the same projection are byte-identical. Everything is
built from frozen values through the project's one canonical serializer -- sorted keys,
compact separators, UTC ISO-8601 -- and nothing here reads a clock of its own.

**Honest about integrity.** The audit verdict travels *inside* the document. An export of a
corrupted trail says so, in the artifact, where a reader cannot miss it. It is not repaired
and it is not omitted.

**Free of secrets.** No credentials, no private keys, no HMAC material, no API keys, no
model prompts or responses. Not because they are stripped -- because the projection it is
built from never held them. :data:`FORBIDDEN_CONTENT` names them so a test can sweep a
rendered export and prove it, since "we did not include it" is worth less than "it is not
reachable from here".

Prompts and responses, specifically
-----------------------------------

``model.decision`` records a request digest and a response digest, never the text. So an
export carries digests, and an investigator can prove a given prompt produced a given
response *if they have the prompt*. What the export does not do is reconstruct one. Part 23
forbids it, and there is nothing to reconstruct from.
"""

from __future__ import annotations

from pydantic import Field

from aegis.control_center.a2a import A2AView
from aegis.control_center.agents import AgentView
from aegis.control_center.causal import CausalChain
from aegis.control_center.governance import GovernanceView
from aegis.control_center.lifecycle import BreakerView, LifecycleView
from aegis.control_center.memory import MemoryView
from aegis.control_center.models import AuditIntegrityView, Provenance
from aegis.control_center.projection import (
    IncidentProjection,
    IncidentSummary,
    ProjectionStatus,
)
from aegis.control_center.security import SecurityView
from aegis.control_center.timeline import IncidentTimeline
from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp, to_json

__all__ = ["EXPORT_FORMAT_VERSION", "FORBIDDEN_CONTENT", "IncidentExport", "export_incident"]

EXPORT_FORMAT_VERSION = "aegis.control-center.export/v1"
"""The export format's own version.

Carried in the document so a reader years later knows what shape they are holding, and so
a future change to the format is a visible version bump rather than a silent difference
between two files that look alike.
"""

FORBIDDEN_CONTENT = frozenset(
    {
        "private_key",
        "secret",
        "api_key",
        "credential",
        "password",
        "token",
        "signature",
        "hmac",
        "verification_key",
        "system_prompt",
        "prompt_text",
        "response_text",
    }
)
"""What an export must never contain, listed so the guarantee is greppable and testable.

Enforced by the closed schemas this document is assembled from rather than by filtering --
none of the views has a field that could hold any of these. The set exists so a test can
sweep a serialized export and assert it, which is a stronger statement than a promise.
"""


class IncidentExport(DomainModel):
    """One incident as a canonical forensic document.

    Frozen and closed, like everything that leaves AEGIS. Serialize with
    :func:`~aegis.core.domain.to_json` -- or with :func:`export_json` below, which is the
    same call named for what it is.
    """

    format_version: NonEmptyStr = EXPORT_FORMAT_VERSION
    incident_id: Identifier
    captured_at: Timestamp
    status: ProjectionStatus
    """The projection's own verdict on how much of this document can be relied on."""

    audit: AuditIntegrityView
    """Carried inside the document. An export of a corrupted trail says so, here."""

    summary: IncidentSummary
    timeline: IncidentTimeline
    causal_chain: CausalChain
    governance: GovernanceView
    lifecycle: LifecycleView
    breakers: tuple[BreakerView, ...] = Field(default_factory=tuple)
    agents: tuple[AgentView, ...] = Field(default_factory=tuple)
    memory: MemoryView
    a2a: A2AView
    security: SecurityView
    sources: tuple[Provenance, ...] = Field(default_factory=tuple)

    @property
    def complete(self) -> bool:
        """Whether every source was readable and the chain verified.

        Not a security property. A complete export of a run that escalated is a complete
        record of an escalation.
        """
        return self.status is ProjectionStatus.COMPLETE

    def __repr__(self) -> str:
        return f"IncidentExport({self.incident_id}, {self.status}, {self.audit.trust})"


def export_incident(projection: IncidentProjection) -> IncidentExport:
    """Turn one projection into a forensic document.

    A pure restructuring: every field is a frozen value the projection already held, so the
    export cannot say anything the projection did not. In particular it cannot say the
    audit chain was fine -- that verdict is copied across, not recomputed and not softened.
    """
    return IncidentExport(
        incident_id=projection.incident_id,
        captured_at=projection.captured_at,
        status=projection.status,
        audit=projection.audit,
        summary=projection.summary,
        timeline=projection.timeline,
        causal_chain=projection.causal_chain,
        governance=projection.governance,
        lifecycle=projection.lifecycle,
        breakers=projection.breakers,
        agents=projection.agents,
        memory=projection.memory,
        a2a=projection.a2a,
        security=projection.security,
        sources=projection.sources,
    )


def export_json(projection: IncidentProjection) -> str:
    """The export as canonical JSON. Deterministic: the same projection, the same bytes.

    Uses the project's one serializer rather than a second formatting path, so an export
    round-trips and digests identically across processes and runs -- which is what makes it
    usable as evidence rather than as a report.
    """
    return to_json(export_incident(projection))
