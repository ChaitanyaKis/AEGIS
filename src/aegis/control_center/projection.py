"""One incident, projected. The object an operator actually holds.

Part 3. :class:`IncidentProjection` assembles every view and carries the two things a
reader needs before believing any of them: **where each view came from**, and **whether the
audit chain behind it verified**.

Freshness is not decoration
---------------------------

Every view has its own :class:`~aegis.control_center.models.Provenance`, and the projection
does not flatten them into one. Two views captured from different sources are two
observations, and presenting them as a single "current state" would be asserting something
that was never true all at once (Part 16).

The audit chain gates the rest
------------------------------

When the chain does not verify, :attr:`IncidentProjection.status` is
:attr:`ProjectionStatus.AUDIT_UNTRUSTED` and every audit-sourced view is downgraded. The
data is still shown -- hiding it helps nobody -- but the claim about it is withdrawn.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum

from pydantic import Field

from aegis.control_center.a2a import A2AView, build_a2a
from aegis.control_center.agents import AgentView, build_agents
from aegis.control_center.capture import ControlCenterInput
from aegis.control_center.causal import CausalChain, build_causal_chain
from aegis.control_center.errors import UnknownIncident
from aegis.control_center.governance import (
    ApprovalView,
    Explanation,
    GovernanceView,
    Question,
    VerificationView,
    build_governance,
    explain,
)
from aegis.control_center.lifecycle import (
    BreakerView,
    LifecycleView,
    build_breakers,
    build_lifecycle,
)
from aegis.control_center.memory import MemoryView, build_memory
from aegis.control_center.models import (
    AuditIntegrityView,
    AuditTrust,
    Completeness,
    Fact,
    Provenance,
    Tri,
    ViewSource,
)
from aegis.control_center.security import SecurityView, build_security
from aegis.control_center.timeline import IncidentTimeline, audit_view, build_timeline
from aegis.core.domain import DomainModel, Identifier, Timestamp

__all__ = [
    "ControlCenter",
    "IncidentProjection",
    "IncidentSummary",
    "ProjectionStatus",
    "project_incident",
]


class ProjectionStatus(StrEnum):
    """How much of this projection a reader may rely on."""

    COMPLETE = "COMPLETE"
    """Every source was readable and the audit chain verified."""

    PARTIAL = "PARTIAL"
    """A source was missing. What is shown is real; what is absent is unknown."""

    AUDIT_UNTRUSTED = "AUDIT_UNTRUSTED"
    """The audit chain does not verify. Part 17: surfaced, never repaired, and never
    rendered as authoritative."""

    UNKNOWN = "UNKNOWN"
    """Nothing could be read. Explicitly not "nothing happened"."""


class IncidentSummary(DomainModel):
    """The one-line answer to "what is this incident doing".

    Every field a :class:`~aegis.control_center.models.Fact` or a
    :class:`~aegis.control_center.models.Tri`, so an unreadable source shows as unknown
    rather than as a reassuring default.
    """

    incident_id: Identifier
    title: Fact
    severity: Fact
    state: Fact
    outcome: Fact
    resource: Fact
    detected_at: Timestamp | None = None

    policy_decision: Fact
    approval_required: Tri = Tri.UNKNOWN
    approval_status: Fact
    executed: Tri = Tri.UNKNOWN
    verified: Tri = Tri.UNKNOWN
    resolved: Tri = Tri.UNKNOWN
    escalated: Tri = Tri.UNKNOWN

    breaker_open: Tri = Tri.UNKNOWN
    """``UNKNOWN`` when the breaker source was unreadable -- never ``FALSE``. An unreadable
    breaker is not a closed one."""

    agents_restricted: Tri = Tri.UNKNOWN
    security_events: int | None = None
    provenance: Provenance

    def __repr__(self) -> str:
        return (
            f"IncidentSummary({self.incident_id} {self.state.value} "
            f"resolved={self.resolved} verified={self.verified})"
        )


class IncidentProjection(DomainModel):
    """Everything the control center knows about one incident.

    Frozen and canonically serializable, which is what makes a forensic export deterministic
    (Part 23). Holds no live object, so nothing here can act.
    """

    incident_id: Identifier
    captured_at: Timestamp
    status: ProjectionStatus
    audit: AuditIntegrityView

    summary: IncidentSummary
    timeline: IncidentTimeline
    causal_chain: CausalChain
    governance: GovernanceView
    agents: tuple[AgentView, ...] = Field(default_factory=tuple)
    lifecycle: LifecycleView
    breakers: tuple[BreakerView, ...] = Field(default_factory=tuple)
    memory: MemoryView
    a2a: A2AView
    security: SecurityView
    sources: tuple[Provenance, ...] = Field(default_factory=tuple)
    """Every source's provenance, kept separately rather than merged. A reader can see that
    the ledger was captured at one instant and the breaker at another."""

    @property
    def approvals(self) -> tuple[ApprovalView, ...]:
        return self.governance.approvals

    @property
    def verification(self) -> VerificationView:
        return self.governance.verification

    def why(self, question: Question) -> Explanation:
        """Answer one operator question. Deterministic, artifact-backed, never generated.

        Kept as a method on the projection so the answer and the views a reader is looking
        at come from the same frozen snapshot.
        """
        return explain(self._input, question)

    def breaker(self, scope_key: str) -> BreakerView | None:
        for view in self.breakers:
            if view.scope_key == scope_key:
                return view
        return None

    def agent(self, agent_id: str) -> AgentView | None:
        for view in self.agents:
            if view.agent_id == agent_id:
                return view
        return None

    # `_input` is excluded from serialization: an export is a document, and embedding the
    # raw capture would duplicate every artifact inside its own projection.
    _input: ControlCenterInput

    def __init__(self, **data) -> None:
        source = data.pop("_input")
        super().__init__(**data)
        object.__setattr__(self, "_input", source)

    def __repr__(self) -> str:
        return f"IncidentProjection({self.incident_id}, {self.status}, {self.audit.trust})"


def project_incident(data: ControlCenterInput) -> IncidentProjection:
    """Build the full projection for one incident. Pure: frozen value in, frozen value out.

    Every view is built independently from the same input, so a failure in one cannot
    silently colour another -- and the assembled ``status`` is the *worst* of what the
    sources reported rather than an average of them.
    """
    audit = audit_view(data)
    timeline = build_timeline(data)
    governance = build_governance(data)
    lifecycle = build_lifecycle(data)
    breakers = build_breakers(data)
    memory = build_memory(data)
    a2a = build_a2a(data)
    security = build_security(data)
    agents = build_agents(data)
    chain = build_causal_chain(data)

    sources = (
        timeline.provenance,
        governance.provenance,
        lifecycle.provenance,
        memory.provenance,
        a2a.provenance,
        security.provenance,
        chain.provenance,
    )
    status = _status(data, audit, sources)
    return IncidentProjection(
        incident_id=data.incident_id,
        captured_at=data.captured_at,
        status=status,
        audit=audit,
        summary=_summary(data, governance, breakers, agents, security, audit),
        timeline=timeline,
        causal_chain=chain,
        governance=governance,
        agents=agents,
        lifecycle=lifecycle,
        breakers=breakers,
        memory=memory,
        a2a=a2a,
        security=security,
        sources=sources,
        _input=data,
    )


def _status(
    data: ControlCenterInput, audit: AuditIntegrityView, sources: Sequence[Provenance]
) -> ProjectionStatus:
    """The worst thing any source reported. Never the average, and never the best.

    A projection is only as trustworthy as its least trustworthy input, and an operator
    reading "COMPLETE" over a partially-read incident would be reading a claim nobody made.
    """
    if audit.trust is AuditTrust.UNTRUSTED:
        return ProjectionStatus.AUDIT_UNTRUSTED
    if not any(
        (
            data.run_available,
            data.audit_available,
            data.memory_available,
            data.a2a_available,
        )
    ):
        return ProjectionStatus.UNKNOWN
    if any(source.completeness is not Completeness.COMPLETE for source in sources):
        return ProjectionStatus.PARTIAL
    return ProjectionStatus.COMPLETE


def _summary(
    data: ControlCenterInput,
    governance: GovernanceView,
    breakers: tuple[BreakerView, ...],
    agents: tuple[AgentView, ...],
    security: SecurityView,
    audit: AuditIntegrityView,
) -> IncidentSummary:
    """The headline view, assembled from the others without re-deriving anything."""
    run = data.run
    incident = getattr(run, "incident", None)
    verification = governance.verification

    return IncidentSummary(
        incident_id=data.incident_id,
        title=Fact.observed(incident.source) if incident is not None else Fact.unknown(),
        severity=Fact.observed(incident.severity) if incident is not None else Fact.unknown(),
        state=Fact.observed(incident.state) if incident is not None else Fact.unknown(),
        outcome=Fact.observed(run.outcome) if run is not None else Fact.unknown(),
        # The resource comes from the *action*, not the incident: an incident describes a
        # situation and an action names the thing that would be touched, and only the
        # second is what an operator scanning for "who is about to change payment-api"
        # means.
        resource=governance.resource,
        detected_at=getattr(incident, "created_at", None),
        policy_decision=governance.policy_decision,
        approval_required=governance.approval_required,
        approval_status=governance.approval_status,
        executed=verification.executed,
        verified=verification.verified,
        resolved=verification.resolved,
        escalated=(
            Tri.of(incident.state.value == "ESCALATED") if incident is not None else Tri.UNKNOWN
        ),
        # An unreadable breaker source is UNKNOWN, not FALSE. `build_breakers` returns an
        # empty tuple in both the "no breakers" and "unreadable" cases, so the availability
        # flag -- not the tuple's length -- decides which answer this is.
        breaker_open=(
            Tri.of(any(view.open.is_true for view in breakers))
            if data.lifecycle_available
            else Tri.UNKNOWN
        ),
        agents_restricted=(
            Tri.of(any(view.quarantined.is_true for view in agents))
            if data.restrictions_available and agents
            else Tri.UNKNOWN
        ),
        security_events=len(security.events) if data.audit_available else None,
        provenance=Provenance(
            source=ViewSource.RUN if data.run_available else ViewSource.NONE,
            as_of=data.captured_at,
            completeness=(
                Completeness.COMPLETE
                if data.run_available and audit.trust is AuditTrust.TRUSTED
                else Completeness.UNKNOWN
            ),
            detail=None if data.run_available else "no run was captured",
        ),
    )


class ControlCenter:
    """A collection of incident projections, queryable and strictly read-only.

    Holds frozen projections and nothing else. There is no method here that changes
    anything, in this package or elsewhere -- an operator action must remain an explicit
    existing governed operation (Part 21), invoked through the orchestrator, not through a
    view.
    """

    __slots__ = ("_projections",)

    def __init__(self, projections: Sequence[IncidentProjection] = ()) -> None:
        self._projections = {
            projection.incident_id: projection
            for projection in sorted(projections, key=lambda p: p.incident_id)
        }

    def add(self, projection: IncidentProjection) -> None:
        """Hold one more projection. Adds an observation; grants nothing."""
        self._projections[projection.incident_id] = projection

    def incident(self, incident_id: str) -> IncidentProjection:
        """One projection.

        Raises:
            UnknownIncident: when this control center holds no projection for that id.
                Raised rather than answered with an empty projection, which would let a
                typo render as an incident where nothing happened.
        """
        projection = self._projections.get(incident_id)
        if projection is None:
            raise UnknownIncident(incident_id, tuple(sorted(self._projections)))
        return projection

    def incidents(self) -> tuple[IncidentProjection, ...]:
        return tuple(self._projections[key] for key in sorted(self._projections))

    def incident_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._projections))

    def __contains__(self, incident_id: object) -> bool:
        return incident_id in self._projections

    def __len__(self) -> int:
        return len(self._projections)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({len(self._projections)} incidents)"
