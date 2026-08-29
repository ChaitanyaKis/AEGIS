"""What an agent is, what it may propose, and what it is currently barred from.

Part 8. Three things operators routinely collapse into one, kept apart by having three
fields with three sources:

``capabilities``
    Capability ids the control plane has **granted**. A grant record. Holding
    ``production.rollback`` does not mean an action is allowed -- policy, approval, the
    lifecycle gate and the execution authorization all still apply, and any of them can
    refuse.

``proposal_capabilities``
    What this agent may **propose**. Proposing is not authorization: a proposal is an input
    to the control plane, and the control plane answers it.

``restriction``
    Whether the agent may participate **right now**. An availability decision made from
    observed failures. It removes a participant; it grants nothing, and it never overrides a
    policy decision in either direction.

A view that merged them would let an operator read "has production.rollback" as "can roll
back", which is exactly the inference AEGIS exists to make false.
"""

from __future__ import annotations

from pydantic import Field

from aegis.control_center.capture import ControlCenterInput
from aegis.control_center.models import (
    Completeness,
    Fact,
    Provenance,
    Tri,
    ViewSource,
)
from aegis.core.audit.events import AuditEventType
from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp

__all__ = ["AgentActivity", "AgentView", "build_agents"]


class AgentActivity(DomainModel):
    """What one agent did during this incident, counted from artifacts."""

    delegations_received: int = Field(default=0, ge=0)
    responses_sent: int = Field(default=0, ge=0)
    findings_returned: int = Field(default=0, ge=0)
    """Responses that carried an attributed finding. Fewer than ``responses_sent`` when a
    task completed without concluding anything."""

    a2a_refusals: int = Field(default=0, ge=0)
    model_failures: int = Field(default=0, ge=0)
    """``model.decision`` events recorded with a failure category rather than a decision."""

    remote_authentications: int = Field(default=0, ge=0)
    remote_refusals: int = Field(default=0, ge=0)

    def __repr__(self) -> str:
        return (
            f"AgentActivity(in={self.delegations_received}, out={self.responses_sent}, "
            f"findings={self.findings_returned})"
        )


class AgentView(DomainModel):
    """One agent, as the control plane records it. Read-only, and three-way separated."""

    agent_id: Identifier
    name: Fact
    version: Fact
    lifecycle_status: Fact
    """Registration standing -- REGISTERED, ACTIVE, RETIRED and so on. **Not** a restriction
    and **not** a permission."""

    capabilities: tuple[Identifier, ...] = Field(default_factory=tuple)
    proposal_capabilities: tuple[Identifier, ...] = Field(default_factory=tuple)

    restriction: Fact
    """ACTIVE or QUARANTINED, for the scope below. ``UNKNOWN`` when the registry could not
    be read -- never ``ACTIVE``, because an unreadable containment mechanism is not a
    containment mechanism reporting that everything is fine."""

    restriction_scope: Fact
    restriction_reason: Fact
    restricted_at: Timestamp | None = None
    failure_counts: tuple[tuple[NonEmptyStr, int], ...] = Field(default_factory=tuple)

    quarantined: Tri = Tri.UNKNOWN
    activity: AgentActivity = Field(default_factory=AgentActivity)
    provenance: Provenance

    @property
    def may_propose(self) -> tuple[Identifier, ...]:
        """What this agent may propose. Named so no caller reads it as "may perform"."""
        return self.proposal_capabilities

    def __repr__(self) -> str:
        return f"AgentView({self.agent_id} {self.restriction.value} {self.activity!r})"


def build_agents(data: ControlCenterInput) -> tuple[AgentView, ...]:
    """One view per registered agent, sorted by id so the output is deterministic.

    An agent with no restriction verdict gets ``UNKNOWN`` rather than ``ACTIVE``. That
    matters: a containment registry that could not be read must not render as one reporting
    good news.
    """
    verdicts = {verdict.agent_id: verdict for verdict in data.restrictions}
    activity = _activity(data)
    provenance = Provenance(
        source=ViewSource.RESTRICTION_REGISTRY,
        as_of=data.captured_at,
        completeness=(
            Completeness.COMPLETE if data.restrictions_available else Completeness.UNKNOWN
        ),
        detail=None if data.restrictions_available else "the restriction registry was unreadable",
    )

    views: list[AgentView] = []
    for profile in sorted(data.agents, key=lambda agent: agent.agent_id):
        verdict = verdicts.get(profile.agent_id)
        views.append(
            AgentView(
                agent_id=profile.agent_id,
                name=Fact.observed(profile.name, profile.agent_id),
                version=Fact.observed(profile.version, profile.agent_id),
                lifecycle_status=Fact.observed(profile.status, profile.agent_id),
                capabilities=profile.capabilities,
                proposal_capabilities=profile.proposal_capabilities,
                restriction=(
                    Fact.observed(verdict.restriction, verdict.scope_key)
                    if verdict is not None
                    else Fact.unknown()
                ),
                restriction_scope=(
                    Fact.observed(verdict.scope_key) if verdict is not None else Fact.unknown()
                ),
                restriction_reason=(
                    Fact.observed(verdict.reason, verdict.scope_key)
                    if verdict is not None and verdict.reason
                    else Fact.unknown()
                ),
                restricted_at=getattr(verdict, "quarantined_at", None),
                failure_counts=(
                    tuple(sorted(verdict.failure_counts.items())) if verdict is not None else ()
                ),
                quarantined=(
                    Tri.of(verdict.restriction.value == "QUARANTINED")
                    if verdict is not None
                    else Tri.UNKNOWN
                ),
                activity=activity.get(profile.agent_id, AgentActivity()),
                provenance=provenance,
            )
        )
    return tuple(views)


def _activity(data: ControlCenterInput) -> dict[str, AgentActivity]:
    """Count what each agent did, from this incident's audit records only.

    Scoped to the incident before anything is counted (Part 18): an agent's activity in a
    different incident is not this incident's story, and merging them would let one
    incident's failures explain another's restriction.
    """
    counters: dict[str, dict[str, int]] = {}

    def bump(agent_id: str | None, field: str) -> None:
        if not agent_id:
            return
        counters.setdefault(agent_id, {})[field] = (
            counters.setdefault(agent_id, {}).get(field, 0) + 1
        )

    if data.audit_available:
        for record in data.audit_records:
            if record.event.incident_id not in (None, data.incident_id):
                continue
            event_type = record.event.event_type
            correlation = record.correlation
            if event_type == AuditEventType.A2A_MESSAGE.value:
                status = correlation.get("status", "")
                if status in {"ISSUED", "ACCEPTED"}:
                    bump(correlation.get("recipient_agent_id"), "delegations_received")
                elif status == "COMPLETED":
                    bump(correlation.get("sender_agent_id"), "responses_sent")
                    if correlation.get("finding_id"):
                        bump(correlation.get("sender_agent_id"), "findings_returned")
                elif status in {"REJECTED", "REFUSED"}:
                    bump(correlation.get("sender_agent_id"), "a2a_refusals")
            elif event_type == AuditEventType.MODEL_DECISION.value:
                if correlation.get("failure_category"):
                    bump(record.event.agent_identity, "model_failures")
            elif event_type == AuditEventType.REMOTE_AUTHENTICATION.value:
                if correlation.get("status") == "AUTHENTICATED":
                    bump(correlation.get("authenticated_agent_id"), "remote_authentications")
                else:
                    bump(correlation.get("claimed_agent_id"), "remote_refusals")

    return {agent_id: AgentActivity(**fields) for agent_id, fields in sorted(counters.items())}
