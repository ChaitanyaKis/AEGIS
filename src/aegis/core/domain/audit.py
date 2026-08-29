"""AuditEvent — the append-only record of everything material that happened."""

from __future__ import annotations

from pydantic import Field

from aegis.core.domain.base import (
    DomainModel,
    EvidenceRef,
    Identifier,
    IncidentRef,
    NonEmptyStr,
    Timestamp,
)
from aegis.core.domain.enums import (
    AgentLifecycleState,
    IncidentState,
    PolicyDecisionType,
)

__all__ = ["AuditEvent", "StateValue"]

type StateValue = IncidentState | AgentLifecycleState
"""Any governed state an audit event can record a transition between.

The two enums share no member names, so a serialized state value is unambiguous.
"""


class AuditEvent(DomainModel):
    """One immutable entry in the AEGIS audit log (``claude.md`` section 20).

    The schema is deliberately *flat* rather than nesting richer objects: audit events
    are transported to and queried from an event store, and flat scalar columns keep
    them stable, cheap to index and independent of how the domain models evolve.
    Related objects are referenced by id.

    Immutability is enforced structurally (the model is frozen). Append-only storage is
    the event store's responsibility and arrives with the audit system milestone.

    Only ``event_id``, ``timestamp``, ``actor`` and ``event_type`` are required: an
    audit entry must always answer *when*, *who* and *what*. Everything else is
    contextual and legitimately absent for some event types.
    """

    event_id: Identifier
    timestamp: Timestamp
    actor: NonEmptyStr
    """What caused the event, e.g. ``agent:remediation``, ``human:oncall``,
    ``system:policy-engine``. Never blank — every event is attributable."""

    agent_identity: NonEmptyStr | None = None
    """Reference to the acting agent's managed identity, when an agent was involved."""

    incident_id: IncidentRef | None = None
    event_type: NonEmptyStr
    """Namespaced event name, e.g. ``policy.decision`` or ``incident.state_changed``.

    Deliberately an open vocabulary: the components that emit events do not exist yet,
    and freezing an enum now would guess at their names.
    """

    input_reference: NonEmptyStr | None = None
    """Pointer to the input that triggered the event, so untrusted content is
    referenced rather than copied into the audit log."""

    decision: PolicyDecisionType | None = None
    policy_reference: NonEmptyStr | None = None
    tool: NonEmptyStr | None = None
    result: NonEmptyStr | None = None
    """Outcome as recorded by the emitter. Note ``claude.md`` section 11: a successful
    tool result is not proof that the operation succeeded."""

    state_before: StateValue | None = None
    state_after: StateValue | None = None
    evidence: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
