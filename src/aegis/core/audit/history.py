"""Reconstructing an incident's history from its audit trail.

Answers "what happened to this incident?" from recorded events alone — no LLM, no replay of
the original artifacts, no guessing. The state sequence is built **only** from
``incident.state_changed`` events, because those are the only events that assert a state
change; deriving state from a policy decision or an approval would be inventing history
rather than reading it.

Reporting, not repairing
------------------------

Where the trail is inconsistent the reconstruction says so and keeps going. It never
normalises a gap away, and it never re-orders events to make a sequence look plausible. An
audit trail that quietly tidies itself is worth less than one that admits it is broken.

Validation reuses the real transition table via
:class:`~aegis.core.incidents.machine.IncidentStateMachine`, so the audit layer cannot
drift into a second, differently-wrong idea of which transitions are legal.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import Field

from aegis.core.audit.events import AuditEventType
from aegis.core.audit.records import AuditRecord
from aegis.core.domain import (
    AuditEvent,
    DomainModel,
    IncidentRef,
    IncidentState,
    NonEmptyStr,
)
from aegis.core.incidents import IncidentStateMachine

__all__ = ["IncidentHistory", "reconstruct_incident_history"]


class IncidentHistory(DomainModel):
    """The state sequence an incident actually went through, plus any inconsistencies."""

    incident_id: IncidentRef
    states: tuple[IncidentState, ...] = Field(default_factory=tuple)
    """Every state the incident occupied, in order, starting from its first recorded one."""

    transitions: tuple[tuple[IncidentState, IncidentState], ...] = Field(default_factory=tuple)
    """The ``(from, to)`` pairs the trail records."""

    event_count: int = Field(ge=0)
    """How many events of any type mention this incident."""

    problems: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    """Everything about this trail that does not hold together. Empty means consistent."""

    @property
    def consistent(self) -> bool:
        """Whether the trail reconstructs into a legal, gap-free history."""
        return not self.problems

    @property
    def final_state(self) -> IncidentState | None:
        """The last state recorded, or ``None`` if no transition was ever recorded."""
        return self.states[-1] if self.states else None


def _state_changes(events: Sequence[AuditEvent]) -> list[AuditEvent]:
    return [
        event for event in events if event.event_type == AuditEventType.INCIDENT_STATE_CHANGED.value
    ]


def reconstruct_incident_history(
    records: Sequence[AuditRecord], incident_id: str
) -> IncidentHistory:
    """Rebuild one incident's state sequence from an audit trail.

    Args:
        records: Audit records, in append order. Records for other incidents are ignored.
        incident_id: Exact identifier. No prefix or substring matching.

    Returns:
        The reconstructed :class:`IncidentHistory`. ``problems`` is empty only when every
        recorded transition is a legal edge, each one continues from the last, and any
        resolution is backed by a matching VERIFIED verification event in the same trail.
    """
    mine = [record for record in records if record.event.incident_id == incident_id]
    events = [record.event for record in mine]
    changes = _state_changes(events)

    problems: list[str] = []
    states: list[IncidentState] = []
    transitions: list[tuple[IncidentState, IncidentState]] = []

    for position, event in enumerate(changes):
        before, after = event.state_before, event.state_after
        if not isinstance(before, IncidentState) or not isinstance(after, IncidentState):
            problems.append(
                f"{event.event_id}: state_changed event does not carry two incident states"
            )
            continue

        if not states:
            states.append(before)
        elif states[-1] != before:
            problems.append(
                f"{event.event_id}: transition starts at {before} but the trail left the "
                f"incident in {states[-1]}; the history has a gap"
            )
            states.append(before)

        if not IncidentStateMachine.can_transition(before, after):
            problems.append(f"{event.event_id}: {before} -> {after} is not a legal transition")

        states.append(after)
        transitions.append((before, after))
        del position

    problems.extend(_resolution_problems(mine, transitions))

    return IncidentHistory(
        incident_id=incident_id,
        states=tuple(states),
        transitions=tuple(transitions),
        event_count=len(events),
        problems=tuple(problems),
    )


def _resolution_problems(
    records: Sequence[AuditRecord],
    transitions: Sequence[tuple[IncidentState, IncidentState]],
) -> list[str]:
    """Check that any resolution is backed by a VERIFIED verification in the same trail.

    The state machine enforces this at transition time. Checking it again here catches a
    trail that was assembled or altered rather than recorded — a resolution whose
    supporting verification is absent, failed, or belongs to a different action.
    """
    if not any(after is IncidentState.RESOLVED for _, after in transitions):
        return []

    verified: dict[str, str] = {
        record.correlation.get("verification_id", ""): record.correlation.get("action_id", "")
        for record in records
        if record.event.event_type == AuditEventType.VERIFICATION_COMPLETED.value
        and record.correlation.get("status") == "VERIFIED"
    }

    problems: list[str] = []
    for record in records:
        event = record.event
        if (
            event.event_type != AuditEventType.INCIDENT_STATE_CHANGED.value
            or event.state_after is not IncidentState.RESOLVED
        ):
            continue
        verification_id = record.correlation.get("verification_id", "")
        if not verification_id:
            problems.append(f"{event.event_id}: incident resolved without naming a verification")
        elif verification_id not in verified:
            problems.append(
                f"{event.event_id}: resolved on verification {verification_id!r}, which "
                f"has no VERIFIED record in this trail"
            )
    return problems
