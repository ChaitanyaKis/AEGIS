"""What happened, in order, with nothing invented in the gaps.

Part 4. The timeline is a reconstruction, and the whole difficulty is what to do when a
phase left no artifact. There are three honest answers and only three:

``OBSERVED``
    An artifact says this happened. The entry names it.
``DERIVED``
    Computed from observed artifacts by a rule stated in the phase's docstring below.
``UNAVAILABLE``
    Nothing says either way. The phase is reported as ``UNKNOWN``.

There is no fourth answer, and in particular there is no "it probably did not happen". A
phase with no evidence is *unknown*, not *false* -- and since AEGIS is built to fail closed,
rendering unknown as false is how an outage comes to look like a clean run.

The one phase the audit trail cannot answer
-------------------------------------------

**Execution.** The audit vocabulary has no ``execution.*`` member: a lifecycle gate being
consumed says authorization was *spent*, which is not the same as production being
*changed*. So :attr:`Phase.EXECUTION` is sourced from the run's own
``ExecutionResult`` and reports ``UNKNOWN`` when no run is available -- even when a gate
was consumed. That is a real limitation of the trail rather than of this module, it is
stated in ``docs/CONTROL_CENTER.md``, and it is not papered over here by treating a spent
gate as evidence of a mutation.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from aegis.control_center.capture import ControlCenterInput
from aegis.control_center.models import (
    AuditIntegrityView,
    AuditTrust,
    Certainty,
    Completeness,
    Provenance,
    Tri,
    ViewSource,
)
from aegis.core.audit.events import AuditEventType
from aegis.core.domain import DomainModel, Identifier, NonEmptyStr, Timestamp

__all__ = ["IncidentTimeline", "Phase", "PhaseSummary", "TimelineEntry", "build_timeline"]


class Phase(StrEnum):
    """The phases Part 4 names. Closed, so an entry cannot describe something unnamed."""

    RECEIVED = "RECEIVED"
    CLASSIFIED = "CLASSIFIED"
    INVESTIGATING = "INVESTIGATING"
    DELEGATION = "DELEGATION"
    SPECIALIST_RESULT = "SPECIALIST_RESULT"
    FINDING = "FINDING"
    """A specialist's answer that carried an attributed finding.

    Distinct from :attr:`SPECIALIST_RESULT` on purpose: a response with no finding is a
    task that completed without concluding anything, and an operator counting findings
    would otherwise count refusals among them.
    """

    ASSESSMENT = "ASSESSMENT"
    POLICY = "POLICY"
    APPROVAL = "APPROVAL"
    GATE = "GATE"
    EXECUTION = "EXECUTION"
    VERIFICATION = "VERIFICATION"
    RECOVERY = "RECOVERY"
    ESCALATION = "ESCALATION"
    RESOLUTION = "RESOLUTION"
    SECURITY = "SECURITY"
    """A detection, a refusal or a containment. Detection is not prevention -- see
    :mod:`aegis.control_center.security`."""


_STATE_PHASES: dict[str, Phase] = {
    "RECEIVED": Phase.RECEIVED,
    "CLASSIFIED": Phase.CLASSIFIED,
    "INVESTIGATING": Phase.INVESTIGATING,
    "IMPACT_ASSESSED": Phase.INVESTIGATING,
    "PLAN_PROPOSED": Phase.INVESTIGATING,
    "POLICY_CHECK": Phase.POLICY,
    "AWAITING_APPROVAL": Phase.APPROVAL,
    "EXECUTING": Phase.EXECUTION,
    "VERIFYING": Phase.VERIFICATION,
    "DEGRADED": Phase.RECOVERY,
    "RECOVERING": Phase.RECOVERY,
    "ESCALATED": Phase.ESCALATION,
    "RESOLVED": Phase.RESOLUTION,
}
"""Which phase an ``incident.state_changed`` event belongs to.

A mapping rather than a chain of conditionals, so a state with no phase is a ``KeyError``
somebody has to answer rather than an event that silently vanishes from the timeline.

``EXECUTING`` maps to :attr:`Phase.EXECUTION` because the *state machine* entering that
state is a genuine observation -- but it is an observation about the state machine, not
about production, and the entry says so in its detail. The execution artifact itself comes
from the run.
"""

_EVENT_PHASES: dict[str, Phase] = {
    AuditEventType.ACTION_ASSESSED.value: Phase.ASSESSMENT,
    AuditEventType.POLICY_DECISION.value: Phase.POLICY,
    AuditEventType.APPROVAL_REQUESTED.value: Phase.APPROVAL,
    AuditEventType.APPROVAL_GRANTED.value: Phase.APPROVAL,
    AuditEventType.APPROVAL_REJECTED.value: Phase.APPROVAL,
    AuditEventType.APPROVAL_EXPIRED.value: Phase.APPROVAL,
    AuditEventType.APPROVAL_CONSUMED.value: Phase.APPROVAL,
    AuditEventType.LIFECYCLE_GATE_ISSUED.value: Phase.GATE,
    AuditEventType.LIFECYCLE_GATE_CONSUMED.value: Phase.GATE,
    AuditEventType.LIFECYCLE_GATE_REJECTED.value: Phase.GATE,
    AuditEventType.VERIFICATION_COMPLETED.value: Phase.VERIFICATION,
    AuditEventType.LIFECYCLE_STOPPED.value: Phase.RECOVERY,
    AuditEventType.CIRCUIT_OPENED.value: Phase.SECURITY,
    AuditEventType.CIRCUIT_PROBE.value: Phase.RECOVERY,
    AuditEventType.CIRCUIT_CLOSED.value: Phase.RECOVERY,
    AuditEventType.AGENT_RESTRICTION_APPLIED.value: Phase.SECURITY,
    AuditEventType.AGENT_RESTRICTION_REFUSED.value: Phase.SECURITY,
    AuditEventType.REMOTE_KEY_REVOKED.value: Phase.SECURITY,
}
"""Event types whose phase does not depend on their contents.

``a2a.message``, ``remote.authentication``, ``model.decision``, ``memory.*`` and
``incident.state_changed`` are absent because their phase *does* depend on contents, and
they are classified individually below.
"""


class TimelineEntry(DomainModel):
    """One thing that happened, and the artifact that says so.

    Frozen. ``evidence_refs`` carries the ids a reader can follow -- event ids, action ids,
    approval ids, message ids -- so no entry is a claim a reader has to take on trust.
    """

    phase: Phase
    at: Timestamp
    actor: NonEmptyStr
    summary: NonEmptyStr
    source: ViewSource
    certainty: Certainty
    event_id: Identifier | None = None
    event_type: NonEmptyStr | None = None
    evidence_refs: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    detail: NonEmptyStr | None = None

    def __repr__(self) -> str:
        return f"{self.at.isoformat()} [{self.phase}] {self.summary}"


class PhaseSummary(DomainModel):
    """Whether one phase happened at all, answered in three values rather than two."""

    phase: Phase
    occurred: Tri
    entries: int = Field(default=0, ge=0)
    first_at: Timestamp | None = None
    last_at: Timestamp | None = None
    detail: NonEmptyStr | None = None

    def __repr__(self) -> str:
        return f"PhaseSummary({self.phase}={self.occurred}, {self.entries})"


class IncidentTimeline(DomainModel):
    """One incident, reconstructed in order, with its own provenance attached.

    ``entries`` is sorted by ``(timestamp, source ordinal, event id)`` so two runs over the
    same artifacts produce the same timeline -- determinism matters here because a forensic
    export embeds it (Part 23).
    """

    incident_id: Identifier
    entries: tuple[TimelineEntry, ...] = Field(default_factory=tuple)
    phases: tuple[PhaseSummary, ...] = Field(default_factory=tuple)
    provenance: Provenance
    audit: AuditIntegrityView

    def phase(self, phase: Phase) -> PhaseSummary:
        """One phase's summary. Always answers -- an absent phase is ``UNKNOWN``, not a
        missing key."""
        for summary in self.phases:
            if summary.phase is phase:
                return summary
        return PhaseSummary(phase=phase, occurred=Tri.UNKNOWN, detail="no evidence either way")

    def occurred(self, phase: Phase) -> Tri:
        return self.phase(phase).occurred

    def of_phase(self, phase: Phase) -> tuple[TimelineEntry, ...]:
        return tuple(entry for entry in self.entries if entry.phase is phase)

    def __len__(self) -> int:
        return len(self.entries)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({self.incident_id}, {len(self.entries)} entries, "
            f"{self.audit.trust})"
        )


def build_timeline(data: ControlCenterInput) -> IncidentTimeline:
    """Reconstruct one incident's timeline from recorded artifacts.

    The audit trail is **re-verified** before anything is read from it (Part 17). When the
    chain does not verify, entries are still shown -- hiding them would help nobody -- but
    the provenance is downgraded to ``UNKNOWN`` and every phase's ``occurred`` becomes
    ``UNKNOWN`` too. An untrusted trail is not evidence, and a timeline built from one must
    not read as though it were.
    """
    audit = audit_view(data)
    entries: list[TimelineEntry] = []

    if data.audit_available:
        for record in data.audit_records:
            if record.event.incident_id not in (None, data.incident_id):
                continue  # Part 18: another incident's events are not this incident's story
            entry = _entry_for(record)
            if entry is not None:
                entries.append(entry)

    entries.extend(_run_entries(data))
    entries.sort(key=lambda entry: (entry.at, entry.source.value, entry.event_id or ""))

    trusted = audit.trust is AuditTrust.TRUSTED
    provenance = Provenance(
        source=ViewSource.AUDIT if data.audit_available else ViewSource.NONE,
        as_of=data.captured_at,
        completeness=_completeness(data, trusted),
        detail=None if trusted and data.audit_available else _why_incomplete(data, audit),
    )
    return IncidentTimeline(
        incident_id=data.incident_id,
        entries=tuple(entries),
        phases=_phase_summaries(entries, trusted=trusted, data=data),
        provenance=provenance,
        audit=audit,
    )


def audit_view(data: ControlCenterInput) -> AuditIntegrityView:
    """The chain's verdict on itself, as a view. Reported; never repaired (Part 17)."""
    if not data.audit_available or data.audit_integrity is None:
        return AuditIntegrityView(
            trust=AuditTrust.UNAVAILABLE,
            records=len(data.audit_records),
            reason="the audit store could not be read",
        )
    report = data.audit_integrity
    return AuditIntegrityView(
        trust=AuditTrust.TRUSTED if report.valid else AuditTrust.UNTRUSTED,
        records=len(data.audit_records),
        checked=report.checked,
        first_invalid_index=report.first_invalid_index,
        reason=report.reason,
        trusted_prefix=report.trusted_prefix,
        truncated=_truncated(data),
    )


def _truncated(data: ControlCenterInput) -> Tri:
    """Whether the record set is demonstrably shorter than the store.

    The last record's digest against the store's own head. Equal means these are all of
    them; different means the end is missing. ``UNKNOWN`` when either is unavailable --
    which is the answer, not an excuse to assume the happier one.
    """
    if not data.audit_head_digest or not data.audit_records:
        return Tri.UNKNOWN
    return Tri.of(data.audit_records[-1].digest != data.audit_head_digest)


def _completeness(data: ControlCenterInput, trusted: bool) -> Completeness:
    """How complete the timeline's source was.

    Three ways to fall short of ``COMPLETE``, and they are genuinely different: an
    unreadable store, a chain that does not verify, and a chain that verifies over records
    that are demonstrably not all of them.
    """
    if not data.audit_available or not trusted:
        return Completeness.UNKNOWN
    if _truncated(data) is not Tri.FALSE:
        return Completeness.UNKNOWN
    return Completeness.COMPLETE if data.run_available else Completeness.PARTIAL


def _why_incomplete(data: ControlCenterInput, audit: AuditIntegrityView) -> str:
    if not data.audit_available:
        return "the audit store could not be read; every phase below is UNKNOWN"
    if audit.trust is AuditTrust.UNTRUSTED:
        return (
            f"the audit chain does not verify from record {audit.first_invalid_index}: "
            f"{audit.reason}; entries are shown but not vouched for"
        )
    if audit.truncated is not Tri.FALSE:
        return (
            "the records shown do not reach the store's head digest, so the end of the "
            "trail is missing; every absence below is UNKNOWN rather than FALSE"
        )
    return "no completed run was captured; the incident may have stopped part-way"


def _entry_for(record) -> TimelineEntry | None:
    """One audit record as a timeline entry, or ``None`` when it belongs to no phase."""
    event = record.event
    phase = _phase_of(record)
    if phase is None:
        return None
    return TimelineEntry(
        phase=phase,
        at=event.timestamp,
        actor=event.actor,
        summary=_summary_of(record, phase),
        source=ViewSource.AUDIT,
        certainty=Certainty.OBSERVED,
        event_id=event.event_id,
        event_type=event.event_type,
        evidence_refs=_evidence_of(record),
        detail=event.result,
    )


def _phase_of(record) -> Phase | None:
    """Which phase a record belongs to. Contents-dependent types are classified here."""
    event_type = record.event.event_type
    fixed = _EVENT_PHASES.get(event_type)
    if fixed is not None:
        return fixed
    if event_type == AuditEventType.INCIDENT_STATE_CHANGED.value:
        return _STATE_PHASES.get(str(record.event.state_after or ""), Phase.INVESTIGATING)
    if event_type == AuditEventType.A2A_MESSAGE.value:
        if record.correlation.get("finding_id"):
            return Phase.FINDING
        status = record.correlation.get("status", "")
        if status == "COMPLETED":
            return Phase.SPECIALIST_RESULT
        if status in {"REJECTED", "REFUSED"}:
            return Phase.SECURITY
        return Phase.DELEGATION
    if event_type == AuditEventType.REMOTE_AUTHENTICATION.value:
        return (
            Phase.DELEGATION
            if record.correlation.get("status") == "AUTHENTICATED"
            else Phase.SECURITY
        )
    if event_type == AuditEventType.MODEL_DECISION.value:
        return Phase.INVESTIGATING
    if event_type in {
        AuditEventType.MEMORY_ADMITTED.value,
        AuditEventType.MEMORY_REVOKED.value,
    }:
        return Phase.RESOLUTION
    return None


def _summary_of(record, phase: Phase) -> str:
    """A short line describing the record. Reads artifacts; states nothing extra."""
    event = record.event
    if event.event_type == AuditEventType.INCIDENT_STATE_CHANGED.value:
        detail = (
            " (state machine entered EXECUTING; this is not evidence production changed)"
            if str(event.state_after or "") == "EXECUTING"
            else ""
        )
        return f"incident moved {event.state_before} -> {event.state_after}{detail}"
    if event.event_type == AuditEventType.A2A_MESSAGE.value:
        return (
            f"a2a {record.correlation.get('status', 'UNKNOWN')} "
            f"{record.correlation.get('sender_agent_id', '?')}"
            f" -> {record.correlation.get('recipient_agent_id', '?')}"
        )
    if event.event_type == AuditEventType.REMOTE_AUTHENTICATION.value:
        return (
            f"remote {record.correlation.get('status', 'UNKNOWN')} for "
            f"{record.correlation.get('claimed_agent_id', '?')}"
        )
    return f"{event.event_type} ({phase})"


def _evidence_of(record) -> tuple[str, ...]:
    """Artifact ids a reader can follow, sorted so the entry is deterministic."""
    references = {record.event.event_id}
    if record.event.input_reference:
        references.add(record.event.input_reference)
    for key in (
        "action_id",
        "approval_id",
        "verification_id",
        "gate_id",
        "message_id",
        "memory_id",
        "finding_id",
        "action_fingerprint",
    ):
        value = record.correlation.get(key)
        if value:
            references.add(value)
    return tuple(sorted(references))


def _run_entries(data: ControlCenterInput) -> list[TimelineEntry]:
    """The phases only the run can answer.

    Exactly one at present: execution. See the module docstring for why a consumed gate is
    not treated as evidence of it.
    """
    run = data.run
    if run is None or run.execution is None:
        return []
    execution = run.execution
    action_id = getattr(execution, "action_id", None) or getattr(run.action, "action_id", "")
    return [
        TimelineEntry(
            phase=Phase.EXECUTION,
            at=execution.executed_at,
            actor="system:executor",
            summary=f"execution recorded: {execution.outcome}",
            source=ViewSource.RUN,
            certainty=Certainty.OBSERVED,
            evidence_refs=tuple(sorted({str(action_id)} - {""})),
            detail="from the run's ExecutionResult; the audit vocabulary has no execution event",
        )
    ]


def _execution_summary(
    found: list[TimelineEntry], data: ControlCenterInput
) -> tuple[Tri, str | None]:
    """Whether production changed -- answered only by the run.

    The phase collects two very different kinds of entry. An ``incident.state_changed``
    event reaching ``EXECUTING`` says the state machine authorised work to begin; the run's
    ``ExecutionResult`` says production actually changed. An operator reading this summary
    is asking the second question, and the audit vocabulary has no event that answers it.

    So a state-machine entry alone is never enough. With no run the answer is ``UNKNOWN``,
    however many transitions were recorded -- which is the honest reading of "authorisation
    was given and nobody wrote down what happened next".
    """
    from_run = [entry for entry in found if entry.source is ViewSource.RUN]
    if from_run:
        return Tri.TRUE, None
    if not data.run_available:
        return Tri.UNKNOWN, (
            "the state machine reached EXECUTING, but no run was captured and the audit "
            "vocabulary has no execution event; whether production changed is unknown"
        )
    return Tri.FALSE, ("the run recorded no ExecutionResult" if found else None)


def _phase_summaries(
    entries: list[TimelineEntry], *, trusted: bool, data: ControlCenterInput
) -> tuple[PhaseSummary, ...]:
    """One summary per phase, with ``UNKNOWN`` wherever nothing can be said.

    Two rules, and both matter:

    * a phase with entries is ``TRUE`` -- but only when the source behind those entries can
      be trusted;
    * a phase with no entries is ``UNKNOWN`` **unless** a complete, trusted source would
      have recorded it, in which case its absence is itself an observation and the phase is
      ``FALSE``.

    The second rule is where a control center earns its keep. "No approval was requested"
    is a genuinely useful thing to be told -- but only when the trail is whole. From a
    partial or untrusted trail the same silence means nothing at all.
    """
    grouped: dict[Phase, list[TimelineEntry]] = {}
    for entry in entries:
        grouped.setdefault(entry.phase, []).append(entry)

    complete = trusted and data.audit_available and _truncated(data) is Tri.FALSE
    summaries: list[PhaseSummary] = []
    for phase in Phase:
        found = grouped.get(phase, [])
        if phase is Phase.EXECUTION:
            occurred, detail = _execution_summary(found, data)
        elif found:
            occurred = Tri.TRUE if trusted else Tri.UNKNOWN
            detail = None if trusted else "entries exist but the audit chain does not verify"
        elif complete:
            occurred = Tri.FALSE
            detail = None
        else:
            occurred = Tri.UNKNOWN
            detail = "the source that would have recorded this could not be trusted"
        summaries.append(
            PhaseSummary(
                phase=phase,
                occurred=occurred,
                entries=len(found),
                first_at=found[0].at if found else None,
                last_at=found[-1].at if found else None,
                detail=detail,
            )
        )
    return tuple(summaries)
