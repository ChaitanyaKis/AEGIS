"""Why AEGIS did that -- answered from artifacts, and from nothing else.

Parts 6, 7, 11 and 12. The most operator-facing module here, and the one where the
temptation to be helpful is most dangerous.

Three rules
-----------

**Explanations point at artifacts.** Every :class:`Explanation` carries the ids it rests
on. There is no free-form rationale, no model-written prose and no "probably". When the
artifacts do not answer the question, the answer is
:attr:`ExplanationOutcome.EXPLANATION_INCOMPLETE` and the missing artifact is named.

**Explaining a decision is not making one.** This module can say "policy required
approval". It holds no policy engine, cannot re-evaluate anything, and has no
representation of a decision other than the one that was recorded. There is no code path
here that turns ``REQUIRE_APPROVAL`` into ``ALLOW`` because there is no code path here that
produces a decision at all.

**An approval is shown with its binding or not at all.** Part 11: a view that says
"approved" without naming the exact action fingerprint is a view that can make an approval
for one action look like an approval for another. :class:`ApprovalView` therefore has no
"approved" boolean -- it has a status *and* a fingerprint, and the fingerprint is
required.
"""

from __future__ import annotations

from enum import StrEnum

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

__all__ = [
    "ApprovalView",
    "Explanation",
    "ExplanationOutcome",
    "GovernanceView",
    "Question",
    "VerificationView",
    "build_approvals",
    "build_governance",
    "build_verification",
    "explain",
]


# --- approvals (Part 11) -----------------------------------------------------------------


class ApprovalView(DomainModel):
    """One approval, always shown with the exact action it authorises.

    There is deliberately no ``approved: bool``. A boolean invites a caller to render
    "Approved" beside whatever action happens to be on screen, and an approval for
    *rollback payment-api* rendered beside *delete payment-db* is the precise failure Part
    11 exists to prevent. The binding is a required field, so it cannot be dropped.
    """

    approval_id: Identifier
    incident_id: Identifier
    action_id: Identifier
    action_fingerprint: NonEmptyStr
    """SHA-256 of the exact action. Required: an approval without its binding is not
    displayable."""

    requested_by: NonEmptyStr
    risk: NonEmptyStr
    blast_radius: NonEmptyStr
    status: NonEmptyStr
    reason: NonEmptyStr
    created_at: Timestamp
    expires_at: Timestamp | None = None
    decided_at: Timestamp | None = None
    decided_by: NonEmptyStr | None = None
    consumed_at: Timestamp | None = None
    provenance: Provenance

    def authorises(self, action_fingerprint: str) -> Tri:
        """Whether this approval authorises that exact action. Exact match, never a prefix.

        Returns :attr:`~aegis.control_center.models.Tri`, not a boolean, so a caller cannot
        write ``if approval.authorises(x)`` and have ``UNKNOWN`` read as permission. It is
        an observation about a recorded artifact either way -- **not** an authorization
        decision, which belongs to the approval engine and has already been made.
        """
        if not self.action_fingerprint or not action_fingerprint:
            return Tri.UNKNOWN
        return Tri.of(self.action_fingerprint == action_fingerprint)

    def __repr__(self) -> str:
        return f"ApprovalView({self.approval_id} {self.status} -> {self.action_fingerprint[:12]})"


def build_approvals(data: ControlCenterInput) -> tuple[ApprovalView, ...]:
    """Every approval this incident produced, from the run and the audit trail.

    The run's authorization is the richest artifact and is used when present. The audit
    trail is read as well, because an approval that was *requested and refused* leaves an
    event and no authorization -- and "a human said no" is exactly the thing an operator
    must be able to see.
    """
    views: list[ApprovalView] = []
    seen: set[str] = set()
    run = data.run
    provenance_run = Provenance(
        source=ViewSource.RUN,
        as_of=data.captured_at,
        completeness=Completeness.COMPLETE if data.run_available else Completeness.UNKNOWN,
    )

    authorization = getattr(run, "authorization", None) if run is not None else None
    approval = getattr(authorization, "approval", None)
    if approval is not None:
        views.append(_approval_view(approval, provenance_run))
        seen.add(str(approval.approval_id))

    for approval_id, records in _approval_events(data).items():
        if approval_id in seen:
            continue
        fingerprint = _first(records, "action_fingerprint")
        if not fingerprint:
            # Without a fingerprint there is no binding, and Part 11 forbids showing an
            # approval without one. Dropping it is the honest outcome: a reader is told
            # nothing rather than told something unbindable.
            continue
        seen.add(approval_id)
        # The *last* event, not the first. An approval that was requested, granted and then
        # consumed is a consumed approval; showing it as REQUESTED would tell an operator a
        # decision is still outstanding when a human already made it.
        final = records[-1]
        views.append(
            ApprovalView(
                approval_id=approval_id,
                incident_id=final.event.incident_id or data.incident_id,
                action_id=_first(records, "action_id") or "unknown",
                action_fingerprint=fingerprint,
                requested_by=_first(records, "requesting_agent") or records[0].event.actor,
                risk=_first(records, "risk") or "UNKNOWN",
                blast_radius=_first(records, "blast_radius") or "UNKNOWN",
                status=final.event.event_type.removeprefix("approval.").upper(),
                reason=final.event.result or "recorded without a reason",
                created_at=records[0].event.timestamp,
                decided_at=_timestamp_of(records, "approval.granted", "approval.rejected"),
                consumed_at=_timestamp_of(records, "approval.consumed"),
                provenance=Provenance(
                    source=ViewSource.AUDIT,
                    as_of=data.captured_at,
                    completeness=Completeness.PARTIAL,
                    detail=(
                        f"reconstructed from {len(records)} approval event(s); no "
                        f"authorization artifact"
                    ),
                ),
            )
        )
    return tuple(views)


def _approval_events(data: ControlCenterInput) -> dict:
    """Approval events grouped by approval id, in the order they were recorded.

    Grouping first is what makes the *final* status readable. Iterating events one at a
    time and taking the first match is how an approval that was granted and consumed comes
    to display as merely requested.
    """
    grouped: dict[str, list] = {}
    for record in _incident_records(data):
        if not record.event.event_type.startswith("approval."):
            continue
        approval_id = record.correlation.get("approval_id") or record.event.input_reference
        if approval_id:
            grouped.setdefault(approval_id, []).append(record)
    return {key: grouped[key] for key in sorted(grouped)}


def _first(records, key: str) -> str:
    """The first non-empty value for a correlation key across an approval's events."""
    for record in records:
        value = record.correlation.get(key)
        if value:
            return value
    return ""


def _timestamp_of(records, *event_types: str):
    """When one of these event types was recorded, or ``None``."""
    for record in records:
        if record.event.event_type in event_types:
            return record.event.timestamp
    return None


def _approval_view(approval, provenance: Provenance) -> ApprovalView:
    return ApprovalView(
        approval_id=str(approval.approval_id),
        incident_id=str(approval.incident_id),
        action_id=str(approval.action_id),
        action_fingerprint=str(approval.action_fingerprint),
        requested_by=str(approval.requesting_agent),
        risk=str(approval.risk),
        blast_radius=str(approval.blast_radius.scope)
        if getattr(approval, "blast_radius", None) is not None
        else "UNKNOWN",
        status=str(approval.status),
        reason=str(approval.reason),
        created_at=approval.created_at,
        expires_at=getattr(approval, "expires_at", None),
        decided_at=getattr(approval, "decided_at", None),
        decided_by=getattr(approval, "decided_by", None),
        consumed_at=getattr(approval, "consumed_at", None),
        provenance=provenance,
    )


# --- verification (Part 12) ---------------------------------------------------------------


class VerificationView(DomainModel):
    """What execution did, what verification established, and whether either resolved anything.

    Three separate tri-states, kept apart because collapsing them is the classic mistake:

        EXECUTED does not mean VERIFIED
        VERIFIED does not mean RESOLVED

    ``resolved`` is read from the incident's *recorded state*, never derived from the other
    two. An incident is resolved when the state machine says so and at no other moment.
    """

    executed: Tri
    execution_outcome: Fact
    world_changed: Tri
    """What the executor recorded. Still not verification: a tool reporting success is not
    an operation having succeeded (``claude.md`` section 11)."""

    verified: Tri
    verification_id: Fact
    verification_status: Fact
    verification_reason: Fact
    observations_used: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    """Evidence ids the verification actually consumed. Its independence rests on these."""

    action_fingerprint: Fact
    """Binds execution and verification to the same exact action, so a reader can check
    that what was verified is what ran."""

    resolved: Tri
    resolution_source: Fact
    provenance: Provenance

    def __repr__(self) -> str:
        return (
            f"VerificationView(executed={self.executed}, verified={self.verified}, "
            f"resolved={self.resolved})"
        )


def build_verification(data: ControlCenterInput) -> VerificationView:
    """Execution, verification and resolution, each from its own artifact.

    When no run was captured every field is ``UNKNOWN``. That is the correct answer and not
    a degraded one: an operator looking at a crashed run must not be told the action did
    not execute, because nobody knows.
    """
    run = data.run
    if run is None:
        return VerificationView(
            executed=Tri.UNKNOWN,
            execution_outcome=Fact.unknown(),
            world_changed=Tri.UNKNOWN,
            verified=Tri.UNKNOWN,
            verification_id=Fact.unknown(),
            verification_status=Fact.unknown(),
            verification_reason=Fact.unknown(),
            action_fingerprint=Fact.unknown(),
            resolved=Tri.UNKNOWN,
            resolution_source=Fact.unknown(),
            provenance=Provenance.unavailable(
                data.captured_at, "no run was captured for this incident"
            ),
        )

    execution = run.execution
    verification = run.verification
    fingerprint = _fingerprint_of(run)

    return VerificationView(
        executed=Tri.of(execution is not None),
        execution_outcome=(
            Fact.observed(execution.outcome, str(execution.action_id))
            if execution is not None
            else Fact.unknown()
        ),
        world_changed=Tri.of(getattr(execution, "world_changed", None)),
        verified=(
            Tri.of(verification.status.value == "VERIFIED")
            if verification is not None
            else Tri.UNKNOWN
        ),
        verification_id=(
            Fact.observed(verification.verification_id, str(verification.verification_id))
            if verification is not None
            else Fact.unknown()
        ),
        verification_status=(
            Fact.observed(verification.status) if verification is not None else Fact.unknown()
        ),
        verification_reason=(
            Fact.observed(verification.reason) if verification is not None else Fact.unknown()
        ),
        observations_used=(
            tuple(str(reference) for reference in verification.observations_used)
            if verification is not None
            else ()
        ),
        action_fingerprint=(Fact.observed(fingerprint) if fingerprint else Fact.unknown()),
        # Read from the incident's recorded state. Never derived from `verified`: the state
        # machine is what resolves an incident, and a view that computed resolution from
        # verification would be re-implementing the guard it exists to display.
        resolved=Tri.of(run.incident.state.value == "RESOLVED"),
        resolution_source=Fact.observed(run.incident.state, str(run.incident.incident_id)),
        provenance=Provenance(
            source=ViewSource.RUN,
            as_of=data.captured_at,
            completeness=Completeness.COMPLETE,
        ),
    )


# --- the governance path (Part 6) ---------------------------------------------------------


class GovernanceView(DomainModel):
    """Everything an operator needs to see about one proposed action's governed path.

    Read-only end to end. Each field is a :class:`~aegis.control_center.models.Fact` so a
    missing stage is visibly missing rather than blank, and no stage's value is computed
    from another's.
    """

    action_id: Fact
    capability: Fact
    resource: Fact
    fingerprint: Fact
    proposed_by: Fact

    risk: Fact
    blast_radius: Fact
    blast_radius_scope: Fact
    assessment_outcome: Fact

    policy_decision: Fact
    policy_reason: Fact
    policy_reference: Fact
    approval_required: Tri

    approvals: tuple[ApprovalView, ...] = Field(default_factory=tuple)
    approval_status: Fact = Field(default_factory=lambda: Fact.unknown())

    gate_issued: Tri = Tri.UNKNOWN
    gate_consumed: Tri = Tri.UNKNOWN
    gates_issued_count: int | None = None
    gates_consumed_count: int | None = None

    verification: VerificationView
    provenance: Provenance

    @property
    def stages(self) -> tuple[tuple[str, Fact | Tri], ...]:
        """The governed path in order, for rendering. Names match the engines, not the UI."""
        return (
            ("action", self.action_id),
            ("risk", self.risk),
            ("blast_radius", self.blast_radius),
            ("policy", self.policy_decision),
            ("approval_required", self.approval_required),
            ("approval", self.approval_status),
            ("gate_issued", self.gate_issued),
            ("gate_consumed", self.gate_consumed),
            ("executed", self.verification.executed),
            ("verified", self.verification.verified),
            ("resolved", self.verification.resolved),
        )

    def __repr__(self) -> str:
        return f"GovernanceView({self.policy_decision!r} -> {self.verification!r})"


def build_governance(data: ControlCenterInput) -> GovernanceView:
    """Assemble the governed path for the run's proposed action.

    Every value comes off exactly one artifact. Nothing is inferred across stages: a
    missing policy evaluation does not become ``DENY``, and a missing approval does not
    become "not required".
    """
    run = data.run
    action = getattr(run, "action", None)
    assessment = getattr(run, "assessment", None)
    evaluation = getattr(run, "evaluation", None)
    decision = getattr(evaluation, "decision", None)
    approvals = build_approvals(data)
    fingerprint = _fingerprint_of(run)

    gate_issued, gate_consumed = _gate_facts(data)

    return GovernanceView(
        action_id=Fact.observed(action.action_id) if action is not None else Fact.unknown(),
        capability=Fact.observed(action.capability) if action is not None else Fact.unknown(),
        resource=(Fact.observed(action.target_resource) if action is not None else Fact.unknown()),
        # Read off the approval or verification artifact rather than recomputed. Those
        # artifacts are what *bound* the fingerprint to a decision; recomputing it here
        # would produce a number that looks the same and proves nothing about the binding.
        fingerprint=Fact.observed(fingerprint) if fingerprint else Fact.unknown(),
        proposed_by=(
            Fact.observed(action.requesting_agent) if action is not None else Fact.unknown()
        ),
        risk=(
            Fact.observed(assessment.risk.risk)
            if assessment is not None and assessment.risk is not None
            else Fact.unknown()
        ),
        blast_radius=(
            Fact.observed(assessment.blast_radius.blast_radius.impact)
            if assessment is not None and assessment.blast_radius is not None
            else Fact.unknown()
        ),
        blast_radius_scope=(
            Fact.observed(assessment.blast_radius.blast_radius.scope)
            if assessment is not None and assessment.blast_radius is not None
            else Fact.unknown()
        ),
        assessment_outcome=(
            Fact.observed(assessment.outcome) if assessment is not None else Fact.unknown()
        ),
        policy_decision=(
            Fact.observed(decision.decision) if decision is not None else Fact.unknown()
        ),
        policy_reason=Fact.observed(decision.reason) if decision is not None else Fact.unknown(),
        policy_reference=(
            Fact.observed(decision.policy_reference) if decision is not None else Fact.unknown()
        ),
        approval_required=(
            Tri.of(decision.decision.value == "REQUIRE_APPROVAL")
            if decision is not None
            else Tri.UNKNOWN
        ),
        approvals=approvals,
        approval_status=(
            Fact.observed(approvals[0].status, approvals[0].approval_id)
            if approvals
            else Fact.unknown()
        ),
        gate_issued=gate_issued,
        gate_consumed=gate_consumed,
        gates_issued_count=data.gates_issued,
        gates_consumed_count=data.gates_consumed,
        verification=build_verification(data),
        provenance=Provenance(
            source=ViewSource.RUN,
            as_of=data.captured_at,
            completeness=Completeness.COMPLETE if data.run_available else Completeness.UNKNOWN,
            detail=None if data.run_available else "no run was captured",
        ),
    )


def _fingerprint_of(run) -> str:
    """The action fingerprint, from whichever artifact recorded a binding.

    Never recomputed from the action. A fingerprint the control center calculated would be
    a number that matches; a fingerprint an approval recorded is the binding itself, and
    only the second is worth showing next to the word "approved".
    """
    for artifact in (
        getattr(run, "authorization", None),
        getattr(run, "verification", None),
    ):
        value = getattr(artifact, "action_fingerprint", None)
        if value:
            return str(value)
    return ""


def _gate_facts(data: ControlCenterInput) -> tuple[Tri, Tri]:
    """Gate issuance and consumption, from two sources that must agree.

    The audit trail proves a gate for *this* incident; the register's count is process-wide
    and proves only that some gate was spent somewhere. Neither alone is enough, so both
    are read:

    * the trail says yes -> ``TRUE``. An event for this incident is direct evidence.
    * the trail says no and the register agrees nothing was spent -> ``FALSE``.
    * the trail says no and the register counted one -> **``UNKNOWN``**, because the two
      sources disagree and the projection cannot tell a truncated trail from a short one.

    That last case is the one that matters. A verifying chain proves no *tampering*; it
    does not prove *completeness*, and a truncated trail looks exactly like a history in
    which nothing happened. Reporting ``FALSE`` there would be the read model claiming
    something it cannot know.
    """
    if not data.audit_available:
        return Tri.UNKNOWN, Tri.UNKNOWN
    records = _incident_records(data)
    issued = any(
        record.event.event_type == AuditEventType.LIFECYCLE_GATE_ISSUED.value for record in records
    )
    consumed = any(
        record.event.event_type == AuditEventType.LIFECYCLE_GATE_CONSUMED.value
        for record in records
    )
    return (
        _corroborate(issued, data.gates_issued),
        _corroborate(consumed, data.gates_consumed),
    )


def _corroborate(from_trail: bool, register_count: int | None) -> Tri:
    """One trail answer, checked against the register's own count.

    A positive stands on its own. A negative needs the register to agree, because a missing
    event and a missing *slice of trail* are indistinguishable from inside the projection.
    """
    if from_trail:
        return Tri.TRUE
    if register_count is None:
        return Tri.UNKNOWN
    return Tri.FALSE if register_count == 0 else Tri.UNKNOWN


def _incident_records(data: ControlCenterInput):
    """Audit records for this incident only. Part 18's isolation, applied at the source."""
    return tuple(
        record
        for record in data.audit_records
        if record.event.incident_id in (None, data.incident_id)
    )


# --- "why did AEGIS do this?" (Part 7) ----------------------------------------------------


class Question(StrEnum):
    """The questions Part 7 names. Closed, so an unanswerable question is not askable."""

    WHY_PROPOSED = "WHY_PROPOSED"
    WHY_DELEGATED = "WHY_DELEGATED"
    WHY_APPROVAL_REQUIRED = "WHY_APPROVAL_REQUIRED"
    WHY_DENIED = "WHY_DENIED"
    WHY_EXECUTION_STOPPED = "WHY_EXECUTION_STOPPED"
    WHY_RECOVERY_BEGAN = "WHY_RECOVERY_BEGAN"
    WHY_BREAKER_OPENED = "WHY_BREAKER_OPENED"
    WHY_AGENT_RESTRICTED = "WHY_AGENT_RESTRICTED"
    WHY_ESCALATED = "WHY_ESCALATED"
    WHY_RESOLVED = "WHY_RESOLVED"


class ExplanationOutcome(StrEnum):
    """Whether the artifacts answered the question."""

    EXPLAINED = "EXPLAINED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    """The thing being asked about did not happen. Distinct from an unanswerable question:
    "why was it denied" has no answer when nothing was denied, and that is not a gap."""

    EXPLANATION_INCOMPLETE = "EXPLANATION_INCOMPLETE"
    """The artifacts that would answer this are missing. Part 7's required outcome, and the
    only honest one when evidence runs out."""


class Explanation(DomainModel):
    """One answer, with the artifacts behind it and nothing else.

    No prose beyond what a recorded ``reason`` field already says. No model output. No
    hedging language -- an explanation is either supported by artifacts or it is
    ``EXPLANATION_INCOMPLETE``, and there is no vocabulary here for "probably".
    """

    question: Question
    outcome: ExplanationOutcome
    answer: NonEmptyStr
    evidence_refs: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    source: ViewSource = ViewSource.NONE
    missing: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)
    """Which artifact would have answered this, when one is missing. Named, so an operator
    knows what to go and look for rather than being told only that we do not know."""

    def __repr__(self) -> str:
        return f"Explanation({self.question}={self.outcome}: {self.answer})"


def explain(data: ControlCenterInput, question: Question) -> Explanation:
    """Answer one operator question from recorded artifacts.

    Deterministic: the same artifacts always produce the same answer. Every branch either
    quotes a recorded ``reason``/``detail`` field or reports
    :attr:`ExplanationOutcome.EXPLANATION_INCOMPLETE` and names what was missing.
    """
    run = data.run
    if run is None:
        return Explanation(
            question=question,
            outcome=ExplanationOutcome.EXPLANATION_INCOMPLETE,
            answer="no run was captured for this incident",
            missing=("OrchestrationRun",),
        )
    handler = _HANDLERS[question]
    return handler(data, run)


def _why_proposed(data: ControlCenterInput, run) -> Explanation:
    action = run.action
    if action is None:
        return _incomplete(Question.WHY_PROPOSED, "no action was proposed", "Action")
    return Explanation(
        question=Question.WHY_PROPOSED,
        outcome=ExplanationOutcome.EXPLAINED,
        answer=(
            f"{action.requesting_agent} proposed {action.capability} on {action.target_resource}"
        ),
        evidence_refs=(str(action.action_id),),
        source=ViewSource.RUN,
    )


def _why_delegated(data: ControlCenterInput, run) -> Explanation:
    delegations = [
        record
        for record in _incident_records(data)
        if record.event.event_type == AuditEventType.A2A_MESSAGE.value
        and record.correlation.get("status") == "ISSUED"
    ]
    if not delegations:
        return _incomplete(
            Question.WHY_DELEGATED, "no delegation message was recorded", "a2a.message"
        )
    targets = sorted({record.correlation.get("recipient_agent_id", "?") for record in delegations})
    tasks = sorted({record.correlation.get("task_type", "?") for record in delegations})
    return Explanation(
        question=Question.WHY_DELEGATED,
        outcome=ExplanationOutcome.EXPLAINED,
        answer=f"the Commander delegated {', '.join(tasks)} to {', '.join(targets)}",
        evidence_refs=tuple(sorted(record.event.event_id for record in delegations)),
        source=ViewSource.AUDIT,
    )


def _why_approval_required(data: ControlCenterInput, run) -> Explanation:
    decision = getattr(run.evaluation, "decision", None)
    if decision is None:
        return _incomplete(
            Question.WHY_APPROVAL_REQUIRED, "no policy evaluation was recorded", "PolicyEvaluation"
        )
    if decision.decision.value != "REQUIRE_APPROVAL":
        return _not_applicable(
            Question.WHY_APPROVAL_REQUIRED,
            f"policy returned {decision.decision}, so no approval was required",
            str(decision.policy_reference),
        )
    return Explanation(
        question=Question.WHY_APPROVAL_REQUIRED,
        outcome=ExplanationOutcome.EXPLAINED,
        answer=f"{decision.policy_reference}: {decision.reason}",
        evidence_refs=(str(decision.policy_reference),),
        source=ViewSource.RUN,
    )


def _why_denied(data: ControlCenterInput, run) -> Explanation:
    decision = getattr(run.evaluation, "decision", None)
    if decision is None:
        return _incomplete(
            Question.WHY_DENIED, "no policy evaluation was recorded", "PolicyEvaluation"
        )
    if decision.decision.value != "DENY":
        return _not_applicable(
            Question.WHY_DENIED, f"nothing was denied; policy returned {decision.decision}", ""
        )
    return Explanation(
        question=Question.WHY_DENIED,
        outcome=ExplanationOutcome.EXPLAINED,
        answer=f"{decision.policy_reference}: {decision.reason}",
        evidence_refs=(str(decision.policy_reference),),
        source=ViewSource.RUN,
    )


def _why_execution_stopped(data: ControlCenterInput, run) -> Explanation:
    record = run.lifecycle
    if record is None:
        return _incomplete(
            Question.WHY_EXECUTION_STOPPED, "no lifecycle record was produced", "LifecycleRecord"
        )
    return Explanation(
        question=Question.WHY_EXECUTION_STOPPED,
        outcome=ExplanationOutcome.EXPLAINED,
        answer=(
            f"{record.stop_reason}: {record.detail}"
            + (f" (limit {record.limit_name}={record.limit_value})" if record.limit_name else "")
        ),
        evidence_refs=(str(record.incident_id),),
        source=ViewSource.LIFECYCLE_STATE,
    )


def _why_recovery_began(data: ControlCenterInput, run) -> Explanation:
    transitions = [
        record
        for record in _incident_records(data)
        if record.event.event_type == AuditEventType.INCIDENT_STATE_CHANGED.value
        and str(record.event.state_after or "") in {"DEGRADED", "RECOVERING"}
    ]
    if not transitions:
        return _not_applicable(Question.WHY_RECOVERY_BEGAN, "recovery was never entered", "")
    first = transitions[0]
    return Explanation(
        question=Question.WHY_RECOVERY_BEGAN,
        outcome=ExplanationOutcome.EXPLAINED,
        answer=f"entered {first.event.state_after}: {first.event.result}",
        evidence_refs=(first.event.event_id,),
        source=ViewSource.AUDIT,
    )


def _why_breaker_opened(data: ControlCenterInput, run) -> Explanation:
    events = [
        record
        for record in _incident_records(data)
        if record.event.event_type == AuditEventType.CIRCUIT_OPENED.value
    ]
    snapshot = getattr(run.lifecycle, "breaker", None)
    if not events and (snapshot is None or snapshot.state.value != "OPEN"):
        return _not_applicable(Question.WHY_BREAKER_OPENED, "the breaker did not open", "")
    if events:
        first = events[0]
        return Explanation(
            question=Question.WHY_BREAKER_OPENED,
            outcome=ExplanationOutcome.EXPLAINED,
            answer=f"{first.correlation.get('scope_key', '?')}: {first.event.result}",
            evidence_refs=(first.event.event_id,),
            source=ViewSource.AUDIT,
        )
    return Explanation(
        question=Question.WHY_BREAKER_OPENED,
        outcome=ExplanationOutcome.EXPLANATION_INCOMPLETE,
        answer=(
            f"the breaker is OPEN for {snapshot.scope_key} but no circuit.opened event was "
            f"recorded for this incident; it may have opened during an earlier one"
        ),
        source=ViewSource.LIFECYCLE_STATE,
        missing=("circuit.opened",),
    )


def _why_agent_restricted(data: ControlCenterInput, run) -> Explanation:
    events = [
        record
        for record in _incident_records(data)
        if record.event.event_type == AuditEventType.AGENT_RESTRICTION_APPLIED.value
    ]
    if not events:
        return _not_applicable(
            Question.WHY_AGENT_RESTRICTED, "no agent was restricted during this incident", ""
        )
    first = events[0]
    return Explanation(
        question=Question.WHY_AGENT_RESTRICTED,
        outcome=ExplanationOutcome.EXPLAINED,
        answer=(
            f"{first.event.agent_identity or first.event.actor} restricted for scope "
            f"{first.correlation.get('scope_key', '?')}: {first.event.result}"
        ),
        evidence_refs=(first.event.event_id,),
        source=ViewSource.AUDIT,
    )


def _why_escalated(data: ControlCenterInput, run) -> Explanation:
    if run.incident.state.value != "ESCALATED":
        return _not_applicable(
            Question.WHY_ESCALATED, f"the incident ended {run.incident.state}, not ESCALATED", ""
        )
    record = run.lifecycle
    reason = getattr(record, "escalation_reason", None) or getattr(record, "detail", None)
    if reason is None:
        return _incomplete(
            Question.WHY_ESCALATED,
            "the incident escalated with no recorded reason",
            "LifecycleRecord",
        )
    return Explanation(
        question=Question.WHY_ESCALATED,
        outcome=ExplanationOutcome.EXPLAINED,
        answer=str(reason),
        evidence_refs=(str(run.incident.incident_id),),
        source=ViewSource.LIFECYCLE_STATE,
    )


def _why_resolved(data: ControlCenterInput, run) -> Explanation:
    if run.incident.state.value != "RESOLVED":
        return _not_applicable(
            Question.WHY_RESOLVED, f"the incident ended {run.incident.state}, not RESOLVED", ""
        )
    verification = run.verification
    if verification is None:
        # Structurally impossible through the state machine, which is exactly why it is
        # worth saying out loud rather than rendering a resolution nothing supports.
        return _incomplete(
            Question.WHY_RESOLVED,
            "the incident is RESOLVED but no verification result was captured",
            "VerificationResult",
        )
    return Explanation(
        question=Question.WHY_RESOLVED,
        outcome=ExplanationOutcome.EXPLAINED,
        answer=(
            f"verification {verification.verification_id} established {verification.status} "
            f"for {verification.resource}: {verification.reason}"
        ),
        evidence_refs=(
            str(verification.verification_id),
            *(str(reference) for reference in verification.observations_used),
        ),
        source=ViewSource.RUN,
    )


def _incomplete(question: Question, answer: str, missing: str) -> Explanation:
    return Explanation(
        question=question,
        outcome=ExplanationOutcome.EXPLANATION_INCOMPLETE,
        answer=answer,
        missing=(missing,),
    )


def _not_applicable(question: Question, answer: str, evidence: str) -> Explanation:
    return Explanation(
        question=question,
        outcome=ExplanationOutcome.NOT_APPLICABLE,
        answer=answer,
        evidence_refs=(evidence,) if evidence else (),
        source=ViewSource.RUN,
    )


_HANDLERS = {
    Question.WHY_PROPOSED: _why_proposed,
    Question.WHY_DELEGATED: _why_delegated,
    Question.WHY_APPROVAL_REQUIRED: _why_approval_required,
    Question.WHY_DENIED: _why_denied,
    Question.WHY_EXECUTION_STOPPED: _why_execution_stopped,
    Question.WHY_RECOVERY_BEGAN: _why_recovery_began,
    Question.WHY_BREAKER_OPENED: _why_breaker_opened,
    Question.WHY_AGENT_RESTRICTED: _why_agent_restricted,
    Question.WHY_ESCALATED: _why_escalated,
    Question.WHY_RESOLVED: _why_resolved,
}
"""One handler per question. A mapping rather than a chain, so adding a question without
answering it is a ``KeyError`` somebody must resolve rather than a silent fall-through."""
