"""The complete incident trail, and reconstructing history from it.

One deterministic run of the whole control plane — assessment, policy, approval,
execution, verification, resolution — with every material artifact recorded. Then the
audit log is asked what happened, and its answer must match what actually did.
"""

from __future__ import annotations

import pytest

from aegis.core.approval import ApprovalEngine
from aegis.core.assessment import AssessmentPipeline
from aegis.core.audit import (
    AuditEventType,
    AuditRecorder,
    AuditStore,
    reconstruct_incident_history,
)
from aegis.core.domain import IncidentState, PolicyDecisionType, to_json
from aegis.core.incidents import IncidentStateMachine
from aegis.core.policy import PolicyEngine, PolicyRule
from aegis.core.verification import VerificationEngine, VerificationStatus
from tests.audit.conftest import make_event
from tests.fleet import (
    DIAGNOSTIC,
    PAYMENT_API,
    PAYMENT_API_RECOVERED,
    REMEDIATION,
    build_action,
    build_incident,
    build_observation,
    healthy_observations,
)

NORMAL_PATH = (
    IncidentState.RECEIVED,
    IncidentState.CLASSIFIED,
    IncidentState.INVESTIGATING,
    IncidentState.IMPACT_ASSESSED,
    IncidentState.PLAN_PROPOSED,
    IncidentState.POLICY_CHECK,
    IncidentState.AWAITING_APPROVAL,
    IncidentState.EXECUTING,
    IncidentState.VERIFYING,
    IncidentState.RESOLVED,
)


def _run_golden_incident(
    *,
    store: AuditStore,
    recorder: AuditRecorder,
    machine: IncidentStateMachine,
    pipeline: AssessmentPipeline,
    policy_engine: PolicyEngine,
    approval_engine: ApprovalEngine,
    verification_engine: VerificationEngine,
):
    """Drive the real control plane end to end, recording every material artifact."""
    incident = build_incident(state=IncidentState.RECEIVED)

    def advance(to_state: IncidentState, reason: str, actor: str, **guards):
        nonlocal incident
        result = machine.transition_detailed(
            incident, to_state, reason=reason, actor=actor, **guards
        )
        incident = result.incident
        recorder.record_state_transition(result.transition)
        return result

    advance(IncidentState.CLASSIFIED, "payment error rate 37%", "agent:commander")
    advance(IncidentState.INVESTIGATING, "diagnostic dispatched", "agent:commander")
    advance(IncidentState.IMPACT_ASSESSED, "customer impact assessed", "agent:impact")
    advance(IncidentState.PLAN_PROPOSED, "rollback to v4.7 proposed", "agent:remediation")

    assessment = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    )
    recorder.record_assessment(assessment)
    action = assessment.require_assessed_action()

    advance(IncidentState.POLICY_CHECK, "submitting plan", "agent:remediation")

    evaluation = policy_engine.evaluate_detailed(action, REMEDIATION)
    recorder.record_policy_decision(evaluation, action, REMEDIATION)
    decision = evaluation.decision

    advance(
        IncidentState.AWAITING_APPROVAL,
        decision.reason,
        "system:policy-engine",
        policy_decision=decision,
    )

    pending = approval_engine.request(
        approval_id="apr-001", action=action, agent=REMEDIATION, decision=decision
    )
    recorder.record_approval(pending)
    approved = approval_engine.approve(pending, by="human:oncall")
    recorder.record_approval(approved)
    authorization = approval_engine.consume_for_execution(approved, action, REMEDIATION)
    recorder.record_approval(authorization.approval)

    advance(
        IncidentState.EXECUTING,
        "approval consumed",
        "agent:remediation",
        authorization=authorization,
    )
    advance(IncidentState.VERIFYING, "rollback issued", "agent:remediation")

    verification = verification_engine.verify(
        action, PAYMENT_API_RECOVERED, healthy_observations(), verification_id="ver-001"
    )
    recorder.record_verification(verification)

    advance(
        IncidentState.RESOLVED,
        verification.reason,
        "system:verification",
        verification=verification,
        action=action,
    )
    return incident, action, verification


# --- the full trail -----------------------------------------------------------------


def test_the_full_incident_trail_is_recorded(
    store, recorder, machine, pipeline, policy_engine, approval_engine, verification_engine
) -> None:
    incident, _, _ = _run_golden_incident(
        store=store,
        recorder=recorder,
        machine=machine,
        pipeline=pipeline,
        policy_engine=policy_engine,
        approval_engine=approval_engine,
        verification_engine=verification_engine,
    )
    assert incident.state is IncidentState.RESOLVED

    events = store.events_for_incident("INC-2026-0001")
    assert len(events) == len(store.events())
    assert [event.event_type for event in events] == [
        AuditEventType.INCIDENT_STATE_CHANGED.value,  # -> CLASSIFIED
        AuditEventType.INCIDENT_STATE_CHANGED.value,  # -> INVESTIGATING
        AuditEventType.INCIDENT_STATE_CHANGED.value,  # -> IMPACT_ASSESSED
        AuditEventType.INCIDENT_STATE_CHANGED.value,  # -> PLAN_PROPOSED
        AuditEventType.ACTION_ASSESSED.value,
        AuditEventType.INCIDENT_STATE_CHANGED.value,  # -> POLICY_CHECK
        AuditEventType.POLICY_DECISION.value,
        AuditEventType.INCIDENT_STATE_CHANGED.value,  # -> AWAITING_APPROVAL
        AuditEventType.APPROVAL_REQUESTED.value,
        AuditEventType.APPROVAL_GRANTED.value,
        AuditEventType.APPROVAL_CONSUMED.value,
        AuditEventType.INCIDENT_STATE_CHANGED.value,  # -> EXECUTING
        AuditEventType.INCIDENT_STATE_CHANGED.value,  # -> VERIFYING
        AuditEventType.VERIFICATION_COMPLETED.value,
        AuditEventType.INCIDENT_STATE_CHANGED.value,  # -> RESOLVED
    ]
    assert store.verify_integrity().valid


def test_the_reconstructed_state_sequence_matches_what_happened(
    store, recorder, machine, pipeline, policy_engine, approval_engine, verification_engine
) -> None:
    _run_golden_incident(
        store=store,
        recorder=recorder,
        machine=machine,
        pipeline=pipeline,
        policy_engine=policy_engine,
        approval_engine=approval_engine,
        verification_engine=verification_engine,
    )
    history = reconstruct_incident_history(store.records(), "INC-2026-0001")

    assert history.states == NORMAL_PATH
    assert history.final_state is IncidentState.RESOLVED
    assert history.consistent
    assert history.problems == ()
    assert history.event_count == 15


def test_the_trail_correlates_by_the_existing_identifiers(
    store, recorder, machine, pipeline, policy_engine, approval_engine, verification_engine
) -> None:
    """One action id, one approval id, one verification id — no parallel scheme."""
    _, action, verification = _run_golden_incident(
        store=store,
        recorder=recorder,
        machine=machine,
        pipeline=pipeline,
        policy_engine=policy_engine,
        approval_engine=approval_engine,
        verification_engine=verification_engine,
    )
    records = store.records_for_incident("INC-2026-0001")
    by_action = [r for r in records if r.correlation.get("action_id") == action.action_id]
    # assessment, policy, three approval events, verification
    assert len(by_action) == 6

    approval_records = [r for r in records if "approval_id" in r.correlation]
    assert {r.correlation["approval_id"] for r in approval_records} == {"apr-001"}

    verification_records = [r for r in records if "verification_id" in r.correlation]
    assert {r.correlation["verification_id"] for r in verification_records} == {"ver-001"}
    assert verification.action_fingerprint in {
        r.correlation.get("action_fingerprint") for r in records
    }


def test_the_whole_trail_is_reproducible(
    pipeline, policy_engine, verification_engine, clock, registry
) -> None:
    from aegis.core.approval import ApprovalEngine as Engine

    def run() -> list[str]:
        store = AuditStore()
        _run_golden_incident(
            store=store,
            recorder=AuditRecorder(store, clock=clock),
            machine=IncidentStateMachine(clock=clock),
            pipeline=pipeline,
            policy_engine=policy_engine,
            approval_engine=Engine(policy_engine, clock=clock),
            verification_engine=verification_engine,
        )
        return [to_json(record) for record in store.records()]

    assert run() == run()


# --- refusals stay visible ----------------------------------------------------------


def test_a_denied_plan_leaves_a_deny_in_the_trail(store, recorder, pipeline, policy_engine) -> None:
    """Part 20: the DENY must be the real one, not a fabricated event."""
    action = pipeline.assess(
        build_action(
            requesting_agent="diagnostic",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    ).require_assessed_action()
    evaluation = policy_engine.evaluate_detailed(action, DIAGNOSTIC)
    assert evaluation.decision.decision is PolicyDecisionType.DENY
    recorder.record_policy_decision(evaluation, action, DIAGNOSTIC)

    (event,) = store.events_for_incident("INC-2026-0001")
    assert event.decision is PolicyDecisionType.DENY
    assert event.policy_reference == PolicyRule.CAPABILITY_NOT_HELD.value
    assert store.verify_integrity().valid


def test_a_refused_approval_is_observable_through_its_policy_decision(
    store, recorder, pipeline, policy_engine, approval_engine
) -> None:
    """A refused creation produces no Approval, so the DENY carries the record.

    Documented strategy: the governance decision stays observable without fabricating an
    approval artifact that never existed.
    """
    from aegis.core.approval import ApprovalCreationRefused

    action = pipeline.assess(
        build_action(
            requesting_agent="diagnostic",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    ).require_assessed_action()
    evaluation = policy_engine.evaluate_detailed(action, DIAGNOSTIC)
    recorder.record_policy_decision(evaluation, action, DIAGNOSTIC)

    with pytest.raises(ApprovalCreationRefused):
        approval_engine.request(
            approval_id="apr-001",
            action=action,
            agent=DIAGNOSTIC,
            decision=evaluation.decision,
        )

    assert len(store) == 1
    assert store.events()[0].decision is PolicyDecisionType.DENY
    assert not any(event.event_type.startswith("approval.") for event in store.events())


def test_a_failed_verification_leaves_a_failure_and_no_resolution(
    store, recorder, machine, verification_engine, rollback_action
) -> None:
    result = verification_engine.verify(
        rollback_action,
        PAYMENT_API_RECOVERED,
        (
            build_observation(
                observation_id="obs-health",
                values={"health": "healthy", "error_rate": 8.0},
            ),
            healthy_observations()[1],
        ),
        verification_id="ver-001",
    )
    assert result.status is VerificationStatus.FAILED
    recorder.record_verification(result)

    degraded = machine.transition_detailed(
        build_incident(state=IncidentState.VERIFYING),
        IncidentState.DEGRADED,
        reason=result.reason,
        actor="system:verification",
    )
    recorder.record_state_transition(degraded.transition)

    history = reconstruct_incident_history(store.records(), "INC-2026-0001")
    assert history.final_state is IncidentState.DEGRADED
    assert IncidentState.RESOLVED not in history.states
    assert history.consistent


# --- reconstruction refuses to invent history ---------------------------------------


def test_reconstruction_uses_only_state_change_events(store) -> None:
    """A policy decision is not a state change, however suggestive."""
    store.append(make_event(event_id="evt-000000", event_type="policy.decision"))
    store.append(make_event(event_id="evt-000001", event_type="action.assessed"))
    history = reconstruct_incident_history(store.records(), "INC-2026-0001")
    assert history.states == ()
    assert history.transitions == ()
    assert history.event_count == 2


def test_reconstruction_ignores_state_fields_on_other_event_types(store) -> None:
    """Only ``incident.state_changed`` asserts a state change.

    An event of another type carrying state fields is not a transition, and treating it as
    one would let the audit layer invent history.
    """
    store.append(
        make_event(event_id="evt-000000", event_type="policy.decision").model_copy(
            update={
                "state_before": IncidentState.RECEIVED,
                "state_after": IncidentState.RESOLVED,
            }
        )
    )
    history = reconstruct_incident_history(store.records(), "INC-2026-0001")
    assert history.states == ()
    assert history.transitions == ()
    assert history.consistent


def test_reconstruction_flags_an_illegal_transition(store) -> None:
    """RECEIVED -> EXECUTING never happened; a trail claiming it did is inconsistent."""
    store.append(
        make_event(event_id="evt-000000", event_type="incident.state_changed").model_copy(
            update={
                "state_before": IncidentState.RECEIVED,
                "state_after": IncidentState.EXECUTING,
            }
        )
    )
    history = reconstruct_incident_history(store.records(), "INC-2026-0001")
    assert not history.consistent
    assert "not a legal transition" in history.problems[0]


def test_reconstruction_flags_a_gap(store) -> None:
    for index, (before, after) in enumerate(
        [
            (IncidentState.RECEIVED, IncidentState.CLASSIFIED),
            (IncidentState.INVESTIGATING, IncidentState.IMPACT_ASSESSED),
        ]
    ):
        store.append(
            make_event(event_id=f"evt-{index:06d}", event_type="incident.state_changed").model_copy(
                update={"state_before": before, "state_after": after}
            )
        )
    history = reconstruct_incident_history(store.records(), "INC-2026-0001")
    assert not history.consistent
    assert any("has a gap" in problem for problem in history.problems)


def test_reconstruction_flags_a_resolution_with_no_verification(store) -> None:
    """VERIFYING -> RESOLVED with nothing backing it is an assembled trail, not a recorded one."""
    store.append(
        make_event(event_id="evt-000000", event_type="incident.state_changed").model_copy(
            update={
                "state_before": IncidentState.VERIFYING,
                "state_after": IncidentState.RESOLVED,
            }
        )
    )
    history = reconstruct_incident_history(store.records(), "INC-2026-0001")
    assert not history.consistent
    assert any("without naming a verification" in p for p in history.problems)


def test_reconstruction_flags_a_resolution_whose_verification_is_absent(store) -> None:
    store.append(
        make_event(event_id="evt-000000", event_type="incident.state_changed").model_copy(
            update={
                "state_before": IncidentState.VERIFYING,
                "state_after": IncidentState.RESOLVED,
            }
        ),
        correlation={"verification_id": "ver-ghost"},
    )
    history = reconstruct_incident_history(store.records(), "INC-2026-0001")
    assert not history.consistent
    assert any("no VERIFIED record" in p for p in history.problems)


def test_reconstruction_flags_a_resolution_backed_by_a_failed_verification(
    store,
) -> None:
    store.append(
        make_event(event_id="evt-000000", event_type="verification.completed"),
        correlation={"verification_id": "ver-001", "status": "FAILED"},
    )
    store.append(
        make_event(event_id="evt-000001", event_type="incident.state_changed").model_copy(
            update={
                "state_before": IncidentState.VERIFYING,
                "state_after": IncidentState.RESOLVED,
            }
        ),
        correlation={"verification_id": "ver-001"},
    )
    history = reconstruct_incident_history(store.records(), "INC-2026-0001")
    assert not history.consistent


def test_reconstruction_ignores_other_incidents(store) -> None:
    store.append(
        make_event(
            event_id="evt-000000",
            event_type="incident.state_changed",
            incident_id="INC-2",
        ).model_copy(
            update={
                "state_before": IncidentState.RECEIVED,
                "state_after": IncidentState.CLASSIFIED,
            }
        )
    )
    history = reconstruct_incident_history(store.records(), "INC-1")
    assert history.states == ()
    assert history.event_count == 0
    assert history.consistent


def test_reconstruction_is_reproducible(store) -> None:
    store.append(
        make_event(event_id="evt-000000", event_type="incident.state_changed").model_copy(
            update={
                "state_before": IncidentState.RECEIVED,
                "state_after": IncidentState.CLASSIFIED,
            }
        )
    )
    first = reconstruct_incident_history(store.records(), "INC-2026-0001")
    second = reconstruct_incident_history(store.records(), "INC-2026-0001")
    assert to_json(first) == to_json(second)
