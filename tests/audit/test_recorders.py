"""Recorders translate real artifacts faithfully.

Every artifact here comes from the real engine that produces it. The recorders are
translators, so the test that matters most is that what the engine decided is what the log
says — a DENY stays a DENY, a rejection stays a rejection, a failed verification stays a
failure.
"""

from __future__ import annotations

from datetime import timedelta

from aegis.core.approval import ApprovalEngine, ApprovalStatus
from aegis.core.assessment import AssessmentPipeline
from aegis.core.audit import (
    APPROVAL_STATUS_EVENTS,
    AuditEventType,
    AuditRecorder,
    AuditStore,
)
from aegis.core.domain import (
    EvidenceType,
    IncidentState,
    PolicyDecisionType,
    RiskLevel,
    to_json,
)
from aegis.core.incidents import IncidentStateMachine
from aegis.core.policy import PolicyEngine, PolicyRule
from aegis.core.verification import VerificationEngine, VerificationStatus
from tests.audit.conftest import MovableClock
from tests.fleet import (
    DIAGNOSTIC,
    PAYMENT_API,
    PAYMENT_API_RECOVERED,
    REMEDIATION,
    UNKNOWN_RESOURCE,
    build_action,
    build_incident,
    build_observation,
    healthy_observations,
)

# --- state transitions --------------------------------------------------------------


def test_a_state_transition_is_recorded_from_the_artifact(
    recorder: AuditRecorder, machine: IncidentStateMachine, clock: MovableClock
) -> None:
    transition = machine.transition_detailed(
        build_incident(state=IncidentState.RECEIVED),
        IncidentState.CLASSIFIED,
        reason="payment error rate 37%",
        actor="agent:commander",
    ).transition

    record = recorder.record_state_transition(transition)
    event = record.event
    assert event.event_type == AuditEventType.INCIDENT_STATE_CHANGED.value
    assert event.incident_id == "INC-2026-0001"
    assert event.state_before is IncidentState.RECEIVED
    assert event.state_after is IncidentState.CLASSIFIED
    assert event.actor == "agent:commander"
    assert event.timestamp == transition.occurred_at
    assert event.result == "payment error rate 37%"
    assert record.correlation["guard"] == "NONE"


def test_the_transition_timestamp_is_the_artifacts_not_the_recorders(
    recorder: AuditRecorder, machine: IncidentStateMachine, clock: MovableClock
) -> None:
    """When a thing happened is a property of the thing."""
    transition = machine.transition_detailed(
        build_incident(state=IncidentState.RECEIVED),
        IncidentState.CLASSIFIED,
        reason="triaged",
        actor="agent:commander",
    ).transition
    clock.advance(timedelta(hours=3))
    record = recorder.record_state_transition(transition)
    assert record.event.timestamp == transition.occurred_at
    assert record.event.timestamp != clock.now


# --- assessment ---------------------------------------------------------------------


def test_an_assessment_is_recorded_with_its_computed_risk(
    recorder: AuditRecorder, pipeline: AssessmentPipeline
) -> None:
    assessment = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    )
    record = recorder.record_assessment(assessment)
    event = record.event

    assert event.event_type == AuditEventType.ACTION_ASSESSED.value
    assert event.input_reference == "act-001"
    assert event.tool == "production.rollback"
    assert record.correlation["risk"] == RiskLevel.HIGH.value
    assert record.correlation["outcome"] == "ASSESSED"
    assert "risk=HIGH" in event.result
    assert "deciding=" in event.result


def test_a_failed_assessment_is_recorded_as_a_failure(
    recorder: AuditRecorder, pipeline: AssessmentPipeline
) -> None:
    """Never as an absent or benign assessment."""
    assessment = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=UNKNOWN_RESOURCE,
        )
    )
    assert not assessment.ok
    record = recorder.record_assessment(assessment)
    assert record.correlation["outcome"] == "INSUFFICIENT_INFORMATION"
    assert "risk" not in record.correlation
    assert "INSUFFICIENT_INFORMATION" in record.event.result


# --- policy -------------------------------------------------------------------------


def test_a_deny_is_recorded_as_a_deny(
    recorder: AuditRecorder, pipeline: AssessmentPipeline, policy_engine: PolicyEngine
) -> None:
    """Diagnostic cannot roll back. The audit trail must say so, verbatim."""
    action = pipeline.assess(
        build_action(
            requesting_agent="diagnostic",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    ).require_assessed_action()
    evaluation = policy_engine.evaluate_detailed(action, DIAGNOSTIC)
    assert evaluation.decision.decision is PolicyDecisionType.DENY

    record = recorder.record_policy_decision(evaluation, action, DIAGNOSTIC)
    event = record.event

    assert event.event_type == AuditEventType.POLICY_DECISION.value
    assert event.decision is PolicyDecisionType.DENY
    assert event.policy_reference == PolicyRule.CAPABILITY_NOT_HELD.value
    assert event.result == evaluation.decision.reason
    assert event.timestamp == evaluation.decision.evaluated_at
    assert event.agent_identity == DIAGNOSTIC.identity_reference
    assert record.correlation["capability_held"] == "false"


def test_an_approval_requirement_is_recorded_as_itself(
    recorder: AuditRecorder, rollback_action, policy_engine: PolicyEngine
) -> None:
    evaluation = policy_engine.evaluate_detailed(rollback_action, REMEDIATION)
    record = recorder.record_policy_decision(evaluation, rollback_action, REMEDIATION)
    assert record.event.decision is PolicyDecisionType.REQUIRE_APPROVAL
    assert record.correlation["approval_required"] == "true"


def test_unreached_policy_checks_are_absent_rather_than_false(
    recorder: AuditRecorder, pipeline: AssessmentPipeline, policy_engine: PolicyEngine
) -> None:
    """ "Not checked" and "checked and failed" stay distinguishable in the log."""
    action = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    ).require_assessed_action()
    evaluation = policy_engine.evaluate_detailed(action, None)
    record = recorder.record_policy_decision(evaluation, action, None)
    assert record.correlation["agent_known"] == "false"
    assert "capability_held" not in record.correlation
    assert record.event.agent_identity is None


# --- approval -----------------------------------------------------------------------


def test_the_approval_status_map_is_total() -> None:
    assert set(APPROVAL_STATUS_EVENTS) == set(ApprovalStatus)


def test_each_approval_status_records_its_own_event(
    recorder: AuditRecorder,
    approval_engine: ApprovalEngine,
    policy_engine: PolicyEngine,
    rollback_action,
) -> None:
    decision = policy_engine.evaluate(rollback_action, REMEDIATION)
    pending = approval_engine.request(
        approval_id="apr-001",
        action=rollback_action,
        agent=REMEDIATION,
        decision=decision,
    )
    approved = approval_engine.approve(pending, by="human:oncall")
    authorization = approval_engine.consume_for_execution(approved, rollback_action, REMEDIATION)

    requested = recorder.record_approval(pending)
    granted = recorder.record_approval(approved)
    consumed = recorder.record_approval(authorization.approval)

    assert requested.event.event_type == AuditEventType.APPROVAL_REQUESTED.value
    assert granted.event.event_type == AuditEventType.APPROVAL_GRANTED.value
    assert consumed.event.event_type == AuditEventType.APPROVAL_CONSUMED.value

    for record in (requested, granted, consumed):
        assert record.correlation["approval_id"] == "apr-001"
        assert record.correlation["action_id"] == "act-001"
        assert record.event.incident_id == "INC-2026-0001"
        assert record.correlation["action_fingerprint"] == pending.action_fingerprint

    assert granted.event.actor == "human:oncall"
    assert granted.event.timestamp == approved.decided_at
    assert consumed.event.timestamp == authorization.approval.consumed_at


def test_a_rejection_is_recorded_as_a_rejection(
    recorder: AuditRecorder,
    approval_engine: ApprovalEngine,
    policy_engine: PolicyEngine,
    rollback_action,
) -> None:
    """Never as a grant."""
    rejected = approval_engine.reject(
        approval_engine.request(
            approval_id="apr-001",
            action=rollback_action,
            agent=REMEDIATION,
            decision=policy_engine.evaluate(rollback_action, REMEDIATION),
        ),
        by="human:oncall",
    )
    record = recorder.record_approval(rejected)
    assert record.event.event_type == AuditEventType.APPROVAL_REJECTED.value
    assert record.correlation["status"] == "REJECTED"
    assert "REJECTED" in record.event.result


def test_an_expiry_is_recorded_as_an_expiry(
    recorder: AuditRecorder,
    approval_engine: ApprovalEngine,
    policy_engine: PolicyEngine,
    rollback_action,
    clock: MovableClock,
) -> None:
    approved = approval_engine.approve(
        approval_engine.request(
            approval_id="apr-001",
            action=rollback_action,
            agent=REMEDIATION,
            decision=policy_engine.evaluate(rollback_action, REMEDIATION),
        ),
        by="human:oncall",
    )
    clock.advance(timedelta(hours=1))
    record = recorder.record_approval(approval_engine.expire(approved))
    assert record.event.event_type == AuditEventType.APPROVAL_EXPIRED.value
    assert record.event.timestamp == approved.expires_at


def test_a_grant_is_never_inferred_from_an_approval_existing(
    recorder: AuditRecorder,
    approval_engine: ApprovalEngine,
    policy_engine: PolicyEngine,
    rollback_action,
) -> None:
    pending = approval_engine.request(
        approval_id="apr-001",
        action=rollback_action,
        agent=REMEDIATION,
        decision=policy_engine.evaluate(rollback_action, REMEDIATION),
    )
    record = recorder.record_approval(pending)
    assert record.event.event_type == AuditEventType.APPROVAL_REQUESTED.value
    assert record.event.event_type != AuditEventType.APPROVAL_GRANTED.value


# --- verification -------------------------------------------------------------------


def test_a_verification_is_recorded_with_its_bindings(
    recorder: AuditRecorder, verification_engine: VerificationEngine, rollback_action
) -> None:
    result = verification_engine.verify(
        rollback_action,
        PAYMENT_API_RECOVERED,
        healthy_observations(),
        verification_id="ver-001",
    )
    assert result.status is VerificationStatus.VERIFIED

    record = recorder.record_verification(result)
    event = record.event

    assert event.event_type == AuditEventType.VERIFICATION_COMPLETED.value
    assert event.input_reference == "ver-001"
    assert event.incident_id == "INC-2026-0001"
    assert event.timestamp == result.evaluated_at
    assert record.correlation["verification_id"] == "ver-001"
    assert record.correlation["action_id"] == "act-001"
    assert record.correlation["resource"] == PAYMENT_API
    assert record.correlation["status"] == "VERIFIED"
    assert event.evidence == result.observations_used
    assert "health=PASS" in event.result


def test_a_failed_verification_is_recorded_as_a_failure(
    recorder: AuditRecorder, verification_engine: VerificationEngine, rollback_action
) -> None:
    """Never as a success, and never omitted."""
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

    record = recorder.record_verification(result)
    assert record.event.event_type == AuditEventType.VERIFICATION_COMPLETED.value
    assert record.correlation["status"] == "FAILED"
    assert "error_rate=FAIL" in record.event.result


def test_a_tool_result_verification_is_recorded_as_insufficient(
    recorder: AuditRecorder, verification_engine: VerificationEngine, rollback_action
) -> None:
    """The audit trail does not launder a tool's optimism into a verification."""
    result = verification_engine.verify(
        rollback_action,
        PAYMENT_API_RECOVERED,
        (
            build_observation(
                observation_id="obs-tool",
                values={"health": "healthy", "error_rate": 0.0, "deployment": "v4.7"},
                evidence_type=EvidenceType.TOOL_RESULT,
            ),
        ),
        verification_id="ver-001",
    )
    record = recorder.record_verification(result)
    assert record.correlation["status"] == "INSUFFICIENT_EVIDENCE"
    assert record.event.evidence == ()


# --- recorder mechanics -------------------------------------------------------------


def test_event_ids_are_sequential_and_unique(
    recorder: AuditRecorder, store: AuditStore, machine: IncidentStateMachine
) -> None:
    for to_state in (IncidentState.CLASSIFIED, IncidentState.DEGRADED):
        recorder.record_state_transition(
            machine.transition_detailed(
                build_incident(state=IncidentState.RECEIVED),
                to_state,
                reason="test",
                actor="system:test",
            ).transition
        )
    assert [event.event_id for event in store.events()] == ["evt-000000", "evt-000001"]


def test_recording_keeps_the_chain_intact(
    recorder: AuditRecorder,
    store: AuditStore,
    pipeline: AssessmentPipeline,
    policy_engine: PolicyEngine,
    rollback_action,
) -> None:
    recorder.record_assessment(pipeline.assess(rollback_action))
    recorder.record_policy_decision(
        policy_engine.evaluate_detailed(rollback_action, REMEDIATION),
        rollback_action,
        REMEDIATION,
    )
    assert store.verify_integrity().valid
    assert len(store) == 2


def test_recording_is_reproducible(
    pipeline: AssessmentPipeline, policy_engine: PolicyEngine, rollback_action, clock
) -> None:
    def run() -> list[str]:
        store = AuditStore()
        recorder = AuditRecorder(store, clock=clock)
        recorder.record_assessment(pipeline.assess(rollback_action))
        recorder.record_policy_decision(
            policy_engine.evaluate_detailed(rollback_action, REMEDIATION),
            rollback_action,
            REMEDIATION,
        )
        return [to_json(record) for record in store.records()]

    assert run() == run()


def test_every_vocabulary_member_has_an_emitter() -> None:
    """No orphan event types: each one is reachable from some recorder."""
    emitted = set(APPROVAL_STATUS_EVENTS.values()) | {
        AuditEventType.INCIDENT_STATE_CHANGED,
        AuditEventType.ACTION_ASSESSED,
        AuditEventType.POLICY_DECISION,
        AuditEventType.VERIFICATION_COMPLETED,
        AuditEventType.MEMORY_ADMITTED,
        AuditEventType.MEMORY_REVOKED,
        AuditEventType.LIFECYCLE_STOPPED,
        AuditEventType.CIRCUIT_OPENED,
        AuditEventType.CIRCUIT_PROBE,
        AuditEventType.CIRCUIT_CLOSED,
        AuditEventType.LIFECYCLE_GATE_ISSUED,
        AuditEventType.LIFECYCLE_GATE_CONSUMED,
        AuditEventType.LIFECYCLE_GATE_REJECTED,
        AuditEventType.AGENT_RESTRICTION_APPLIED,
        AuditEventType.AGENT_RESTRICTION_REFUSED,
        AuditEventType.MODEL_DECISION,
        AuditEventType.A2A_MESSAGE,
        AuditEventType.REMOTE_AUTHENTICATION,
        AuditEventType.REMOTE_KEY_REVOKED,
    }
    assert emitted == set(AuditEventType)
