"""Approval engine: creation boundaries, lifecycle, expiry, replay and re-evaluation.

The engine's whole job is refusing. An approval that authorises anything beyond one exact
action, for a bounded time, under one policy context, exactly once, is a security defect.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from aegis.core.approval import (
    DEFAULT_APPROVAL_TTL,
    Approval,
    ApprovalConsumptionRefused,
    ApprovalCreationRefused,
    ApprovalEngine,
    ApprovalRefusal,
    ApprovalStatus,
    action_fingerprint,
)
from aegis.core.capabilities import CapabilityRegistry
from aegis.core.domain import (
    AgentLifecycleState,
    PolicyDecision,
    PolicyDecisionType,
    RiskLevel,
    to_json,
)
from aegis.core.policy import PolicyEngine
from tests.approval.conftest import MovableClock
from tests.fleet import (
    ALL_CAPABILITIES,
    CUSTOMER_DATABASE,
    DIAGNOSTIC,
    FIXED_EVALUATION_TIME,
    ORDER_SERVICE,
    PAYMENT_API,
    REMEDIATION,
    build_action,
    fixed_clock,
)


def _request(engine: ApprovalEngine, action, agent=REMEDIATION, **kwargs) -> Approval:
    decision = engine.policy_engine.evaluate(action, agent)
    return engine.request(
        approval_id=kwargs.pop("approval_id", "apr-001"),
        action=action,
        agent=agent,
        decision=decision,
        **kwargs,
    )


# --- fingerprints -------------------------------------------------------------------


def test_fingerprint_is_stable_and_hex(rollback_action) -> None:
    digest = action_fingerprint(rollback_action)
    assert len(digest) == 64
    assert all(character in "0123456789abcdef" for character in digest)
    assert digest == action_fingerprint(rollback_action.model_copy())


def test_fingerprint_changes_with_any_field(rollback_action) -> None:
    """Every field participates; none is a free variable an attacker could edit."""
    baseline = action_fingerprint(rollback_action)
    for update in (
        {"target_resource": ORDER_SERVICE},
        {"arguments": {"target_version": "v0.1"}},
        {"risk": RiskLevel.LOW},
        {"capability": "production.scale"},
        {"requesting_agent": "diagnostic"},
    ):
        assert action_fingerprint(rollback_action.model_copy(update=update)) != baseline


# --- creation boundaries ------------------------------------------------------------


def test_approval_is_raised_from_a_require_approval_decision(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    approval = _request(approval_engine, rollback_action)
    assert approval.status is ApprovalStatus.PENDING
    assert approval.action_fingerprint == action_fingerprint(rollback_action)
    assert approval.risk is RiskLevel.HIGH
    assert approval.blast_radius is not None
    assert approval.incident_id == rollback_action.incident_id
    assert approval.policy_decision.decision is PolicyDecisionType.REQUIRE_APPROVAL


def test_deny_can_never_become_an_approval_request(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    """The critical boundary: no amount of human sign-off converts a denial."""
    denial = PolicyDecision(
        decision=PolicyDecisionType.DENY,
        reason="not permitted",
        policy_reference="policy:aegis/v1#capability-not-held",
        evaluated_at=FIXED_EVALUATION_TIME,
    )
    with pytest.raises(ApprovalCreationRefused) as excinfo:
        approval_engine.request(
            approval_id="apr-001",
            action=rollback_action,
            agent=REMEDIATION,
            decision=denial,
        )
    assert excinfo.value.refusal is ApprovalRefusal.POLICY_DENIES


def test_allow_needs_no_approval_artifact(approval_engine: ApprovalEngine, assess) -> None:
    read = assess(capability="telemetry.read", requesting_agent="diagnostic")
    decision = approval_engine.policy_engine.evaluate(read, DIAGNOSTIC)
    assert decision.decision is PolicyDecisionType.ALLOW
    with pytest.raises(ApprovalCreationRefused) as excinfo:
        approval_engine.request(
            approval_id="apr-001", action=read, agent=DIAGNOSTIC, decision=decision
        )
    assert excinfo.value.refusal is ApprovalRefusal.POLICY_DOES_NOT_REQUIRE_APPROVAL


def test_a_forged_decision_does_not_open_the_door(approval_engine: ApprovalEngine, assess) -> None:
    """A handed-in REQUIRE_APPROVAL is a claim; policy is asked again."""
    forbidden = assess(capability="production.rollback", requesting_agent="diagnostic")
    forged = PolicyDecision(
        decision=PolicyDecisionType.REQUIRE_APPROVAL,
        reason="trust me",
        policy_reference="policy:aegis/v1#approval-required",
        evaluated_at=FIXED_EVALUATION_TIME,
    )
    with pytest.raises(ApprovalCreationRefused) as excinfo:
        approval_engine.request(
            approval_id="apr-001",
            action=forbidden,
            agent=DIAGNOSTIC,
            decision=forged,
        )
    assert excinfo.value.refusal is ApprovalRefusal.POLICY_DENIES


def test_agent_must_be_the_requesting_agent(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    decision = approval_engine.policy_engine.evaluate(rollback_action, REMEDIATION)
    with pytest.raises(ApprovalCreationRefused) as excinfo:
        approval_engine.request(
            approval_id="apr-001",
            action=rollback_action,
            agent=DIAGNOSTIC,
            decision=decision,
        )
    assert excinfo.value.refusal is ApprovalRefusal.AGENT_MISMATCH


def test_unassessed_risk_cannot_be_approved(approval_engine: ApprovalEngine) -> None:
    """A human cannot sign off on something nobody measured."""
    unassessed = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_API,
    )
    decision = PolicyDecision(
        decision=PolicyDecisionType.REQUIRE_APPROVAL,
        reason="needs sign-off",
        policy_reference="policy:aegis/v1#approval-required",
        evaluated_at=FIXED_EVALUATION_TIME,
    )
    with pytest.raises(ApprovalCreationRefused) as excinfo:
        approval_engine.request(
            approval_id="apr-001",
            action=unassessed,
            agent=REMEDIATION,
            decision=decision,
        )
    assert excinfo.value.refusal is ApprovalRefusal.RISK_UNASSESSED


def test_unassessed_blast_radius_cannot_be_approved(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    stripped = rollback_action.model_copy(update={"blast_radius": None})
    decision = PolicyDecision(
        decision=PolicyDecisionType.REQUIRE_APPROVAL,
        reason="needs sign-off",
        policy_reference="policy:aegis/v1#approval-required",
        evaluated_at=FIXED_EVALUATION_TIME,
    )
    with pytest.raises(ApprovalCreationRefused) as excinfo:
        approval_engine.request(
            approval_id="apr-001",
            action=stripped,
            agent=REMEDIATION,
            decision=decision,
        )
    assert excinfo.value.refusal is ApprovalRefusal.BLAST_RADIUS_UNASSESSED


def test_a_quarantined_agent_cannot_have_an_approval_raised(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    quarantined = REMEDIATION.model_copy(update={"status": AgentLifecycleState.QUARANTINED})
    decision = PolicyDecision(
        decision=PolicyDecisionType.REQUIRE_APPROVAL,
        reason="needs sign-off",
        policy_reference="policy:aegis/v1#approval-required",
        evaluated_at=FIXED_EVALUATION_TIME,
    )
    with pytest.raises(ApprovalCreationRefused) as excinfo:
        approval_engine.request(
            approval_id="apr-001",
            action=rollback_action,
            agent=quarantined,
            decision=decision,
        )
    assert excinfo.value.refusal is ApprovalRefusal.POLICY_DENIES


# --- human decisions ----------------------------------------------------------------


def test_approve_records_who_and_when(
    approval_engine: ApprovalEngine, rollback_action, clock: MovableClock
) -> None:
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    assert approved.status is ApprovalStatus.APPROVED
    assert approved.decided_by == "human:oncall"
    assert approved.decided_at == clock.now


def test_reject_is_terminal(approval_engine: ApprovalEngine, rollback_action) -> None:
    rejected = approval_engine.reject(_request(approval_engine, rollback_action), by="human:oncall")
    assert rejected.status is ApprovalStatus.REJECTED
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.approve(rejected, by="human:oncall")
    assert excinfo.value.refusal is ApprovalRefusal.ALREADY_DECIDED


def test_a_rejected_approval_can_never_authorise_execution(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    rejected = approval_engine.reject(_request(approval_engine, rollback_action), by="human:oncall")
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.consume_for_execution(rejected, rollback_action, REMEDIATION)
    assert excinfo.value.refusal is ApprovalRefusal.NOT_APPROVED


def test_a_pending_approval_cannot_authorise_execution(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    pending = _request(approval_engine, rollback_action)
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.consume_for_execution(pending, rollback_action, REMEDIATION)
    assert excinfo.value.refusal is ApprovalRefusal.NOT_APPROVED


def test_decisions_produce_new_records(approval_engine: ApprovalEngine, rollback_action) -> None:
    pending = _request(approval_engine, rollback_action)
    before = to_json(pending)
    approved = approval_engine.approve(pending, by="human:oncall")
    assert to_json(pending) == before
    assert approved is not pending


# --- expiry -------------------------------------------------------------------------


def test_default_ttl_is_applied(approval_engine: ApprovalEngine, rollback_action) -> None:
    approval = _request(approval_engine, rollback_action)
    assert approval.expires_at - approval.created_at == DEFAULT_APPROVAL_TTL


def test_an_expired_approval_cannot_be_consumed(
    approval_engine: ApprovalEngine, rollback_action, clock: MovableClock
) -> None:
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    clock.advance(DEFAULT_APPROVAL_TTL + timedelta(seconds=1))
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.consume_for_execution(approved, rollback_action, REMEDIATION)
    assert excinfo.value.refusal is ApprovalRefusal.EXPIRED


def test_an_expired_approval_cannot_be_approved(
    approval_engine: ApprovalEngine, rollback_action, clock: MovableClock
) -> None:
    pending = _request(approval_engine, rollback_action)
    clock.advance(DEFAULT_APPROVAL_TTL)
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.approve(pending, by="human:oncall")
    assert excinfo.value.refusal is ApprovalRefusal.EXPIRED


def test_expiry_is_computed_from_the_clock_not_the_stored_status(
    approval_engine: ApprovalEngine, rollback_action, clock: MovableClock
) -> None:
    """Nothing guarantees an expiry sweep ran, so consumption must not depend on one."""
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    clock.advance(DEFAULT_APPROVAL_TTL)
    assert approved.status is ApprovalStatus.APPROVED
    assert approved.is_expired(clock.now)
    with pytest.raises(ApprovalConsumptionRefused):
        approval_engine.consume_for_execution(approved, rollback_action, REMEDIATION)


def test_expiry_is_not_silently_renewed(
    approval_engine: ApprovalEngine, rollback_action, clock: MovableClock
) -> None:
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    clock.advance(DEFAULT_APPROVAL_TTL)
    expired = approval_engine.expire(approved)
    assert expired.status is ApprovalStatus.EXPIRED
    with pytest.raises(ApprovalConsumptionRefused):
        approval_engine.consume_for_execution(expired, rollback_action, REMEDIATION)


def test_a_custom_ttl_is_honoured(
    approval_engine: ApprovalEngine, rollback_action, clock: MovableClock
) -> None:
    approval = _request(approval_engine, rollback_action, ttl=timedelta(minutes=1))
    assert approval.expires_at - approval.created_at == timedelta(minutes=1)
    approved = approval_engine.approve(approval, by="human:oncall")
    clock.advance(timedelta(minutes=2))
    with pytest.raises(ApprovalConsumptionRefused):
        approval_engine.consume_for_execution(approved, rollback_action, REMEDIATION)


def test_a_non_positive_ttl_is_rejected(policy_engine: PolicyEngine) -> None:
    with pytest.raises(ValueError, match="ttl must be positive"):
        ApprovalEngine(policy_engine, ttl=timedelta(0))


def test_expires_at_must_follow_created_at() -> None:
    with pytest.raises(ValidationError, match="expires_at must be after created_at"):
        Approval(
            approval_id="apr-001",
            incident_id="INC-2026-0001",
            action_id="act-001",
            action_fingerprint="a" * 64,
            requesting_agent="remediation",
            policy_decision=PolicyDecision(
                decision=PolicyDecisionType.REQUIRE_APPROVAL,
                reason="r",
                policy_reference="p",
                evaluated_at=FIXED_EVALUATION_TIME,
            ),
            risk=RiskLevel.HIGH,
            blast_radius={"scope": (PAYMENT_API,), "impact": "HIGH"},
            reason="r",
            status=ApprovalStatus.PENDING,
            created_at=FIXED_EVALUATION_TIME,
            expires_at=FIXED_EVALUATION_TIME,
        )


# --- consumption and replay ---------------------------------------------------------


def test_consumption_yields_an_execution_authorization(
    approval_engine: ApprovalEngine, rollback_action, clock: MovableClock
) -> None:
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    authorization = approval_engine.consume_for_execution(approved, rollback_action, REMEDIATION)
    assert authorization.approval.status is ApprovalStatus.CONSUMED
    assert authorization.approval.consumed_at == clock.now
    assert authorization.action_id == rollback_action.action_id
    assert authorization.action_fingerprint == action_fingerprint(rollback_action)
    assert authorization.agent_id == REMEDIATION.agent_id
    assert authorization.policy_decision.decision is PolicyDecisionType.REQUIRE_APPROVAL
    assert authorization.authorized_at == clock.now


def test_an_approval_is_consumable_exactly_once(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    approval_engine.consume_for_execution(approved, rollback_action, REMEDIATION)
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.consume_for_execution(approved, rollback_action, REMEDIATION)
    assert excinfo.value.refusal is ApprovalRefusal.ALREADY_CONSUMED


def test_replay_with_a_stale_copy_is_refused(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    """Holding a pre-consumption copy must not resurrect the approval.

    This is why the engine keeps a consumption ledger: the immutable record alone cannot
    stop a caller who kept the old value.
    """
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    stale_copy = approved.model_copy()
    approval_engine.consume_for_execution(approved, rollback_action, REMEDIATION)

    assert stale_copy.status is ApprovalStatus.APPROVED
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.consume_for_execution(stale_copy, rollback_action, REMEDIATION)
    assert excinfo.value.refusal is ApprovalRefusal.ALREADY_CONSUMED


def test_a_consumed_approval_cannot_be_re_decided(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    stale_copy = approved.model_copy(update={"status": ApprovalStatus.PENDING})
    approval_engine.consume_for_execution(approved, rollback_action, REMEDIATION)
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.approve(stale_copy, by="human:oncall")
    assert excinfo.value.refusal is ApprovalRefusal.ALREADY_CONSUMED


def test_a_refused_consumption_does_not_spend_the_approval(
    approval_engine: ApprovalEngine, rollback_action, assess
) -> None:
    """A rejected attempt must not burn a valid approval."""
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    tampered = rollback_action.model_copy(update={"target_resource": ORDER_SERVICE})
    with pytest.raises(ApprovalConsumptionRefused):
        approval_engine.consume_for_execution(approved, tampered, REMEDIATION)

    assert not approval_engine.is_consumed(approved.approval_id)
    authorization = approval_engine.consume_for_execution(approved, rollback_action, REMEDIATION)
    assert authorization.approval.status is ApprovalStatus.CONSUMED


# --- action binding -----------------------------------------------------------------


def test_a_modified_action_cannot_be_executed(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    """Approve a safe action, swap it, execute — the classic escalation, refused."""
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    swapped = rollback_action.model_copy(
        update={"arguments": {"target_version": "v0.0.1-malicious"}}
    )
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.consume_for_execution(approved, swapped, REMEDIATION)
    assert excinfo.value.refusal is ApprovalRefusal.ACTION_FINGERPRINT_MISMATCH


def test_a_different_action_id_is_refused(
    approval_engine: ApprovalEngine, rollback_action, assess
) -> None:
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    other = assess(action_id="act-002")
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.consume_for_execution(approved, other, REMEDIATION)
    assert excinfo.value.refusal is ApprovalRefusal.ACTION_IDENTITY_MISMATCH


def test_a_different_incident_is_refused(approval_engine: ApprovalEngine, rollback_action) -> None:
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    other_incident = rollback_action.model_copy(update={"incident_id": "INC-2026-0002"})
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.consume_for_execution(approved, other_incident, REMEDIATION)
    assert excinfo.value.refusal is ApprovalRefusal.INCIDENT_MISMATCH


def test_a_downgraded_risk_is_refused(approval_engine: ApprovalEngine, rollback_action) -> None:
    """Risk is inside the fingerprint, so it cannot be edited after sign-off."""
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    downgraded = rollback_action.model_copy(update={"risk": RiskLevel.LOW})
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.consume_for_execution(approved, downgraded, REMEDIATION)
    assert excinfo.value.refusal is ApprovalRefusal.ACTION_FINGERPRINT_MISMATCH


# --- policy re-evaluation at consumption --------------------------------------------


def test_an_agent_quarantined_after_approval_cannot_execute(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    quarantined = REMEDIATION.model_copy(update={"status": AgentLifecycleState.QUARANTINED})
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.consume_for_execution(approved, rollback_action, quarantined)
    assert excinfo.value.refusal is ApprovalRefusal.POLICY_DENIES


def test_an_agent_restricted_after_approval_cannot_execute(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    restricted = REMEDIATION.model_copy(update={"status": AgentLifecycleState.RESTRICTED})
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.consume_for_execution(approved, rollback_action, restricted)
    assert excinfo.value.refusal is ApprovalRefusal.POLICY_DENIES


def test_an_unresolvable_agent_cannot_execute(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    approved = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        approval_engine.consume_for_execution(approved, rollback_action, None)
    assert excinfo.value.refusal is ApprovalRefusal.POLICY_DENIES


def test_a_narrowed_capability_scope_invalidates_an_approval(
    policy_engine: PolicyEngine, clock: MovableClock, pipeline, rollback_action
) -> None:
    """The approval was granted under a policy context that no longer exists."""
    engine = ApprovalEngine(policy_engine, clock=clock)
    approved = engine.approve(
        engine.request(
            approval_id="apr-001",
            action=rollback_action,
            agent=REMEDIATION,
            decision=policy_engine.evaluate(rollback_action, REMEDIATION),
        ),
        by="human:oncall",
    )

    # The capability is re-registered with payment-api removed from its scope.
    narrowed = CapabilityRegistry(
        [
            capability.model_copy(update={"resource_scope": (ORDER_SERVICE,)})
            if capability.capability_id == "production.rollback"
            else capability
            for capability in ALL_CAPABILITIES
        ]
    )
    engine_after = ApprovalEngine(PolicyEngine(narrowed, clock=fixed_clock), clock=clock)
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        engine_after.consume_for_execution(approved, rollback_action, REMEDIATION)
    assert excinfo.value.refusal is ApprovalRefusal.POLICY_DENIES


def test_a_revoked_capability_grant_invalidates_an_approval(
    policy_engine: PolicyEngine, clock: MovableClock, rollback_action
) -> None:
    approved = ApprovalEngine(policy_engine, clock=clock).approve(
        ApprovalEngine(policy_engine, clock=clock).request(
            approval_id="apr-001",
            action=rollback_action,
            agent=REMEDIATION,
            decision=policy_engine.evaluate(rollback_action, REMEDIATION),
        ),
        by="human:oncall",
    )
    ungranted = REMEDIATION.model_copy(update={"capabilities": ()})
    engine = ApprovalEngine(policy_engine, clock=clock)
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        engine.consume_for_execution(approved, rollback_action, ungranted)
    assert excinfo.value.refusal is ApprovalRefusal.POLICY_DENIES


def test_an_approval_that_no_longer_needs_approval_is_refused(
    policy_engine: PolicyEngine, clock: MovableClock, rollback_action
) -> None:
    """Policy relaxed to ALLOW: the artifact is for a context that no longer applies."""
    engine = ApprovalEngine(policy_engine, clock=clock)
    approved = engine.approve(
        engine.request(
            approval_id="apr-001",
            action=rollback_action,
            agent=REMEDIATION,
            decision=policy_engine.evaluate(rollback_action, REMEDIATION),
        ),
        by="human:oncall",
    )
    relaxed = CapabilityRegistry(
        [
            capability.model_copy(update={"approval_requirement": "NONE"})
            if capability.capability_id == "production.rollback"
            else capability
            for capability in ALL_CAPABILITIES
        ]
    )
    engine_after = ApprovalEngine(PolicyEngine(relaxed, clock=fixed_clock), clock=clock)
    with pytest.raises(ApprovalConsumptionRefused) as excinfo:
        engine_after.consume_for_execution(approved, rollback_action, REMEDIATION)
    assert excinfo.value.refusal is ApprovalRefusal.POLICY_NO_LONGER_REQUIRES_APPROVAL


def test_an_out_of_scope_target_is_refused_at_consumption(
    approval_engine: ApprovalEngine, pipeline
) -> None:
    """Even a perfectly formed approval cannot reach a resource policy forbids."""
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=CUSTOMER_DATABASE,
    )
    assessed = pipeline.assess(proposal).require_assessed_action()
    decision = approval_engine.policy_engine.evaluate(assessed, REMEDIATION)
    assert decision.decision is PolicyDecisionType.DENY
    with pytest.raises(ApprovalCreationRefused):
        approval_engine.request(
            approval_id="apr-001",
            action=assessed,
            agent=REMEDIATION,
            decision=decision,
        )


# --- record invariants and determinism ----------------------------------------------


def test_status_and_decision_fields_stay_coherent() -> None:
    base = dict(
        approval_id="apr-001",
        incident_id="INC-2026-0001",
        action_id="act-001",
        action_fingerprint="a" * 64,
        requesting_agent="remediation",
        policy_decision=PolicyDecision(
            decision=PolicyDecisionType.REQUIRE_APPROVAL,
            reason="r",
            policy_reference="p",
            evaluated_at=FIXED_EVALUATION_TIME,
        ),
        risk=RiskLevel.HIGH,
        blast_radius={"scope": (PAYMENT_API,), "impact": "HIGH"},
        reason="r",
        created_at=FIXED_EVALUATION_TIME,
        expires_at=FIXED_EVALUATION_TIME + timedelta(minutes=5),
    )
    with pytest.raises(ValidationError, match="requires decided_at"):
        Approval(**base, status=ApprovalStatus.APPROVED)
    with pytest.raises(ValidationError, match="must not carry a decision"):
        Approval(
            **base,
            status=ApprovalStatus.PENDING,
            decided_at=FIXED_EVALUATION_TIME,
            decided_by="human:oncall",
        )
    with pytest.raises(ValidationError, match="requires consumed_at"):
        Approval(
            **base,
            status=ApprovalStatus.CONSUMED,
            decided_at=FIXED_EVALUATION_TIME,
            decided_by="human:oncall",
        )


def test_a_malformed_fingerprint_is_rejected() -> None:
    with pytest.raises(ValidationError, match="64 lowercase hex"):
        Approval(
            approval_id="apr-001",
            incident_id="INC-2026-0001",
            action_id="act-001",
            action_fingerprint="not-a-digest",
            requesting_agent="remediation",
            policy_decision=PolicyDecision(
                decision=PolicyDecisionType.REQUIRE_APPROVAL,
                reason="r",
                policy_reference="p",
                evaluated_at=FIXED_EVALUATION_TIME,
            ),
            risk=RiskLevel.HIGH,
            blast_radius={"scope": (PAYMENT_API,), "impact": "HIGH"},
            reason="r",
            status=ApprovalStatus.PENDING,
            created_at=FIXED_EVALUATION_TIME,
            expires_at=FIXED_EVALUATION_TIME + timedelta(minutes=5),
        )


def test_approval_lifecycle_has_exactly_five_statuses() -> None:
    assert [status.name for status in ApprovalStatus] == [
        "PENDING",
        "APPROVED",
        "REJECTED",
        "EXPIRED",
        "CONSUMED",
    ]


def test_repeated_requests_are_byte_identical(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    first = _request(approval_engine, rollback_action)
    second = _request(approval_engine, rollback_action)
    assert to_json(first) == to_json(second)


def test_approval_round_trips_through_serialization(
    approval_engine: ApprovalEngine, rollback_action
) -> None:
    from aegis.core.domain import from_json

    approval = approval_engine.approve(
        _request(approval_engine, rollback_action), by="human:oncall"
    )
    assert from_json(Approval, to_json(approval)) == approval
