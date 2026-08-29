"""The lifecycle gate: bound, single-use, unforgeable-in-practice, and never authority.

Every test here is a way of trying to execute without having crossed the lifecycle. The one
positive case exists as a control: if the legitimate path did not work, the refusals below
would prove nothing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from aegis.core.approval import action_fingerprint
from aegis.core.domain import IncidentState, RiskLevel
from aegis.lifecycle import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    FailureClass,
    GateRegister,
    LifecycleAction,
    LifecycleCoordinator,
    LifecycleDecision,
    LifecycleGate,
    LifecycleGateRejected,
    LifecycleLimits,
    LifecycleManager,
    gate_seal,
)
from tests.fleet import PAYMENT_API, REMEDIATION, build_action

START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def coordinator(clock) -> LifecycleCoordinator:
    manager = LifecycleManager(
        limits=LifecycleLimits(),
        breaker=CircuitBreaker(CircuitBreakerConfig(), clock=clock),
        clock=clock,
    )
    manager.begin("INC-2026-0001")
    return LifecycleCoordinator(manager, clock=clock)


def action(
    action_id: str = "act-001",
    incident_id: str = "INC-2026-0001",
    capability: str = "production.rollback",
    resource: str = PAYMENT_API,
):
    return build_action(
        requesting_agent="remediation",
        capability=capability,
        target_resource=resource,
        risk=RiskLevel.HIGH,
        action_id=action_id,
        incident_id=incident_id,
    )


def issue(coordinator, subject=None):
    subject = subject if subject is not None else action()
    result = coordinator.request_gate(
        subject,
        accountable_agent=REMEDIATION,
        incident_state=IncidentState.EXECUTING,
        lifecycle_decision=LifecycleDecision(
            action=LifecycleAction.CONTINUE,
            detail="within budget",
            counters=coordinator.manager.counters,
        ),
    )
    assert result.issued, result.refused_reason
    return result.gate


class TestTheLegitimatePathWorks:
    """The control. Without this the refusals below would prove nothing."""

    def test_a_gate_is_issued_and_consumed(self, coordinator) -> None:
        subject = action()
        gate = issue(coordinator, subject)
        assert coordinator.verifier.validate(gate, subject) is None
        coordinator.verifier.consume(gate, subject)
        assert coordinator.verifier.was_consumed(gate.gate_id)

    def test_the_gate_binds_to_the_action_it_was_issued_for(self, coordinator) -> None:
        subject = action()
        gate = issue(coordinator, subject)
        assert gate.action_id == subject.action_id
        assert gate.incident_id == subject.incident_id
        assert gate.action_fingerprint == action_fingerprint(subject)
        assert gate.capability_id == subject.capability
        assert gate.resource == subject.target_resource


class TestGateBindings:
    def test_a_gate_for_another_action_is_refused(self, coordinator) -> None:
        gate = issue(coordinator, action(action_id="act-001"))
        rejection = coordinator.verifier.validate(gate, action(action_id="act-999"))
        assert rejection is not None
        assert rejection.check == "action_binding"

    def test_a_gate_for_another_incident_is_refused(self, coordinator) -> None:
        gate = issue(coordinator, action())
        other = action(incident_id="INC-2026-0002")
        rejection = coordinator.verifier.validate(gate, other)
        assert rejection is not None
        assert rejection.check in {"incident_binding", "fingerprint_binding"}

    def test_a_gate_for_another_fingerprint_is_refused(self, coordinator) -> None:
        # Same ids, different action. Ids can be reused; fingerprints cannot.
        subject = action()
        gate = issue(coordinator, subject)
        altered = subject.model_copy(update={"arguments": {"target_version": "v9.9"}})
        rejection = coordinator.verifier.validate(gate, altered)
        assert rejection is not None
        assert rejection.check == "fingerprint_binding"

    def test_a_gate_for_another_capability_is_refused(self, coordinator) -> None:
        gate = issue(coordinator, action())
        rejection = coordinator.verifier.validate(gate, action(capability="production.scale"))
        assert rejection is not None

    def test_a_gate_for_another_resource_is_refused(self, coordinator) -> None:
        gate = issue(coordinator, action())
        rejection = coordinator.verifier.validate(gate, action(resource="service:order-service"))
        assert rejection is not None

    def test_a_gate_for_another_lifecycle_scope_cannot_be_transferred(self, coordinator) -> None:
        # The scope is derived from capability and resource, so a gate issued for one
        # scope carries the wrong scope for another and fails its bindings first.
        gate = issue(coordinator, action())
        other = action(resource="service:order-service")
        assert gate.lifecycle_scope != coordinator.manager.scope_for(other)
        assert coordinator.verifier.validate(gate, other) is not None


class TestGatesCannotBeForged:
    def test_a_hand_built_gate_is_refused_even_with_a_perfect_seal(self, coordinator) -> None:
        # The seal formula is public; anyone in this process can compute it. Authenticity
        # comes from the issuer's register, which an attacker cannot write to.
        subject = action()
        draft = LifecycleGate(
            gate_id="gate-forged-001",
            incident_id=subject.incident_id,
            action_id=subject.action_id,
            action_fingerprint=action_fingerprint(subject),
            capability_id=subject.capability,
            resource=subject.target_resource,
            lifecycle_scope=coordinator.manager.scope_for(subject),
            lifecycle_decision="CONTINUE",
            lifecycle_state="EXECUTING",
            breaker_state=CircuitState.CLOSED,
            lifecycle_generation=0,
            steps_used=0,
            remediation_attempts=0,
            execution_count=0,
            issued_at=START,
            seal="0" * 64,
        )
        forged = draft.model_copy(update={"seal": gate_seal(draft)})
        assert forged.rebind_check(), "the seal is genuinely correct"

        rejection = coordinator.verifier.validate(forged, subject)
        assert rejection is not None
        assert rejection.check == "issuer"

    def test_a_modified_gate_fails_its_seal(self, coordinator) -> None:
        subject = action()
        gate = issue(coordinator, subject)
        tampered = gate.model_copy(update={"lifecycle_scope": "anything@anywhere"})
        assert not tampered.rebind_check()
        rejection = coordinator.verifier.validate(tampered, subject)
        assert rejection.check == "seal"

    def test_a_resealed_modification_still_fails_the_issuer_check(self, coordinator) -> None:
        # The interesting attacker reseals. The register still never issued this.
        subject = action()
        gate = issue(coordinator, subject)
        changed = gate.model_copy(update={"execution_count": 99})
        resealed = changed.model_copy(update={"seal": gate_seal(changed)})
        assert resealed.rebind_check()
        rejection = coordinator.verifier.validate(resealed, subject)
        assert rejection.check == "issuer"

    def test_a_gate_from_another_register_is_refused(self, clock) -> None:
        # Two coordinators, two registers. A gate is valid only where it was issued.
        subject = action()
        first = LifecycleCoordinator(
            LifecycleManager(breaker=CircuitBreaker(clock=clock), clock=clock), clock=clock
        )
        first.manager.begin(subject.incident_id)
        second = LifecycleCoordinator(
            LifecycleManager(breaker=CircuitBreaker(clock=clock), clock=clock), clock=clock
        )
        second.manager.begin(subject.incident_id)

        gate = issue(first, subject)
        assert second.verifier.validate(gate, subject).check == "issuer"

    def test_a_gate_is_frozen(self, coordinator) -> None:
        gate = issue(coordinator)
        with pytest.raises(ValidationError):
            gate.gate_id = "gate-other"  # type: ignore[misc]


class TestGatesAreSingleUse:
    def test_a_consumed_gate_cannot_be_consumed_again(self, coordinator) -> None:
        subject = action()
        gate = issue(coordinator, subject)
        coordinator.verifier.consume(gate, subject)
        with pytest.raises(LifecycleGateRejected) as refusal:
            coordinator.verifier.consume(gate, subject)
        assert refusal.value.rejection.check == "replay"

    def test_a_gate_cannot_be_replayed_after_verification(self, coordinator) -> None:
        subject = action()
        gate = issue(coordinator, subject)
        coordinator.verifier.consume(gate, subject)
        coordinator.record_outcome(
            subject,
            accountable_agent=REMEDIATION,
            execution_outcome="APPLIED",
            verification_status="VERIFIED",
        )
        assert coordinator.verifier.validate(gate, subject).check == "replay"

    def test_replay_is_refused_however_often_it_is_tried(self, coordinator) -> None:
        subject = action()
        gate = issue(coordinator, subject)
        coordinator.verifier.consume(gate, subject)
        for _ in range(5):
            with pytest.raises(LifecycleGateRejected):
                coordinator.verifier.consume(gate, subject)


class TestGatesExpire:
    def test_a_stale_gate_is_refused(self, coordinator, clock) -> None:
        subject = action()
        gate = issue(coordinator, subject)
        clock.advance(61)
        rejection = coordinator.verifier.validate(gate, subject)
        assert rejection.check == "expiry"

    def test_a_fresh_gate_is_accepted(self, coordinator, clock) -> None:
        subject = action()
        gate = issue(coordinator, subject)
        clock.advance(59)
        assert coordinator.verifier.validate(gate, subject) is None

    def test_expiry_uses_the_injected_clock(self, coordinator) -> None:
        subject = action()
        gate = issue(coordinator, subject)
        for _ in range(10):
            assert coordinator.verifier.validate(gate, subject) is None


class TestLifecycleMovementInvalidatesGates:
    def test_a_breaker_that_opens_after_issue_refuses_the_gate(self, coordinator) -> None:
        subject = action()
        gate = issue(coordinator, subject)
        scope = coordinator.manager.scope_for(subject)
        for _ in range(3):
            coordinator.manager.breaker.record(
                scope, FailureClass.EXECUTION_FAILURE, reason="failed"
            )
        rejection = coordinator.verifier.validate(gate, subject)
        assert rejection is not None
        assert rejection.check in {"breaker_state", "lifecycle_generation"}

    def test_a_governance_anomaly_invalidates_outstanding_gates(self, coordinator) -> None:
        from aegis.core.domain import PolicyDecisionType

        subject = action()
        gate = issue(coordinator, subject)
        coordinator.record_governance_anomaly(
            subject,
            accountable_agent=REMEDIATION,
            executed=True,
            authorization_present=False,
            policy_decision=PolicyDecisionType.REQUIRE_APPROVAL,
            authorized_action_id=None,
            verified_action_id=subject.action_id,
            audit_valid=True,
        )
        assert coordinator.verifier.validate(gate, subject) is not None


class TestAGateIsNotAuthority:
    def test_a_gate_carries_no_policy_approval_or_verification_authority(self) -> None:
        fields = set(LifecycleGate.model_fields)
        for forbidden in (
            "policy_decision",
            "approval",
            "approval_id",
            "authorization",
            "risk",
            "blast_radius",
            "verified",
            "verification",
            "allowed",
            "permitted",
        ):
            assert forbidden not in fields, forbidden

    def test_the_lifecycle_decision_on_a_gate_is_a_record_not_a_permission(
        self, coordinator
    ) -> None:
        # The only verdict that reaches a gate is CONTINUE, and CONTINUE means
        # "nothing objects" — the manager has no EXECUTE action to record.
        gate = issue(coordinator)
        assert gate.lifecycle_decision == LifecycleAction.CONTINUE.value
        assert "EXECUTE" not in {member.value for member in LifecycleAction}

    def test_the_register_cannot_approve_or_authorize(self, coordinator) -> None:
        register = coordinator.verifier
        for forbidden in ("approve", "authorize", "grant", "permit_execution"):
            assert not hasattr(register, forbidden)

    def test_a_gate_alone_does_not_execute(self, coordinator) -> None:
        # Proven against the real executor in test_execution_boundary.py; here it is the
        # type-level statement: nothing on a gate says an execution may proceed.
        gate = issue(coordinator)
        assert not hasattr(gate, "execute")
        assert not hasattr(gate, "authorization")


class TestTheRegisterIsTheAuthenticitySource:
    def test_a_register_reports_what_it_issued(self, coordinator) -> None:
        gate = issue(coordinator)
        assert coordinator.verifier.was_issued(gate.gate_id)
        assert not coordinator.verifier.was_issued("gate-never-minted")

    def test_gate_ids_are_deterministic(self, clock) -> None:
        # Reproducibility matters more than unpredictability: being in the register is
        # what makes a gate authentic, not being hard to guess.
        def mint() -> str:
            manager = LifecycleManager(breaker=CircuitBreaker(clock=clock), clock=clock)
            manager.begin("INC-2026-0001")
            return issue(LifecycleCoordinator(manager, clock=clock)).gate_id

        assert mint() == mint()

    def test_the_seal_covers_every_binding(self) -> None:
        from aegis.lifecycle.gate import _SealPayload

        covered = set(_SealPayload.model_fields)
        bindings = set(LifecycleGate.model_fields) - {"seal"}
        assert bindings <= covered, f"unsealed: {bindings - covered}"

    def test_changing_any_binding_changes_the_seal(self, coordinator) -> None:
        gate = issue(coordinator)
        for field, value in (
            ("action_id", "act-other"),
            ("incident_id", "INC-other"),
            ("capability_id", "production.scale"),
            ("resource", "service:order-service"),
            ("lifecycle_scope", "other@scope"),
            ("lifecycle_generation", 7),
            ("execution_count", 9),
        ):
            assert gate_seal(gate.model_copy(update={field: value})) != gate.seal, field

    def test_a_disabled_ttl_is_available_only_by_explicit_configuration(self, clock) -> None:
        register = GateRegister(clock=clock, ttl_seconds=None)
        assert (
            register.expires_at(  # type: ignore[arg-type]
                LifecycleGate(
                    gate_id="g-1",
                    incident_id="INC-1",
                    action_id="act-1",
                    action_fingerprint="a" * 64,
                    capability_id="production.rollback",
                    resource=PAYMENT_API,
                    lifecycle_scope="s",
                    lifecycle_decision="CONTINUE",
                    lifecycle_state="EXECUTING",
                    breaker_state=CircuitState.CLOSED,
                    lifecycle_generation=0,
                    steps_used=0,
                    remediation_attempts=0,
                    execution_count=0,
                    issued_at=START,
                    seal="0" * 64,
                )
            )
            is None
        )
