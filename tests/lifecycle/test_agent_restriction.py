"""Agent abuse containment: who may keep participating, never what is allowed.

Two things are being tested and they must not blur.

**Containment works** — an agent that repeatedly causes governed failures is quarantined
for the narrow scope it failed in, and stops being able to participate there.

**Containment is not authorization, and not contagious** — quarantine grants nothing,
overrides no policy decision, cannot be triggered or cleared by an agent, and does not
spread to other agents, capabilities or resources. A containment mechanism that
over-reaches is itself a denial-of-service, which is the problem it was built to solve.
"""

from __future__ import annotations

import ast
import pathlib
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from aegis.core.domain import IncidentState, PolicyDecisionType, RiskLevel
from aegis.enterprise import PAYMENT_API
from aegis.lifecycle import (
    AgentRestriction,
    AgentRestrictionConfig,
    AgentRestrictionRegistry,
    CircuitBreaker,
    CircuitState,
    FailureClass,
    LifecycleAction,
    LifecycleCoordinator,
    LifecycleDecision,
    LifecycleManager,
    RestrictionScope,
)
from tests.fleet import COMMANDER, REMEDIATION, SECURITY, build_action

ROLLBACK = "production.rollback"
ORDERS = "service:order-service"
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
def registry(clock) -> AgentRestrictionRegistry:
    return AgentRestrictionRegistry(clock=clock)


def fail(
    registry,
    agent: str,
    times: int = 3,
    *,
    capability=ROLLBACK,
    resource=PAYMENT_API,
    failure_class=FailureClass.EXECUTION_FAILURE,
):
    for _ in range(times):
        registry.record_failure(
            agent, failure_class, capability=capability, resource=resource, reason="failed"
        )


class TestContainmentWorks:
    def test_an_agent_below_the_threshold_stays_active(self, registry) -> None:
        fail(registry, "remediation", times=2)
        verdict = registry.check("remediation", capability=ROLLBACK, resource=PAYMENT_API)
        assert verdict.restriction is AgentRestriction.ACTIVE
        assert verdict.permitted

    def test_repeated_execution_failures_quarantine_the_agent(self, registry) -> None:
        fail(registry, "remediation", times=3)
        verdict = registry.check("remediation", capability=ROLLBACK, resource=PAYMENT_API)
        assert verdict.restriction is AgentRestriction.QUARANTINED
        assert not verdict.permitted

    def test_repeated_verification_failures_quarantine_the_agent(self, registry) -> None:
        fail(registry, "remediation", times=3, failure_class=FailureClass.VERIFICATION_FAILURE)
        assert (
            registry.restriction_of("remediation", capability=ROLLBACK, resource=PAYMENT_API)
            is AgentRestriction.QUARANTINED
        )

    def test_governance_anomalies_quarantine_sooner(self, registry) -> None:
        # Two rather than three: an anomaly describes something that should be unreachable.
        fail(registry, "remediation", times=1, failure_class=FailureClass.GOVERNANCE_ANOMALY)
        assert (
            registry.restriction_of("remediation", capability=ROLLBACK, resource=PAYMENT_API)
            is AgentRestriction.ACTIVE
        )
        fail(registry, "remediation", times=1, failure_class=FailureClass.GOVERNANCE_ANOMALY)
        assert (
            registry.restriction_of("remediation", capability=ROLLBACK, resource=PAYMENT_API)
            is AgentRestriction.QUARANTINED
        )

    def test_the_verdict_names_what_tripped_it(self, registry) -> None:
        fail(registry, "remediation", times=3)
        verdict = registry.check("remediation", capability=ROLLBACK, resource=PAYMENT_API)
        assert verdict.trip_class is FailureClass.EXECUTION_FAILURE
        assert verdict.quarantined_at == START
        assert verdict.failure_counts == {"EXECUTION_FAILURE": 3}

    def test_a_verified_success_clears_the_counters(self, registry) -> None:
        fail(registry, "remediation", times=2)
        registry.record_failure(
            "remediation", FailureClass.NONE, capability=ROLLBACK, resource=PAYMENT_API
        )
        fail(registry, "remediation", times=2)
        assert (
            registry.restriction_of("remediation", capability=ROLLBACK, resource=PAYMENT_API)
            is AgentRestriction.ACTIVE
        )

    def test_a_quarantined_agent_cannot_succeed_its_way_out(self, registry) -> None:
        # It cannot participate, so it cannot generate a success; and if something else
        # reported one, that must not release the quarantine.
        fail(registry, "remediation", times=3)
        registry.record_failure(
            "remediation", FailureClass.NONE, capability=ROLLBACK, resource=PAYMENT_API
        )
        assert (
            registry.restriction_of("remediation", capability=ROLLBACK, resource=PAYMENT_API)
            is AgentRestriction.QUARANTINED
        )


class TestIsolation:
    """§16. Containment that over-reaches is the denial-of-service it exists to prevent."""

    def test_another_resource_is_unaffected(self, registry) -> None:
        fail(registry, "remediation", times=3, resource=PAYMENT_API)
        assert registry.check("remediation", capability=ROLLBACK, resource=ORDERS).permitted

    def test_another_capability_is_unaffected(self, registry) -> None:
        fail(registry, "remediation", times=3, capability=ROLLBACK)
        assert registry.check(
            "remediation", capability="production.scale", resource=PAYMENT_API
        ).permitted

    def test_another_agent_is_unaffected(self, registry) -> None:
        fail(registry, "remediation", times=3)
        assert registry.check("diagnostic", capability=ROLLBACK, resource=PAYMENT_API).permitted

    def test_the_documented_scope_matrix_holds(self, registry) -> None:
        # Agent A fails at payment-api rollback. The declared semantics, exactly.
        fail(registry, "agent-a", times=3, capability=ROLLBACK, resource=PAYMENT_API)
        assert not registry.check("agent-a", capability=ROLLBACK, resource=PAYMENT_API).permitted
        assert registry.check("agent-a", capability=ROLLBACK, resource=ORDERS).permitted
        assert registry.check("agent-b", capability=ROLLBACK, resource=PAYMENT_API).permitted
        assert registry.check("agent-b", capability=ROLLBACK, resource=ORDERS).permitted

    def test_nothing_becomes_globally_contaminated(self, registry) -> None:
        fail(registry, "remediation", times=9)
        for agent in ("commander", "diagnostic", "security", "business-impact"):
            for capability in (ROLLBACK, "production.scale", "customer.notify"):
                for resource in (PAYMENT_API, ORDERS, "service:auth"):
                    assert registry.check(agent, capability=capability, resource=resource).permitted

    def test_a_wider_scope_is_available_and_does_what_it_says(self, clock) -> None:
        wide = AgentRestrictionRegistry(
            AgentRestrictionConfig(scope=RestrictionScope.AGENT), clock=clock
        )
        fail(wide, "remediation", times=3, resource=PAYMENT_API)
        assert not wide.check("remediation", capability=ROLLBACK, resource=ORDERS).permitted
        assert wide.check("diagnostic", capability=ROLLBACK, resource=ORDERS).permitted

    def test_the_default_scope_is_the_narrowest(self) -> None:
        from aegis.lifecycle import DEFAULT_RESTRICTION_CONFIG

        assert DEFAULT_RESTRICTION_CONFIG.scope is RestrictionScope.AGENT_CAPABILITY_RESOURCE


class TestRestrictionIsNotAuthorization:
    """§15. It answers "may this agent keep participating", never "is this allowed"."""

    def test_an_active_verdict_carries_no_permission(self, registry) -> None:
        verdict = registry.check("remediation", capability=ROLLBACK, resource=PAYMENT_API)
        fields = set(type(verdict).model_fields)
        for forbidden in ("policy_decision", "approval", "authorization", "risk", "allowed"):
            assert forbidden not in fields

    def test_quarantine_does_not_change_a_policy_decision(self, clock) -> None:
        # The same action, evaluated by the real policy engine, before and after the
        # proposing agent is quarantined. Policy must not notice.
        from aegis.core.policy import PolicyEngine
        from tests.fleet import build_registry, fixed_clock

        policy = PolicyEngine(build_registry(), clock=fixed_clock)
        subject = build_action(
            requesting_agent="remediation",
            capability=ROLLBACK,
            target_resource=PAYMENT_API,
            risk=RiskLevel.HIGH,
        )
        before = policy.evaluate(subject, REMEDIATION)

        registry = AgentRestrictionRegistry(clock=clock)
        fail(registry, REMEDIATION.agent_id, times=3)

        after = policy.evaluate(subject, REMEDIATION)
        assert before.decision is after.decision is PolicyDecisionType.REQUIRE_APPROVAL

    def test_quarantine_cannot_permit_a_denied_action(self, clock) -> None:
        # Restriction removes a participant; it never adds a permission, so a quarantined
        # *or* active agent gets the same DENY.
        from aegis.core.policy import PolicyEngine
        from tests.fleet import QUARANTINED_REMEDIATION, build_registry, fixed_clock

        policy = PolicyEngine(build_registry(), clock=fixed_clock)
        subject = build_action(
            requesting_agent=QUARANTINED_REMEDIATION.agent_id,
            capability=ROLLBACK,
            target_resource=PAYMENT_API,
            risk=RiskLevel.HIGH,
        )
        assert policy.evaluate(subject, QUARANTINED_REMEDIATION).decision is (
            PolicyDecisionType.DENY
        )

    def test_the_registry_has_no_method_that_grants_anything(self, registry) -> None:
        for forbidden in ("allow", "permit", "authorize", "approve", "grant"):
            assert not hasattr(registry, forbidden)


class TestAgentsCannotControlRestriction:
    """§11, §14. Nothing an agent produces reaches any of this."""

    def test_there_is_no_public_clear_or_reset(self, registry) -> None:
        for forbidden in ("clear", "reset", "release", "unquarantine", "restore", "set_state"):
            assert not hasattr(registry, forbidden), forbidden

    def test_a_decision_has_no_field_naming_restriction_state(self) -> None:
        from aegis.agents.decisions import CommanderDecision, CommanderProposal

        for model in (CommanderDecision, CommanderProposal):
            fields = set(model.model_fields)
            for forbidden in (
                "restriction",
                "quarantine",
                "agent_restriction",
                "failure_counts",
                "threshold",
                "breaker",
                "scope",
            ):
                assert forbidden not in fields, f"{model.__name__}.{forbidden}"

    def test_a_decision_rejects_an_invented_restriction_field(self) -> None:
        from aegis.agents.decisions import CommanderDecision, DecisionType

        with pytest.raises(ValidationError):
            CommanderDecision(
                decision_type=DecisionType.WAIT,
                reasoning_summary="clearing my own quarantine",
                restriction="ACTIVE",
            )

    def test_the_config_is_frozen(self) -> None:
        from aegis.lifecycle import DEFAULT_RESTRICTION_CONFIG

        with pytest.raises(ValidationError):
            DEFAULT_RESTRICTION_CONFIG.execution_failure_threshold = 999  # type: ignore[misc]

    def test_restriction_state_never_reaches_a_model(self) -> None:
        from aegis.agents.model import ModelRequest

        for forbidden in ("restriction", "quarantine", "breaker", "thresholds"):
            assert forbidden not in ModelRequest.model_fields

    def test_no_agent_module_imports_the_restriction_registry(self) -> None:
        offenders: list[str] = []
        for path in sorted(pathlib.Path("src/aegis/agents").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                module = None
                if isinstance(node, ast.Import):
                    module = ",".join(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module
                if module and "aegis.lifecycle" in module:
                    offenders.append(str(path))
        assert not offenders

    def test_memory_cannot_reach_restriction(self) -> None:
        for path in sorted(pathlib.Path("src/aegis/memory").rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert "lifecycle" not in node.module, path.name


class TestAuthoritativeIdentity:
    """§12, §17. Attribution comes from the wiring, never from model text."""

    def coordinator(self, clock, restrictions=None) -> LifecycleCoordinator:
        manager = LifecycleManager(breaker=CircuitBreaker(clock=clock), clock=clock)
        manager.begin("INC-2026-0001")
        return LifecycleCoordinator(
            manager,
            restrictions=restrictions or AgentRestrictionRegistry(clock=clock),
            clock=clock,
        )

    def assessed(self):
        from aegis.core.assessment import AssessmentPipeline
        from aegis.enterprise import build_dependency_graph
        from tests.fleet import build_registry

        proposed = build_action(
            requesting_agent="remediation",
            capability=ROLLBACK,
            target_resource=PAYMENT_API,
            risk=RiskLevel.HIGH,
        ).model_copy(update={"arguments": {"target_version": "v4.7"}})
        return (
            AssessmentPipeline(build_registry(), build_dependency_graph())
            .assess(proposed)
            .require_assessed_action()
        )

    def test_failures_are_attributed_to_the_accountable_agent(self, clock) -> None:
        restrictions = AgentRestrictionRegistry(clock=clock)
        coordinator = self.coordinator(clock, restrictions)
        subject = self.assessed()
        coordinator.record_outcome(
            subject,
            accountable_agent=REMEDIATION,
            execution_outcome="FAILED",
            verification_status="FAILED",
        )
        assert restrictions.check(
            "remediation", capability=ROLLBACK, resource=PAYMENT_API
        ).failure_counts

    def test_a_model_claiming_another_identity_changes_nothing(self, clock) -> None:
        # The Commander is accountable. A model naming itself "remediation" is text.
        restrictions = AgentRestrictionRegistry(clock=clock)
        coordinator = self.coordinator(clock, restrictions)
        subject = self.assessed()
        coordinator.record_outcome(
            subject,
            accountable_agent=COMMANDER,
            execution_outcome="FAILED",
            verification_status="FAILED",
        )
        assert restrictions.check(
            "commander", capability=ROLLBACK, resource=PAYMENT_API
        ).failure_counts
        assert not restrictions.check(
            "remediation", capability=ROLLBACK, resource=PAYMENT_API
        ).failure_counts

    def test_one_specialist_cannot_attribute_failure_to_another(self, clock) -> None:
        restrictions = AgentRestrictionRegistry(clock=clock)
        coordinator = self.coordinator(clock, restrictions)
        subject = self.assessed()
        coordinator.record_outcome(
            subject,
            accountable_agent=SECURITY,
            execution_outcome="FAILED",
            verification_status="FAILED",
        )
        for other in ("commander", "remediation", "diagnostic", "business-impact"):
            assert not restrictions.check(
                other, capability=ROLLBACK, resource=PAYMENT_API
            ).failure_counts

    def test_capability_and_resource_come_from_the_action(self, clock) -> None:
        # Not from anything a model described. The action is the authoritative artifact.
        restrictions = AgentRestrictionRegistry(clock=clock)
        coordinator = self.coordinator(clock, restrictions)
        subject = self.assessed()
        coordinator.record_outcome(
            subject,
            accountable_agent=REMEDIATION,
            execution_outcome="FAILED",
            verification_status="FAILED",
        )
        key = restrictions.key_for(
            "remediation", capability=subject.capability, resource=subject.target_resource
        )
        assert key == f"remediation@{ROLLBACK}@{PAYMENT_API}"

    def test_the_coordinator_refuses_a_gate_to_a_quarantined_agent(self, clock) -> None:
        restrictions = AgentRestrictionRegistry(clock=clock)
        fail(restrictions, REMEDIATION.agent_id, times=3)
        coordinator = self.coordinator(clock, restrictions)
        issue = coordinator.request_gate(
            self.assessed(),
            accountable_agent=REMEDIATION,
            incident_state=IncidentState.EXECUTING,
            lifecycle_decision=LifecycleDecision(
                action=LifecycleAction.CONTINUE,
                detail="within budget",
                counters=coordinator.manager.counters,
            ),
        )
        assert not issue.issued
        assert "quarantined" in issue.refused_reason

    def test_a_quarantined_agent_cannot_act_through_an_unrestricted_one(self, clock) -> None:
        # The other agent's own accountability applies; the quarantined one gains nothing,
        # and the substitute is subject to every gate as usual.
        restrictions = AgentRestrictionRegistry(clock=clock)
        fail(restrictions, REMEDIATION.agent_id, times=3)
        coordinator = self.coordinator(clock, restrictions)
        issue = coordinator.request_gate(
            self.assessed(),
            accountable_agent=COMMANDER,
            incident_state=IncidentState.EXECUTING,
            lifecycle_decision=LifecycleDecision(
                action=LifecycleAction.CONTINUE,
                detail="within budget",
                counters=coordinator.manager.counters,
            ),
        )
        # Commander is not quarantined, so restriction does not block — and the gate it
        # gets still confers nothing without policy, approval and an authorization.
        assert issue.issued
        assert issue.gate.lifecycle_decision == "CONTINUE"


class TestRestrictionAndBreakerStaySeparate:
    """§13. Two mechanisms, two questions, and they must be able to disagree."""

    def test_agent_failures_do_not_by_themselves_open_the_breaker(self, clock) -> None:
        registry = AgentRestrictionRegistry(clock=clock)
        breaker = CircuitBreaker(clock=clock)
        fail(registry, "remediation", times=5)
        key = breaker.key_for(capability=ROLLBACK, resource=PAYMENT_API)
        assert breaker.state_of(key) is CircuitState.CLOSED

    def test_breaker_failures_do_not_by_themselves_quarantine_an_agent(self, clock) -> None:
        registry = AgentRestrictionRegistry(clock=clock)
        breaker = CircuitBreaker(clock=clock)
        key = breaker.key_for(capability=ROLLBACK, resource=PAYMENT_API)
        for _ in range(3):
            breaker.record(key, FailureClass.EXECUTION_FAILURE, reason="failed")
        assert breaker.state_of(key) is CircuitState.OPEN
        assert registry.check("remediation", capability=ROLLBACK, resource=PAYMENT_API).permitted

    def test_they_are_keyed_differently(self, clock) -> None:
        registry = AgentRestrictionRegistry(clock=clock)
        breaker = CircuitBreaker(clock=clock)
        assert registry.key_for(
            "remediation", capability=ROLLBACK, resource=PAYMENT_API
        ) != breaker.key_for(capability=ROLLBACK, resource=PAYMENT_API)


class TestQuarantineRelease:
    def test_there_is_no_automatic_release_by_default(self, clock) -> None:
        registry = AgentRestrictionRegistry(clock=clock)
        fail(registry, "remediation", times=3)
        clock.advance(60 * 60 * 24 * 365)
        assert not registry.check(
            "remediation", capability=ROLLBACK, resource=PAYMENT_API
        ).permitted

    def test_a_configured_cooldown_releases_on_the_injected_clock(self, clock) -> None:
        registry = AgentRestrictionRegistry(
            AgentRestrictionConfig(quarantine_cooldown_seconds=600.0), clock=clock
        )
        fail(registry, "remediation", times=3)
        clock.advance(599)
        assert not registry.check(
            "remediation", capability=ROLLBACK, resource=PAYMENT_API
        ).permitted
        clock.advance(2)
        assert registry.check("remediation", capability=ROLLBACK, resource=PAYMENT_API).permitted

    def test_a_released_agent_starts_from_zero_not_from_the_threshold(self, clock) -> None:
        registry = AgentRestrictionRegistry(
            AgentRestrictionConfig(quarantine_cooldown_seconds=60.0), clock=clock
        )
        fail(registry, "remediation", times=3)
        clock.advance(61)
        registry.check("remediation", capability=ROLLBACK, resource=PAYMENT_API)
        fail(registry, "remediation", times=2)
        assert registry.check("remediation", capability=ROLLBACK, resource=PAYMENT_API).permitted
