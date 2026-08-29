"""The coordinator is a sequencing boundary, not a second control plane.

§10 is a hard architectural constraint, and the failure mode it guards against is a quiet
one: a coordinator that started by *calling* the policy engine and ended up *deciding* what
policy would have said. These tests are structural on purpose — they check the API surface
and the imports, so the constraint fails at review time rather than after it has already
been crossed.

Also here: the audit trail for gates and restrictions, and the reconstruction a security
investigator actually needs.
"""

from __future__ import annotations

import ast
import pathlib
from datetime import UTC, datetime, timedelta

from aegis.core.audit import AuditEventType, reconstruct_incident_history
from aegis.core.domain import RiskLevel
from aegis.enterprise import PAYMENT_API, EnterpriseWorld, FailureType
from aegis.lifecycle import (
    AgentRestrictionConfig,
    AgentRestrictionRegistry,
    CircuitBreaker,
    LifecycleCoordinator,
    LifecycleManager,
)
from tests.fleet import build_action
from tests.orchestration.conftest import build_incident, build_orchestrator

START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


def coordinator_source() -> str:
    return pathlib.Path("src/aegis/lifecycle/coordinator.py").read_text(encoding="utf-8")


def imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


class TestTheCoordinatorIsNotASecondAuthority:
    def test_it_has_no_method_that_grants_permission(self) -> None:
        coordinator = LifecycleCoordinator(LifecycleManager())
        for forbidden in (
            "approve",
            "authorize",
            "grant",
            "permit",
            "allow",
            "evaluate",
            "decide_policy",
            "verify",
            "resolve",
            "create_authorization",
        ):
            assert not hasattr(coordinator, forbidden), forbidden

    def test_its_public_surface_is_narrow(self) -> None:
        coordinator = LifecycleCoordinator(LifecycleManager())
        public = {
            name
            for name in dir(coordinator)
            if not name.startswith("_") and callable(getattr(coordinator, name, None))
        }
        assert public == {
            "request_gate",
            "check_restriction",
            "record_outcome",
            "record_governance_anomaly",
        }

    def test_it_imports_no_policy_approval_or_verification_engine(self) -> None:
        imported = imported_modules(pathlib.Path("src/aegis/lifecycle/coordinator.py"))
        for forbidden in (
            "aegis.core.policy",
            "aegis.core.verification",
            "aegis.core.incidents",
            "aegis.enterprise",
            "aegis.orchestration",
            "aegis.agents",
            "aegis.memory",
        ):
            assert not any(m.startswith(forbidden) for m in imported), forbidden

    def test_it_never_constructs_an_execution_authorization(self) -> None:
        source = coordinator_source()
        assert "ExecutionAuthorization(" not in source
        assert "consume_for_execution" not in source

    def test_it_never_writes_risk_or_blast_radius(self) -> None:
        tree = ast.parse(coordinator_source())
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
                assert node.attr not in {"risk", "blast_radius"}

    def test_the_lifecycle_package_imports_no_agent_module(self) -> None:
        for path in sorted(pathlib.Path("src/aegis/lifecycle").rglob("*.py")):
            for module in imported_modules(path):
                assert not module.startswith("aegis.agents"), path.name

    def test_the_gate_is_the_only_artifact_it_constructs(self) -> None:
        # Everything else it hands on is something another engine produced.
        source = coordinator_source()
        assert "self._register.issue(" in source


class TestNoAgentReachesTheCoordinator:
    def test_the_commander_holds_no_coordinator_or_executor(self) -> None:
        orchestrator = build_orchestrator()
        for forbidden in ("coordinator", "executor", "lifecycle", "breaker", "restrictions"):
            assert not hasattr(orchestrator.commander, forbidden), forbidden

    def test_specialists_hold_no_coordinator_or_executor(self) -> None:
        orchestrator = build_orchestrator()
        for agent_id in orchestrator.specialists.ids():
            specialist = orchestrator.specialists.get(agent_id)
            for forbidden in ("coordinator", "executor", "lifecycle"):
                assert not hasattr(specialist, forbidden), forbidden

    def test_no_agent_module_imports_the_executor(self) -> None:
        for path in sorted(pathlib.Path("src/aegis/agents").rglob("*.py")):
            for module in imported_modules(path):
                assert "ActionExecutor" not in module
                assert not module.startswith("aegis.enterprise"), path.name


class TestGateAndRestrictionAudit:
    def test_a_governed_run_records_the_gate_being_issued_and_consumed(self) -> None:
        orchestrator = build_orchestrator()
        orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        types = [record.event.event_type for record in orchestrator.audit.records()]
        assert AuditEventType.LIFECYCLE_GATE_ISSUED.value in types
        assert AuditEventType.LIFECYCLE_GATE_CONSUMED.value in types
        assert orchestrator.audit.verify_integrity().valid

    def test_a_gate_event_carries_every_binding(self) -> None:
        orchestrator = build_orchestrator()
        orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        issued = next(
            record
            for record in orchestrator.audit.records()
            if record.event.event_type == AuditEventType.LIFECYCLE_GATE_ISSUED.value
        )
        assert set(issued.correlation) >= {
            "gate_id",
            "action_id",
            "action_fingerprint",
            "lifecycle_scope",
            "lifecycle_state",
            "breaker_state",
        }

    def test_a_refused_gate_is_recorded(self) -> None:
        # A pre-opened breaker is refused *earlier*, at the manager's own gate, and shows
        # up as lifecycle.stopped. The case that reaches gate issuance and is refused
        # there is a quarantined accountable agent, so that is what this exercises.
        from aegis.lifecycle import FailureClass

        restrictions = AgentRestrictionRegistry(clock=lambda: START)
        for _ in range(3):
            restrictions.record_failure(
                "remediation",
                FailureClass.EXECUTION_FAILURE,
                capability="production.rollback",
                resource=PAYMENT_API,
                reason="failed in earlier incidents",
            )
        orchestrator = build_orchestrator(restrictions=restrictions)
        orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        types = [record.event.event_type for record in orchestrator.audit.records()]
        assert AuditEventType.LIFECYCLE_GATE_REJECTED.value in types
        assert AuditEventType.LIFECYCLE_GATE_CONSUMED.value not in types

    def test_a_pre_opened_breaker_stops_before_gate_issuance(self) -> None:
        # Recorded as its own expectation rather than left implicit: the breaker refusal
        # happens at the lifecycle manager, which is strictly earlier than the gate.
        from aegis.lifecycle import FailureClass

        breaker = CircuitBreaker(clock=lambda: START)
        key = breaker.key_for(capability="production.rollback", resource=PAYMENT_API)
        for _ in range(3):
            breaker.record(key, FailureClass.EXECUTION_FAILURE, reason="failed earlier")
        orchestrator = build_orchestrator(breaker=breaker)
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)

        types = [record.event.event_type for record in orchestrator.audit.records()]
        assert AuditEventType.LIFECYCLE_STOPPED.value in types
        assert AuditEventType.LIFECYCLE_GATE_ISSUED.value not in types
        assert run.execution is None
        assert orchestrator.audit.verify_integrity().valid

    def test_a_quarantine_and_the_refusal_it_causes_are_both_recorded(self) -> None:
        # The trail must reconstruct: failures accumulated, restriction applied, next
        # attempt refused. Recording only the restriction would leave the refusal
        # indistinguishable from the restriction not working.
        restrictions = AgentRestrictionRegistry(
            AgentRestrictionConfig(execution_failure_threshold=1, verification_failure_threshold=1),
            clock=lambda: START,
        )
        world = EnterpriseWorld()
        world.inject_failure(FailureType.ROLLBACK_FAILURE)
        orchestrator = build_orchestrator(world=world, restrictions=restrictions, max_steps=9)
        orchestrator.run(build_incident(), affected_resource=PAYMENT_API)

        types = [record.event.event_type for record in orchestrator.audit.records()]
        assert AuditEventType.AGENT_RESTRICTION_APPLIED.value in types
        assert AuditEventType.AGENT_RESTRICTION_REFUSED.value in types
        assert orchestrator.audit.verify_integrity().valid

    def test_a_restriction_event_carries_the_accountable_identity_and_scope(self) -> None:
        restrictions = AgentRestrictionRegistry(
            AgentRestrictionConfig(execution_failure_threshold=1, verification_failure_threshold=1),
            clock=lambda: START,
        )
        world = EnterpriseWorld()
        world.inject_failure(FailureType.ROLLBACK_FAILURE)
        orchestrator = build_orchestrator(world=world, restrictions=restrictions, max_steps=9)
        orchestrator.run(build_incident(), affected_resource=PAYMENT_API)

        applied = next(
            record
            for record in orchestrator.audit.records()
            if record.event.event_type == AuditEventType.AGENT_RESTRICTION_APPLIED.value
        )
        assert applied.event.agent_identity == "remediation"
        assert set(applied.correlation) >= {
            "agent_id",
            "scope_key",
            "restriction",
            "capability",
            "resource",
        }

    def test_the_incident_history_still_reconstructs(self) -> None:
        orchestrator = build_orchestrator()
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        history = reconstruct_incident_history(
            orchestrator.audit.records(), run.incident.incident_id
        )
        assert history.consistent
        assert [state.value for state in history.states][-1] == "RESOLVED"

    def test_no_audit_event_creates_authority(self) -> None:
        # Every new event type is a statement of fact. None of them names a permission.
        for event in (
            AuditEventType.LIFECYCLE_GATE_ISSUED,
            AuditEventType.LIFECYCLE_GATE_CONSUMED,
            AuditEventType.LIFECYCLE_GATE_REJECTED,
            AuditEventType.AGENT_RESTRICTION_APPLIED,
            AuditEventType.AGENT_RESTRICTION_REFUSED,
        ):
            assert "allow" not in event.value
            assert "approve" not in event.value
            assert "authorize" not in event.value

    def test_the_audit_package_imports_no_lifecycle_or_agent_module(self) -> None:
        for path in sorted(pathlib.Path("src/aegis/core/audit").rglob("*.py")):
            for module in imported_modules(path):
                assert not module.startswith("aegis.lifecycle"), path.name
                assert not module.startswith("aegis.agents"), path.name


class TestDeterminism:
    def test_two_identical_runs_produce_identical_gates(self) -> None:
        from aegis.core.domain import to_json

        first = build_orchestrator().run(build_incident(), affected_resource=PAYMENT_API)
        second = build_orchestrator().run(build_incident(), affected_resource=PAYMENT_API)
        assert to_json(first) == to_json(second)

    def test_the_coordinator_uses_the_injected_clock(self) -> None:
        clock = Clock()
        manager = LifecycleManager(breaker=CircuitBreaker(clock=clock), clock=clock)
        manager.begin("INC-1")
        coordinator = LifecycleCoordinator(manager, clock=clock)
        from aegis.core.assessment import AssessmentPipeline
        from aegis.core.domain import IncidentState
        from aegis.enterprise import build_dependency_graph
        from aegis.lifecycle import LifecycleAction, LifecycleDecision
        from tests.fleet import REMEDIATION, build_registry

        proposed = build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
            risk=RiskLevel.HIGH,
        )
        assessed = (
            AssessmentPipeline(build_registry(), build_dependency_graph())
            .assess(proposed)
            .require_assessed_action()
        )
        issue = coordinator.request_gate(
            assessed,
            accountable_agent=REMEDIATION,
            incident_state=IncidentState.EXECUTING,
            lifecycle_decision=LifecycleDecision(
                action=LifecycleAction.CONTINUE,
                detail="ok",
                counters=manager.counters,
            ),
        )
        assert issue.gate.issued_at == START
