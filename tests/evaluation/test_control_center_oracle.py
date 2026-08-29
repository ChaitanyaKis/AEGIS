"""Part 19: the evaluator must not trust the projection.

The eighth application of a lesson this project has learned once per milestone since Prompt
10: **the evaluator must never trust the component it audits.** A read model that lied
would report success exactly as loudly as an honest one, so the benchmark does not ask it.
It reconstructs what should be displayed from artifacts the projection cannot see -- the
**enterprise world** foremost among them -- and compares.

Every test here installs a projection that lies in one specific way and asserts the oracle
catches it. A distortion the oracle misses is a lie the benchmark would certify, which
means the check aimed at it could be deleted with every metric still green.

Why the world matters most
--------------------------

``capture.py`` deliberately does not capture the enterprise world. If the control center
could read it, the projection would report "the deployment changed" as an execution and this
oracle would be comparing the read model with itself. Because it cannot, "did production
change" is a question only the oracle can answer -- and that is what makes a *hidden
execution* detectable at all.
"""

from __future__ import annotations

import pytest

from aegis.control_center import Tri, capture_incident, project_incident
from aegis.enterprise import PAYMENT_API
from aegis.evaluation.control_center_stage import (
    Distortion,
    control_center_observations,
    distort,
    fleet_profiles,
    projection_discrepancies,
    system_fingerprint,
)
from tests.fleet import (
    BUSINESS_IMPACT,
    COMMANDER,
    DIAGNOSTIC,
    REMEDIATION,
    SECURITY,
    fixed_clock,
)
from tests.orchestration.conftest import build_incident, build_orchestrator

FLEET = (COMMANDER, DIAGNOSTIC, SECURITY, BUSINESS_IMPACT, REMEDIATION)

CAUGHT = (
    Distortion.HIDE_EXECUTION,
    Distortion.SWAP_INCIDENT,
)
"""The distortions that genuinely contradict a *cleanly resolved* run's artifacts.

Deliberately short, and the shortness is the point. On a clean run most distortions are not
lies: ``INVENT_APPROVAL`` claims a grant that really happened, ``FAKE_RESOLUTION`` claims a
resolution that really happened, ``HIDE_BREAKER`` shows a breaker that really is closed.
Listing them here would assert that the oracle objects to the truth.

Each is exercised below on an arrangement where it *does* lie -- an approval stripped from
the trail, an escalated incident, a register that consumed nothing. That is the harder test
and the only one that means anything.
"""


@pytest.fixture
def projected():
    """A clean resolved incident, captured and projected for real."""
    orchestrator = build_orchestrator()
    run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
    data = capture_incident(
        orchestrator, run, agents=fleet_profiles(orchestrator, FLEET), clock=fixed_clock
    )
    return orchestrator, run, project_incident(data)


class TestTheHonestProjectionPasses:
    """The control for every control. If this failed, every catch below would be passing
    because the oracle simply always objects."""

    def test_a_faithful_projection_has_no_discrepancies(self, projected) -> None:
        orchestrator, run, projection = projected
        assert projection_discrepancies(orchestrator, run, projection) == ()

    def test_and_is_reported_as_faithful(self, projected) -> None:
        orchestrator, run, projection = projected
        observed = control_center_observations(orchestrator, run, projection)
        assert observed["control_center_faithful"] is True
        assert observed["control_center_leaks"] == 0


class TestTheOracleCatchesALyingProjection:
    @pytest.mark.parametrize("distortion", CAUGHT)
    def test_each_distortion_is_caught(self, projected, distortion: Distortion) -> None:
        orchestrator, run, projection = projected
        lying = distort(projection, distortion)
        assert projection_discrepancies(orchestrator, run, lying) != (), distortion

    def test_a_hidden_execution_is_caught_by_the_world(self, projected) -> None:
        """The headline. The projection says nothing executed; the deployment moved. Only
        the world can settle it, and only the oracle can see the world."""
        orchestrator, run, projection = projected
        lying = distort(projection, Distortion.HIDE_EXECUTION)
        found = projection_discrepancies(orchestrator, run, lying)
        assert any("the world changed" in detail for detail in found)

    def test_an_invented_approval_is_caught_by_the_raw_events(self, projected) -> None:
        orchestrator, run, projection = projected
        # Strip the grant from the trail, then have the projection claim one anyway.
        stripped = [
            record
            for record in orchestrator.audit.records()
            if not record.event.event_type.startswith("approval.")
        ]

        class _Blind:
            audit = type("S", (), {"records": staticmethod(lambda: tuple(stripped))})()
            world = orchestrator.world
            coordinator = orchestrator.coordinator
            lifecycle = orchestrator.lifecycle

        lying = distort(projection, Distortion.INVENT_APPROVAL)
        found = projection_discrepancies(_Blind(), run, lying)
        assert any("records no grant" in detail for detail in found)

    def test_a_fabricated_resolution_is_caught_by_the_incident_state(self, projected) -> None:
        from aegis.core.domain import IncidentState

        orchestrator, run, projection = projected
        escalating = run.model_copy(
            update={"incident": run.incident.model_copy(update={"state": IncidentState.ESCALATED})}
        )
        found = projection_discrepancies(orchestrator, escalating, projection)
        assert any("resolved=" in detail for detail in found)

    def test_a_swapped_incident_is_caught_as_a_leak(self, projected) -> None:
        orchestrator, run, projection = projected
        lying = distort(projection, Distortion.SWAP_INCIDENT)
        found = projection_discrepancies(orchestrator, run, lying)
        assert any("belongs to" in detail for detail in found)

    def test_a_hidden_breaker_is_caught_by_the_live_snapshot(self, projected) -> None:
        """Compared against the breaker's own ``state_of``, not against the captured
        snapshot -- so a projection that lied about what it captured is still caught."""
        orchestrator, run, projection = projected
        lying = distort(projection, Distortion.HIDE_BREAKER)
        lying = lying.model_copy(
            update={
                "breakers": tuple(
                    view.model_copy(
                        update={"state": view.state.model_copy(update={"value": "OPEN"})}
                    )
                    for view in lying.breakers
                )
            }
        )
        object.__setattr__(lying, "_input", projection._input)
        assert projection_discrepancies(orchestrator, run, lying) != ()

    def test_a_fabricated_gate_is_caught_by_the_register(self, projected) -> None:
        orchestrator, run, projection = projected

        class _NoGates:
            audit = orchestrator.audit
            world = orchestrator.world
            lifecycle = orchestrator.lifecycle
            coordinator = type("C", (), {"verifier": type("R", (), {"consumed_count": 0})()})()

        lying = distort(projection, Distortion.FAKE_GATE)
        found = projection_discrepancies(_NoGates(), run, lying)
        assert any("gate_consumed" in detail for detail in found)

    def test_revoked_memory_shown_as_active_is_caught(self, projected) -> None:
        """Even with no memory in this run, the rule is exercised by giving the projection
        a revoked entry and then flipping it -- otherwise the check would be untested."""
        orchestrator, run, projection = projected
        from aegis.control_center import MemoryEntryView

        entry = MemoryEntryView(
            memory_id="mem-revoked",
            incident_id=projection.incident_id,
            agent_id="commander",
            memory_type="REMEDIATION_OUTCOME",
            status="REVOKED",
            summary="a conclusion that was withdrawn",
            source="VERIFIED_OUTCOME",
            created_at=run.incident.created_at,
            action_fingerprint=projection.governance.fingerprint,
            verification_id=projection.verification.verification_id,
            revoked=Tri.TRUE,
            revoked_by=projection.governance.fingerprint,
            revocation_reason=projection.governance.policy_reason,
            authoritative=Tri.TRUE,
            integrity=projection.governance.fingerprint,
        )
        with_memory = projection.model_copy(
            update={"memory": projection.memory.model_copy(update={"entries": (entry,)})}
        )
        object.__setattr__(with_memory, "_input", projection._input)
        found = projection_discrepancies(orchestrator, run, with_memory)
        assert any("revoked and shown as authoritative" in detail for detail in found)

    def test_unverified_memory_shown_as_authoritative_is_caught(self, projected) -> None:
        orchestrator, run, projection = projected
        from aegis.control_center import Fact, MemoryEntryView

        entry = MemoryEntryView(
            memory_id="mem-unverified",
            incident_id=projection.incident_id,
            agent_id="commander",
            memory_type="REMEDIATION_OUTCOME",
            status="AUTHORITATIVE",
            summary="a conclusion nothing established",
            source="AGENT_CLAIM",
            created_at=run.incident.created_at,
            action_fingerprint=Fact.unknown(),
            verification_id=Fact.unknown(),
            revoked=Tri.FALSE,
            revoked_by=Fact.unknown(),
            revocation_reason=Fact.unknown(),
            authoritative=Tri.TRUE,
            integrity=Fact.unknown(),
        )
        with_memory = projection.model_copy(
            update={"memory": projection.memory.model_copy(update={"entries": (entry,)})}
        )
        object.__setattr__(with_memory, "_input", projection._input)
        found = projection_discrepancies(orchestrator, run, with_memory)
        assert any("unverified and shown as authoritative" in detail for detail in found)


class TestHidingIsCaughtOnRunsThatHaveSomethingToHide:
    def test_a_hidden_restriction_is_caught_by_the_events(self) -> None:
        """A clean run has no restriction to conceal, so this needs a run that produced
        one. The oracle compares against the raw ``agent.restriction_applied`` events."""
        from aegis.core.audit import AuditEventType
        from aegis.lifecycle import AgentRestrictionConfig, AgentRestrictionRegistry, FailureClass

        registry = AgentRestrictionRegistry(AgentRestrictionConfig(), clock=fixed_clock)
        orchestrator = build_orchestrator(restrictions=registry)
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        orchestrator.recorder.record_agent_restriction(
            AuditEventType.AGENT_RESTRICTION_APPLIED,
            agent_id="remediation",
            incident_id=run.incident.incident_id,
            scope_key="production.rollback@service:payment-api",
            restriction="QUARANTINED",
            failure_class=FailureClass.EXECUTION_FAILURE.value,
            reason="restricted after repeated failures",
        )
        data = capture_incident(
            orchestrator, run, agents=fleet_profiles(orchestrator, FLEET), clock=fixed_clock
        )
        projection = project_incident(data)
        hiding = distort(projection, Distortion.HIDE_RESTRICTION)
        found = projection_discrepancies(orchestrator, run, hiding)
        assert any("restricted by an event" in detail for detail in found)

    def test_a_pre_existing_quarantine_is_not_a_fabrication(self, projected) -> None:
        """The other direction, and why the rule is one-directional. A quarantine applied
        during an earlier incident is still in force; a view that hid it because *this*
        incident did not cause it would be worse than useless."""
        orchestrator, run, projection = projected
        showing = projection.model_copy(
            update={
                "agents": tuple(
                    view.model_copy(update={"quarantined": Tri.TRUE}) for view in projection.agents
                )
            }
        )
        object.__setattr__(showing, "_input", projection._input)
        found = projection_discrepancies(orchestrator, run, showing)
        assert not any("quarantined" in detail for detail in found)

    def test_a_failed_execution_is_not_a_fabrication(self, projected) -> None:
        """Same reasoning for execution. An execution that ran and failed leaves an
        artifact and an unchanged world -- that is what ``world_changed`` is for, and
        flagging it would push the read model towards hiding real executions."""
        orchestrator, run, projection = projected

        class _Unchanged:
            audit = orchestrator.audit
            coordinator = orchestrator.coordinator
            lifecycle = orchestrator.lifecycle
            world = type(
                "W",
                (),
                {"state": staticmethod(lambda _resource: type("S", (), {"deployment": "v4.8"})())},
            )()

        found = projection_discrepancies(_Unchanged(), run, projection)
        assert not any("executed=" in detail for detail in found)


class TestTheOracleReadsRawArtifacts:
    def test_it_never_asks_the_projection_whether_it_was_right(self) -> None:
        """Structural. The oracle must not reach for a field the projection computed about
        its own faithfulness."""
        import ast
        import pathlib

        tree = ast.parse(
            pathlib.Path("src/aegis/evaluation/control_center_stage.py").read_text(encoding="utf-8")
        )
        function = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "projection_discrepancies"
        )
        names = {node.attr for node in ast.walk(function) if isinstance(node, ast.Attribute)}
        for forbidden in ("faithful", "trustworthy", "usable", "complete"):
            assert forbidden not in names, forbidden

    def test_it_reads_the_world(self) -> None:
        """The one source the projection cannot see, and the reason a hidden execution is
        detectable."""
        import ast
        import pathlib

        source = pathlib.Path("src/aegis/evaluation/control_center_stage.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        function = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "_world_changed"
        )
        body = ast.unparse(function)
        assert "world.state" in body
        assert "PAYMENT_API_FAULTY_VERSION" in body

    def test_the_capture_never_reads_the_world(self) -> None:
        """The other half, checked over the *code* rather than the prose.

        If capture read the world, the projection could report a changed deployment as an
        execution and the oracle would be comparing the read model with itself. The module
        docstring says so; this asserts that what runs agrees.
        """
        import ast
        import pathlib

        tree = ast.parse(
            pathlib.Path("src/aegis/control_center/capture.py").read_text(encoding="utf-8")
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                node.value.value = ""
        code = ast.unparse(tree).lower()
        assert "world" not in code
        assert "payment_api" not in code

    def test_the_projection_has_no_route_to_the_world_either(self) -> None:
        """Nor does anything downstream of capture: the whole package is swept."""
        import ast
        import pathlib

        for path in sorted(pathlib.Path("src/aegis/control_center").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    assert "enterprise" not in (node.module or ""), path.name


class TestSideEffectsAreMeasured:
    def test_the_fingerprint_covers_audit_world_and_gates(self, projected) -> None:
        orchestrator, _, _ = projected
        fingerprint = system_fingerprint(orchestrator)
        assert len(fingerprint) == 5
        assert all(value is not None for value in fingerprint)

    def test_observing_moves_nothing(self, projected) -> None:
        orchestrator, run, _ = projected
        before = system_fingerprint(orchestrator)
        data = capture_incident(
            orchestrator, run, agents=fleet_profiles(orchestrator, FLEET), clock=fixed_clock
        )
        project_incident(data)
        assert system_fingerprint(orchestrator) == before
