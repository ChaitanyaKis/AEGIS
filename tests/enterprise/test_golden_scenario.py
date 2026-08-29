"""The golden incident, end to end, against the simulated enterprise.

Every engine is real. Nothing here sets a risk, a policy decision, an approval status, a
verification status or a final incident state by hand — each is whatever the control plane
computed from the world as it actually was.
"""

from __future__ import annotations

import pytest

from aegis.core.audit import AuditEventType, reconstruct_incident_history
from aegis.core.domain import (
    IncidentState,
    PolicyDecisionType,
    RiskLevel,
    to_json,
)
from aegis.core.verification import VerificationStatus
from aegis.enterprise import (
    GOLDEN_ACTION_ID,
    GOLDEN_APPROVAL_ID,
    GOLDEN_INCIDENT_ID,
    GOLDEN_VERIFICATION_ID,
    PAYMENT_API,
    PAYMENT_API_FAULTY_VERSION,
    PAYMENT_API_GOOD_VERSION,
    EnterpriseWorld,
    ExecutionOutcome,
    FailureType,
    GoldenIncidentScenario,
    ServiceHealth,
)
from tests.fleet import DIAGNOSTIC, REMEDIATION, build_registry, fixed_clock

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


def _fresh(**kwargs) -> GoldenIncidentScenario:
    return GoldenIncidentScenario(build_registry(), REMEDIATION, clock=fixed_clock, **kwargs)


# --- the happy path -----------------------------------------------------------------


def test_the_incident_starts_in_the_golden_condition(
    scenario: GoldenIncidentScenario,
) -> None:
    run = scenario.run()
    before = run.world_before.resource(PAYMENT_API)
    assert before.deployment == PAYMENT_API_FAULTY_VERSION == "v4.8"
    assert before.error_rate == 37.0
    assert before.health is ServiceHealth.UNHEALTHY


def test_the_control_plane_takes_the_incident_to_resolved(
    scenario: GoldenIncidentScenario,
) -> None:
    run = scenario.run()

    assert run.assessment.ok
    assert run.assessment.require_assessed_action().risk is RiskLevel.HIGH
    assert run.evaluation.decision.decision is PolicyDecisionType.REQUIRE_APPROVAL
    assert run.authorization is not None
    assert run.execution.outcome is ExecutionOutcome.APPLIED
    assert run.verification.status is VerificationStatus.VERIFIED
    assert run.incident.state is IncidentState.RESOLVED
    assert run.resolved


def test_the_world_actually_changed(scenario: GoldenIncidentScenario) -> None:
    run = scenario.run()
    after = run.world_after.resource(PAYMENT_API)
    assert after.deployment == PAYMENT_API_GOOD_VERSION == "v4.7"
    assert after.error_rate == 0.7
    assert after.health is ServiceHealth.HEALTHY


def test_verification_read_the_changed_world(scenario: GoldenIncidentScenario) -> None:
    """The VERIFIED result came from observations, not from the execution report."""
    run = scenario.run()
    telemetry = next(o for o in run.observations if "health" in o.values)
    assert telemetry.values == {"error_rate": 0.7, "health": "healthy"}
    assert set(run.verification.observations_used) == {o.observation_id for o in run.observations}


def test_risk_and_blast_radius_came_from_the_engines(
    scenario: GoldenIncidentScenario,
) -> None:
    """The proposal declares neither; the pipeline computes both."""
    proposal = scenario.proposal()
    assert proposal.risk is None
    assert proposal.blast_radius is None

    run = scenario.run()
    assessed = run.assessment.require_assessed_action()
    assert assessed.risk is RiskLevel.HIGH
    assert assessed.blast_radius is not None
    assert assessed.blast_radius.impact is RiskLevel.HIGH


# --- the audit trail ----------------------------------------------------------------


def test_the_run_leaves_a_complete_audit_trail(
    scenario: GoldenIncidentScenario,
) -> None:
    scenario.run()
    events = scenario.audit.events_for_incident(GOLDEN_INCIDENT_ID)
    emitted = {event.event_type for event in events}

    assert emitted >= {
        AuditEventType.ACTION_ASSESSED.value,
        AuditEventType.POLICY_DECISION.value,
        AuditEventType.APPROVAL_REQUESTED.value,
        AuditEventType.APPROVAL_GRANTED.value,
        AuditEventType.APPROVAL_CONSUMED.value,
        AuditEventType.INCIDENT_STATE_CHANGED.value,
        AuditEventType.VERIFICATION_COMPLETED.value,
    }
    assert scenario.audit.verify_integrity().valid
    assert len(events) == len(scenario.audit.events())


def test_the_trail_reconstructs_the_real_state_sequence(
    scenario: GoldenIncidentScenario,
) -> None:
    scenario.run()
    history = reconstruct_incident_history(scenario.audit.records(), GOLDEN_INCIDENT_ID)
    assert history.states == NORMAL_PATH
    assert history.consistent
    assert history.problems == ()


def test_the_trail_correlates_by_the_real_identifiers(
    scenario: GoldenIncidentScenario,
) -> None:
    scenario.run()
    records = scenario.audit.records_for_incident(GOLDEN_INCIDENT_ID)
    assert {r.correlation["approval_id"] for r in records if "approval_id" in r.correlation} == {
        GOLDEN_APPROVAL_ID
    }
    assert {
        r.correlation["verification_id"] for r in records if "verification_id" in r.correlation
    } == {GOLDEN_VERIFICATION_ID}
    assert {r.correlation["action_id"] for r in records if "action_id" in r.correlation} == {
        GOLDEN_ACTION_ID
    }


# --- determinism --------------------------------------------------------------------


def test_two_identical_runs_are_byte_equivalent() -> None:
    """Same world, same clock, same inputs — including the audit head digest."""
    first, second = _fresh().run(), _fresh().run()
    assert to_json(first) == to_json(second)
    assert first.audit_head_digest == second.audit_head_digest


@pytest.mark.parametrize("failure", list(FailureType), ids=lambda f: f.value)
def test_every_failure_mode_runs_deterministically(failure: FailureType) -> None:
    first = _fresh().run(failures=(failure,))
    second = _fresh().run(failures=(failure,))
    assert to_json(first) == to_json(second)


def test_the_audit_head_digest_distinguishes_different_runs() -> None:
    clean = _fresh().run()
    failed = _fresh().run(failures=(FailureType.ROLLBACK_FAILURE,))
    assert clean.audit_head_digest != failed.audit_head_digest


# --- failure injection, end to end --------------------------------------------------


@pytest.mark.parametrize(
    ("failure", "expected_execution", "expected_verification"),
    [
        (
            FailureType.ROLLBACK_FAILURE,
            ExecutionOutcome.FAILED,
            VerificationStatus.FAILED,
        ),
        (
            FailureType.TOOL_TIMEOUT,
            ExecutionOutcome.BLOCKED,
            VerificationStatus.FAILED,
        ),
        (FailureType.TOOL_500, ExecutionOutcome.BLOCKED, VerificationStatus.FAILED),
        (
            FailureType.STALE_TELEMETRY,
            ExecutionOutcome.APPLIED,
            VerificationStatus.STALE,
        ),
        (
            FailureType.VERIFICATION_FAILURE,
            ExecutionOutcome.APPLIED,
            VerificationStatus.INSUFFICIENT_EVIDENCE,
        ),
    ],
    ids=lambda value: str(value),
)
def test_no_injected_failure_can_reach_resolved(
    failure: FailureType,
    expected_execution: ExecutionOutcome,
    expected_verification: VerificationStatus,
) -> None:
    run = _fresh().run(failures=(failure,))
    assert run.execution.outcome is expected_execution
    assert run.verification.status is expected_verification
    assert not run.resolved
    assert run.incident.state is IncidentState.DEGRADED


def test_a_failed_rollback_leaves_the_world_on_the_bad_version() -> None:
    """The causal chain: no world change -> honest observations -> FAILED verification."""
    run = _fresh().run(failures=(FailureType.ROLLBACK_FAILURE,))
    after = run.world_after.resource(PAYMENT_API)
    assert after.deployment == PAYMENT_API_FAULTY_VERSION
    assert after.health is ServiceHealth.UNHEALTHY

    telemetry = next(o for o in run.observations if "health" in o.values)
    assert telemetry.values["health"] == "unhealthy"
    assert run.verification.status is VerificationStatus.FAILED


def test_stale_telemetry_leaves_a_genuinely_recovered_world() -> None:
    """The rollback worked; the evidence is simply too old to say so."""
    run = _fresh().run(failures=(FailureType.STALE_TELEMETRY,))
    after = run.world_after.resource(PAYMENT_API)
    assert after.deployment == PAYMENT_API_GOOD_VERSION
    assert after.health is ServiceHealth.HEALTHY
    assert run.execution.outcome is ExecutionOutcome.APPLIED
    assert run.verification.status is VerificationStatus.STALE
    assert not run.resolved


def test_a_degraded_run_still_leaves_a_consistent_trail() -> None:
    scenario = _fresh()
    scenario.run(failures=(FailureType.TOOL_500,))
    history = reconstruct_incident_history(scenario.audit.records(), GOLDEN_INCIDENT_ID)
    assert history.final_state is IncidentState.DEGRADED
    assert IncidentState.RESOLVED not in history.states
    assert history.consistent
    assert scenario.audit.verify_integrity().valid


# --- the simulator cannot bypass the control plane ----------------------------------


def test_execution_success_is_not_verification(scenario: GoldenIncidentScenario) -> None:
    """Proven where it matters: an APPLIED execution alongside a non-VERIFIED result."""
    run = _fresh().run(failures=(FailureType.STALE_TELEMETRY,))
    assert run.execution.applied
    assert run.verification.status is not VerificationStatus.VERIFIED
    assert not run.resolved


def test_a_denied_agent_never_reaches_execution() -> None:
    """Diagnostic cannot roll back.

    The state machine stops it before approval is even attempted: a DENY does not satisfy
    the guard on POLICY_CHECK -> AWAITING_APPROVAL. The world is never touched, and the
    denial is in the audit trail as the DENY it was.
    """
    from aegis.core.incidents import InvalidIncidentTransition

    scenario = GoldenIncidentScenario(build_registry(), DIAGNOSTIC, clock=fixed_clock)
    with pytest.raises(InvalidIncidentTransition, match="got DENY"):
        scenario.run()

    assert scenario.world.state(PAYMENT_API).deployment == PAYMENT_API_FAULTY_VERSION
    assert scenario.world.state(PAYMENT_API).health is ServiceHealth.UNHEALTHY

    events = scenario.audit.events_for_incident(GOLDEN_INCIDENT_ID)
    assert [e for e in events if e.decision is PolicyDecisionType.DENY]
    assert not any(e.event_type.startswith("approval.") for e in events)
    assert scenario.audit.verify_integrity().valid


def test_a_denied_action_cannot_have_an_approval_raised() -> None:
    """And if a caller skipped the state machine, the approval engine refuses too."""
    from aegis.core.approval import ApprovalCreationRefused

    scenario = GoldenIncidentScenario(build_registry(), DIAGNOSTIC, clock=fixed_clock)
    action = scenario.pipeline.assess(scenario.proposal()).require_assessed_action()
    decision = scenario.policy_engine.evaluate(action, DIAGNOSTIC)
    assert decision.decision is PolicyDecisionType.DENY

    with pytest.raises(ApprovalCreationRefused):
        scenario.approval_engine.request(
            approval_id=GOLDEN_APPROVAL_ID,
            action=action,
            agent=DIAGNOSTIC,
            decision=decision,
        )


def test_the_scenario_never_sets_an_outcome_by_hand() -> None:
    """A static check that the wiring layer assigns none of the governed values."""
    import pathlib

    import aegis.enterprise as enterprise

    text = (pathlib.Path(enterprise.__path__[0]) / "scenarios.py").read_text(encoding="utf-8")
    for forbidden in (
        '"risk":',
        '"blast_radius":',
        "VerificationStatus.VERIFIED",
        "PolicyDecisionType.ALLOW",
        "ApprovalStatus.",
        "model_copy",
    ):
        assert forbidden not in text, forbidden


def test_the_enterprise_never_imports_the_policy_engine() -> None:
    """A static check of actual imports, so prose about policy does not trip it.

    The simulator supplies data and effects. Deciding is the control plane's job, and the
    world and its execution boundary cannot even reach the engine that decides.
    """
    import ast
    import pathlib

    import aegis.enterprise as enterprise

    package = pathlib.Path(enterprise.__path__[0])
    offenders: list[str] = []
    for module in ("world.py", "mutations.py", "observations.py", "models.py"):
        tree = ast.parse((package / module).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                modules = [node.module or ""]
            elif isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            else:
                continue
            offenders += [
                f"{module}: {name}" for name in modules if name.startswith("aegis.core.policy")
            ]
    assert offenders == []


def test_a_changed_world_changes_what_the_run_concludes() -> None:
    """Pre-recovering payment-api makes the rollback unsupported, and it is reported so."""
    world = EnterpriseWorld()
    world.rollback(PAYMENT_API, PAYMENT_API_GOOD_VERSION)
    run = _fresh(world=world).run()

    assert run.execution.outcome is ExecutionOutcome.UNSUPPORTED
    assert "already running" in run.execution.detail
    # The world was already recovered, so verification still establishes the state.
    assert run.verification.status is VerificationStatus.VERIFIED
    assert run.resolved


def test_the_run_reports_the_incident_state_it_actually_reached() -> None:
    for failures, expected in (
        ((), IncidentState.RESOLVED),
        ((FailureType.ROLLBACK_FAILURE,), IncidentState.DEGRADED),
    ):
        run = _fresh().run(failures=failures)
        assert run.incident.state is expected
