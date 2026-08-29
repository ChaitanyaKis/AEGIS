"""The resolution invariant.

    There is no path from VERIFYING to RESOLVED without a VERIFIED result bound to the
    correct incident and action.

Everything here drives the real state machine and real verification engine. Nothing mocks
the guard, and no result is hand-constructed where the engine could produce one.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from aegis.core.domain import EvidenceType, IncidentState
from aegis.core.incidents import (
    IncidentStateMachine,
    InvalidIncidentTransition,
    TransitionGuard,
)
from aegis.core.verification import (
    VerificationEngine,
    VerificationResult,
    VerificationStatus,
)
from tests.fleet import (
    DEPLOYMENT_SOURCE,
    FIXED_EVALUATION_TIME,
    ORDER_SERVICE,
    PAYMENT_API,
    PAYMENT_API_RECOVERED,
    TELEMETRY_SOURCE,
    UNTRUSTED_SOURCE,
    build_action,
    build_incident,
    build_observation,
    healthy_observations,
)
from tests.verification.conftest import MovableClock


def _resolve(
    machine: IncidentStateMachine,
    verification: VerificationResult | None,
    action=None,
    *,
    incident_id: str = "INC-2026-0001",
):
    return machine.transition(
        build_incident(state=IncidentState.VERIFYING, incident_id=incident_id),
        IncidentState.RESOLVED,
        reason="verification complete",
        actor="system:verification",
        verification=verification,
        action=action,
    )


def _resolve_with(
    machine: IncidentStateMachine,
    verification: VerificationResult,
    action,
    *,
    proposed_actions: tuple[str, ...],
):
    """Resolve an incident that lists several proposed actions."""
    return machine.transition(
        build_incident(state=IncidentState.VERIFYING, proposed_actions=proposed_actions),
        IncidentState.RESOLVED,
        reason="verification complete",
        actor="system:verification",
        verification=verification,
        action=action,
    )


def _verify(engine: VerificationEngine, action, observations, expected=None):
    return engine.verify(
        action,
        expected or PAYMENT_API_RECOVERED,
        observations,
        verification_id="ver-001",
    )


# --- the positive path --------------------------------------------------------------


def test_a_verified_result_resolves_the_incident(
    machine: IncidentStateMachine, engine: VerificationEngine, rollback_action
) -> None:
    """Rollback to v4.7, observed healthy at 0.7% on v4.7 -> VERIFIED -> RESOLVED."""
    verification = _verify(engine, rollback_action, healthy_observations())
    assert verification.status is VerificationStatus.VERIFIED

    resolved = _resolve(machine, verification, rollback_action)
    assert resolved.state is IncidentState.RESOLVED


def test_the_resolving_transition_records_its_verification(
    machine: IncidentStateMachine, engine: VerificationEngine, rollback_action
) -> None:
    verification = _verify(engine, rollback_action, healthy_observations())
    result = machine.transition_detailed(
        build_incident(state=IncidentState.VERIFYING),
        IncidentState.RESOLVED,
        reason=verification.reason,
        actor="system:verification",
        verification=verification,
        action=rollback_action,
    )
    record = result.transition
    assert record.guard is TransitionGuard.VERIFICATION
    assert record.verification_id == "ver-001"
    assert record.action_fingerprint == verification.action_fingerprint
    assert record.to_state is IncidentState.RESOLVED


def test_the_guard_is_declared_on_the_edge() -> None:
    machine = IncidentStateMachine()
    assert machine.guard_for(IncidentState.VERIFYING, IncidentState.RESOLVED) is (
        TransitionGuard.VERIFICATION
    )


# --- the failure path ---------------------------------------------------------------


def test_a_failed_verification_cannot_resolve_but_can_degrade(
    machine: IncidentStateMachine, engine: VerificationEngine, rollback_action
) -> None:
    """Expected error_rate <= 1%, observed 8%. The failure stays visible."""
    observations = (
        build_observation(
            observation_id="obs-health",
            values={"health": "healthy", "error_rate": 8.0},
        ),
        healthy_observations()[1],
    )
    verification = _verify(engine, rollback_action, observations)
    assert verification.status is VerificationStatus.FAILED

    with pytest.raises(InvalidIncidentTransition, match="not VERIFIED"):
        _resolve(machine, verification, rollback_action)

    degraded = machine.transition(
        build_incident(state=IncidentState.VERIFYING),
        IncidentState.DEGRADED,
        reason=verification.reason,
        actor="system:verification",
    )
    assert degraded.state is IncidentState.DEGRADED


# --- the invariant ------------------------------------------------------------------


def _observations_for(case: str, clock: MovableClock):
    """Observation sets that each defeat verification in a different way."""
    match case:
        case "failed":
            return (
                build_observation(
                    observation_id="obs-health",
                    values={"health": "healthy", "error_rate": 8.0},
                ),
                healthy_observations()[1],
            )
        case "stale":
            return healthy_observations(observed_at=FIXED_EVALUATION_TIME - timedelta(hours=1))
        case "insufficient":
            return ()
        case "conflicting":
            return (
                *healthy_observations(),
                build_observation(
                    observation_id="obs-second-opinion",
                    values={"error_rate": 37.0},
                ),
            )
        case "tool-result-only":
            return (
                build_observation(
                    observation_id="obs-tool",
                    values={"health": "healthy", "error_rate": 0.0, "deployment": "v4.7"},
                    evidence_type=EvidenceType.TOOL_RESULT,
                ),
            )
        case "untrusted-source-only":
            return (
                build_observation(
                    observation_id="obs-external",
                    values={"health": "healthy", "error_rate": 0.0, "deployment": "v4.7"},
                    source=UNTRUSTED_SOURCE,
                ),
            )
        case "wrong-resource-only":
            return (
                build_observation(
                    observation_id="obs-order",
                    values={"health": "healthy", "error_rate": 0.0, "deployment": "v4.7"},
                    resource=ORDER_SERVICE,
                ),
            )
    raise AssertionError(f"unknown case {case}")


@pytest.mark.parametrize(
    "case",
    [
        "failed",
        "stale",
        "insufficient",
        "conflicting",
        "tool-result-only",
        "untrusted-source-only",
        "wrong-resource-only",
    ],
)
def test_no_unverified_evidence_can_resolve_an_incident(
    machine: IncidentStateMachine,
    engine: VerificationEngine,
    rollback_action,
    clock: MovableClock,
    case: str,
) -> None:
    verification = _verify(engine, rollback_action, _observations_for(case, clock))
    assert verification.status is not VerificationStatus.VERIFIED
    with pytest.raises(InvalidIncidentTransition):
        _resolve(machine, verification, rollback_action)


def test_no_verification_at_all_cannot_resolve(machine: IncidentStateMachine) -> None:
    """Absence is not proof."""
    with pytest.raises(InvalidIncidentTransition, match="none supplied"):
        _resolve(machine, None)


def test_a_verification_without_its_action_cannot_resolve(
    machine: IncidentStateMachine, engine: VerificationEngine, rollback_action
) -> None:
    """The result alone is not enough — the machine must see what it verified."""
    verification = _verify(engine, rollback_action, healthy_observations())
    assert verification.status is VerificationStatus.VERIFIED
    with pytest.raises(InvalidIncidentTransition, match="the action that was verified"):
        _resolve(machine, verification)


def test_an_execution_authorization_does_not_open_the_resolution_edge(
    machine: IncidentStateMachine,
) -> None:
    """A different guard's artifact is not a substitute."""
    with pytest.raises(InvalidIncidentTransition, match="none supplied"):
        machine.transition(
            build_incident(state=IncidentState.VERIFYING),
            IncidentState.RESOLVED,
            reason="approved earlier",
            actor="agent:remediation",
        )


# --- binding ------------------------------------------------------------------------


def test_a_verification_for_another_incident_cannot_resolve(
    machine: IncidentStateMachine, engine: VerificationEngine, rollback_action
) -> None:
    verification = _verify(engine, rollback_action, healthy_observations())
    with pytest.raises(InvalidIncidentTransition, match="belongs to incident"):
        _resolve(machine, verification, rollback_action, incident_id="INC-2026-0002")


def test_a_verification_for_another_action_cannot_resolve(
    machine: IncidentStateMachine, engine: VerificationEngine, pipeline
) -> None:
    """The incident's proposed actions are the only ones that can close it."""
    other = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
            action_id="act-999",
        )
    ).require_assessed_action()
    verification = _verify(engine, other, healthy_observations())
    assert verification.status is VerificationStatus.VERIFIED
    with pytest.raises(InvalidIncidentTransition, match="not one of this incident"):
        _resolve(machine, verification, other)


def test_a_verification_of_another_resource_cannot_resolve(
    machine: IncidentStateMachine,
    engine: VerificationEngine,
    pipeline,
    rollback_action,
) -> None:
    """Verifying order-service says nothing about a payment-api rollback."""
    order_action = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=ORDER_SERVICE,
        )
    ).require_assessed_action()
    order_expectation = PAYMENT_API_RECOVERED.model_copy(update={"resource": ORDER_SERVICE})
    order_observations = (
        build_observation(
            observation_id="obs-order-health",
            values={"health": "healthy", "error_rate": 0.7},
            resource=ORDER_SERVICE,
        ),
        build_observation(
            observation_id="obs-order-deployment",
            values={"deployment": "v4.7"},
            resource=ORDER_SERVICE,
            source=DEPLOYMENT_SOURCE,
            evidence_type=EvidenceType.DEPLOYMENT,
        ),
    )
    verification = engine.verify(
        order_action,
        order_expectation,
        order_observations,
        verification_id="ver-order",
    )
    assert verification.status is VerificationStatus.VERIFIED
    assert verification.resource == ORDER_SERVICE

    # It verifies a real thing — just not the resource this incident's action targeted.
    with pytest.raises(InvalidIncidentTransition, match="established the state of"):
        _resolve(machine, verification, rollback_action)


def test_a_verification_of_a_sibling_action_cannot_resolve(
    machine: IncidentStateMachine, engine: VerificationEngine, pipeline, rollback_action
) -> None:
    """Both actions belong to the incident, but only one of them was verified.

    Guards against resolving on the strength of a sibling remediation's success.
    """
    sibling = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
            action_id="act-002",
        )
    ).require_assessed_action()

    verification = _verify(engine, rollback_action, healthy_observations())
    assert verification.action_id == "act-001"

    with pytest.raises(InvalidIncidentTransition, match="verifies action"):
        _resolve_with(
            machine,
            verification,
            sibling,
            proposed_actions=("act-001", "act-002"),
        )


def test_an_action_edited_after_verification_cannot_resolve(
    machine: IncidentStateMachine, engine: VerificationEngine, rollback_action
) -> None:
    """Same id, same resource, different content. The fingerprint is what catches it."""
    verification = _verify(engine, rollback_action, healthy_observations())
    tampered = rollback_action.model_copy(
        update={"arguments": {"target_version": "v0.0.1-malicious"}}
    )
    assert tampered.action_id == rollback_action.action_id
    assert tampered.target_resource == rollback_action.target_resource

    with pytest.raises(InvalidIncidentTransition, match="changed after verification"):
        _resolve(machine, verification, tampered)


def test_a_verification_cannot_be_reused_across_incidents(
    machine: IncidentStateMachine, engine: VerificationEngine, rollback_action
) -> None:
    """One artifact, one incident. It is not a general-purpose resolution token."""
    verification = _verify(engine, rollback_action, healthy_observations())
    assert _resolve(machine, verification, rollback_action).state is IncidentState.RESOLVED
    for other in ("INC-2026-0002", "INC-2025-9999"):
        with pytest.raises(InvalidIncidentTransition):
            _resolve(machine, verification, rollback_action, incident_id=other)


# --- tool success is not verification -----------------------------------------------


def test_a_successful_tool_call_does_not_resolve_an_incident(
    machine: IncidentStateMachine, engine: VerificationEngine, rollback_action
) -> None:
    """The constitution's central claim, end to end.

    The tool reports a perfectly healthy service. Because that is execution metadata and
    not an independent observation, nothing is established and the incident stays open.
    """
    tool_says_everything_is_fine = (
        build_observation(
            observation_id="obs-tool",
            values={"health": "healthy", "error_rate": 0.0, "deployment": "v4.7"},
            source=TELEMETRY_SOURCE,
            evidence_type=EvidenceType.TOOL_RESULT,
        ),
    )
    verification = _verify(engine, rollback_action, tool_says_everything_is_fine)
    assert verification.status is VerificationStatus.INSUFFICIENT_EVIDENCE
    assert verification.observations_used == ()

    with pytest.raises(InvalidIncidentTransition):
        _resolve(machine, verification, rollback_action)


def test_the_same_readings_from_telemetry_do_resolve(
    machine: IncidentStateMachine, engine: VerificationEngine, rollback_action
) -> None:
    """The counterpart: identical values, but independently observed."""
    observations = (
        build_observation(
            observation_id="obs-telemetry",
            values={"health": "healthy", "error_rate": 0.0},
            evidence_type=EvidenceType.TELEMETRY,
        ),
        healthy_observations()[1],
    )
    verification = _verify(engine, rollback_action, observations)
    assert verification.status is VerificationStatus.VERIFIED
    assert _resolve(machine, verification, rollback_action).state is IncidentState.RESOLVED


# --- staleness at the guard ---------------------------------------------------------


def test_evidence_that_goes_cold_stops_resolving(
    machine: IncidentStateMachine,
    engine: VerificationEngine,
    rollback_action,
    clock: MovableClock,
) -> None:
    """Fresh at t1, verified. Evaluated much later, the same readings resolve nothing."""
    observations = healthy_observations()
    assert (
        _resolve(machine, _verify(engine, rollback_action, observations), rollback_action).state
        is IncidentState.RESOLVED
    )

    clock.advance(timedelta(hours=1))
    stale = _verify(engine, rollback_action, observations)
    assert stale.status is VerificationStatus.STALE
    with pytest.raises(InvalidIncidentTransition):
        _resolve(machine, stale, rollback_action)


def test_resolution_is_reproducible(
    machine: IncidentStateMachine, engine: VerificationEngine, rollback_action
) -> None:
    from aegis.core.domain import to_json

    observations = healthy_observations()
    first = _resolve(machine, _verify(engine, rollback_action, observations), rollback_action)
    second = _resolve(machine, _verify(engine, rollback_action, observations), rollback_action)
    assert to_json(first) == to_json(second)
