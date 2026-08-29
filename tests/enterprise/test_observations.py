"""The observation source: it reports what the world shows, and nothing else."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from aegis.core.dependencies import UnknownResourceError
from aegis.core.domain import EvidenceType, to_json
from aegis.core.verification import (
    OBSERVABLE_EVIDENCE_TYPES,
    VerificationEngine,
    VerificationStatus,
)
from aegis.enterprise import (
    ORDER_SERVICE,
    PAYMENT_API,
    PAYMENT_API_GOOD_VERSION,
    PAYMENT_API_RECOVERED,
    STALE_TELEMETRY_OFFSET,
    EnterpriseWorld,
    FailureType,
    ObservationSource,
    ServiceHealth,
)
from tests.enterprise.conftest import MovableClock
from tests.fleet import FIXED_EVALUATION_TIME

AT = FIXED_EVALUATION_TIME


# --- what the source reports --------------------------------------------------------


def test_observations_reflect_the_current_world(source: ObservationSource) -> None:
    telemetry, deployment = source.observe(PAYMENT_API, at=AT)
    assert telemetry.values == {"error_rate": 37.0, "health": "unhealthy"}
    assert deployment.values == {"deployment": "v4.8"}


def test_changing_the_world_changes_the_observations(
    source: ObservationSource, world: EnterpriseWorld
) -> None:
    before = source.observe(PAYMENT_API, at=AT)
    world.rollback(PAYMENT_API, PAYMENT_API_GOOD_VERSION)
    after = source.observe(PAYMENT_API, at=AT)

    assert before[0].values["health"] == "unhealthy"
    assert after[0].values == {"error_rate": 0.7, "health": "healthy"}
    assert after[1].values == {"deployment": PAYMENT_API_GOOD_VERSION}


def test_observing_never_changes_the_world(
    source: ObservationSource, world: EnterpriseWorld
) -> None:
    before = to_json(world.snapshot())
    source.observe(PAYMENT_API, at=AT)
    source.observe_all(at=AT)
    assert to_json(world.snapshot()) == before


def test_an_observation_cannot_be_edited(source: ObservationSource) -> None:
    observation = source.observe(PAYMENT_API, at=AT)[0]
    with pytest.raises(ValidationError):
        observation.resource = ORDER_SERVICE  # type: ignore[misc]


def test_editing_a_copy_of_an_observation_cannot_reach_the_world(
    source: ObservationSource, world: EnterpriseWorld
) -> None:
    observation = source.observe(PAYMENT_API, at=AT)[0]
    observation.model_copy(update={"values": {"health": "healthy", "error_rate": 0.0}})
    assert world.state(PAYMENT_API).health is ServiceHealth.UNHEALTHY
    assert source.observe(PAYMENT_API, at=AT)[0].values["health"] == "unhealthy"


# --- provenance and trust boundary --------------------------------------------------


def test_evidence_types_are_ones_verification_already_accepts(
    source: ObservationSource,
) -> None:
    """The simulator adapts to the contract; the allowlist was not widened for it."""
    telemetry, deployment = source.observe(PAYMENT_API, at=AT)
    assert telemetry.evidence.type is EvidenceType.TELEMETRY
    assert deployment.evidence.type is EvidenceType.DEPLOYMENT
    assert telemetry.evidence.type in OBSERVABLE_EVIDENCE_TYPES
    assert deployment.evidence.type in OBSERVABLE_EVIDENCE_TYPES


def test_no_observation_is_ever_a_tool_result(source: ObservationSource) -> None:
    """A tool reporting success must never be able to establish enterprise state."""
    for observation in source.observe_all(at=AT):
        assert observation.evidence.type is not EvidenceType.TOOL_RESULT
        assert observation.is_observable


def test_sources_match_what_the_expectation_trusts(source: ObservationSource) -> None:
    telemetry, deployment = source.observe(PAYMENT_API, at=AT)
    assert telemetry.source == "telemetry.payment-api"
    assert deployment.source == "deployments.payment-api"
    assert telemetry.source in PAYMENT_API_RECOVERED.accepted_sources
    assert deployment.source in PAYMENT_API_RECOVERED.accepted_sources


def test_observations_carry_full_provenance(source: ObservationSource) -> None:
    telemetry = source.observe(PAYMENT_API, at=AT)[0]
    assert telemetry.resource == PAYMENT_API
    assert telemetry.observed_at == AT
    assert telemetry.observation_id
    assert telemetry.evidence.reference
    assert 0.0 <= telemetry.evidence.confidence <= 1.0


def test_resource_binding_is_exact(source: ObservationSource) -> None:
    for observation in source.observe(ORDER_SERVICE, at=AT):
        assert observation.resource == ORDER_SERVICE
        assert observation.source.endswith("order-service")


def test_an_unknown_resource_produces_no_observation(source: ObservationSource) -> None:
    """Never a reassuring one, and never an empty tuple that could read as 'all fine'."""
    with pytest.raises(UnknownResourceError):
        source.observe("service:totally-unknown", at=AT)


# --- determinism --------------------------------------------------------------------


def test_the_same_world_and_time_produce_identical_observations(
    source: ObservationSource,
) -> None:
    first = source.observe(PAYMENT_API, at=AT)
    second = source.observe(PAYMENT_API, at=AT)
    assert [to_json(o) for o in first] == [to_json(o) for o in second]


def test_two_identical_worlds_observe_identically() -> None:
    first = ObservationSource(EnterpriseWorld()).observe_all(at=AT)
    second = ObservationSource(EnterpriseWorld()).observe_all(at=AT)
    assert [to_json(o) for o in first] == [to_json(o) for o in second]


def test_observation_ids_are_derived_not_generated(source: ObservationSource) -> None:
    telemetry, deployment = source.observe(PAYMENT_API, at=AT)
    assert telemetry.observation_id == "obs-telemetry-payment-api-20260101T120000Z"
    assert deployment.observation_id == "obs-deployment-payment-api-20260101T120000Z"


def test_the_injected_timestamp_is_respected(source: ObservationSource) -> None:
    later = AT + timedelta(minutes=3)
    assert source.observe(PAYMENT_API, at=later)[0].observed_at == later


def test_the_source_never_reads_a_clock() -> None:
    """The scenario controls time, so freshness behaviour stays predictable."""
    import pathlib

    import aegis.enterprise as enterprise

    source_file = pathlib.Path(enterprise.__path__[0]) / "observations.py"
    text = source_file.read_text(encoding="utf-8")
    assert "datetime.now" not in text
    assert "utc_now" not in text


def test_observe_all_covers_every_resource_in_order(source: ObservationSource) -> None:
    observations = source.observe_all(at=AT)
    resources = [observation.resource for observation in observations]
    assert resources == sorted(resources)
    assert len(set(resources)) == 8


# --- the source feeds the real verification engine ----------------------------------


def test_simulated_observations_verify_a_real_rollback(
    source: ObservationSource, world: EnterpriseWorld, clock: MovableClock
) -> None:
    """The whole point: hand-written fixtures are no longer needed."""
    from aegis.core.domain import Action

    action = Action(
        action_id="act-001",
        incident_id="INC-2026-0001",
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_API,
    )
    engine = VerificationEngine(clock=clock)

    before = engine.verify(
        action, PAYMENT_API_RECOVERED, source.observe(PAYMENT_API, at=AT), verification_id="v1"
    )
    assert before.status is VerificationStatus.FAILED

    world.rollback(PAYMENT_API, PAYMENT_API_GOOD_VERSION)
    after = engine.verify(
        action, PAYMENT_API_RECOVERED, source.observe(PAYMENT_API, at=AT), verification_id="v2"
    )
    assert after.status is VerificationStatus.VERIFIED


# --- observation-layer failures -----------------------------------------------------


def test_stale_telemetry_backdates_measurements(
    source: ObservationSource, world: EnterpriseWorld
) -> None:
    world.inject_failure(FailureType.STALE_TELEMETRY)
    for observation in source.observe(PAYMENT_API, at=AT):
        assert observation.observed_at == AT - STALE_TELEMETRY_OFFSET


def test_stale_telemetry_still_reports_accurate_values(
    source: ObservationSource, world: EnterpriseWorld
) -> None:
    """The readings are true; they are simply too old to establish the state now."""
    world.rollback(PAYMENT_API, PAYMENT_API_GOOD_VERSION)
    world.inject_failure(FailureType.STALE_TELEMETRY)
    telemetry = source.observe(PAYMENT_API, at=AT)[0]
    assert telemetry.values["health"] == "healthy"
    assert telemetry.observed_at < AT


def test_stale_telemetry_is_beyond_any_reasonable_window() -> None:
    assert PAYMENT_API_RECOVERED.max_observation_age < STALE_TELEMETRY_OFFSET


def test_verification_failure_takes_the_telemetry_source_dark(
    source: ObservationSource, world: EnterpriseWorld
) -> None:
    world.inject_failure(FailureType.VERIFICATION_FAILURE)
    observations = source.observe(PAYMENT_API, at=AT)
    assert len(observations) == 1
    assert observations[0].evidence.type is EvidenceType.DEPLOYMENT
    assert "health" not in observations[0].values


def test_verification_failure_leaves_the_world_alone(
    source: ObservationSource, world: EnterpriseWorld
) -> None:
    """An observation-layer failure changes what is seen, not what is true."""
    world.rollback(PAYMENT_API, PAYMENT_API_GOOD_VERSION)
    world.inject_failure(FailureType.VERIFICATION_FAILURE)
    before = world.snapshot().resources

    source.observe(PAYMENT_API, at=AT)

    assert world.snapshot().resources == before
    assert world.state(PAYMENT_API).health is ServiceHealth.HEALTHY


def test_execution_layer_failures_do_not_touch_observations(
    source: ObservationSource, world: EnterpriseWorld
) -> None:
    """Each failure affects the smallest layer that can produce it."""
    baseline = [to_json(o) for o in source.observe(PAYMENT_API, at=AT)]
    for failure in (
        FailureType.TOOL_TIMEOUT,
        FailureType.TOOL_500,
        FailureType.ROLLBACK_FAILURE,
    ):
        world.clear_failures()
        world.inject_failure(failure)
        assert [to_json(o) for o in source.observe(PAYMENT_API, at=AT)] == baseline
