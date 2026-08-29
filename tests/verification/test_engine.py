"""Verification engine: predicates, freshness, sources, conflicts and bindings.

The engine's job is to be unpersuadable. It establishes enterprise state from independent
observations or it establishes nothing — and "nothing" is never reported as success.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from aegis.core.approval import action_fingerprint
from aegis.core.domain import EvidenceType, RiskLevel, to_json
from aegis.core.verification import (
    OBSERVABLE_EVIDENCE_TYPES,
    CheckOutcome,
    Comparator,
    ExpectedState,
    Observation,
    Predicate,
    VerificationEngine,
    VerificationRequestError,
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
    build_observation,
    healthy_observations,
)
from tests.verification.conftest import MovableClock


def _verify(engine: VerificationEngine, action, observations, expected=None):
    return engine.verify(
        action,
        expected or PAYMENT_API_RECOVERED,
        observations,
        verification_id="ver-001",
    )


# --- the success path ---------------------------------------------------------------


def test_fresh_trusted_observations_verify(engine: VerificationEngine, rollback_action) -> None:
    """Golden incident: health healthy, error rate 0.7%, deployment v4.7."""
    result = _verify(engine, rollback_action, healthy_observations())
    assert result.status is VerificationStatus.VERIFIED
    assert result.verified
    assert [check.outcome for check in result.checks] == [CheckOutcome.PASS] * 3
    assert result.observations_used == ("obs-deployment", "obs-health")


def test_a_verified_result_is_bound_to_its_action_and_incident(
    engine: VerificationEngine, rollback_action
) -> None:
    result = _verify(engine, rollback_action, healthy_observations())
    assert result.incident_id == rollback_action.incident_id
    assert result.action_id == rollback_action.action_id
    assert result.resource == rollback_action.target_resource
    assert result.action_fingerprint == action_fingerprint(rollback_action)


def test_checks_explain_the_result_from_data(engine: VerificationEngine, rollback_action) -> None:
    """ "Why verified?" is answerable without a model."""
    result = _verify(engine, rollback_action, healthy_observations())
    by_attribute = {check.attribute: check for check in result.checks}
    assert by_attribute["error_rate"].expected == 1.0
    assert by_attribute["error_rate"].observed == 0.7
    assert by_attribute["error_rate"].comparator is Comparator.AT_MOST
    assert by_attribute["error_rate"].observation_ids == ("obs-health",)
    assert "observed 0.7 -> PASS" in by_attribute["error_rate"].detail
    assert by_attribute["deployment"].observation_ids == ("obs-deployment",)


def test_boundary_values_satisfy_ordered_comparisons(
    engine: VerificationEngine, rollback_action
) -> None:
    """AT_MOST is inclusive: exactly at the bound passes."""
    observations = (
        build_observation(
            observation_id="obs-health",
            values={"health": "healthy", "error_rate": 1.0},
        ),
        healthy_observations()[1],
    )
    assert _verify(engine, rollback_action, observations).status is (VerificationStatus.VERIFIED)


# --- predicate failure --------------------------------------------------------------


def test_a_failing_predicate_fails_the_verification(
    engine: VerificationEngine, rollback_action
) -> None:
    observations = (
        build_observation(
            observation_id="obs-health",
            values={"health": "healthy", "error_rate": 8.0},
        ),
        healthy_observations()[1],
    )
    result = _verify(engine, rollback_action, observations)
    assert result.status is VerificationStatus.FAILED
    assert not result.verified
    failing = [c for c in result.checks if c.outcome is CheckOutcome.FAIL]
    assert [c.attribute for c in failing] == ["error_rate"]
    assert failing[0].observed == 8.0


def test_a_categorical_mismatch_fails(engine: VerificationEngine, rollback_action) -> None:
    observations = (
        build_observation(
            observation_id="obs-health",
            values={"health": "degraded", "error_rate": 0.7},
        ),
        healthy_observations()[1],
    )
    assert _verify(engine, rollback_action, observations).status is (VerificationStatus.FAILED)


def test_a_wrong_deployment_version_fails(engine: VerificationEngine, rollback_action) -> None:
    """The rollback did not actually land."""
    observations = (
        healthy_observations()[0],
        build_observation(
            observation_id="obs-deployment",
            values={"deployment": "v4.8"},
            source=DEPLOYMENT_SOURCE,
            evidence_type=EvidenceType.DEPLOYMENT,
        ),
    )
    result = _verify(engine, rollback_action, observations)
    assert result.status is VerificationStatus.FAILED


def test_a_categorical_value_cannot_satisfy_an_ordered_comparison(
    engine: VerificationEngine, rollback_action
) -> None:
    observations = (
        build_observation(
            observation_id="obs-health",
            values={"health": "healthy", "error_rate": "low"},
        ),
        healthy_observations()[1],
    )
    assert _verify(engine, rollback_action, observations).status is (VerificationStatus.FAILED)


# --- missing evidence ---------------------------------------------------------------


def test_no_observations_at_all_is_insufficient_evidence(
    engine: VerificationEngine, rollback_action
) -> None:
    """Missing data is never success."""
    result = _verify(engine, rollback_action, ())
    assert result.status is VerificationStatus.INSUFFICIENT_EVIDENCE
    assert all(check.outcome is CheckOutcome.MISSING for check in result.checks)
    assert all(check.observed is None for check in result.checks)
    assert result.observations_used == ()


def test_a_missing_required_attribute_is_insufficient_evidence(
    engine: VerificationEngine, rollback_action
) -> None:
    """Two of three predicates satisfied is not two-thirds verified."""
    result = _verify(engine, rollback_action, (healthy_observations()[0],))
    assert result.status is VerificationStatus.INSUFFICIENT_EVIDENCE
    by_attribute = {check.attribute: check for check in result.checks}
    assert by_attribute["health"].outcome is CheckOutcome.PASS
    assert by_attribute["deployment"].outcome is CheckOutcome.MISSING


# --- freshness ----------------------------------------------------------------------


def test_stale_observations_cannot_verify(
    engine: VerificationEngine, rollback_action, clock: MovableClock
) -> None:
    observations = healthy_observations()
    clock.advance(timedelta(minutes=6))
    result = _verify(engine, rollback_action, observations)
    assert result.status is VerificationStatus.STALE
    assert all(check.outcome is CheckOutcome.STALE for check in result.checks)


def test_an_observation_at_the_freshness_boundary_is_still_usable(
    engine: VerificationEngine, rollback_action, clock: MovableClock
) -> None:
    observations = healthy_observations()
    clock.advance(timedelta(minutes=5))
    assert _verify(engine, rollback_action, observations).status is (VerificationStatus.VERIFIED)


def test_one_stale_attribute_blocks_the_whole_verification(
    engine: VerificationEngine, rollback_action
) -> None:
    observations = (
        healthy_observations()[0],
        build_observation(
            observation_id="obs-deployment",
            values={"deployment": "v4.7"},
            source=DEPLOYMENT_SOURCE,
            evidence_type=EvidenceType.DEPLOYMENT,
            observed_at=FIXED_EVALUATION_TIME - timedelta(hours=1),
        ),
    )
    result = _verify(engine, rollback_action, observations)
    assert result.status is VerificationStatus.STALE
    by_attribute = {check.attribute: check for check in result.checks}
    assert by_attribute["deployment"].outcome is CheckOutcome.STALE
    assert by_attribute["health"].outcome is CheckOutcome.PASS


def test_stale_is_distinguished_from_missing(engine: VerificationEngine, rollback_action) -> None:
    """ "The data went cold" and "nobody is watching" call for different responses."""
    stale_only = (
        build_observation(
            observation_id="obs-health",
            values={"health": "healthy", "error_rate": 0.7},
            observed_at=FIXED_EVALUATION_TIME - timedelta(hours=1),
        ),
    )
    result = _verify(engine, rollback_action, stale_only)
    by_attribute = {check.attribute: check for check in result.checks}
    assert by_attribute["health"].outcome is CheckOutcome.STALE
    assert by_attribute["deployment"].outcome is CheckOutcome.MISSING
    assert result.status is VerificationStatus.INSUFFICIENT_EVIDENCE


def test_a_fresh_observation_becomes_stale_as_the_clock_advances(
    engine: VerificationEngine, rollback_action, clock: MovableClock
) -> None:
    observations = healthy_observations()
    assert _verify(engine, rollback_action, observations).status is (VerificationStatus.VERIFIED)
    clock.advance(timedelta(minutes=5, seconds=1))
    assert _verify(engine, rollback_action, observations).status is (VerificationStatus.STALE)


def test_an_explicit_evaluation_time_overrides_the_clock(
    engine: VerificationEngine, rollback_action
) -> None:
    result = engine.verify(
        rollback_action,
        PAYMENT_API_RECOVERED,
        healthy_observations(),
        verification_id="ver-001",
        evaluated_at=FIXED_EVALUATION_TIME + timedelta(hours=2),
    )
    assert result.status is VerificationStatus.STALE


# --- conflicting evidence -----------------------------------------------------------


def test_conflicting_observations_produce_a_mismatch(
    engine: VerificationEngine, rollback_action
) -> None:
    """0.7% from one source, 37% from another. The engine does not pick a winner."""
    observations = (
        *healthy_observations(),
        build_observation(
            observation_id="obs-second-opinion",
            values={"error_rate": 37.0},
        ),
    )
    result = _verify(engine, rollback_action, observations)
    assert result.status is VerificationStatus.MISMATCH
    conflicted = [c for c in result.checks if c.outcome is CheckOutcome.CONFLICT]
    assert [c.attribute for c in conflicted] == ["error_rate"]
    assert conflicted[0].observed is None
    assert set(conflicted[0].observation_ids) == {"obs-health", "obs-second-opinion"}


def test_conflict_applies_even_when_both_values_would_pass(
    engine: VerificationEngine, rollback_action
) -> None:
    """Contradictory sources mean the state is unknown, however benign each reading is."""
    observations = (
        *healthy_observations(),
        build_observation(observation_id="obs-second-opinion", values={"error_rate": 0.5}),
    )
    assert _verify(engine, rollback_action, observations).status is (VerificationStatus.MISMATCH)


def test_agreeing_observations_are_not_a_conflict(
    engine: VerificationEngine, rollback_action
) -> None:
    observations = (
        *healthy_observations(),
        build_observation(observation_id="obs-confirm", values={"error_rate": 0.7}),
    )
    result = _verify(engine, rollback_action, observations)
    assert result.status is VerificationStatus.VERIFIED
    error_rate = next(c for c in result.checks if c.attribute == "error_rate")
    assert set(error_rate.observation_ids) == {"obs-health", "obs-confirm"}


def test_a_stale_dissenting_observation_does_not_create_a_conflict(
    engine: VerificationEngine, rollback_action
) -> None:
    """Only usable observations can contradict each other."""
    observations = (
        *healthy_observations(),
        build_observation(
            observation_id="obs-old",
            values={"error_rate": 37.0},
            observed_at=FIXED_EVALUATION_TIME - timedelta(hours=1),
        ),
    )
    assert _verify(engine, rollback_action, observations).status is (VerificationStatus.VERIFIED)


# --- tool results are not observations ----------------------------------------------


def test_a_tool_result_cannot_verify_anything(engine: VerificationEngine, rollback_action) -> None:
    """The central rule: HTTP 200 is not enterprise truth (claude.md section 11)."""
    tool_says_success = (
        build_observation(
            observation_id="obs-tool",
            values={"health": "healthy", "error_rate": 0.0, "deployment": "v4.7"},
            source=TELEMETRY_SOURCE,
            evidence_type=EvidenceType.TOOL_RESULT,
        ),
    )
    result = _verify(engine, rollback_action, tool_says_success)
    assert result.status is VerificationStatus.INSUFFICIENT_EVIDENCE
    assert result.observations_used == ()


def test_tool_result_is_not_an_observable_evidence_type() -> None:
    assert EvidenceType.TOOL_RESULT not in OBSERVABLE_EVIDENCE_TYPES


@pytest.mark.parametrize(
    "evidence_type",
    [
        EvidenceType.TOOL_RESULT,
        EvidenceType.AGENT_FINDING,
        EvidenceType.HUMAN_INPUT,
        EvidenceType.MEMORY,
        EvidenceType.VERIFICATION,
    ],
    ids=lambda value: value.value,
)
def test_non_observable_evidence_types_are_ignored(
    engine: VerificationEngine, rollback_action, evidence_type: EvidenceType
) -> None:
    observations = (
        build_observation(
            observation_id="obs-claim",
            values={"health": "healthy", "error_rate": 0.0, "deployment": "v4.7"},
            evidence_type=evidence_type,
        ),
    )
    assert _verify(engine, rollback_action, observations).status is (
        VerificationStatus.INSUFFICIENT_EVIDENCE
    )


def test_an_agents_own_finding_cannot_verify_its_own_remediation(
    engine: VerificationEngine, rollback_action
) -> None:
    """Trust zone B is not authoritative, least of all about its own work."""
    observations = (
        *healthy_observations(),
        build_observation(
            observation_id="obs-agent",
            values={"error_rate": 0.0},
            evidence_type=EvidenceType.AGENT_FINDING,
        ),
    )
    result = _verify(engine, rollback_action, observations)
    assert "obs-agent" not in result.observations_used
    assert result.status is VerificationStatus.VERIFIED


# --- source trust -------------------------------------------------------------------


def test_an_unaccepted_source_is_ignored(engine: VerificationEngine, rollback_action) -> None:
    observations = (
        build_observation(
            observation_id="obs-external",
            values={"health": "healthy", "error_rate": 0.0, "deployment": "v4.7"},
            source=UNTRUSTED_SOURCE,
        ),
    )
    result = _verify(engine, rollback_action, observations)
    assert result.status is VerificationStatus.INSUFFICIENT_EVIDENCE
    assert result.observations_used == ()


def test_an_untrusted_source_cannot_contradict_a_trusted_one(
    engine: VerificationEngine, rollback_action
) -> None:
    """An external payload is ignored, not weighed — so it cannot even force a MISMATCH."""
    observations = (
        *healthy_observations(),
        build_observation(
            observation_id="obs-external",
            values={"error_rate": 37.0},
            source=UNTRUSTED_SOURCE,
        ),
    )
    assert _verify(engine, rollback_action, observations).status is (VerificationStatus.VERIFIED)


# --- resource binding ---------------------------------------------------------------


def test_an_observation_of_another_resource_is_ignored(
    engine: VerificationEngine, rollback_action
) -> None:
    """A dependent service's health does not establish the target's."""
    observations = (
        build_observation(
            observation_id="obs-order",
            values={"health": "healthy", "error_rate": 0.0, "deployment": "v4.7"},
            resource=ORDER_SERVICE,
        ),
    )
    result = _verify(engine, rollback_action, observations)
    assert result.status is VerificationStatus.INSUFFICIENT_EVIDENCE


def test_a_dependent_observation_supplements_but_never_substitutes(
    engine: VerificationEngine, rollback_action
) -> None:
    observations = (
        *healthy_observations(),
        build_observation(
            observation_id="obs-order",
            values={"health": "healthy"},
            resource=ORDER_SERVICE,
        ),
    )
    result = _verify(engine, rollback_action, observations)
    assert result.status is VerificationStatus.VERIFIED
    assert "obs-order" not in result.observations_used


def test_an_expectation_for_the_wrong_resource_is_a_wiring_error(
    engine: VerificationEngine, rollback_action
) -> None:
    wrong = PAYMENT_API_RECOVERED.model_copy(update={"resource": ORDER_SERVICE})
    with pytest.raises(VerificationRequestError, match="targets"):
        engine.verify(rollback_action, wrong, healthy_observations(), verification_id="ver-001")


# --- status precedence --------------------------------------------------------------


def test_evidential_problems_outrank_evaluation_problems(
    engine: VerificationEngine, rollback_action
) -> None:
    """One predicate fails outright, another has no evidence: report the weaker position."""
    observations = (build_observation(observation_id="obs-health", values={"error_rate": 8.0}),)
    result = _verify(engine, rollback_action, observations)
    by_attribute = {check.attribute: check for check in result.checks}
    assert by_attribute["error_rate"].outcome is CheckOutcome.FAIL
    assert by_attribute["health"].outcome is CheckOutcome.MISSING
    assert result.status is VerificationStatus.INSUFFICIENT_EVIDENCE


def test_stale_outranks_failed(engine: VerificationEngine, rollback_action) -> None:
    observations = (
        build_observation(
            observation_id="obs-health",
            values={"health": "healthy", "error_rate": 8.0},
        ),
        build_observation(
            observation_id="obs-deployment",
            values={"deployment": "v4.7"},
            source=DEPLOYMENT_SOURCE,
            evidence_type=EvidenceType.DEPLOYMENT,
            observed_at=FIXED_EVALUATION_TIME - timedelta(hours=1),
        ),
    )
    assert _verify(engine, rollback_action, observations).status is (VerificationStatus.STALE)


# --- model invariants ---------------------------------------------------------------


def test_ordered_comparisons_reject_a_categorical_bound() -> None:
    with pytest.raises(ValidationError, match="requires a numeric value"):
        Predicate(attribute="error_rate", comparator=Comparator.AT_MOST, value="low")


@pytest.mark.parametrize(
    "update",
    [
        {"predicates": ()},
        {"accepted_sources": ()},
        {"max_observation_age": timedelta(0)},
    ],
    ids=["no-predicates", "no-accepted-sources", "no-freshness-window"],
)
def test_an_expectation_needs_predicates_sources_and_a_window(update: dict) -> None:
    """Each omission would quietly widen what counts as verified."""
    fields = {**PAYMENT_API_RECOVERED.model_dump(), **update}
    with pytest.raises(ValidationError):
        ExpectedState(**fields)


def test_an_observation_needs_at_least_one_value() -> None:
    with pytest.raises(ValidationError):
        build_observation(values={})


def test_observation_provenance_is_reachable() -> None:
    observation = build_observation(values={"health": "healthy"})
    assert observation.observation_id == "obs-001"
    assert observation.source == TELEMETRY_SOURCE
    assert observation.observed_at == FIXED_EVALUATION_TIME
    assert observation.resource == PAYMENT_API
    assert observation.is_observable


def test_verification_models_are_frozen_and_closed() -> None:
    for model in (Observation, ExpectedState, Predicate, VerificationResult):
        assert model.model_config["frozen"] is True
        assert model.model_config["extra"] == "forbid"


def test_verification_has_exactly_five_statuses() -> None:
    assert [status.name for status in VerificationStatus] == [
        "VERIFIED",
        "FAILED",
        "STALE",
        "MISMATCH",
        "INSUFFICIENT_EVIDENCE",
    ]


# --- determinism --------------------------------------------------------------------


def test_repeated_verification_is_byte_identical(
    engine: VerificationEngine, rollback_action
) -> None:
    observations = healthy_observations()
    assert to_json(_verify(engine, rollback_action, observations)) == to_json(
        _verify(engine, rollback_action, observations)
    )


def test_observation_order_does_not_change_the_result(
    engine: VerificationEngine, rollback_action
) -> None:
    observations = healthy_observations()
    assert to_json(_verify(engine, rollback_action, observations)) == to_json(
        _verify(engine, rollback_action, tuple(reversed(observations)))
    )


def test_the_engine_holds_no_state(engine: VerificationEngine, rollback_action) -> None:
    observations = healthy_observations()
    first = _verify(engine, rollback_action, observations)
    _verify(engine, rollback_action, ())
    assert to_json(_verify(engine, rollback_action, observations)) == to_json(first)


def test_verification_does_not_mutate_its_inputs(
    engine: VerificationEngine, rollback_action
) -> None:
    observations = healthy_observations()
    before = [to_json(observation) for observation in observations]
    action_before = to_json(rollback_action)
    _verify(engine, rollback_action, observations)
    assert [to_json(observation) for observation in observations] == before
    assert to_json(rollback_action) == action_before


def test_a_result_round_trips_through_serialization(
    engine: VerificationEngine, rollback_action
) -> None:
    from aegis.core.domain import from_json

    result = _verify(engine, rollback_action, healthy_observations())
    assert from_json(VerificationResult, to_json(result)) == result


def test_the_assessed_risk_is_irrelevant_to_verification(
    engine: VerificationEngine, rollback_action
) -> None:
    """Verification measures the world, not the plan."""
    downgraded = rollback_action.model_copy(update={"risk": RiskLevel.LOW})
    assert (
        _verify(engine, downgraded, healthy_observations()).status
        is _verify(engine, rollback_action, healthy_observations()).status
    )
