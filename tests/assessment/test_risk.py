"""Risk engine behaviour: conservatism, monotonicity and explainability."""

from __future__ import annotations

import pytest

from aegis.core.assessment import (
    IRREVERSIBLE_FLOOR,
    RISK_ORDER,
    SENSITIVITY_FLOORS,
    RiskEngine,
    max_risk,
)
from aegis.core.domain import (
    BlastRadius,
    Capability,
    DataClassification,
    RiskLevel,
    to_json,
)
from tests.fleet import (
    CUSTOMER_NOTIFY,
    PAYMENT_API,
    PRODUCTION_ROLLBACK,
    TELEMETRY_READ,
    build_action,
)

ACTION = build_action(
    requesting_agent="remediation",
    capability="production.rollback",
    target_resource=PAYMENT_API,
)


def _blast(impact: RiskLevel, size: int = 1) -> BlastRadius:
    return BlastRadius(scope=tuple(f"service:r{index}" for index in range(size)), impact=impact)


def _risk(engine: RiskEngine, capability: Capability, impact: RiskLevel) -> RiskLevel:
    return engine.assess(ACTION, capability, _blast(impact)).risk


# --- the scale ----------------------------------------------------------------------


def test_risk_order_is_low_to_critical() -> None:
    assert [level for level, _ in sorted(RISK_ORDER.items(), key=lambda item: item[1])] == [
        RiskLevel.LOW,
        RiskLevel.MEDIUM,
        RiskLevel.HIGH,
        RiskLevel.CRITICAL,
    ]


def test_max_risk_picks_the_most_severe() -> None:
    assert max_risk([RiskLevel.LOW, RiskLevel.CRITICAL, RiskLevel.MEDIUM]) is (RiskLevel.CRITICAL)
    assert max_risk([RiskLevel.LOW]) is RiskLevel.LOW


def test_max_risk_refuses_an_empty_input() -> None:
    """There is no neutral element: absence must not become LOW."""
    with pytest.raises(ValueError, match="at least one"):
        max_risk([])


# --- basic outcomes -----------------------------------------------------------------


def test_low_capability_with_low_blast_radius_is_low(risk_engine: RiskEngine) -> None:
    assert _risk(risk_engine, TELEMETRY_READ, RiskLevel.LOW) is RiskLevel.LOW


def test_high_capability_cannot_become_low(risk_engine: RiskEngine) -> None:
    """A reversible, unreaching HIGH capability is still HIGH."""
    assert PRODUCTION_ROLLBACK.risk_class is RiskLevel.HIGH
    assert PRODUCTION_ROLLBACK.reversible
    assert _risk(risk_engine, PRODUCTION_ROLLBACK, RiskLevel.LOW) is RiskLevel.HIGH


def test_critical_capability_cannot_become_low(risk_engine: RiskEngine) -> None:
    critical = TELEMETRY_READ.model_copy(update={"risk_class": RiskLevel.CRITICAL})
    assert _risk(risk_engine, critical, RiskLevel.LOW) is RiskLevel.CRITICAL


def test_irreversibility_alone_lifts_risk(risk_engine: RiskEngine) -> None:
    assert CUSTOMER_NOTIFY.risk_class is RiskLevel.LOW
    assert not CUSTOMER_NOTIFY.reversible
    assert _risk(risk_engine, CUSTOMER_NOTIFY, RiskLevel.LOW) is IRREVERSIBLE_FLOOR


def test_restricted_data_lifts_risk(risk_engine: RiskEngine) -> None:
    restricted = TELEMETRY_READ.model_copy(
        update={"data_classification": DataClassification.RESTRICTED}
    )
    assert _risk(risk_engine, restricted, RiskLevel.LOW) is RiskLevel.HIGH


def test_blast_radius_alone_lifts_risk(risk_engine: RiskEngine) -> None:
    assert _risk(risk_engine, TELEMETRY_READ, RiskLevel.CRITICAL) is RiskLevel.CRITICAL


# --- monotonicity -------------------------------------------------------------------


@pytest.mark.parametrize("impact", list(RiskLevel))
def test_risk_is_never_below_the_capability_risk_class(
    risk_engine: RiskEngine, impact: RiskLevel
) -> None:
    for risk_class in RiskLevel:
        capability = TELEMETRY_READ.model_copy(update={"risk_class": risk_class})
        assert RISK_ORDER[_risk(risk_engine, capability, impact)] >= RISK_ORDER[risk_class]


@pytest.mark.parametrize("risk_class", list(RiskLevel))
def test_risk_is_never_below_the_blast_radius_impact(
    risk_engine: RiskEngine, risk_class: RiskLevel
) -> None:
    capability = TELEMETRY_READ.model_copy(update={"risk_class": risk_class})
    for impact in RiskLevel:
        assert RISK_ORDER[_risk(risk_engine, capability, impact)] >= RISK_ORDER[impact]


def test_raising_the_capability_risk_class_never_lowers_risk(
    risk_engine: RiskEngine,
) -> None:
    previous = -1
    for risk_class in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
        capability = TELEMETRY_READ.model_copy(update={"risk_class": risk_class})
        rank = RISK_ORDER[_risk(risk_engine, capability, RiskLevel.MEDIUM)]
        assert rank >= previous
        previous = rank


def test_raising_the_blast_radius_never_lowers_risk(risk_engine: RiskEngine) -> None:
    previous = -1
    for impact in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
        rank = RISK_ORDER[_risk(risk_engine, PRODUCTION_ROLLBACK, impact)]
        assert rank >= previous
        previous = rank


def test_removing_reversibility_never_lowers_risk(risk_engine: RiskEngine) -> None:
    for risk_class in RiskLevel:
        for impact in RiskLevel:
            reversible = TELEMETRY_READ.model_copy(
                update={"risk_class": risk_class, "reversible": True}
            )
            irreversible = reversible.model_copy(update={"reversible": False})
            assert (
                RISK_ORDER[_risk(risk_engine, irreversible, impact)]
                >= RISK_ORDER[_risk(risk_engine, reversible, impact)]
            )


def test_raising_data_sensitivity_never_lowers_risk(risk_engine: RiskEngine) -> None:
    ordered = [
        DataClassification.PUBLIC,
        DataClassification.INTERNAL,
        DataClassification.CONFIDENTIAL,
        DataClassification.RESTRICTED,
    ]
    previous = -1
    for classification in ordered:
        capability = TELEMETRY_READ.model_copy(update={"data_classification": classification})
        rank = RISK_ORDER[_risk(risk_engine, capability, RiskLevel.LOW)]
        assert rank >= previous
        previous = rank


def test_a_benign_property_never_pulls_a_dangerous_one_down(
    risk_engine: RiskEngine,
) -> None:
    """The whole point of taking a maximum."""
    dangerous_but_reversible = PRODUCTION_ROLLBACK.model_copy(
        update={
            "risk_class": RiskLevel.CRITICAL,
            "reversible": True,
            "data_classification": DataClassification.PUBLIC,
        }
    )
    assert _risk(risk_engine, dangerous_but_reversible, RiskLevel.LOW) is (RiskLevel.CRITICAL)


def test_every_sensitivity_class_has_a_floor() -> None:
    assert set(SENSITIVITY_FLOORS) == set(DataClassification)


# --- explanation --------------------------------------------------------------------


def test_assessment_reports_every_factor(risk_engine: RiskEngine) -> None:
    assessment = risk_engine.assess(ACTION, PRODUCTION_ROLLBACK, _blast(RiskLevel.HIGH, size=3))
    assert [factor.name for factor in assessment.factors] == [
        "capability_risk_class",
        "blast_radius_impact",
        "reversibility",
        "data_classification",
    ]
    assert all(factor.detail for factor in assessment.factors)


def test_deciding_factors_explain_the_result(risk_engine: RiskEngine) -> None:
    """ "Why was this HIGH?" is answerable from data, with no model involved."""
    assessment = risk_engine.assess(ACTION, PRODUCTION_ROLLBACK, _blast(RiskLevel.LOW, size=1))
    assert assessment.risk is RiskLevel.HIGH
    assert [factor.name for factor in assessment.deciding_factors] == ["capability_risk_class"]


def test_deciding_factors_can_be_several(risk_engine: RiskEngine) -> None:
    assessment = risk_engine.assess(ACTION, PRODUCTION_ROLLBACK, _blast(RiskLevel.HIGH, size=3))
    assert {factor.name for factor in assessment.deciding_factors} == {
        "capability_risk_class",
        "blast_radius_impact",
    }


def test_final_risk_is_the_maximum_of_the_factors(risk_engine: RiskEngine) -> None:
    for capability in (TELEMETRY_READ, CUSTOMER_NOTIFY, PRODUCTION_ROLLBACK):
        for impact in RiskLevel:
            assessment = risk_engine.assess(ACTION, capability, _blast(impact))
            assert assessment.risk is max_risk(factor.contribution for factor in assessment.factors)


# --- determinism --------------------------------------------------------------------


def test_repeated_assessment_is_byte_identical(risk_engine: RiskEngine) -> None:
    blast = _blast(RiskLevel.HIGH, size=3)
    first = risk_engine.assess(ACTION, PRODUCTION_ROLLBACK, blast)
    second = risk_engine.assess(ACTION, PRODUCTION_ROLLBACK, blast)
    assert to_json(first) == to_json(second)


def test_engine_holds_no_state(risk_engine: RiskEngine) -> None:
    blast = _blast(RiskLevel.LOW)
    first = risk_engine.assess(ACTION, TELEMETRY_READ, blast)
    risk_engine.assess(ACTION, PRODUCTION_ROLLBACK, _blast(RiskLevel.CRITICAL))
    second = risk_engine.assess(ACTION, TELEMETRY_READ, blast)
    assert to_json(first) == to_json(second)


@pytest.mark.parametrize("declared", [None, *list(RiskLevel)])
def test_the_action_own_risk_is_never_read(
    risk_engine: RiskEngine, declared: RiskLevel | None
) -> None:
    """Every self-declared value produces the same assessment."""
    proposal = ACTION.model_copy(update={"risk": declared})
    assessment = risk_engine.assess(proposal, PRODUCTION_ROLLBACK, _blast(RiskLevel.LOW))
    assert assessment.risk is RiskLevel.HIGH
