"""Assessment pipeline: authority over risk, preservation of the proposal, failing closed."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.core.assessment import (
    RISK_ORDER,
    Assessment,
    AssessmentOutcome,
    AssessmentPipeline,
)
from aegis.core.domain import BlastRadius, RiskLevel, from_json, to_json
from tests.fleet import (
    CUSTOMER_DATABASE,
    ORDER_SERVICE,
    PAYMENT_API,
    UNKNOWN_RESOURCE,
    build_action,
)

# --- successful assessment ----------------------------------------------------------


def test_assessment_populates_risk_and_blast_radius(
    pipeline: AssessmentPipeline,
) -> None:
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_API,
    )
    assert proposal.risk is None
    assert proposal.blast_radius is None

    assessment = pipeline.assess(proposal)
    assessed = assessment.require_assessed_action()

    assert assessment.ok
    assert assessment.outcome is AssessmentOutcome.ASSESSED
    assert assessed.risk is RiskLevel.HIGH
    assert assessed.blast_radius is not None
    assert set(assessed.blast_radius.scope) == {
        PAYMENT_API,
        ORDER_SERVICE,
        "service:api-gateway",
    }


def test_low_risk_read_assesses_low(pipeline: AssessmentPipeline) -> None:
    assessment = pipeline.assess(
        build_action(
            requesting_agent="diagnostic",
            capability="telemetry.read",
            target_resource=PAYMENT_API,
        )
    )
    assert assessment.require_assessed_action().risk is RiskLevel.LOW


def test_assessment_carries_both_sub_assessments(pipeline: AssessmentPipeline) -> None:
    assessment = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    )
    assert assessment.blast_radius is not None
    assert assessment.risk is not None
    assert assessment.blast_radius.affected_count == 3
    assert assessment.risk.deciding_factors


# --- the proposal is not trusted, and not lost --------------------------------------


def test_agent_declared_low_is_replaced_by_the_computed_high(
    pipeline: AssessmentPipeline,
) -> None:
    """The mandatory case: a proposal that understates its own risk."""
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_API,
        risk=RiskLevel.LOW,
    )
    assessed = pipeline.assess(proposal).require_assessed_action()
    assert proposal.risk is RiskLevel.LOW
    assert assessed.risk is RiskLevel.HIGH


def test_agent_declared_critical_is_also_replaced(pipeline: AssessmentPipeline) -> None:
    """Overstated risk is replaced too — the engine decides, not the agent."""
    proposal = build_action(
        requesting_agent="diagnostic",
        capability="telemetry.read",
        target_resource=PAYMENT_API,
        risk=RiskLevel.CRITICAL,
    )
    assessed = pipeline.assess(proposal).require_assessed_action()
    assert assessed.risk is RiskLevel.LOW


@pytest.mark.parametrize("declared", [None, *list(RiskLevel)])
def test_every_declared_risk_yields_the_same_assessment(
    pipeline: AssessmentPipeline, declared: RiskLevel | None
) -> None:
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_API,
        risk=declared,
    )
    assessed = pipeline.assess(proposal).require_assessed_action()
    assert assessed.risk is RiskLevel.HIGH


def test_agent_declared_blast_radius_is_replaced(pipeline: AssessmentPipeline) -> None:
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_API,
    ).model_copy(
        update={
            "blast_radius": BlastRadius(scope=("service:nothing-important",), impact=RiskLevel.LOW)
        }
    )
    assessed = pipeline.assess(proposal).require_assessed_action()
    assert assessed.blast_radius is not None
    assert assessed.blast_radius.impact is RiskLevel.HIGH
    assert "service:nothing-important" not in assessed.blast_radius.scope


def test_the_original_proposal_survives_assessment(pipeline: AssessmentPipeline) -> None:
    """Audit needs both what was asked for and what was measured."""
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_API,
        risk=RiskLevel.LOW,
    )
    before = to_json(proposal)
    assessment = pipeline.assess(proposal)

    assert to_json(proposal) == before
    assert to_json(assessment.proposal) == before
    assert assessment.proposal.risk is RiskLevel.LOW
    assert assessment.require_assessed_action().risk is RiskLevel.HIGH


def test_assessment_changes_only_risk_and_blast_radius(
    pipeline: AssessmentPipeline,
) -> None:
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_API,
    )
    assessed = pipeline.assess(proposal).require_assessed_action()
    for field in proposal.__class__.model_fields:
        if field in {"risk", "blast_radius"}:
            continue
        assert getattr(assessed, field) == getattr(proposal, field), field


# --- failing closed -----------------------------------------------------------------


def test_unknown_resource_produces_insufficient_information(
    pipeline: AssessmentPipeline,
) -> None:
    """Never LOW, never an assessed action."""
    assessment = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=UNKNOWN_RESOURCE,
        )
    )
    assert not assessment.ok
    assert assessment.outcome is AssessmentOutcome.INSUFFICIENT_INFORMATION
    assert assessment.assessed_action is None
    assert assessment.risk is None
    assert UNKNOWN_RESOURCE in assessment.failure_reason


def test_unknown_capability_produces_insufficient_information(
    pipeline: AssessmentPipeline,
) -> None:
    assessment = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.nuke",
            target_resource=PAYMENT_API,
        )
    )
    assert not assessment.ok
    assert assessment.assessed_action is None


def test_a_failed_assessment_cannot_be_read_as_an_assessed_one(
    pipeline: AssessmentPipeline,
) -> None:
    assessment = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=UNKNOWN_RESOURCE,
        )
    )
    with pytest.raises(ValueError, match="was not assessed"):
        assessment.require_assessed_action()


def test_a_self_declared_risk_does_not_survive_a_failed_assessment(
    pipeline: AssessmentPipeline,
) -> None:
    """An unknown resource plus a confident agent must not produce an assessed action."""
    assessment = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=UNKNOWN_RESOURCE,
            risk=RiskLevel.LOW,
        )
    )
    assert assessment.assessed_action is None
    assert assessment.proposal.risk is RiskLevel.LOW


# --- result invariants --------------------------------------------------------------


def test_assessed_result_must_be_complete() -> None:
    proposal = build_action(requesting_agent="remediation", capability="production.rollback")
    with pytest.raises(ValidationError, match="missing"):
        Assessment(proposal=proposal, outcome=AssessmentOutcome.ASSESSED)


def test_failed_result_must_carry_a_reason() -> None:
    proposal = build_action(requesting_agent="remediation", capability="production.rollback")
    with pytest.raises(ValidationError, match="failure_reason"):
        Assessment(proposal=proposal, outcome=AssessmentOutcome.INSUFFICIENT_INFORMATION)


def test_failed_result_must_not_carry_an_assessed_action() -> None:
    proposal = build_action(requesting_agent="remediation", capability="production.rollback")
    with pytest.raises(ValidationError, match="must not carry an assessed_action"):
        Assessment(
            proposal=proposal,
            outcome=AssessmentOutcome.INSUFFICIENT_INFORMATION,
            assessed_action=proposal,
            failure_reason="nope",
        )


def test_assessment_outcome_is_not_a_risk_level() -> None:
    """Assessment failure is a property of the attempt, not a fourth severity."""
    assert set(AssessmentOutcome) == {
        AssessmentOutcome.ASSESSED,
        AssessmentOutcome.INSUFFICIENT_INFORMATION,
    }
    assert "UNKNOWN" not in {level.name for level in RiskLevel}
    assert len(RiskLevel) == 4


# --- determinism --------------------------------------------------------------------


def test_repeated_assessment_is_byte_identical(pipeline: AssessmentPipeline) -> None:
    proposal = build_action(
        requesting_agent="remediation",
        capability="production.rollback",
        target_resource=PAYMENT_API,
    )
    assert to_json(pipeline.assess(proposal)) == to_json(pipeline.assess(proposal))


def test_assessment_round_trips_through_serialization(
    pipeline: AssessmentPipeline,
) -> None:
    """The whole record is transportable to a future audit store."""
    assessment = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=PAYMENT_API,
        )
    )
    assert from_json(Assessment, to_json(assessment)) == assessment


def test_isolated_critical_resource_is_not_treated_as_small(
    pipeline: AssessmentPipeline,
) -> None:
    """Zero dependents is not the same as low impact."""
    assessment = pipeline.assess(
        build_action(
            requesting_agent="remediation",
            capability="production.rollback",
            target_resource=CUSTOMER_DATABASE,
        )
    )
    assessed = assessment.require_assessed_action()
    assert assessment.blast_radius is not None
    assert assessment.blast_radius.affected_count == 1
    assert assessed.risk is RiskLevel.CRITICAL
    assert RISK_ORDER[assessed.risk] > RISK_ORDER[RiskLevel.LOW]
