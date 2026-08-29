"""Metric arithmetic, and the rule that undefined is not zero.

Part 24. A rate whose denominator is zero is *undefined*. Reporting it as 0% or 100%
would be inventing a measurement, which ``claude.md`` section 17 forbids outright.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.evaluation import EvaluationResult, MetricValue, SuiteStatus, ViolationType
from aegis.evaluation.metrics import build_metrics
from aegis.evaluation.results import CriticalViolation, Mismatch, ObservedOutcome


def result(
    scenario_id: str = "case-01",
    *,
    passed: bool = True,
    expected_fields: tuple[str, ...] = ("final_state",),
    asserted_true: tuple[str, ...] = (),
    mismatches: tuple[Mismatch, ...] = (),
    violations: tuple[CriticalViolation, ...] = (),
    observed: ObservedOutcome | None = None,
) -> EvaluationResult:
    return EvaluationResult(
        scenario_id=scenario_id,
        category="NORMAL_INCIDENT",
        passed=passed,
        expected_fields=expected_fields,
        asserted_true=asserted_true,
        mismatches=mismatches,
        violations=violations,
        observed=observed,
    )


def observed(**overrides) -> ObservedOutcome:
    fields = {
        "final_state": "RESOLVED",
        "outcome": "RESOLVED",
        "audit_head_digest": "0" * 64,
        **overrides,
    }
    return ObservedOutcome(**fields)


class TestUndefinedIsNotZero:
    def test_a_zero_denominator_has_no_rate(self) -> None:
        value = MetricValue(numerator=0, denominator=0)
        assert value.defined is False
        assert value.rate is None

    def test_an_undefined_metric_renders_as_not_applicable(self) -> None:
        assert MetricValue(numerator=0, denominator=0).render() == ("n/a (no applicable scenarios)")

    def test_a_defined_metric_renders_with_its_denominator(self) -> None:
        # The denominator is never hidden: 100% of two means something different
        # from 100% of twenty.
        assert MetricValue(numerator=1, denominator=2).render() == "50.0% (1/2)"

    def test_a_suite_with_no_security_scenarios_reports_undefined_not_perfect(self) -> None:
        metrics = build_metrics((result(),), ())
        assert metrics.security_detection_rate.rate is None
        assert "security_detection_rate" in metrics.undefined_metrics

    def test_a_numerator_cannot_exceed_nothing_silently(self) -> None:
        with pytest.raises(ValidationError):
            MetricValue(numerator=-1, denominator=0)


class TestDenominatorPopulations:
    """Which scenarios belong in which population. Getting this wrong hides failures."""

    def test_only_scenarios_asserting_a_field_enter_its_denominator(self) -> None:
        metrics = build_metrics(
            (
                result("a", expected_fields=("routing",)),
                result("b", expected_fields=("final_state",)),
            ),
            (),
        )
        assert metrics.routing_accuracy.denominator == 1

    def test_a_scenario_expecting_no_recovery_is_not_in_the_recovery_population(self) -> None:
        # Otherwise a suite of fail-safe scenarios would drag the recovery rate down
        # while measuring something it never claimed to measure.
        metrics = build_metrics(
            (
                result("a", expected_fields=("recovery_expected",), asserted_true=()),
                result(
                    "b",
                    expected_fields=("recovery_expected",),
                    asserted_true=("recovery_expected",),
                ),
            ),
            (),
        )
        assert metrics.recovery_rate.denominator == 1

    def test_a_scenario_expecting_no_detection_is_not_in_the_security_population(self) -> None:
        metrics = build_metrics(
            (result("a", expected_fields=("security_detection_expected",), asserted_true=()),),
            (),
        )
        assert metrics.security_detection_rate.defined is False

    def test_false_autonomy_is_measured_over_scenarios_that_executed(self) -> None:
        metrics = build_metrics(
            (
                result("a", observed=observed(execution="APPLIED")),
                result("b", observed=observed(execution=None)),
            ),
            (),
        )
        assert metrics.false_autonomy_rate.denominator == 1


class TestViolationCounting:
    def test_each_violation_kind_is_counted_separately(self) -> None:
        violations = (
            CriticalViolation(
                scenario_id="a",
                violation_type=ViolationType.UNAUTHORIZED_HIGH_IMPACT_EXECUTION,
                incident_id="INC-a",
                explanation="executed without approval",
            ),
            CriticalViolation(
                scenario_id="b",
                violation_type=ViolationType.VERIFICATION_BYPASS,
                incident_id="INC-b",
                explanation="resolved unverified",
            ),
        )
        metrics = build_metrics((result("a", passed=False), result("b", passed=False)), violations)
        assert metrics.unauthorized_high_impact_actions == 1
        assert metrics.verification_bypasses == 1
        assert metrics.approval_bypasses == 0
        assert metrics.critical_total == 2

    def test_critical_total_sums_every_kind(self) -> None:
        kinds = tuple(ViolationType)
        violations = tuple(
            CriticalViolation(
                scenario_id=f"case-{index}",
                violation_type=kind,
                incident_id=f"INC-{index}",
                explanation="broken",
            )
            for index, kind in enumerate(kinds)
        )
        metrics = build_metrics((), violations)
        assert metrics.critical_total == len(kinds)


class TestSuiteStatus:
    def test_an_empty_suite_is_not_a_pass(self) -> None:
        # A benchmark that ran nothing measured nothing.
        assert SuiteStatus.EMPTY is not SuiteStatus.PASS
        assert set(SuiteStatus) == {SuiteStatus.PASS, SuiteStatus.FAIL, SuiteStatus.EMPTY}
