"""The scenario contract.

A scenario is data. These tests hold it to that: closed, frozen, canonically
serializable, and incapable of expressing a case that asserts nothing.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.core.domain import IncidentState, PolicyDecisionType, to_json
from aegis.evaluation import (
    ExpectedOutcome,
    RoutingExpectation,
    Scenario,
    ScenarioCategory,
)


def scenario(expected: ExpectedOutcome, **overrides) -> Scenario:
    return Scenario(
        scenario_id="case-01",
        name="a case",
        category=ScenarioCategory.NORMAL_INCIDENT,
        description="why this case exists",
        expected=expected,
        **overrides,
    )


class TestMeaningfulExpectations:
    """Part 15. A scenario that only checks the run did not crash measures nothing."""

    def test_an_empty_expectation_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="asserts nothing testable"):
            scenario(ExpectedOutcome())

    def test_audit_valid_alone_is_not_a_meaningful_expectation(self) -> None:
        # It defaults to True on every scenario, so it distinguishes nothing.
        with pytest.raises(ValidationError, match="asserts nothing testable"):
            scenario(ExpectedOutcome(audit_valid=True))

    def test_an_empty_routing_expectation_is_not_meaningful(self) -> None:
        with pytest.raises(ValidationError, match="asserts nothing testable"):
            scenario(ExpectedOutcome(routing=RoutingExpectation()))

    def test_one_asserted_field_is_enough(self) -> None:
        case = scenario(ExpectedOutcome(final_state=IncidentState.RESOLVED))
        assert case.expected.is_meaningful
        assert case.expected.specified_fields == ("final_state",)

    def test_an_expectation_of_false_is_meaningful(self) -> None:
        # False asserts "this must not happen". Only None means unspecified.
        case = scenario(ExpectedOutcome(execution_occurred=False))
        assert case.expected.specified_fields == ("execution_occurred",)

    def test_routing_counts_as_a_specified_field_when_it_names_anyone(self) -> None:
        case = scenario(ExpectedOutcome(routing=RoutingExpectation(forbidden=("remediation",))))
        assert "routing" in case.expected.specified_fields


class TestRoutingExpectation:
    def test_a_specialist_cannot_be_both_required_and_forbidden(self) -> None:
        with pytest.raises(ValidationError, match="both required and forbidden"):
            RoutingExpectation(required=("diagnostic",), forbidden=("diagnostic",))

    def test_required_and_forbidden_may_name_different_agents(self) -> None:
        routing = RoutingExpectation(required=("diagnostic",), forbidden=("remediation",))
        assert routing.specified


class TestScenarioIsData:
    def test_a_scenario_is_frozen(self) -> None:
        case = scenario(ExpectedOutcome(final_state=IncidentState.RESOLVED))
        with pytest.raises(ValidationError):
            case.scenario_id = "case-02"  # type: ignore[misc]

    def test_unknown_fields_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            scenario(
                ExpectedOutcome(final_state=IncidentState.RESOLVED),
                should_pass=True,
            )

    def test_an_expectation_cannot_carry_an_unknown_field(self) -> None:
        with pytest.raises(ValidationError):
            ExpectedOutcome(final_state=IncidentState.RESOLVED, expected_to_work=True)

    def test_a_scenario_serializes_canonically(self) -> None:
        case = scenario(ExpectedOutcome(policy_decision=PolicyDecisionType.DENY))
        assert to_json(case) == to_json(case.model_copy())

    def test_max_steps_must_allow_at_least_one_decision(self) -> None:
        with pytest.raises(ValidationError):
            scenario(ExpectedOutcome(final_state=IncidentState.RESOLVED), max_steps=0)

    def test_specified_fields_is_sorted_and_excludes_unset(self) -> None:
        case = scenario(
            ExpectedOutcome(
                world_changed=True,
                final_state=IncidentState.RESOLVED,
                approval_required=True,
            )
        )
        assert case.expected.specified_fields == (
            "approval_required",
            "final_state",
            "world_changed",
        )
