"""Part 34 — the evaluator must be able to fail.

A benchmark that passes everything proves nothing until it is shown catching runs that
are deliberately wrong. Each test here takes a real run, breaks one property of it, and
asserts the evaluator notices.

Two kinds of finding are checked separately:

* a **mismatch** — AEGIS did not do what the scenario declared;
* a **violation** — AEGIS did something it must never do, which fails the suite
  regardless of any metric.
"""

from __future__ import annotations

import pytest

from aegis.core.domain import IncidentState, PolicyDecisionType, to_json
from aegis.core.verification import VerificationStatus
from aegis.evaluation import (
    CriticalViolation,
    EvaluationRunner,
    RoutingExpectation,
    Scenario,
    SuiteStatus,
    ViolationType,
)
from aegis.evaluation.catalogue import GOLDEN_INCIDENT
from aegis.orchestration import OrchestrationOutcome


@pytest.fixture
def golden(runner: EvaluationRunner):
    """A real, correct golden-incident run and everything needed to re-judge it."""
    world = runner.build_world(GOLDEN_INCIDENT)
    orchestrator = runner.build_orchestrator(GOLDEN_INCIDENT, world)
    run = orchestrator.run(
        runner.build_incident(GOLDEN_INCIDENT),
        affected_resource=GOLDEN_INCIDENT.affected_resource,
    )
    return orchestrator, run


def rewrite(scenario: Scenario, **expected) -> Scenario:
    """The same scenario with a different expectation."""
    return scenario.model_copy(update={"expected": scenario.expected.model_copy(update=expected)})


def kinds(violations) -> set[ViolationType]:
    return {violation.violation_type for violation in violations}


class TestTheGoldenRunIsActuallyClean:
    """The control group for every test below.

    Each later test breaks one property and asserts a finding. These two show there was
    nothing broken to start with, so a finding is the injected fault and not a stale bug.
    """

    def test_the_unmodified_golden_run_has_no_mismatches(self, runner, golden) -> None:
        orchestrator, run = golden
        observed = runner.observe(GOLDEN_INCIDENT, orchestrator, run)
        assert runner.compare(GOLDEN_INCIDENT, observed) == ()

    def test_the_unmodified_golden_run_has_no_violations(self, runner, golden) -> None:
        orchestrator, run = golden
        observed = runner.observe(GOLDEN_INCIDENT, orchestrator, run)
        assert runner.detect_violations(GOLDEN_INCIDENT, orchestrator, run, observed) == ()


class TestMismatchesAreCaught:
    """Expected one thing, observed another. The evaluator must name the field."""

    def test_expected_resolved_but_observed_degraded(self, runner, golden) -> None:
        orchestrator, run = golden
        observed = runner.observe(GOLDEN_INCIDENT, orchestrator, run).model_copy(
            update={"final_state": IncidentState.DEGRADED.value}
        )
        mismatches = runner.compare(GOLDEN_INCIDENT, observed)
        assert {m.field for m in mismatches} == {"final_state"}
        assert mismatches[0].expected == "RESOLVED"
        assert mismatches[0].actual == "DEGRADED"

    def test_expected_deny_but_observed_allow(self, runner, golden) -> None:
        orchestrator, run = golden
        scenario = rewrite(GOLDEN_INCIDENT, policy_decision=PolicyDecisionType.DENY)
        observed = runner.observe(scenario, orchestrator, run)
        assert "policy_decision" in {m.field for m in runner.compare(scenario, observed)}

    def test_expected_approval_but_observed_direct_execution(self, runner, golden) -> None:
        orchestrator, run = golden
        observed = runner.observe(GOLDEN_INCIDENT, orchestrator, run).model_copy(
            update={"approval_required": False, "approval_granted": False}
        )
        fields = {m.field for m in runner.compare(GOLDEN_INCIDENT, observed)}
        assert {"approval_required", "approval_granted"} <= fields

    def test_expected_verified_but_observed_stale(self, runner, golden) -> None:
        orchestrator, run = golden
        observed = runner.observe(GOLDEN_INCIDENT, orchestrator, run).model_copy(
            update={"verification": VerificationStatus.STALE.value}
        )
        assert "verification" in {m.field for m in runner.compare(GOLDEN_INCIDENT, observed)}

    def test_a_required_specialist_that_was_never_consulted(self, runner, golden) -> None:
        orchestrator, run = golden
        observed = runner.observe(GOLDEN_INCIDENT, orchestrator, run).model_copy(
            update={"delegated_to": ("diagnostic",)}
        )
        assert "routing" in {m.field for m in runner.compare(GOLDEN_INCIDENT, observed)}

    def test_a_forbidden_specialist_that_was_consulted(self, runner, golden) -> None:
        orchestrator, run = golden
        scenario = rewrite(GOLDEN_INCIDENT, routing=RoutingExpectation(forbidden=("remediation",)))
        observed = runner.observe(scenario, orchestrator, run)
        assert "routing" in {m.field for m in runner.compare(scenario, observed)}

    def test_a_blast_radius_smaller_than_the_declared_floor(self, runner, golden) -> None:
        orchestrator, run = golden
        scenario = rewrite(GOLDEN_INCIDENT, min_affected_resources=999)
        observed = runner.observe(scenario, orchestrator, run)
        assert "min_affected_resources" in {m.field for m in runner.compare(scenario, observed)}

    def test_an_unspecified_expectation_is_not_checked(self, runner, golden) -> None:
        # None means silent. Silence must never be read as an assertion of False.
        orchestrator, run = golden
        scenario = rewrite(GOLDEN_INCIDENT, escalation_expected=None)
        observed = runner.observe(scenario, orchestrator, run)
        assert "escalation_expected" not in {m.field for m in runner.compare(scenario, observed)}

    def test_an_expectation_of_false_is_checked(self, runner, golden) -> None:
        orchestrator, run = golden
        scenario = rewrite(GOLDEN_INCIDENT, world_changed=False)
        observed = runner.observe(scenario, orchestrator, run)
        assert "world_changed" in {m.field for m in runner.compare(scenario, observed)}


class TestViolationsAreCaught:
    """Safety properties broken. These fail the suite whatever the metrics say."""

    def test_execution_with_no_policy_evaluation_on_record(self, runner, golden) -> None:
        orchestrator, run = golden
        broken = run.model_copy(update={"evaluation": None})
        observed = runner.observe(GOLDEN_INCIDENT, orchestrator, broken)
        found = kinds(runner.detect_violations(GOLDEN_INCIDENT, orchestrator, broken, observed))
        assert ViolationType.POLICY_BYPASS in found
        assert ViolationType.UNAUTHORIZED_EXECUTION in found
        assert ViolationType.UNAUTHORIZED_HIGH_IMPACT_EXECUTION in found

    def test_execution_after_require_approval_with_no_authorization(self, runner, golden) -> None:
        # The single most important invariant in claude.md section 21.
        orchestrator, run = golden
        broken = run.model_copy(update={"authorization": None})
        observed = runner.observe(GOLDEN_INCIDENT, orchestrator, broken)
        found = kinds(runner.detect_violations(GOLDEN_INCIDENT, orchestrator, broken, observed))
        assert ViolationType.APPROVAL_BYPASS in found
        assert ViolationType.UNAUTHORIZED_HIGH_IMPACT_EXECUTION in found

    def test_resolution_without_any_verification(self, runner, golden) -> None:
        orchestrator, run = golden
        broken = run.model_copy(update={"verification": None})
        observed = runner.observe(GOLDEN_INCIDENT, orchestrator, broken)
        found = kinds(runner.detect_violations(GOLDEN_INCIDENT, orchestrator, broken, observed))
        assert ViolationType.VERIFICATION_BYPASS in found

    def test_resolution_on_a_failed_verification(self, runner, golden) -> None:
        orchestrator, run = golden
        failed = run.verification.model_copy(update={"status": VerificationStatus.FAILED})
        broken = run.model_copy(update={"verification": failed})
        observed = runner.observe(GOLDEN_INCIDENT, orchestrator, broken)
        found = kinds(runner.detect_violations(GOLDEN_INCIDENT, orchestrator, broken, observed))
        assert ViolationType.VERIFICATION_BYPASS in found

    def test_a_corrupted_audit_digest(self, runner, golden) -> None:
        orchestrator, run = golden
        records = orchestrator.audit.records()
        tampered = records[3].model_copy(update={"digest": "0" * 64})
        orchestrator.audit._records[3] = tampered
        observed = runner.observe(GOLDEN_INCIDENT, orchestrator, run)
        found = kinds(runner.detect_violations(GOLDEN_INCIDENT, orchestrator, run, observed))
        assert ViolationType.AUDIT_INTEGRITY_FAILURE in found
        assert observed.audit_valid is False

    def test_a_broken_audit_link_also_fails_the_comparison(self, runner, golden) -> None:
        orchestrator, run = golden
        records = orchestrator.audit.records()
        orchestrator.audit._records[2] = records[2].model_copy(update={"previous_digest": "f" * 64})
        observed = runner.observe(GOLDEN_INCIDENT, orchestrator, run)
        assert "audit_valid" in {m.field for m in runner.compare(GOLDEN_INCIDENT, observed)}


class TestAResultCarriesTheEvidence:
    def test_a_clean_run_passes_with_nothing_recorded_against_it(self, runner) -> None:
        result, _ = runner.run(GOLDEN_INCIDENT)
        assert result.passed is True
        assert result.violations == ()
        assert result.mismatches == ()

    def test_a_crash_is_a_failure_and_not_a_pass(self, runner, monkeypatch) -> None:
        class Exploding:
            audit = None

            def run(self, *args, **kwargs):
                raise RuntimeError("the orchestrator fell over")

        monkeypatch.setattr(
            EvaluationRunner, "build_orchestrator", lambda self, s, w, memory=None: Exploding()
        )
        result, run = runner.run(GOLDEN_INCIDENT)
        assert result.passed is False
        assert run is None
        assert result.error is not None
        assert "the orchestrator fell over" in result.error

    def test_a_result_records_which_expectations_were_checked(self, runner) -> None:
        result, _ = runner.run(GOLDEN_INCIDENT)
        assert set(result.expected_fields) == set(GOLDEN_INCIDENT.expected.specified_fields)


class TestReproducibility:
    """Part 33. The same scenario twice must produce the same bytes."""

    def test_two_runs_of_one_scenario_are_byte_identical(self, runner) -> None:
        first, _ = runner.run(GOLDEN_INCIDENT)
        second, _ = runner.run(GOLDEN_INCIDENT)
        assert to_json(first) == to_json(second)

    def test_reproducibility_includes_the_audit_head_digest(self, runner) -> None:
        first, _ = runner.run(GOLDEN_INCIDENT)
        second, _ = runner.run(GOLDEN_INCIDENT)
        assert first.observed.audit_head_digest == second.observed.audit_head_digest

    def test_a_separately_built_environment_produces_the_same_result(self, runner) -> None:
        from tests.evaluation.conftest import build_environment

        other = EvaluationRunner(build_environment())
        mine, _ = runner.run(GOLDEN_INCIDENT)
        theirs, _ = other.run(GOLDEN_INCIDENT)
        assert to_json(mine) == to_json(theirs)


class TestTheGoldenIncidentItself:
    """claude.md section 16, asserted directly rather than through the suite."""

    def test_the_golden_incident_resolves_through_the_full_governance_path(self, runner) -> None:
        result, run = runner.run(GOLDEN_INCIDENT)
        assert result.passed, result.mismatches
        assert run.outcome is OrchestrationOutcome.RESOLVED
        assert run.evaluation.decision.decision is PolicyDecisionType.REQUIRE_APPROVAL
        assert run.authorization is not None
        assert run.verification.status is VerificationStatus.VERIFIED

    def test_the_golden_incident_consults_all_four_specialists(self, runner) -> None:
        result, _ = runner.run(GOLDEN_INCIDENT)
        assert set(result.observed.delegated_to) == {
            "diagnostic",
            "security",
            "business-impact",
            "remediation",
        }

    def test_the_golden_incident_expectation_is_not_vacuous(self) -> None:
        assert len(GOLDEN_INCIDENT.expected.specified_fields) >= 8


def _inject_violation(self, scenario, orchestrator, run, observed, store=None):
    """Stand in for violation detection, always reporting one. TEST DOUBLE."""
    return (
        CriticalViolation(
            scenario_id=scenario.scenario_id,
            violation_type=ViolationType.UNAUTHORIZED_HIGH_IMPACT_EXECUTION,
            incident_id="INC-injected",
            explanation="injected by the test to prove a violation is fatal",
        ),
    )


class TestAViolationFailsRegardlessOfMismatches:
    """A safety violation is not a kind of mismatch. It fails on its own.

    Nothing in the benchmark actually violates, so these inject a violation into the
    judging path directly. Without them a run that broke a safety property but matched
    every declared expectation would be reported as a pass.
    """

    def test_a_scenario_with_a_violation_never_passes(self, runner, monkeypatch) -> None:
        monkeypatch.setattr(EvaluationRunner, "detect_violations", _inject_violation)
        result, _ = runner.run(GOLDEN_INCIDENT)
        assert result.mismatches == (), "the run itself still matches every expectation"
        assert result.violations != ()
        assert result.passed is False

    def test_a_suite_with_a_violation_fails_even_with_perfect_metrics(
        self, suite_runner, monkeypatch
    ) -> None:
        monkeypatch.setattr(EvaluationRunner, "detect_violations", _inject_violation)
        report = suite_runner.run((GOLDEN_INCIDENT,))
        assert report.status is SuiteStatus.FAIL
        assert report.metrics.unauthorized_high_impact_actions == 1
        assert report.metrics.critical_total == 1

    def test_the_headline_invariant_alone_fails_the_suite(self, suite_runner, monkeypatch) -> None:
        # Every rate is perfect and every expectation matches; one violation still
        # decides the verdict.
        monkeypatch.setattr(EvaluationRunner, "detect_violations", _inject_violation)
        report = suite_runner.run((GOLDEN_INCIDENT,))
        assert report.metrics.governance_accuracy.rate == 1.0
        assert report.status is SuiteStatus.FAIL
        assert "CRITICAL VIOLATIONS:" in report.render()
