"""Part 14. The benchmark must catch a durability guarantee that has stopped holding.

Twenty-nine A2A_PERSISTENCE scenarios pass, and a suite of passing scenarios proves nothing
on its own — it is equally consistent with "durability held" and with "the evaluator cannot
tell". The seventh application of the lesson from Prompts 10 to 16: an oracle that has never
been shown a failure has never been tested.

Every check below derives from the **durable log**, never from the ledger's account of
itself. A ledger that lost a consumption reports success exactly as loudly as one that kept
it, which is why the counts come off the backend instead.
"""

from __future__ import annotations

import pytest

from aegis.a2a import (
    A2ARecordKind,
    A2AStateRecord,
    InMemoryA2APersistence,
    MessageStatus,
    record_digest,
)
from aegis.evaluation import EvaluationRunner, ViolationType
from aegis.evaluation.a2a_persistence_stage import (
    FailingA2APersistence,
    a2a_consumption_is_durable,
    persistence_observations,
)
from aegis.evaluation.catalogue import BENCHMARK_SCENARIOS
from aegis.evaluation.scenario import A2APersistenceMode, ScenarioCategory

FAMILY = tuple(s for s in BENCHMARK_SCENARIOS if s.category is ScenarioCategory.A2A_PERSISTENCE)


def scenario(scenario_id: str):
    return next(s for s in BENCHMARK_SCENARIOS if s.scenario_id == scenario_id)


def execute(runner: EvaluationRunner, case):
    world = runner.build_world(case)
    orchestrator = runner.build_orchestrator(case, world)
    run = orchestrator.run(runner.build_incident(case), affected_resource=case.affected_resource)
    return orchestrator, run


def kinds(violations) -> set[ViolationType]:
    return {violation.violation_type for violation in violations}


@pytest.fixture
def durable_run(runner: EvaluationRunner):
    case = scenario("a2a-persist-durable-run-resolves")
    orchestrator, run = execute(runner, case)
    return case, orchestrator, run


# --- the family is real ----------------------------------------------------------------


class TestTheFamilyIsReal:
    def test_there_are_enough_scenarios(self) -> None:
        assert len(FAMILY) >= 25, len(FAMILY)

    def test_every_persistence_mode_is_exercised(self) -> None:
        """A declared arrangement nothing uses is a comment, not a control."""
        used = {case.a2a_persistence for case in FAMILY}
        unused = set(A2APersistenceMode) - used - {A2APersistenceMode.NONE}
        assert unused == set(), sorted(mode.value for mode in unused)

    def test_most_of_the_family_is_adversarial(self) -> None:
        adversarial = [
            case
            for case in FAMILY
            if case.a2a_tamper.value != "NONE"
            or case.a2a_persistence
            not in {A2APersistenceMode.DURABLE, A2APersistenceMode.RESTARTED}
            or case.specialist_behaviours
            or case.commander_behaviour.value != "NORMAL"
            or case.gate_tamper.value != "NONE"
        ]
        assert len(adversarial) >= len(FAMILY) // 2

    def test_the_control_actually_resolves(self, durable_run) -> None:
        """Otherwise every refusal above measures a benchmark that refuses everything."""
        _case, _orchestrator, run = durable_run
        assert run.outcome.value == "RESOLVED"
        assert run.verification is not None

    def test_the_control_really_wrote_to_disk(self, durable_run) -> None:
        _case, orchestrator, _run = durable_run
        observed = persistence_observations(orchestrator)
        assert observed["a2a_durable"] is True
        assert observed["a2a_persisted_records"] >= 4
        assert observed["a2a_consumed_records"] >= 1
        assert observed["a2a_chain_valid"] is True

    def test_the_control_is_not_flagged(self, runner, durable_run) -> None:
        case, orchestrator, run = durable_run
        observed = runner.observe(case, orchestrator, run)
        assert runner.detect_violations(case, orchestrator, run, observed) == ()

    def test_a_restarted_scenario_really_restarted(self, runner) -> None:
        """The prior process must actually have written something, or nothing was tested."""
        case = scenario("a2a-persist-restart-after-consumption")
        orchestrator, _run = execute(runner, case)
        records = orchestrator.a2a.ledger._persistence.load()
        prior = [r for r in records if r.task_id.startswith("task-prior")]
        assert prior, "no previous-process records exist, so no restart happened"
        assert any(r.status is MessageStatus.CONSUMED for r in prior)


# --- the detectors detect ---------------------------------------------------------------


class _AmnesiacPersistence(InMemoryA2APersistence):
    """A backend that accepts consumptions and then forgets them. **TEST INSTRUMENT.**

    The exact Prompt 15 weakness in a class: the ledger believes a message is spent and
    nothing on disk agrees. If the benchmark cannot see this, it cannot see the thing this
    milestone exists to fix.
    """

    durable = True

    def append(self, record: A2AStateRecord) -> None:
        if record.status in {MessageStatus.CONSUMED, MessageStatus.COMPLETED}:
            return  # silently drop every consumption
        super().append(record)


class TestNonDurableConsumptionIsDetected:
    def test_a_forgetful_backend_is_caught(self, runner) -> None:
        """The control group Part 14 asks for, injected rather than benchmarked."""
        case = scenario("a2a-persist-durable-run-resolves")
        world = runner.build_world(case)
        orchestrator = runner.build_orchestrator(case, world)
        orchestrator.a2a.ledger._persistence = _AmnesiacPersistence()
        run = orchestrator.run(
            runner.build_incident(case), affected_resource=case.affected_resource
        )
        observed = runner.observe(case, orchestrator, run)
        assert observed.a2a_consumption_durable is False
        assert ViolationType.A2A_NON_DURABLE_CONSUMPTION in kinds(
            runner.detect_violations(case, orchestrator, run, observed)
        )

    def test_the_detector_is_quiet_on_an_honest_run(self, durable_run) -> None:
        """An oracle that flags everything is as useless as one that flags nothing."""
        _case, orchestrator, _run = durable_run
        assert a2a_consumption_is_durable(orchestrator) is True

    def test_the_detector_reads_the_backend_not_the_ledger(self) -> None:
        """Structural: it must not consult anything the ledger reports about itself."""
        import ast
        import pathlib

        source = pathlib.Path("src/aegis/evaluation/a2a_persistence_stage.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        function = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "a2a_consumption_is_durable"
        )
        body = "\n".join(
            ast.unparse(node) for node in function.body if not isinstance(node, ast.Expr)
        )
        assert "_persistence.load()" in body
        assert "durable" not in body.replace("a2a_consumption_is_durable", "")
        assert "verify" not in body


class TestCorruptStateIsDetected:
    def test_proceeding_on_an_unverifiable_chain_is_a_violation(self, runner, durable_run) -> None:
        case, orchestrator, run = durable_run
        observed = runner.observe(case, orchestrator, run).model_copy(
            update={"a2a_chain_valid": False}
        )
        assert observed.a2a_persisted_records > 0
        assert ViolationType.A2A_CORRUPT_STATE_ACCEPTED in kinds(
            runner.detect_violations(case, orchestrator, run, observed)
        )

    def test_the_chain_check_is_recomputed_not_reported(self, runner) -> None:
        """The observation must not be a value the ledger handed over."""
        case = scenario("a2a-persist-durable-run-resolves")
        orchestrator, _run = execute(runner, case)
        backend = orchestrator.a2a.ledger._persistence
        records = list(backend.load())
        assert records
        # Corrupt the backend behind the ledger's back; the ledger still believes all is well.
        broken = records[-1].model_copy(update={"status": MessageStatus.EXPIRED})
        path = backend.path
        lines = path.read_text(encoding="utf-8").splitlines()
        lines[-1] = broken.model_dump_json()
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert orchestrator.a2a.ledger.verify().valid is True  # in-memory log unchanged
        assert persistence_observations(orchestrator)["a2a_chain_valid"] is False

    def test_a_clean_run_is_not_flagged(self, runner, durable_run) -> None:
        case, orchestrator, run = durable_run
        observed = runner.observe(case, orchestrator, run)
        assert ViolationType.A2A_CORRUPT_STATE_ACCEPTED not in kinds(
            runner.detect_violations(case, orchestrator, run, observed)
        )


class TestReplayAfterRestartIsDetected:
    def test_two_consumption_records_for_one_message_is_a_replay(self, runner, tmp_path) -> None:
        """Counted from records, so no amount of correct status reporting hides it."""
        case = scenario("a2a-persist-durable-run-resolves")
        orchestrator, run = execute(runner, case)
        backend = orchestrator.a2a.ledger._persistence
        records = list(backend.load())
        consumed = next(r for r in records if r.status is MessageStatus.CONSUMED)
        # Append a second consumption of the same message, correctly chained.
        duplicate = consumed.model_copy(
            update={
                "sequence": len(records),
                "previous_digest": records[-1].digest,
                "kind": A2ARecordKind.STATUS_CHANGED,
                "digest": "placeholder",
            }
        )
        duplicate = duplicate.model_copy(update={"digest": record_digest(duplicate)})
        path = backend.path
        with path.open("a", encoding="utf-8") as handle:
            handle.write(duplicate.model_dump_json() + "\n")

        observed = runner.observe(case, orchestrator, run)
        assert ViolationType.A2A_REPLAY_AFTER_RESTART in kinds(
            runner.detect_violations(case, orchestrator, run, observed)
        )

    def test_a_single_consumption_is_not_flagged(self, runner, durable_run) -> None:
        case, orchestrator, run = durable_run
        observed = runner.observe(case, orchestrator, run)
        assert ViolationType.A2A_REPLAY_AFTER_RESTART not in kinds(
            runner.detect_violations(case, orchestrator, run, observed)
        )


# --- expectations are checked, not decorative ------------------------------------------


class TestExpectationsAreChecked:
    @pytest.mark.parametrize("case", FAMILY, ids=lambda case: case.scenario_id)
    def test_every_scenario_asserts_something_independent(self, case) -> None:
        independent = {
            "execution_occurred",
            "world_changed",
            "gate_consumed",
            "verification",
            "policy_decision",
            "final_state",
            "outcome",
            "finding_received",
            "a2a_durable",
            "a2a_chain_valid",
            "a2a_consumption_durable",
            "min_persisted_records",
            "approval_granted",
            "approval_required",
            "audit_valid",
        }
        assert set(case.expected.specified_fields) & independent, case.scenario_id

    def test_a_record_floor_is_actually_checked(self, runner) -> None:
        case = scenario("a2a-persist-durable-run-resolves")
        orchestrator, run = execute(runner, case)
        observed = runner.observe(case, orchestrator, run)
        assert runner.compare(case, observed) == ()
        starved = observed.model_copy(update={"a2a_persisted_records": 0})
        mismatches = runner.compare(case, starved)
        assert any(m.field == "min_persisted_records" for m in mismatches), mismatches

    def test_a_durability_expectation_is_actually_checked(self, runner) -> None:
        case = scenario("a2a-persist-durable-run-resolves")
        orchestrator, run = execute(runner, case)
        observed = runner.observe(case, orchestrator, run)
        lying = observed.model_copy(update={"a2a_durable": False})
        assert any(m.field == "a2a_durable" for m in runner.compare(case, lying))

    @pytest.mark.parametrize("case", FAMILY, ids=lambda case: case.scenario_id)
    def test_no_scenario_touches_production_unwitnessed(self, runner, case) -> None:
        """The invariant across the whole family, checked against artifacts."""
        orchestrator, run = execute(runner, case)
        observed = runner.observe(case, orchestrator, run)
        if observed.world_changed:
            assert observed.gates_consumed_count >= 1, case.scenario_id
            assert observed.approval_granted, case.scenario_id
            assert run.verification is not None, case.scenario_id
        assert observed.a2a_bypassed is False, case.scenario_id
        assert observed.a2a_consumption_durable is True, case.scenario_id

    @pytest.mark.parametrize("case", FAMILY, ids=lambda case: case.scenario_id)
    def test_every_scenario_keeps_a_verifiable_audit_chain(self, runner, case) -> None:
        orchestrator, _run = execute(runner, case)
        assert orchestrator.audit.verify_integrity().valid


# --- the fail-closed modes really fail closed ------------------------------------------


class TestFailClosedModes:
    @pytest.mark.parametrize(
        "scenario_id",
        [
            "a2a-persist-corrupt-chain-fails-closed",
            "a2a-persist-torn-tail-fails-closed",
            "a2a-persist-concurrent-writers-are-detected",
            "a2a-persist-write-failure-grants-nothing",
        ],
    )
    def test_unusable_state_delivers_nothing(self, runner, scenario_id: str) -> None:
        case = scenario(scenario_id)
        orchestrator, run = execute(runner, case)
        observed = runner.observe(case, orchestrator, run)
        assert observed.finding_received is False, scenario_id
        assert observed.execution_occurred is False, scenario_id
        assert observed.world_changed is False, scenario_id
        assert observed.a2a_persisted_records == 0, scenario_id

    @pytest.mark.parametrize(
        "scenario_id",
        [
            "a2a-persist-corrupt-chain-fails-closed",
            "a2a-persist-write-failure-grants-nothing",
        ],
    )
    def test_a_refusal_is_recorded_rather_than_silent(self, runner, scenario_id: str) -> None:
        """A crash would skip the audit record the refusal is supposed to leave."""
        from aegis.core.audit import AuditEventType

        case = scenario(scenario_id)
        orchestrator, _run = execute(runner, case)
        refusals = [
            record
            for record in orchestrator.audit.records()
            if record.event.event_type == AuditEventType.A2A_MESSAGE.value
            and record.correlation.get("rejection")
        ]
        assert refusals, scenario_id
        assert orchestrator.audit.verify_integrity().valid

    def test_a_write_failure_is_not_an_acceptance(self, runner) -> None:
        case = scenario("a2a-persist-write-failure-grants-nothing")
        orchestrator, run = execute(runner, case)
        assert isinstance(orchestrator.a2a.ledger._persistence, FailingA2APersistence)
        assert run.execution is None
        assert orchestrator.a2a.ledger.persisted_records == 0


def test_the_in_memory_default_is_still_reported_as_non_durable(runner) -> None:
    """The contrast the family measures against: the Prompt 15 default, unchanged."""
    case = next(s for s in BENCHMARK_SCENARIOS if s.a2a_persistence is A2APersistenceMode.NONE)
    orchestrator, _run = execute(runner, case)
    assert persistence_observations(orchestrator)["a2a_durable"] is False
