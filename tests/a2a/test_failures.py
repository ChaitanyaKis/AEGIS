"""Every way A2A can fail, and the fact that none of them becomes success.

Parts 11 and 22. The shape of the guarantee: a failure produces a typed refusal, the
incident keeps whatever it had already established, and the lifecycle — not a new
mechanism invented here — decides whether the Commander gets another go.

There is no retry loop in the A2A package. A retry is the Commander deciding to delegate
again, which costs a step from the same bounded budget every other decision costs one from.
"""

from __future__ import annotations

import ast
import pathlib
from typing import ClassVar

import pytest

from aegis.a2a import (
    A2ABroker,
    A2ARejection,
    A2AVerdict,
    InMemoryA2ATransport,
    MessageLedger,
    MessageStatus,
)
from aegis.agents.decisions import TaskType
from aegis.agents.model import ModelTimeout
from aegis.agents.specialists import FailingSpecialistModel
from aegis.core.domain import IncidentState
from aegis.enterprise import PAYMENT_API, PAYMENT_API_FAULTY_VERSION
from aegis.orchestration import OrchestrationOutcome
from tests.orchestration.conftest import build_incident, build_orchestrator

from .conftest import INCIDENT, admit, issue, reseal

# --- Part 11: every failure fails closed ----------------------------------------------


class TestEveryFailureFailsClosed:
    def test_a_timeout_is_a_refusal(self, broker, clock) -> None:
        envelope = issue(broker)
        clock.advance(3600)
        verdict = admit(broker, envelope)
        assert not verdict.accepted
        assert verdict.rejection is A2ARejection.EXPIRED

    def test_an_unavailable_recipient_is_a_refusal(self, broker, clock) -> None:
        unreachable = A2ABroker(
            broker.directory,
            transport=InMemoryA2ATransport(unavailable=frozenset({"diagnostic"})),
            ledger=MessageLedger(clock=clock),
            clock=clock,
        )
        verdict = unreachable.send(issue(unreachable))
        assert verdict.rejection is A2ARejection.RECIPIENT_UNAVAILABLE

    def test_a_malformed_message_is_a_refusal(self, broker) -> None:
        outcome = broker.issue(
            accountable_sender="commander",
            recipient_agent_id="commander",  # an agent may not message itself
            incident_id=INCIDENT,
            conversation_id="conv-x",
            task_id="task-x",
            task_type=TaskType.DIAGNOSE_SERVICE,
        )
        assert isinstance(outcome, A2AVerdict)
        assert outcome.rejection is A2ARejection.MALFORMED

    @pytest.mark.parametrize(
        ("name", "make", "expected"),
        [
            (
                "integrity",
                lambda b, e: e.model_copy(update={"payload": {"x": 1}}),
                A2ARejection.INTEGRITY_FAILURE,
            ),
            (
                "not-issued",
                lambda b, e: reseal(e, message_id="msg-elsewhere0000000000000"),
                A2ARejection.NOT_ISSUED,
            ),
            ("identity", lambda b, e: e, A2ARejection.SENDER_MISMATCH),
        ],
    )
    def test_named_failures_produce_their_named_rejection(
        self, broker, name: str, make, expected
    ) -> None:
        envelope = issue(broker)
        candidate = make(broker, envelope)
        sender = "remediation" if name == "identity" else "commander"
        assert admit(broker, candidate, accountable_sender=sender).rejection is expected

    def test_no_refusal_is_ever_an_acceptance(self, broker, clock) -> None:
        """The headline: sweep every refusal path and assert ``accepted`` is False."""
        # Distinct task ids: the per-task message budget is itself one of the bounds
        # under test, and tripping it here would mask the refusals being swept for.
        cases = [
            admit(
                broker,
                issue(broker, task_id="task-a"),
                accountable_sender="remediation",
                expected_task_id="task-a",
            ),
            admit(
                broker,
                issue(broker, recipient_agent_id="shadow", task_id="task-b"),
                expected_task_id="task-b",
            ),
            admit(broker, issue(broker, task_id="task-c"), expected_incident_id="INC-OTHER"),
            admit(broker, issue(broker, task_id="task-d"), expected_conversation_id="conv-other"),
            admit(broker, issue(broker, task_id="task-e"), expected_task_id="task-other"),
            admit(
                broker,
                reseal(issue(broker, task_id="task-f"), payload={"x": 1}),
                expected_task_id="task-f",
            ),
        ]
        assert all(not verdict.accepted for verdict in cases)
        assert all(verdict.rejection is not None for verdict in cases)

    def test_a_refused_message_is_never_marked_consumed_as_success(self, broker) -> None:
        envelope = issue(broker)
        admit(broker, envelope, accountable_sender="remediation")
        assert broker.ledger.status_of(envelope.message_id) is MessageStatus.REJECTED
        assert not broker.ledger.consumed(envelope.message_id)

    def test_a_verdict_has_no_field_that_reads_as_permission(self) -> None:
        assert set(A2AVerdict.model_fields) == {
            "accepted",
            "rejection",
            "detail",
            "message_id",
        }


class TestSpecialistFailure:
    def test_a_failing_specialist_produces_no_finding(self) -> None:
        orchestrator = build_orchestrator(
            specialist_models={"diagnostic": FailingSpecialistModel(ModelTimeout("model down"))}
        )
        orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        assert all(finding.agent_id != "diagnostic" for finding in orchestrator.findings)

    def test_a_failing_specialist_is_not_healthy_verified_or_resolved(self) -> None:
        orchestrator = build_orchestrator(
            specialist_models={
                agent: FailingSpecialistModel(ModelTimeout("down"))
                for agent in ("diagnostic", "security", "business-impact", "remediation")
            }
        )
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        assert run.execution is None
        assert run.verification is None
        assert run.incident.state is not IncidentState.RESOLVED
        assert orchestrator.world.state(PAYMENT_API).deployment == PAYMENT_API_FAULTY_VERSION

    def test_a_failing_specialist_preserves_prior_evidence(self) -> None:
        orchestrator = build_orchestrator(
            specialist_models={"remediation": FailingSpecialistModel(ModelTimeout("down"))}
        )
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        assert run.context.evidence_references, "evidence was discarded on failure"

    def test_the_failure_is_recorded_rather_than_silent(self) -> None:
        from aegis.core.audit import AuditEventType

        orchestrator = build_orchestrator(
            specialist_models={"diagnostic": FailingSpecialistModel(ModelTimeout("down"))}
        )
        orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        messages = [
            record
            for record in orchestrator.audit.records()
            if record.event.event_type == AuditEventType.A2A_MESSAGE.value
        ]
        assert any(
            record.correlation.get("recipient_agent_id") == "diagnostic" for record in messages
        )


# --- Part 22: recovery, using the existing lifecycle ----------------------------------


class TestRecovery:
    def test_the_commander_continues_after_one_specialist_fails(self) -> None:
        """A failed consult is not the end of an incident."""
        orchestrator = build_orchestrator(
            specialist_models={"diagnostic": FailingSpecialistModel(ModelTimeout("down"))}
        )
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        consulted = {finding.agent_id for finding in orchestrator.findings}
        assert consulted, "the run stopped at the first failure"
        assert run.incident.state in {IncidentState.RESOLVED, IncidentState.ESCALATED}

    def test_a_permanently_unavailable_specialist_terminates_boundedly(self) -> None:
        orchestrator = build_orchestrator(
            specialist_models={
                agent: FailingSpecialistModel(ModelTimeout("permanently down"))
                for agent in ("diagnostic", "security", "business-impact", "remediation")
            },
            max_steps=8,
        )
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        assert run.outcome in {
            OrchestrationOutcome.ESCALATED,
            OrchestrationOutcome.LIFECYCLE_STOPPED,
        }
        assert run.steps_used <= 8
        assert run.execution is None

    def test_there_is_no_infinite_delegation(self) -> None:
        orchestrator = build_orchestrator(
            specialist_models={
                agent: FailingSpecialistModel(ModelTimeout("down"))
                for agent in ("diagnostic", "security", "business-impact", "remediation")
            },
            max_steps=6,
        )
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        assert run.steps_used <= 6
        assert len(orchestrator.a2a.ledger) <= 6 * 2

    def test_every_retry_consumes_a_lifecycle_step(self) -> None:
        """No budget of A2A's own: a retry costs the same step any decision costs."""
        orchestrator = build_orchestrator(max_steps=8)
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        assert orchestrator.lifecycle.counters.steps_used == run.steps_used

    def test_recovery_reaches_a_verified_resolution_when_the_specialist_works(self) -> None:
        """The positive path, end to end, through the A2A boundary."""
        orchestrator = build_orchestrator()
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        assert run.outcome is OrchestrationOutcome.RESOLVED
        assert run.verification is not None
        assert run.verification.status.value == "VERIFIED"
        assert orchestrator.world.state(PAYMENT_API).deployment == "v4.7"

    def test_a2a_defines_no_retry_mechanism_of_its_own(self) -> None:
        """Part 22: do not create a new recovery mechanism where one already exists."""
        root = pathlib.Path("src/aegis/a2a")
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.While):
                    raise AssertionError(f"{path.name} contains a while loop")
                if isinstance(node, ast.FunctionDef):
                    assert "retry" not in node.name.lower(), f"{path.name}:{node.name}"


# --- Part 15: A2A is not a tool channel ------------------------------------------------


class TestNotAToolChannel:
    FORBIDDEN_CALLS: ClassVar[set[str]] = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "setattr",
    }
    FORBIDDEN_IMPORTS: ClassVar[set[str]] = {
        "subprocess",
        "importlib",
        "socket",
        "shutil",
        "pickle",
        "httpx",
        "requests",
        "urllib",
        "aiohttp",
    }

    OS_IS_ALLOWED_IN: ClassVar[set[str]] = {"persistence.py"}
    """The one module that may touch the filesystem, and the only one.

    ``os`` left the blanket ban in Prompt 16 because durable persistence needs ``fsync`` —
    the same reason ``aegis/lifecycle/persistence.py`` needs it. Removing it from the ban
    without replacing it would have been a weakening, so it is replaced by two narrower and
    strictly stronger assertions: only this module may import it, and even here it may only
    reach the handful of names durability actually requires.
    """

    DANGEROUS_OS_ATTRIBUTES: ClassVar[set[str]] = {
        "system",
        "popen",
        "execv",
        "execve",
        "execl",
        "spawnv",
        "spawnl",
        "remove",
        "unlink",
        "rmdir",
        "removedirs",
        "rename",
        "replace",
        "truncate",
        "chmod",
        "kill",
    }
    """What ``os`` must never be used for here. Every one of these could rewrite or destroy
    the very log the replay guarantee rests on."""

    def _modules(self):
        return sorted(pathlib.Path("src/aegis/a2a").rglob("*.py"))

    def test_no_dynamic_execution_anywhere(self) -> None:
        for path in self._modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            called = {
                node.func.id
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            assert not (called & self.FORBIDDEN_CALLS), (
                f"{path.name}: {called & self.FORBIDDEN_CALLS}"
            )

    def _imports(self, path) -> set[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names.add((node.module or "").split(".")[0])
            elif isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
        return names

    def test_no_process_network_or_dynamic_import(self) -> None:
        for path in self._modules():
            names = self._imports(path)
            assert not (names & self.FORBIDDEN_IMPORTS), (
                f"{path.name}: {names & self.FORBIDDEN_IMPORTS}"
            )

    def test_only_the_persistence_module_may_touch_the_filesystem(self) -> None:
        """Durability needs ``os``; nothing else here does."""
        offenders = [
            path.name
            for path in self._modules()
            if "os" in self._imports(path) and path.name not in self.OS_IS_ALLOWED_IN
        ]
        assert offenders == [], offenders

    def test_the_persistence_module_uses_os_only_for_durability(self) -> None:
        """And even there, only for the names durability requires.

        A persistence layer that could ``os.remove`` or ``os.truncate`` its own log would be
        an escape hatch wearing a filesystem costume: the append-only guarantee would hold
        right up until something called the method that deletes it.
        """
        import pathlib as _pathlib

        source = (_pathlib.Path("src/aegis/a2a") / "persistence.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        used = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
        }
        assert used, "the test found no os usage at all, so it is checking nothing"
        assert not (used & self.DANGEROUS_OS_ATTRIBUTES), used & self.DANGEROUS_OS_ATTRIBUTES
        assert used <= {"fsync", "PathLike"}, used

    def test_every_getattr_names_a_literal_attribute(self) -> None:
        """``getattr`` is permitted; *dynamic dispatch* is not.

        The original blanket ban was aimed at turning a model-supplied name into a callable.
        A ``getattr`` whose attribute is a string literal cannot do that — the name is in the
        source, not in the message. One whose attribute is a variable could, so that is what
        is actually forbidden.
        """
        for path in self._modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "getattr"
                    and node.args
                ):
                    attribute = node.args[1] if len(node.args) > 1 else None
                    assert isinstance(attribute, ast.Constant), (
                        f"{path.name}: getattr with a computed attribute name"
                    )

    def test_a_task_type_never_becomes_a_callable(self) -> None:
        """Closed enum in, dictionary lookup out. There is no name-to-function step."""
        for path in self._modules():
            text = path.read_text(encoding="utf-8")
            assert "globals()" not in text, path.name
            assert "locals()" not in text, path.name
