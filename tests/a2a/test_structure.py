"""What the A2A package may and may not import, and what the audit must reconstruct.

Parts 17, 20 and 23.

The import rules are the structural reason every behavioural claim in this suite holds. A
broker that could reach the policy engine would be a control plane with a delivery API
attached, however carefully it was written not to use it; the point of asserting over
parsed imports is that the *option* does not exist.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest

from aegis.core.audit import AuditEventType, reconstruct_incident_history
from aegis.enterprise import PAYMENT_API
from tests.orchestration.conftest import build_incident, build_orchestrator

A2A_ROOT = pathlib.Path("src/aegis/a2a")

FORBIDDEN_PACKAGES = (
    "aegis.core.policy",
    "aegis.core.approval",
    "aegis.core.assessment",
    "aegis.core.verification",
    "aegis.core.audit",
    "aegis.core.capabilities",
    "aegis.core.dependencies",
    "aegis.core.incidents",
    "aegis.enterprise",
    "aegis.orchestration",
    "aegis.memory",
    "aegis.lifecycle",
    "aegis.evaluation",
    "aegis.integrations",
)


def imported_names(tree: ast.AST) -> set[str]:
    """Every module an import statement brings into scope, package and child alike.

    Both halves of an ``ImportFrom``: reading only ``node.module`` would let
    ``from aegis.core import policy`` through, which a Prompt 14 mutation proved is a real
    blind spot rather than a theoretical one.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names.add(module)
            names.update(f"{module}.{alias.name}" if module else alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    return names


def a2a_modules() -> list[pathlib.Path]:
    return sorted(A2A_ROOT.rglob("*.py"))


class TestTheA2APackageIsIndependent:
    def test_there_are_modules_to_check(self) -> None:
        """Guards every scan below: an empty sweep passes trivially."""
        assert len(a2a_modules()) >= 5

    @pytest.mark.parametrize("forbidden", FORBIDDEN_PACKAGES)
    def test_no_a2a_module_imports_a_control_plane_package(self, forbidden: str) -> None:
        offenders = [
            f"{path.name}: {name}"
            for path in a2a_modules()
            for name in imported_names(ast.parse(path.read_text(encoding="utf-8")))
            if name == forbidden or name.startswith(forbidden + ".")
        ]
        assert offenders == [], offenders

    def test_no_a2a_module_imports_google_or_a_provider(self) -> None:
        offenders = [
            f"{path.name}: {name}"
            for path in a2a_modules()
            for name in imported_names(ast.parse(path.read_text(encoding="utf-8")))
            if name.startswith("google") or "gemini" in name.lower()
        ]
        assert offenders == []

    def test_the_only_aegis_packages_a2a_depends_on_are_domain_and_agent_contracts(self) -> None:
        """Positive statement of the rule, so the allowed set is explicit and reviewable."""
        allowed = {
            "aegis.a2a",
            "aegis.core.domain",
            "aegis.agents.decisions",
            "aegis.agents.findings",
        }
        for path in a2a_modules():
            for name in imported_names(ast.parse(path.read_text(encoding="utf-8"))):
                if not name.startswith("aegis"):
                    continue
                assert any(name == root or name.startswith(root + ".") for root in allowed), (
                    f"{path.name}: {name}"
                )

    def test_the_agent_plane_gained_no_control_plane_import(self) -> None:
        """A2A existing must not have widened what agents can reach."""
        offenders = []
        for path in sorted(pathlib.Path("src/aegis/agents").rglob("*.py")):
            for name in imported_names(ast.parse(path.read_text(encoding="utf-8"))):
                if name.startswith(
                    (
                        "aegis.core.policy",
                        "aegis.core.approval",
                        "aegis.core.verification",
                        "aegis.enterprise",
                        "aegis.orchestration",
                        "aegis.memory",
                        "aegis.lifecycle",
                    )
                ):
                    offenders.append(f"{path.name}: {name}")
        assert offenders == []

    def test_the_agent_plane_does_not_import_a2a_either(self) -> None:
        """Agents are *carried* by A2A; they do not reach into the transport."""
        offenders = [
            f"{path.name}: {name}"
            for path in sorted(pathlib.Path("src/aegis/agents").rglob("*.py"))
            for name in imported_names(ast.parse(path.read_text(encoding="utf-8")))
            if name.startswith("aegis.a2a")
        ]
        assert offenders == []

    def test_the_dependency_arrow_points_from_orchestration_to_a2a(self) -> None:
        """One delegation policy, injected downwards rather than imported upwards."""
        orchestrator = pathlib.Path("src/aegis/orchestration/orchestrator.py")
        names = imported_names(ast.parse(orchestrator.read_text(encoding="utf-8")))
        assert any(name.startswith("aegis.a2a") for name in names)
        for path in a2a_modules():
            assert not any(
                name.startswith("aegis.orchestration")
                for name in imported_names(ast.parse(path.read_text(encoding="utf-8")))
            ), path.name

    def test_the_audit_package_knows_nothing_about_a2a(self) -> None:
        """Plain scalar recorders: the trail records messages without importing them."""
        for path in sorted(pathlib.Path("src/aegis/core/audit").rglob("*.py")):
            names = imported_names(ast.parse(path.read_text(encoding="utf-8")))
            assert not any(name.startswith("aegis.a2a") for name in names), path.name


# --- Parts 17 and 23: observability and reconstruction --------------------------------


@pytest.fixture
def completed_run():
    orchestrator = build_orchestrator()
    run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
    return orchestrator, run


class TestAuditReconstruction:
    def test_the_run_resolved_so_the_reconstruction_is_of_a_full_chain(self, completed_run) -> None:
        _orchestrator, run = completed_run
        assert run.outcome.value == "RESOLVED"

    def test_the_whole_chain_is_present_in_order(self, completed_run) -> None:
        """Part 23: incident to resolution, with A2A between decision and finding."""
        orchestrator, _run = completed_run
        types = [record.event.event_type for record in orchestrator.audit.records()]
        for expected in (
            AuditEventType.INCIDENT_STATE_CHANGED,
            AuditEventType.MODEL_DECISION,
            AuditEventType.A2A_MESSAGE,
            AuditEventType.ACTION_ASSESSED,
            AuditEventType.POLICY_DECISION,
            AuditEventType.APPROVAL_REQUESTED,
            AuditEventType.APPROVAL_GRANTED,
            AuditEventType.LIFECYCLE_GATE_ISSUED,
            AuditEventType.LIFECYCLE_GATE_CONSUMED,
            AuditEventType.VERIFICATION_COMPLETED,
        ):
            assert expected.value in types, expected

    def test_a2a_messages_precede_the_policy_decision_they_led_to(self, completed_run) -> None:
        orchestrator, _run = completed_run
        types = [record.event.event_type for record in orchestrator.audit.records()]
        assert types.index(AuditEventType.A2A_MESSAGE.value) < types.index(
            AuditEventType.POLICY_DECISION.value
        )

    def test_every_message_is_reconstructible(self, completed_run) -> None:
        """Part 17: who, to whom, for which incident, task, resource, when, and what came back."""
        orchestrator, _run = completed_run
        messages = [
            record
            for record in orchestrator.audit.records()
            if record.event.event_type == AuditEventType.A2A_MESSAGE.value
        ]
        assert messages
        for record in messages:
            for field in (
                "message_id",
                "conversation_id",
                "sender_agent_id",
                "recipient_agent_id",
                "task_id",
                "task_type",
                "status",
                "digest",
                "sequence",
            ):
                assert field in record.correlation, field
            assert record.event.timestamp is not None
            assert record.event.incident_id

    def test_a_returned_finding_is_linked_to_its_message(self, completed_run) -> None:
        orchestrator, _run = completed_run
        completed = [
            record
            for record in orchestrator.audit.records()
            if record.event.event_type == AuditEventType.A2A_MESSAGE.value
            and record.correlation.get("status") == "COMPLETED"
        ]
        assert completed
        finding_ids = {finding.finding_id for finding in orchestrator.findings}
        linked = {
            record.correlation["finding_id"]
            for record in completed
            if "finding_id" in record.correlation
        }
        assert linked <= finding_ids
        assert linked

    def test_the_digest_identifies_the_exact_message(self, completed_run) -> None:
        orchestrator, _run = completed_run
        digests = {
            record.correlation["digest"]
            for record in orchestrator.audit.records()
            if record.event.event_type == AuditEventType.A2A_MESSAGE.value
        }
        for digest in digests:
            assert len(digest) == 64, digest

    def test_the_chain_verifies_and_the_history_is_consistent(self, completed_run) -> None:
        orchestrator, run = completed_run
        assert orchestrator.audit.verify_integrity().valid
        history = reconstruct_incident_history(
            orchestrator.audit.records(), run.incident.incident_id
        )
        assert history.consistent

    def test_no_prompt_or_response_text_is_recorded(self, completed_run) -> None:
        """Part 17: identifiers and digests, never model text."""
        orchestrator, _run = completed_run
        messages = json.dumps(
            [
                dict(record.correlation) | {"result": record.event.result}
                for record in orchestrator.audit.records()
                if record.event.event_type == AuditEventType.A2A_MESSAGE.value
            ]
        )
        for phrase in ("Rolling", "reasoning", "summary", "Carry out", "please investigate"):
            assert phrase not in messages, phrase

    def test_a_refused_message_leaves_a_detectable_trail(self) -> None:
        """Part 23: a forged or replayed message must not vanish quietly."""
        from aegis.agents import ScriptedCommanderModel
        from aegis.agents.decisions import CommanderDecision, DecisionType, DelegationRequest
        from aegis.agents.decisions import TaskType as TT

        model = ScriptedCommanderModel(
            CommanderDecision(
                decision_type=DecisionType.DELEGATE,
                reasoning_summary="Asking an agent that does not exist.",
                delegation=DelegationRequest(
                    target_agent_id="shadow-executor", task_type=TT.DIAGNOSE_SERVICE
                ),
            ),
            CommanderDecision(
                decision_type=DecisionType.ESCALATE, reasoning_summary="Handing over."
            ),
        )
        orchestrator = build_orchestrator(model=model, max_steps=3)
        orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        refusals = [
            record
            for record in orchestrator.audit.records()
            if record.event.event_type == AuditEventType.A2A_MESSAGE.value
            and record.correlation.get("rejection")
        ]
        assert refusals, "a refused delegation left no trail"
        assert refusals[0].correlation["rejection"] == "UNKNOWN_RECIPIENT"
        assert orchestrator.audit.verify_integrity().valid

    def test_the_recorder_takes_only_scalars(self) -> None:
        """Structural: nothing in the recorder signature can carry an envelope."""
        import inspect

        from aegis.core.audit import AuditRecorder

        signature = inspect.signature(AuditRecorder.record_a2a_message)
        for name, parameter in signature.parameters.items():
            if name == "self":
                continue
            rendered = str(parameter.annotation)
            assert any(primitive in rendered for primitive in ("str", "int", "datetime", "None")), (
                name,
                rendered,
            )
