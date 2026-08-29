"""Part 20: observability must not create authority.

The invariant this milestone rests on, and the one worth enforcing structurally rather than
behaviourally. A read model that merely *happens* not to call the policy engine today is a
read model somebody will make call it tomorrow.

Three layers of enforcement, each strictly stronger than the last:

1. **No engine is importable.** The package cannot name a policy engine, an approval engine,
   an executor, a verification engine, a memory store, an A2A broker, a gate register or an
   orchestrator.
2. **No mutating call exists.** No function in the package calls anything named ``execute``,
   ``approve``, ``authorize``, ``issue``, ``revoke``, ``reset`` or their kin.
3. **Nothing it holds could act.** Every view is a pure function of a frozen
   :class:`~aegis.control_center.capture.ControlCenterInput`, so downstream of capture there
   is no object to ask.

And a fourth, measured rather than asserted: building a projection changes nothing. See
:class:`TestObservingChangesNothing`.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from aegis.control_center import project_incident
from aegis.evaluation.control_center_stage import system_fingerprint

from .conftest import capture

ROOT = pathlib.Path("src/aegis/control_center")

FORBIDDEN_NAMES = frozenset(
    {
        # engines that decide
        "PolicyEngine",
        "ApprovalEngine",
        "AssessmentPipeline",
        "RiskEngine",
        "BlastRadiusEngine",
        "VerificationEngine",
        # things that act
        "ActionExecutor",
        "IncidentOrchestrator",
        "LifecycleManager",
        "LifecycleCoordinator",
        "CircuitBreaker",
        "AgentRestrictionRegistry",
        "GateRegister",
        "A2ABroker",
        "RemoteGateway",
        "RemoteChannel",
        "RemoteAgentRegistry",
        "MessageLedger",
        # stores that can be written
        "AuditStore",
        "AuditRecorder",
        "MemoryStore",
        "EnterpriseWorld",
        "ToolRegistry",
        "GovernedToolbox",
        "ApprovalProvider",
        "SpecialistRegistry",
    }
)
"""Every name that can decide, act or be written to.

Checked as *imported names* rather than as modules, because Part 2 explicitly sanctions
consuming ``OrchestrationRun`` -- and that lives in the same package as the orchestrator.
The rule is about what the control center can *name*, which is what it can use.
"""

MUTATING_CALLS = frozenset(
    {
        "execute",
        "approve",
        "authorize",
        "issue",
        "consume",
        "revoke",
        "reset",
        "release",
        "quarantine",
        "record_failure",
        "record_outcome",
        "request_gate",
        "admit",
        "bind_response",
        "trip",
        "persist",
        "prune_expired",
    }
)
"""Method names that unambiguously change something.

Deliberately narrow. ``append``, ``write``, ``open`` and ``close`` were here first and had
to go: they match ``list.append`` on a local variable, which is how every view assembles
its own results. A rule that fires on ordinary list building is a rule somebody will
delete, and a deleted rule catches nothing.

The narrowing costs less than it looks. What actually keeps this package harmless is that
it holds no live object at all -- the import ban above and ``capture.py``'s literal-only
read helpers -- and this sweep is the third layer, not the first.
"""

FORBIDDEN_IMPORTS = frozenset(
    {"subprocess", "importlib", "socket", "shutil", "pickle", "httpx", "requests", "urllib", "os"}
)

FORBIDDEN_BUILTINS = frozenset({"eval", "exec", "compile", "__import__", "setattr", "delattr"})


def modules() -> list[pathlib.Path]:
    return sorted(ROOT.rglob("*.py"))


def imported_names(tree: ast.AST) -> set[str]:
    """Every name an import statement brings into scope.

    Both halves of an ``ImportFrom``: reading only ``node.module`` would let
    ``from aegis.core import policy`` through, which a Prompt 14 mutation proved is a real
    blind spot rather than a theoretical one.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names.add(module)
            names.update(alias.name for alias in node.names)
            names.update(f"{module}.{alias.name}" for alias in node.names if module)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    return names


class TestNoEngineIsImportable:
    def test_there_are_modules_to_check(self) -> None:
        """Guards every sweep below: an empty scan passes trivially."""
        assert len(modules()) >= 12

    @pytest.mark.parametrize("forbidden", sorted(FORBIDDEN_NAMES))
    def test_the_package_never_names_a_thing_that_can_act(self, forbidden: str) -> None:
        offenders = [
            path.name
            for path in modules()
            if forbidden in imported_names(ast.parse(path.read_text(encoding="utf-8")))
        ]
        assert offenders == [], offenders

    def test_no_module_import_form_is_used_for_aegis_packages(self) -> None:
        """``import aegis.orchestration`` would put every engine one attribute away. Only
        the ``from X import name`` form is permitted, so what is reachable is what is
        listed."""
        for path in modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert not alias.name.startswith("aegis"), f"{path.name}: {alias.name}"

    def test_the_package_reaches_no_process_network_or_dynamic_import(self) -> None:
        for path in modules():
            names = {
                name.split(".")[0]
                for name in imported_names(ast.parse(path.read_text(encoding="utf-8")))
            }
            assert not (names & FORBIDDEN_IMPORTS), (path.name, names & FORBIDDEN_IMPORTS)

    def test_no_dynamic_execution_anywhere(self) -> None:
        for path in modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            called = {
                node.func.id
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            assert not (called & FORBIDDEN_BUILTINS), (path.name, called & FORBIDDEN_BUILTINS)

    def test_no_credentials_are_referenced(self) -> None:
        """Over *identifiers*, not raw text.

        A raw-text sweep matched ``a2a.py``'s own guard list -- the constant naming the
        field names that view must never carry. Forbidding a module from *listing* what it
        forbids would be a rule that punishes documenting the guarantee.
        """
        for path in modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            identifiers = {
                node.id if isinstance(node, ast.Name) else node.attr
                for node in ast.walk(tree)
                if isinstance(node, ast.Name | ast.Attribute)
            }
            for word in ("api_key", "password", "secret_key", "getenv", "environ", "token"):
                offenders = {name for name in identifiers if word in name.lower()}
                assert not offenders, f"{path.name}: {offenders}"


class TestNoMutatingCallExists:
    def test_the_package_calls_nothing_that_changes_state(self) -> None:
        """Swept over method calls. ``capture.py`` reads through ``_call`` with literal
        names, and those names are checked separately below."""
        for path in modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                    continue
                assert node.func.attr not in MUTATING_CALLS, f"{path.name}: {node.func.attr}"

    def test_the_capture_module_reads_only_read_only_methods(self) -> None:
        """``_call`` is a dispatcher, so its *arguments* are what matter. Every call site
        must name a method from the read-only list, or the helper becomes a route to a
        mutating one."""
        allowed = {
            "records",
            "verify_integrity",
            "conversation_ids",
            "messages_for",
            "snapshot",
            "check",
            "key_for",
        }
        tree = ast.parse((ROOT / "capture.py").read_text(encoding="utf-8"))
        named = {
            node.args[1].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_call"
            and len(node.args) > 1
            and isinstance(node.args[1], ast.Constant)
        }
        assert named, "the test found no _call sites, so it is checking nothing"
        assert named <= allowed, named - allowed

    def test_every_dynamic_attribute_name_is_enumerated_in_the_source(self) -> None:
        """``getattr`` is permitted; letting *data* choose an attribute is not.

        A literal name is obviously fine. A loop variable over a literal tuple of strings is
        equally fine and much more readable than eleven near-identical lines -- the set of
        reachable attributes is still exactly what is written on the page, which is the
        property that matters.

        What this forbids is a name that could come from a captured record. Nothing in this
        package does that, and this is what keeps it so.
        """
        for path in modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            enumerated = _names_from_literal_loops(tree) | _parameters_of(tree, {"_read", "_call"})
            for node in ast.walk(tree):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "getattr"
                    and len(node.args) > 1
                ):
                    continue
                name = node.args[1]
                if isinstance(name, ast.Constant):
                    continue
                assert isinstance(name, ast.Name) and name.id in enumerated, (
                    f"{path.name}: getattr with an attribute name that is not enumerated "
                    f"in the source"
                )

    def test_every_read_site_in_capture_names_a_literal_attribute(self) -> None:
        """The other half. ``_read`` may take a variable; nothing outside the two helpers
        may *pass* it one -- so the reachable attribute set is the literal list below."""
        tree = ast.parse((ROOT / "capture.py").read_text(encoding="utf-8"))
        helpers = {"_read", "_call"}
        sites = [
            node
            for function in ast.walk(tree)
            if isinstance(function, ast.FunctionDef) and function.name not in helpers
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in helpers
            and len(node.args) > 1
        ]
        assert len(sites) >= 15, "the test found too few read sites to be checking anything"
        for node in sites:
            assert isinstance(node.args[1], ast.Constant), (
                f"capture.py: {node.func.id} with a computed attribute name"
            )


def _names_from_literal_loops(tree: ast.AST) -> set[str]:
    """Loop variables whose iterable is a literal collection of strings.

    ``for field in ("executed", "verified"): getattr(summary, field)`` reaches exactly two
    attributes, both written in the source. That is not dynamic dispatch; it is a list.
    """
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.For) or not isinstance(node.target, ast.Name):
            continue
        iterable = node.iter
        if isinstance(iterable, ast.Tuple | ast.List | ast.Set) and all(
            isinstance(item, ast.Constant) and isinstance(item.value, str) for item in iterable.elts
        ):
            found.add(node.target.id)
    return found


def _parameters_of(tree: ast.AST, functions: set[str]) -> set[str]:
    """Parameter names of the named helper functions.

    ``_read`` takes the attribute name as a parameter by design: it is the single door every
    attribute access goes through, and its *callers* are what must pass literals.
    """
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            found.update(argument.arg for argument in node.args.args)
    return found


class TestNoOperatorActionExists:
    """Part 21: no admin override, anywhere."""

    @pytest.mark.parametrize(
        "forbidden",
        [
            "force",
            "override",
            "reset",
            "approve",
            "authorize",
            "execute",
            "release",
            "grant",
            "bypass",
            "mark_verified",
            "mark_resolved",
        ],
    )
    def test_no_public_function_is_named_like_an_action(self, forbidden: str) -> None:
        for path in modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
                    assert forbidden not in node.name.lower(), f"{path.name}:{node.name}"

    def test_the_control_center_offers_only_reads(self) -> None:
        from aegis.control_center import ControlCenter

        surface = {name for name in dir(ControlCenter) if not name.startswith("_")}
        assert surface == {"add", "incident", "incident_ids", "incidents"}

    def test_add_holds_a_projection_and_nothing_else(self, projection) -> None:
        """``add`` is the only non-read method, and it stores a frozen value. It adds an
        observation; it grants nothing."""
        from aegis.control_center import ControlCenter

        center = ControlCenter()
        center.add(projection)
        assert center.incident(projection.incident_id) is projection


class TestNothingItHoldsCouldAct:
    def test_the_input_holds_only_frozen_values(self, data) -> None:
        """Downstream of capture there is no object to ask. That is the invariant, and it
        is a property of the type rather than a promise."""
        from datetime import datetime

        from aegis.core.domain import DomainModel

        for name in type(data).model_fields:
            value = getattr(data, name)
            if isinstance(value, tuple):
                assert all(isinstance(item, DomainModel) for item in value), name
            elif value is not None:
                # ``datetime`` counts: it is immutable, and a captured timestamp is a value
                # in exactly the way a captured record is.
                assert isinstance(value, DomainModel | str | bool | int | datetime), name

    def test_the_projection_is_frozen(self, projection) -> None:
        with pytest.raises(ValueError):
            projection.status = "COMPLETE"

    def test_the_projection_serialises_canonically(self, projection) -> None:
        from aegis.core.domain import to_json

        assert to_json(projection) == to_json(projection)


class TestObservingChangesNothing:
    """Measured, not asserted. The structural bans say the control center *cannot* act;
    this says it *did not*."""

    def test_building_a_projection_moves_nothing(self, resolved) -> None:
        orchestrator, run = resolved
        before = system_fingerprint(orchestrator)
        project_incident(capture(orchestrator, run))
        assert system_fingerprint(orchestrator) == before

    def test_projecting_ten_times_moves_nothing(self, resolved) -> None:
        orchestrator, run = resolved
        before = system_fingerprint(orchestrator)
        for _ in range(10):
            project_incident(capture(orchestrator, run))
        assert system_fingerprint(orchestrator) == before

    def test_exporting_moves_nothing(self, resolved, projection) -> None:
        from aegis.control_center import export_json

        orchestrator, _ = resolved
        before = system_fingerprint(orchestrator)
        export_json(projection)
        assert system_fingerprint(orchestrator) == before

    def test_asking_every_question_moves_nothing(self, resolved, projection) -> None:
        from aegis.control_center import Question

        orchestrator, _ = resolved
        before = system_fingerprint(orchestrator)
        for question in Question:
            projection.why(question)
        assert system_fingerprint(orchestrator) == before

    def test_the_fingerprint_would_notice_a_change(self, resolved) -> None:
        """The control for the controls. If the fingerprint were insensitive, every test
        above would pass by not looking."""
        orchestrator, _ = resolved
        before = system_fingerprint(orchestrator)
        orchestrator.recorder.record_state_transition(_a_transition(orchestrator))
        assert system_fingerprint(orchestrator) != before


def _a_transition(orchestrator):
    """One real state transition, so the fingerprint has something genuine to notice."""
    from aegis.core.domain import IncidentState
    from aegis.core.incidents import StateTransition, TransitionGuard

    return StateTransition(
        incident_id="INC-2026-0001",
        from_state=IncidentState.RESOLVED,
        to_state=IncidentState.RESOLVED,
        guard=TransitionGuard.NONE,
        actor="test",
        reason="a change the fingerprint must notice",
        occurred_at=orchestrator.audit.records()[-1].event.timestamp,
    )
