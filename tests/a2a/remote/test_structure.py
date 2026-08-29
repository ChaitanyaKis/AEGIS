"""Parts 13, 19 and 20: dependency rules, the audit trail, and the reconstruction chain.

Structural tests, because the properties here are about what the code *can* do rather than
what it does on a given input. A boundary that merely happens not to call the policy engine
today is a boundary somebody will make call it tomorrow.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from aegis.core.audit import AuditEventType
from aegis.enterprise import PAYMENT_API
from tests.orchestration.conftest import build_incident, build_orchestrator

REMOTE_ROOT = pathlib.Path("src/aegis/a2a/remote")

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
    """Every module an import brings into scope, package and child alike.

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


def remote_modules() -> list[pathlib.Path]:
    return sorted(REMOTE_ROOT.rglob("*.py"))


class TestTheRemotePackageIsIndependent:
    def test_there_are_modules_to_check(self) -> None:
        """Guards every sweep below: an empty scan passes trivially."""
        assert len(remote_modules()) >= 9

    @pytest.mark.parametrize("forbidden", FORBIDDEN_PACKAGES)
    def test_no_remote_module_imports_a_control_plane_package(self, forbidden: str) -> None:
        offenders = [
            f"{path.name}: {name}"
            for path in remote_modules()
            for name in imported_names(ast.parse(path.read_text(encoding="utf-8")))
            if name == forbidden or name.startswith(forbidden + ".")
        ]
        assert offenders == [], offenders

    def test_the_only_aegis_packages_it_depends_on_are_a2a_domain_and_agent_contracts(
        self,
    ) -> None:
        """Positive statement of the rule, so the allowed set is explicit and reviewable."""
        allowed = {
            "aegis.a2a",
            "aegis.core.domain",
            "aegis.agents.decisions",
            "aegis.agents.findings",
        }
        for path in remote_modules():
            for name in imported_names(ast.parse(path.read_text(encoding="utf-8"))):
                if not name.startswith("aegis"):
                    continue
                assert any(name == root or name.startswith(root + ".") for root in allowed), (
                    f"{path.name}: {name}"
                )

    def test_no_remote_module_imports_google_or_a_provider(self) -> None:
        offenders = [
            f"{path.name}: {name}"
            for path in remote_modules()
            for name in imported_names(ast.parse(path.read_text(encoding="utf-8")))
            if name.startswith("google") or "gemini" in name.lower()
        ]
        assert offenders == []


class TestOneModuleOwnsTheCryptographyLibrary:
    def test_only_the_ed25519_module_imports_cryptography(self) -> None:
        """The discipline ``aegis/integrations/gemini.py`` follows for Google: one file, one
        import, one test. "Provider-neutral" has to mean something structural or it means
        nothing."""
        offenders = [
            path.name
            for path in sorted(pathlib.Path("src/aegis").rglob("*.py"))
            for name in imported_names(ast.parse(path.read_text(encoding="utf-8")))
            if name.split(".")[0] == "cryptography" and path.name != "ed25519.py"
        ]
        assert offenders == [], offenders

    def test_the_protocol_layer_names_algorithms_not_libraries(self) -> None:
        """Over the *code*, docstrings blanked: prose is free to discuss cryptography, and
        what must not appear is a library name in something that runs."""
        for module in ("authenticator.py", "envelope.py", "gateway.py", "identity.py"):
            tree = ast.parse((REMOTE_ROOT / module).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                    node.value.value = ""
            assert "cryptography" not in ast.unparse(tree), module

    def test_cryptography_is_optional(self) -> None:
        """The safety benchmark must need no third-party package (Part 21)."""
        pyproject = pathlib.Path("pyproject.toml").read_text(encoding="utf-8")
        dependencies = pyproject.split("[project.optional-dependencies]")[0]
        assert "cryptography" not in dependencies

    def test_the_benchmark_pins_a_standard_library_algorithm(self) -> None:
        from aegis.a2a.remote import KeyAlgorithm
        from aegis.evaluation.remote_stage import BENCHMARK_ALGORITHM

        assert BENCHMARK_ALGORITHM is KeyAlgorithm.HMAC_SHA256


class TestNoCredentialsInTheRepository:
    def test_no_private_key_material_is_committed(self) -> None:
        """Part 24: no authentication credentials in the repository."""
        # Assembled rather than written out, so this test does not match its own source --
        # the sweep has to be able to read every file including this one.
        markers = tuple(
            "BEGIN " + kind + "PRIVATE " + "KEY" for kind in ("", "RSA ", "OPENSSH ", "EC ")
        )
        for path in sorted(pathlib.Path(".").glob("**/*.py")):
            if ".venv" in str(path):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for marker in markers:
                assert marker not in text, f"{path}: {marker}"

    def test_no_key_file_is_committed(self) -> None:
        for pattern in ("*.pem", "*.key", "*.p12", "*.pfx"):
            found = [p for p in pathlib.Path(".").glob(f"**/{pattern}") if ".venv" not in str(p)]
            assert found == [], found

    def test_seeds_used_in_the_benchmark_are_visibly_not_secrets(self) -> None:
        """Derived from printable strings in plain sight, so nobody mistakes one for key
        management. The docs say the same thing in words."""
        text = pathlib.Path("src/aegis/evaluation/remote_stage.py").read_text(encoding="utf-8")
        assert "not production key management" in text


class TestTheAuditVocabularyGrewByExactlyTwo:
    def test_the_two_new_members_are_the_two_new_facts(self) -> None:
        remote_events = {
            member.value for member in AuditEventType if member.value.startswith("remote.")
        }
        assert remote_events == {"remote.authentication", "remote.key_revoked"}

    def test_authentication_is_one_member_with_a_status_not_four(self) -> None:
        """``remote.identity_verified`` and ``remote.message_rejected`` would be two names
        for one fact and would drift apart -- the same reasoning that kept ``a2a.message``
        to one member."""
        assert not any(
            member.value.startswith("remote.") and "verified" in member.value
            for member in AuditEventType
        )
        assert not any(
            member.value.startswith("remote.") and "rejected" in member.value
            for member in AuditEventType
        )

    def test_no_redundant_transport_failure_event_was_added(self) -> None:
        """A transport failure is "this message did not authenticate, and here is why",
        which the one member already says."""
        assert "remote.transport_failure" not in {m.value for m in AuditEventType}

    def test_the_vocabulary_version_did_not_change(self) -> None:
        """Adding a member is a compatible change under this module's own rule: no
        historical record changes meaning."""
        from aegis.core.audit.events import EVENT_VOCABULARY_VERSION

        assert EVENT_VOCABULARY_VERSION == "aegis.audit/v1"


class TestTheAuditPackageKnowsNothingAboutTheRemoteBoundary:
    def test_it_imports_no_remote_module(self) -> None:
        for path in sorted(pathlib.Path("src/aegis/core/audit").rglob("*.py")):
            for name in imported_names(ast.parse(path.read_text(encoding="utf-8"))):
                assert not name.startswith("aegis.a2a"), f"{path.name}: {name}"
                assert name.split(".")[0] != "cryptography", f"{path.name}: {name}"

    def test_the_recorder_takes_only_scalars(self) -> None:
        """No parameter here can carry key material, a signature, payload text, a prompt or
        a credential -- not by convention, but because no such parameter exists."""
        import inspect

        from aegis.core.audit.recorders import AuditRecorder

        for name in ("record_remote_authentication", "record_remote_key_revoked"):
            signature = inspect.signature(getattr(AuditRecorder, name))
            for parameter in signature.parameters.values():
                if parameter.name in {"self", "at"}:
                    continue
                annotation = str(parameter.annotation)
                assert annotation.replace("str | None", "str") in {"str", "int"}, (
                    name,
                    parameter.name,
                    annotation,
                )

    def test_no_recorder_parameter_could_hold_a_secret(self) -> None:
        import inspect

        from aegis.core.audit.recorders import AuditRecorder

        forbidden = ("signature", "secret", "private", "material", "payload", "token")
        for name in ("record_remote_authentication", "record_remote_key_revoked"):
            parameters = set(inspect.signature(getattr(AuditRecorder, name)).parameters)
            for word in forbidden:
                assert not any(word in p for p in parameters), (name, word)


class TestReconstruction:
    """Part 19: identity to verification, recoverable from the trail alone."""

    @pytest.fixture
    def run_with_remote(self):
        from aegis.evaluation.remote_stage import build_remote_channel
        from aegis.evaluation.scenario import (
            ExpectedOutcome,
            RemoteMode,
            Scenario,
            ScenarioCategory,
        )
        from tests.fleet import fixed_clock

        orchestrator = build_orchestrator()
        scenario = Scenario(
            scenario_id="structural-remote",
            name="structural",
            category=ScenarioCategory.REMOTE_A2A,
            description="a full remote run, for reconstruction",
            remote=RemoteMode.ENABLED,
            expected=ExpectedOutcome(remote_admissions_authentic=True),
        )
        orchestrator.remote = build_remote_channel(scenario, orchestrator, fixed_clock)
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        return orchestrator, run

    def test_the_run_resolved_so_the_chain_is_a_full_one(self, run_with_remote) -> None:
        _, run = run_with_remote
        assert run.verification is not None
        assert run.verification.status.value == "VERIFIED"

    def test_the_whole_chain_is_present_in_order(self, run_with_remote) -> None:
        """The Part 19 chain, in the order it genuinely happens.

        A message is *issued* before it is authenticated -- the sender builds it, then signs
        it, then the receiver establishes who signed it. So ``a2a.message`` opens the
        sequence and ``remote.authentication`` follows, which is the opposite of the order
        Part 19 lists the concepts in and is what the code actually does.
        """
        orchestrator, _ = run_with_remote
        order = [record.event.event_type for record in orchestrator.audit.records()]
        required = [
            AuditEventType.A2A_MESSAGE.value,
            AuditEventType.REMOTE_AUTHENTICATION.value,
            AuditEventType.POLICY_DECISION.value,
            AuditEventType.APPROVAL_GRANTED.value,
            AuditEventType.LIFECYCLE_GATE_ISSUED.value,
            AuditEventType.VERIFICATION_COMPLETED.value,
        ]
        positions = [order.index(name) for name in required]
        assert positions == sorted(positions), list(zip(required, positions, strict=True))

    def test_a_finding_is_reachable_from_the_authentication_that_admitted_it(
        self, run_with_remote
    ) -> None:
        """Identity -> authentication -> admission -> finding, joined by conversation id."""
        orchestrator, _ = run_with_remote
        authentications = {
            record.correlation["conversation_id"]
            for record in orchestrator.audit.records()
            if record.event.event_type == AuditEventType.REMOTE_AUTHENTICATION.value
            and record.correlation.get("status") == "AUTHENTICATED"
        }
        messages = {
            record.correlation["conversation_id"]
            for record in orchestrator.audit.records()
            if record.event.event_type == AuditEventType.A2A_MESSAGE.value
            and "finding_id" in record.correlation
        }
        assert messages and messages <= authentications

    def test_authentication_precedes_the_message_it_admitted(self, run_with_remote) -> None:
        orchestrator, _ = run_with_remote
        order = [record.event.event_type for record in orchestrator.audit.records()]
        assert order.index(AuditEventType.REMOTE_AUTHENTICATION.value) < order.index(
            AuditEventType.POLICY_DECISION.value
        )

    def test_every_authentication_names_its_key_and_algorithm(self, run_with_remote) -> None:
        orchestrator, _ = run_with_remote
        records = [
            record
            for record in orchestrator.audit.records()
            if record.event.event_type == AuditEventType.REMOTE_AUTHENTICATION.value
        ]
        assert records
        for record in records:
            assert record.correlation["protocol_version"]
            assert record.correlation["claimed_agent_id"]
            assert record.correlation["status"] in {"AUTHENTICATED", "REFUSED"}

    def test_the_claimed_and_established_identities_are_recorded_separately(
        self, run_with_remote
    ) -> None:
        """A trail recording only the established identity could not show the moment a
        claim and a fact disagreed, which is the moment worth recording."""
        orchestrator, _ = run_with_remote
        records = [
            record
            for record in orchestrator.audit.records()
            if record.event.event_type == AuditEventType.REMOTE_AUTHENTICATION.value
        ]
        assert any("authenticated_agent_id" in record.correlation for record in records)
        assert all("claimed_agent_id" in record.correlation for record in records)

    def test_no_signature_or_key_material_is_recorded(self, run_with_remote) -> None:
        orchestrator, _ = run_with_remote
        channel = orchestrator.remote
        secrets = {
            channel.key_ring.signer(key_id).material  # type: ignore[union-attr]
            for key_id in channel.key_ring.key_ids()
            if hasattr(channel.key_ring.signer(key_id), "material")
        }
        rendered = "".join(
            str(record.correlation) + str(record.event) for record in orchestrator.audit.records()
        )
        for secret in secrets:
            assert secret not in rendered

    def test_the_chain_still_verifies(self, run_with_remote) -> None:
        orchestrator, _ = run_with_remote
        assert orchestrator.audit.verify_integrity().valid


class TestTheLocalPathIsUnchangedWhenNoChannelIsWired:
    def test_the_orchestrator_defaults_to_local(self) -> None:
        """Optional rather than mandatory: a remote boundary is a deployment choice, not an
        architectural one, and every scenario written before Prompt 17 still runs locally."""
        orchestrator = build_orchestrator()
        assert orchestrator.remote is None

    def test_a_local_run_still_resolves(self) -> None:
        orchestrator = build_orchestrator()
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        assert run.verification is not None
        assert run.verification.status.value == "VERIFIED"

    def test_a_local_run_records_no_remote_events(self) -> None:
        orchestrator = build_orchestrator()
        orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        assert not [
            record
            for record in orchestrator.audit.records()
            if record.event.event_type.startswith("remote.")
        ]
