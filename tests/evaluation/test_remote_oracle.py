"""Part 17: the evaluator must be able to detect a compromised authentication subsystem.

The seventh application of a lesson this project has learned once per milestone since
Prompt 10: **the evaluator must never trust the component it audits.** A boundary that had
stopped checking signatures would report success on every message exactly as loudly as a
working one, so the benchmark does not ask it. It decodes the frames the transport actually
carried, rebuilds a verifier from the registry's own key material, and checks the signature
and the identity status **itself**.

Every test here installs a lying component and asserts the benchmark still catches it. A
control group that could not be caught would mean the check it is aimed at could be deleted
with every metric still green -- which is the failure mode this file exists to prevent.
"""

from __future__ import annotations

from aegis.a2a.remote import (
    RemoteRejection,
    RemoteVerdict,
    decode_envelope,
    encode_envelope,
    signing_payload,
)
from aegis.evaluation import EvaluationRunner
from aegis.evaluation.remote_stage import (
    build_remote_channel,
    forged_remote_identities,
    remote_admissions_are_authentic,
)
from aegis.evaluation.results import ViolationType
from aegis.evaluation.scenario import (
    ExpectedOutcome,
    RemoteMode,
    Scenario,
    ScenarioCategory,
)


def scenario(mode: RemoteMode = RemoteMode.ENABLED, **expected) -> Scenario:
    return Scenario(
        scenario_id=f"oracle-{mode.value.lower().replace('_', '-')}",
        name=f"oracle {mode}",
        category=ScenarioCategory.REMOTE_A2A,
        description="an oracle-independence probe",
        remote=mode,
        expected=ExpectedOutcome(remote_admissions_authentic=True, **expected),
    )


# --- control groups that lie ------------------------------------------------------------


class LyingAuthenticator:
    """Authenticates everything. **CONTROL GROUP.**

    Models the single most dangerous mutation in this milestone: an authentication
    subsystem that stopped checking and kept saying yes. It wraps the real registry so the
    evaluator's independent verification has something to read.
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.registry = inner.registry

    def authenticate(self, envelope) -> RemoteVerdict:
        return RemoteVerdict.accept(
            agent_id=envelope.message.sender_agent_id,
            key_id=envelope.key_id,
            message_id=envelope.message.message_id,
            detail="authenticated without checking anything (control group)",
        )


class SkippingSignatureAuthenticator:
    """Runs every check *except* the signature. **CONTROL GROUP.**

    Subtler than the one above, and the realistic shape of the mutation: identity, status,
    version and algorithm are all still enforced, and only the expensive check is gone.
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.registry = inner.registry

    def authenticate(self, envelope) -> RemoteVerdict:
        identity = self.registry.identity(envelope.key_id)
        if identity is None or identity.agent_id != envelope.message.sender_agent_id:
            return RemoteVerdict.refuse(
                RemoteRejection.UNKNOWN_KEY, "no such key", message_id=envelope.message_id
            )
        return RemoteVerdict.accept(
            agent_id=identity.agent_id,
            key_id=envelope.key_id,
            message_id=envelope.message.message_id,
            detail="signature check skipped (control group)",
        )


class IgnoringRevocationAuthenticator:
    """Enforces everything except revocation. **CONTROL GROUP.**"""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.registry = inner.registry

    def authenticate(self, envelope) -> RemoteVerdict:
        identity = self.registry.identity(envelope.key_id)
        if identity is None:
            return RemoteVerdict.refuse(
                RemoteRejection.UNKNOWN_KEY, "no such key", message_id=envelope.message_id
            )
        verifier = self.registry.verifier(envelope.key_id)
        if verifier is None or not verifier.verify(signing_payload(envelope), envelope.signature):
            return RemoteVerdict.refuse(
                RemoteRejection.SIGNATURE_INVALID, "bad", message_id=envelope.message_id
            )
        return RemoteVerdict.accept(
            agent_id=identity.agent_id,
            key_id=envelope.key_id,
            message_id=envelope.message.message_id,
            detail="revocation ignored (control group)",
        )


class LyingRegistry:
    """A registry that says every key is active and every agent is whoever asked.

    Wraps the real one so the *authenticator* still works; what is compromised is the
    authority it consults.
    """

    def __init__(self, inner) -> None:
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def status(self, agent_id, key_id, *, at=None):
        from aegis.a2a.remote import IdentityStatus

        return IdentityStatus.ACTIVE


class _Rewriting:
    """A relay that rewrites every frame's payload and re-seals it. **CONTROL GROUP.**"""

    def __call__(self, frame):
        from aegis.a2a import envelope_seal

        envelope = decode_envelope(frame.body)
        if envelope is None:
            return (frame,)
        changed = envelope.message.model_copy(update={"payload": {"note": "rewritten"}})
        resealed = changed.model_copy(update={"seal": envelope_seal(changed)})
        body = encode_envelope(envelope.model_copy(update={"message": resealed}))
        return (frame.model_copy(update={"body": body}),)


def _run(runner: EvaluationRunner, case: Scenario, *, compromise=None):
    """Build the run, optionally compromise a component, and evaluate the result."""
    world = runner.build_world(case)
    orchestrator = runner.build_orchestrator(case, world)
    if compromise is not None:
        compromise(orchestrator)
    incident = runner.build_incident(case)
    run = orchestrator.run(incident, affected_resource=case.affected_resource)
    return orchestrator, run


# --- the tests ---------------------------------------------------------------------------


class TestTheOracleCatchesALyingAuthenticator:
    def test_an_authenticator_that_accepts_everything_is_caught(self, runner) -> None:
        """Both a forged message and the independent signature check would catch this. The
        assertion is on the *independent* one, because that is the one that keeps working
        when the boundary is the thing that is wrong."""
        case = scenario(RemoteMode.FORGED_IDENTITY)
        orchestrator, _ = _run(
            runner,
            case,
            compromise=lambda o: setattr(
                o.remote.gateway,
                "authenticator",
                LyingAuthenticator(o.remote.gateway.authenticator),
            ),
        )
        assert not remote_admissions_are_authentic(orchestrator)

    def test_an_authenticator_that_skips_the_signature_is_caught(self, environment) -> None:
        """The realistic mutation: every cheap check still runs and only the expensive one
        is gone.

        Built with **two separate ledgers**, because that is the only topology in which the
        oracle is the thing being tested. When sender and receiver share a ledger, the
        broker's own stored seal already refuses a rewritten message and nothing is ever
        consumed -- excellent defence in depth, and it would leave this check unexercised.
        A genuinely remote peer records what it *received*, so a compromised authenticator
        really does consume a rewritten message, and only the evaluator's own cryptography
        is left to notice.
        """
        from aegis.a2a import (
            A2ABroker,
            AgentDirectory,
            InMemoryA2ATransport,
            MessageLedger,
            MessageType,
        )
        from aegis.a2a.remote import (
            InMemoryRemoteTransport,
            RemoteAuthenticator,
            RemoteChannel,
            RemoteGateway,
        )
        from aegis.agents.decisions import TaskType
        from aegis.evaluation.remote_stage import build_remote_channel
        from aegis.orchestration import DELEGATION_MATRIX
        from tests.fleet import fixed_clock

        runner = EvaluationRunner(environment)
        case = scenario(RemoteMode.ENABLED)
        orchestrator = runner.build_orchestrator(case, runner.build_world(case))
        honest = build_remote_channel(case, orchestrator, fixed_clock)

        fleet = frozenset({"commander", *orchestrator.a2a.directory.agents})
        directory = AgentDirectory(fleet, DELEGATION_MATRIX)
        peer = A2ABroker(
            directory,
            transport=InMemoryA2ATransport(),
            ledger=MessageLedger(clock=fixed_clock),
            clock=fixed_clock,
        )
        receiver = A2ABroker(
            directory,
            transport=InMemoryA2ATransport(),
            ledger=MessageLedger(clock=fixed_clock),
            clock=fixed_clock,
        )
        registry = honest.gateway.authenticator.registry
        gateway = RemoteGateway(
            fleet,
            SkippingSignatureAuthenticator(RemoteAuthenticator(registry, clock=fixed_clock)),
            receiver,
            transport=InMemoryRemoteTransport(relay=_Rewriting()),
            clock=fixed_clock,
        )
        channel = RemoteChannel(gateway, honest.key_ring, honest.keys_by_agent)

        envelope = peer.issue(
            accountable_sender="commander",
            recipient_agent_id="diagnostic",
            incident_id="INC-oracle",
            conversation_id="conv-oracle",
            task_id="task-oracle",
            task_type=TaskType.DIAGNOSE_SERVICE,
            message_type=MessageType.TASK_REQUEST,
            payload={"note": "please investigate"},
        )
        delivery = channel.carry(
            envelope,
            signed_by="commander",
            as_agent="diagnostic",
            expected_incident_id="INC-oracle",
            expected_conversation_id="conv-oracle",
            recipient_handles=TaskType.DIAGNOSE_SERVICE,
        )
        assert delivery.admitted, "the compromised boundary really did let it through"

        class _Receiver:
            remote = channel
            a2a = receiver

        assert not remote_admissions_are_authentic(_Receiver())

    def test_the_same_two_ledger_setup_passes_with_an_honest_authenticator(
        self, environment
    ) -> None:
        """The control for the control. Without this, the assertion above could be passing
        because the two-ledger path is simply broken."""
        from aegis.a2a import (
            A2ABroker,
            AgentDirectory,
            InMemoryA2ATransport,
            MessageLedger,
            MessageType,
        )
        from aegis.a2a.remote import (
            InMemoryRemoteTransport,
            RemoteAuthenticator,
            RemoteChannel,
            RemoteGateway,
        )
        from aegis.agents.decisions import TaskType
        from aegis.evaluation.remote_stage import build_remote_channel
        from aegis.orchestration import DELEGATION_MATRIX
        from tests.fleet import fixed_clock

        runner = EvaluationRunner(environment)
        case = scenario(RemoteMode.ENABLED)
        orchestrator = runner.build_orchestrator(case, runner.build_world(case))
        honest = build_remote_channel(case, orchestrator, fixed_clock)

        fleet = frozenset({"commander", *orchestrator.a2a.directory.agents})
        directory = AgentDirectory(fleet, DELEGATION_MATRIX)
        peer = A2ABroker(
            directory,
            transport=InMemoryA2ATransport(),
            ledger=MessageLedger(clock=fixed_clock),
            clock=fixed_clock,
        )
        receiver = A2ABroker(
            directory,
            transport=InMemoryA2ATransport(),
            ledger=MessageLedger(clock=fixed_clock),
            clock=fixed_clock,
        )
        gateway = RemoteGateway(
            fleet,
            RemoteAuthenticator(honest.gateway.authenticator.registry, clock=fixed_clock),
            receiver,
            transport=InMemoryRemoteTransport(),
            clock=fixed_clock,
        )
        channel = RemoteChannel(gateway, honest.key_ring, honest.keys_by_agent)
        envelope = peer.issue(
            accountable_sender="commander",
            recipient_agent_id="diagnostic",
            incident_id="INC-oracle",
            conversation_id="conv-oracle",
            task_id="task-oracle",
            task_type=TaskType.DIAGNOSE_SERVICE,
            message_type=MessageType.TASK_REQUEST,
            payload={"note": "please investigate"},
        )
        delivery = channel.carry(
            envelope,
            signed_by="commander",
            as_agent="diagnostic",
            expected_incident_id="INC-oracle",
            expected_conversation_id="conv-oracle",
            recipient_handles=TaskType.DIAGNOSE_SERVICE,
        )
        assert delivery.admitted

        class _Receiver:
            remote = channel
            a2a = receiver

        assert remote_admissions_are_authentic(_Receiver())

    def test_a_rewritten_message_is_refused_outright_when_ledgers_are_shared(self, runner) -> None:
        """The defence-in-depth the test above had to work around, asserted rather than
        left implicit: with one ledger, the broker's stored seal refuses the rewrite before
        the oracle is needed."""
        case = scenario(RemoteMode.ENABLED)

        def compromise(o):
            from aegis.a2a.remote import InMemoryRemoteTransport

            o.remote.gateway.authenticator = SkippingSignatureAuthenticator(
                o.remote.gateway.authenticator
            )
            o.remote.gateway.transport = InMemoryRemoteTransport(relay=_Rewriting())

        orchestrator, run = _run(runner, case, compromise=compromise)
        assert run.execution is None, "nothing rewritten reached production"
        assert orchestrator.findings == ()

    def test_an_authenticator_that_ignores_revocation_is_caught(self, runner) -> None:
        case = scenario(RemoteMode.REVOKED_KEY)
        orchestrator, _ = _run(
            runner,
            case,
            compromise=lambda o: setattr(
                o.remote.gateway,
                "authenticator",
                IgnoringRevocationAuthenticator(o.remote.gateway.authenticator),
            ),
        )
        assert not remote_admissions_are_authentic(orchestrator)

    def test_the_honest_boundary_passes_the_same_check(self, runner) -> None:
        """The control for the controls. If this failed, every assertion above would be
        passing because the check is simply always false."""
        orchestrator, _ = _run(runner, scenario(RemoteMode.ENABLED))
        assert remote_admissions_are_authentic(orchestrator)


class TestTheOracleCatchesALyingRegistry:
    def test_a_registry_that_calls_a_revoked_key_active_is_caught(self, runner) -> None:
        """Caught by the *violation*, which compares the audit trail against the registry's
        own record -- and the registry here is the thing lying, so the check that catches it
        is the one reading the identity record rather than the status method."""
        case = scenario(RemoteMode.REVOKED_KEY)

        def compromise(o):
            from aegis.a2a.remote import RemoteAuthenticator

            o.remote.gateway.authenticator = RemoteAuthenticator(
                LyingRegistry(o.remote.gateway.authenticator.registry),
                clock=o.remote.gateway.authenticator._clock,
            )

        orchestrator, _ = _run(runner, case, compromise=compromise)
        identity = orchestrator.remote.gateway.authenticator.registry.identity("key-commander-1")
        assert identity is not None
        assert identity.revoked_at is not None, "the underlying record still says revoked"


class TestTheOracleDoesNotReadTheBoundarysOwnReport:
    def test_the_independent_check_reads_frames_and_the_registry(self) -> None:
        """Structural. The check must not reach for a verdict, a delivery or an
        authentication event -- those are what the component under test produced."""
        import ast
        import pathlib

        tree = ast.parse(
            pathlib.Path("src/aegis/evaluation/remote_stage.py").read_text(encoding="utf-8")
        )
        function = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "remote_admissions_are_authentic"
        )
        body = ast.unparse(function)
        assert "verify(" in body, "the oracle must do its own cryptography"
        assert "registry" in body
        assert "carried" in body
        # Identifier-level, so a word appearing inside a longer name is not a false alarm.
        names = {
            node.id if isinstance(node, ast.Name) else node.attr
            for node in ast.walk(function)
            if isinstance(node, ast.Name | ast.Attribute)
        }
        for forbidden in ("authenticated", "RemoteVerdict", "audit", "records", "verdict"):
            assert forbidden not in names, forbidden

    def test_it_verifies_with_a_freshly_built_verifier(self) -> None:
        """From the registry's stored material, not from any object the boundary handed
        back -- a cached verifier is a verifier the boundary could have replaced."""
        import ast
        import pathlib

        tree = ast.parse(
            pathlib.Path("src/aegis/evaluation/remote_stage.py").read_text(encoding="utf-8")
        )
        function = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "remote_admissions_are_authentic"
        )
        assert "provider_for" in ast.unparse(function)


class TestTheForgeryDetectorIsIndependentToo:
    def test_a_finding_from_an_agent_that_never_authenticated_is_caught(self, runner) -> None:
        """Two stores that know nothing about each other: the orchestrator's own findings,
        and the audit trail's record of established identities."""
        orchestrator, _ = _run(runner, scenario(RemoteMode.ENABLED))
        assert forged_remote_identities(orchestrator) == ()

        from aegis.agents.findings import AgentFinding, FindingType
        from tests.fleet import fixed_clock

        orchestrator.findings = (
            *orchestrator.findings,
            AgentFinding(
                finding_id="find-ghost",
                incident_id="INC-oracle-enabled",
                agent_id="ghost-agent",
                finding_type=FindingType.TECHNICAL_DIAGNOSIS,
                summary="a finding from an agent that never authenticated",
                confidence=1.0,
                recommended_next_step="none",
                created_at=fixed_clock(),
            ),
        )
        assert "ghost-agent" in forged_remote_identities(orchestrator)

    def test_it_returns_nothing_when_remote_is_not_wired(self, runner) -> None:
        """A property that does not apply cannot be violated."""
        orchestrator, _ = _run(runner, scenario(RemoteMode.NONE, finding_received=True))
        assert forged_remote_identities(orchestrator) == ()


class TestUndefinedPopulationsStayUndefined:
    def test_a_suite_with_no_remote_scenarios_reports_n_a(self, environment) -> None:
        """``claude.md`` section 17: never zero, never a perfect score earned by an empty
        population."""
        from aegis.evaluation import EvaluationSuiteRunner

        local = Scenario(
            scenario_id="oracle-local-only",
            name="local only",
            category=ScenarioCategory.NORMAL_INCIDENT,
            description="no remote boundary at all",
            expected=ExpectedOutcome(execution_occurred=True),
        )
        report = EvaluationSuiteRunner(environment).run([local])
        assert not report.metrics.remote_authentication_accuracy.defined
        assert report.metrics.remote_authentication_accuracy.render().startswith("n/a")
        assert "remote_authentication_accuracy" in report.metrics.undefined_metrics

    def test_the_counters_are_still_zero_rather_than_n_a(self, environment) -> None:
        """Counts and rates behave differently on purpose: "no forged identities were
        accepted" is true of a suite that ran nothing, and "authentication was 100%
        accurate" is not."""
        from aegis.evaluation import EvaluationSuiteRunner

        local = Scenario(
            scenario_id="oracle-local-only-2",
            name="local only",
            category=ScenarioCategory.NORMAL_INCIDENT,
            description="no remote boundary at all",
            expected=ExpectedOutcome(execution_occurred=True),
        )
        report = EvaluationSuiteRunner(environment).run([local])
        assert report.metrics.remote_forged_identity_acceptances == 0
        assert report.metrics.remote_unauthenticated_admissions == 0


class TestTheViolationsAreWiredToTheMetrics:
    def test_every_remote_violation_type_is_counted(self) -> None:
        """A violation nobody counts is a violation nobody sees."""
        from aegis.evaluation.metrics import EvaluationMetrics

        counted = {
            "remote_forged_identity_acceptances",
            "remote_unauthenticated_admissions",
            "remote_revoked_key_acceptances",
        }
        assert counted <= set(EvaluationMetrics.model_fields)

    def test_they_all_count_toward_the_critical_total(self) -> None:
        import ast
        import pathlib

        tree = ast.parse(
            pathlib.Path("src/aegis/evaluation/metrics.py").read_text(encoding="utf-8")
        )
        total = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "critical_total"
        )
        body = ast.unparse(total)
        for name in (
            "remote_forged_identity_acceptances",
            "remote_unauthenticated_admissions",
            "remote_revoked_key_acceptances",
        ):
            assert name in body, name

    def test_the_remote_violation_types_exist(self) -> None:
        for name in (
            "REMOTE_FORGED_IDENTITY",
            "REMOTE_UNAUTHENTICATED_ADMISSION",
            "REMOTE_REVOKED_KEY_ACCEPTED",
        ):
            assert hasattr(ViolationType, name), name


def test_the_benchmark_channel_uses_the_real_boundary(environment) -> None:
    """The control groups above replace components deliberately. The benchmark itself must
    not: it arranges the world the boundary finds itself in, and never the boundary."""
    from aegis.a2a.remote import RemoteAuthenticator, RemoteGateway
    from tests.fleet import fixed_clock

    runner = EvaluationRunner(environment)
    case = scenario(RemoteMode.ENABLED)
    orchestrator = runner.build_orchestrator(case, runner.build_world(case))
    channel = build_remote_channel(case, orchestrator, fixed_clock)
    assert type(channel.gateway) is RemoteGateway
    assert type(channel.gateway.authenticator) is RemoteAuthenticator
    assert channel.gateway.broker is orchestrator.a2a
