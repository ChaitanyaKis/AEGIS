"""Recording what a provider did, and staying independent of which provider it was.

Parts 5, 8 and 9.

Part 5 insists the deterministic safety guarantees stay separate from probabilistic model
behaviour. The recorder here is the instrument for the second: it observes and never
intervenes. Every test that matters in this file is a test that recording changed nothing.

Part 8 wants a cost and latency baseline. What can honestly be established offline is the
*shape* of the measurement and the deterministic run's numbers. Live numbers require a live
call, and none has been made — so nothing here invents one, and
``ProviderTrace.total_tokens`` returns ``None`` rather than zero when no provider reported
any.
"""

from __future__ import annotations

import ast
import json
import pathlib
from typing import ClassVar

import pytest

from aegis.agents import Commander, DeterministicCommanderModel, ScriptedCommanderModel
from aegis.agents.decisions import CommanderDecision, DecisionType
from aegis.agents.model import ModelClient, ModelRequest, ModelTimeout, ModelUnavailable
from aegis.enterprise import PAYMENT_API
from aegis.integrations.provider import (
    FailureCategory,
    ProviderCall,
    ProviderTrace,
    RecordingModelClient,
    request_digest,
)
from aegis.integrations.replay import CaptureEntry, ReplayModelClient, load_capture, write_capture
from tests.orchestration.conftest import build_incident, build_orchestrator

WAIT = json.dumps({"decision_type": "WAIT", "reasoning_summary": "Holding for telemetry."})
ESCALATE = json.dumps({"decision_type": "ESCALATE", "reasoning_summary": "Handing over."})
INVESTIGATE = json.dumps(
    {
        "decision_type": "INVESTIGATE",
        "reasoning_summary": "Reading health.",
        "tool_request": {"tool_id": "get_service_health", "arguments": {"resource": PAYMENT_API}},
    }
)
DELEGATE = json.dumps(
    {
        "decision_type": "DELEGATE",
        "reasoning_summary": "Asking diagnostic.",
        "delegation": {"target_agent_id": "diagnostic", "task_type": "DIAGNOSE_SERVICE"},
    }
)
PROPOSE = json.dumps(
    {
        "decision_type": "PROPOSE_ACTION",
        "reasoning_summary": "Rolling back.",
        "proposal": {
            "capability_id": "production.rollback",
            "target_resource": PAYMENT_API,
            "arguments": {"target_version": "v4.7"},
        },
    }
)


class FakeClock:
    """Deterministic elapsed time, so latency assertions are not flaky."""

    def __init__(self, *steps: float) -> None:
        self._steps = list(steps) or [0.0, 0.25]

    def __call__(self) -> float:
        return self._steps.pop(0) if self._steps else 0.0


def a_request(step: int = 0) -> ModelRequest:
    return ModelRequest(task="Decide.", data={"n": step}, step=step, max_steps=8)


# --- Part 5: the recorder observes and never intervenes ------------------------------


class TestRecordingIsTransparent:
    def test_the_recorded_decision_is_the_inner_decision(self) -> None:
        inner = ReplayModelClient(WAIT)
        recorder = RecordingModelClient(inner)
        decision = recorder.decide(a_request())
        assert isinstance(decision, CommanderDecision)
        assert decision.decision_type is DecisionType.WAIT

    def test_a_failure_is_re_raised_unchanged(self) -> None:
        original = ModelUnavailable("provider is down")
        recorder = RecordingModelClient(ReplayModelClient(original))
        with pytest.raises(ModelUnavailable) as caught:
            recorder.decide(a_request())
        assert caught.value is original

    def test_a_failure_is_recorded_before_it_is_re_raised(self) -> None:
        recorder = RecordingModelClient(ReplayModelClient(ModelTimeout("late")))
        with pytest.raises(ModelTimeout):
            recorder.decide(a_request())
        assert recorder.trace.call_count == 1
        assert recorder.trace.calls[0].failure_category is FailureCategory.TIMEOUT

    def test_the_recorder_has_no_way_to_produce_a_decision(self) -> None:
        """Structural: nothing in the class constructs an output or swallows an error."""
        source = pathlib.Path(RecordingModelClient.__module__.replace(".", "/") + ".py")
        text = pathlib.Path("src") / source
        tree = ast.parse(text.read_text(encoding="utf-8"))
        recorder = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == "RecordingModelClient"
        )
        constructed = {
            node.func.id
            for node in ast.walk(recorder)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert "CommanderDecision" not in constructed
        assert "AgentFinding" not in constructed
        # Every except clause in decide() re-raises rather than returning.
        decide = next(
            node
            for node in recorder.body
            if isinstance(node, ast.FunctionDef) and node.name == "decide"
        )
        for handler in ast.walk(decide):
            if isinstance(handler, ast.ExceptHandler):
                assert any(isinstance(stmt, ast.Raise) for stmt in handler.body)

    def test_a_broken_provider_metadata_property_does_not_break_the_run(self) -> None:
        class ExplodingMetadata(ReplayModelClient):
            @property
            def last_call_metadata(self):
                raise RuntimeError("provider telemetry is broken")

        recorder = RecordingModelClient(ExplodingMetadata(WAIT))
        assert recorder.decide(a_request()).decision_type is DecisionType.WAIT
        assert recorder.trace.calls[0].total_tokens is None

    def test_the_recorder_is_itself_a_model_client(self) -> None:
        assert isinstance(RecordingModelClient(ReplayModelClient(WAIT)), ModelClient)

    def test_recording_does_not_change_the_orchestration_outcome(self) -> None:
        """The property Part 5 actually needs: measurement must not perturb the run."""
        plain = build_orchestrator(model=DeterministicCommanderModel())
        recorded = build_orchestrator(model=RecordingModelClient(DeterministicCommanderModel()))
        first = plain.run(build_incident(), affected_resource=PAYMENT_API)
        second = recorded.run(build_incident(), affected_resource=PAYMENT_API)
        assert first.outcome is second.outcome
        assert first.incident.state is second.incident.state
        assert first.audit_head_digest == second.audit_head_digest


# --- Part 5: what is recorded, and what is deliberately not --------------------------


class TestWhatIsRecorded:
    def test_the_request_is_recorded_as_a_digest_not_as_content(self) -> None:
        secret_ish = ModelRequest(
            task="Decide.",
            data={"incident": {"note": "customer 4471 card ending 9931"}},
            step=0,
            max_steps=4,
        )
        recorder = RecordingModelClient(ReplayModelClient(WAIT))
        recorder.decide(secret_ish)
        rendered = json.dumps(recorder.trace.as_record())
        assert "4471" not in rendered
        assert "9931" not in rendered
        assert recorder.trace.calls[0].request_digest == request_digest(secret_ish)

    def test_the_digest_is_stable_across_identical_requests(self) -> None:
        assert request_digest(a_request(3)) == request_digest(a_request(3))
        assert request_digest(a_request(3)) != request_digest(a_request(4))

    def test_a_provider_call_has_nowhere_to_put_prompt_or_response_text(self) -> None:
        fields = set(ProviderCall.model_fields)
        assert not any(
            word in name for name in fields for word in ("prompt_text", "response_text", "content")
        )
        assert "request_digest" in fields and "response_digest" in fields

    def test_the_decision_tool_and_delegation_sequences_are_recorded(self) -> None:
        recorder = RecordingModelClient(ReplayModelClient(INVESTIGATE, DELEGATE, PROPOSE))
        for step in range(3):
            recorder.decide(a_request(step))
        assert recorder.trace.decision_sequence() == (
            "INVESTIGATE",
            "DELEGATE",
            "PROPOSE_ACTION",
        )
        assert recorder.trace.tool_sequence() == ("get_service_health",)
        assert recorder.trace.delegation_sequence() == ("diagnostic",)
        assert recorder.trace.calls[2].proposed_capability == "production.rollback"

    def test_recording_a_proposal_is_not_honouring_one(self) -> None:
        """The trace says the model asked for a rollback; the world says it did not happen."""
        model = RecordingModelClient(ReplayModelClient(PROPOSE))
        orchestrator = build_orchestrator(model=model)
        orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        assert model.trace.calls[0].proposed_capability == "production.rollback"
        assert orchestrator.world.state(PAYMENT_API).deployment != "v4.7"

    def test_failure_categories_are_recorded_per_call(self) -> None:
        recorder = RecordingModelClient(
            ReplayModelClient(WAIT, ModelTimeout("t"), ModelUnavailable("u"))
        )
        recorder.decide(a_request(0))
        for step, failure in ((1, ModelTimeout), (2, ModelUnavailable)):
            with pytest.raises(failure):
                recorder.decide(a_request(step))
        assert recorder.trace.failure_categories() == ("TIMEOUT", "UNAVAILABLE")
        assert recorder.trace.failure_count == 2
        assert recorder.trace.call_count == 3


# --- Part 8: latency and cost, without inventing numbers -----------------------------


class TestCostAndLatency:
    def test_latency_is_measured_per_call(self) -> None:
        recorder = RecordingModelClient(ReplayModelClient(WAIT), clock=FakeClock(10.0, 10.25))
        recorder.decide(a_request())
        assert recorder.trace.calls[0].latency_ms == pytest.approx(250.0)

    def test_total_latency_sums_every_call(self) -> None:
        recorder = RecordingModelClient(
            ReplayModelClient(WAIT, WAIT), clock=FakeClock(0.0, 0.1, 1.0, 1.4)
        )
        recorder.decide(a_request(0))
        recorder.decide(a_request(1))
        assert recorder.trace.total_latency_ms == pytest.approx(500.0)

    def test_latency_is_recorded_for_failures_too(self) -> None:
        recorder = RecordingModelClient(
            ReplayModelClient(ModelTimeout("t")), clock=FakeClock(0.0, 2.0)
        )
        with pytest.raises(ModelTimeout):
            recorder.decide(a_request())
        assert recorder.trace.calls[0].latency_ms == pytest.approx(2000.0)

    def test_a_provider_reporting_no_tokens_reports_none_not_zero(self) -> None:
        """Reporting zero would be inventing a measurement (Part 8, and section 17)."""
        recorder = RecordingModelClient(ReplayModelClient(WAIT))
        recorder.decide(a_request())
        assert recorder.trace.total_tokens is None

    def test_tokens_are_summed_when_a_provider_does_report_them(self) -> None:
        class Reporting(ReplayModelClient):
            last_call_metadata: ClassVar[dict[str, int]] = {
                "prompt_tokens": 100,
                "response_tokens": 20,
                "total_tokens": 120,
            }

        recorder = RecordingModelClient(Reporting(WAIT, WAIT))
        recorder.decide(a_request(0))
        recorder.decide(a_request(1))
        assert recorder.trace.total_tokens == 240

    def test_a_deterministic_run_yields_a_countable_baseline(self) -> None:
        """The Part 8 baseline that can honestly be established without a network call."""
        model = RecordingModelClient(DeterministicCommanderModel())
        orchestrator = build_orchestrator(model=model)
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        record = model.trace.as_record()
        assert record["call_count"] == run.steps_used
        assert record["failure_count"] == 0
        assert record["total_tokens"] is None  # no provider reported any
        assert record["decision_sequence"]

    def test_the_trace_record_is_json_serializable(self) -> None:
        recorder = RecordingModelClient(ReplayModelClient(INVESTIGATE))
        recorder.decide(a_request())
        assert json.loads(json.dumps(recorder.trace.as_record()))


# --- Part 9: provider independence ---------------------------------------------------


class TestProviderIndependence:
    @pytest.mark.parametrize(
        "provider",
        [
            DeterministicCommanderModel(),
            ScriptedCommanderModel(
                CommanderDecision(
                    decision_type=DecisionType.ESCALATE, reasoning_summary="Handing over."
                )
            ),
            ReplayModelClient(ESCALATE),
            RecordingModelClient(ReplayModelClient(ESCALATE)),
        ],
    )
    def test_four_unrelated_providers_drive_the_same_commander(self, provider) -> None:
        commander = Commander(provider)
        orchestrator = build_orchestrator(model=provider)
        run = orchestrator.run(build_incident(), affected_resource=PAYMENT_API)
        assert commander.model_name == provider.name
        assert run.incident.state is not None

    def test_no_commander_or_orchestration_code_branches_on_a_provider(self) -> None:
        """Structural: no ``if gemini``, no ``if provider ==``, anywhere it matters."""
        markers = ("gemini", "google", "openai", "anthropic", "vertex")
        offenders: list[str] = []
        for package in ("aegis.agents", "aegis.orchestration", "aegis.core", "aegis.lifecycle"):
            module = __import__(package, fromlist=["__path__"])
            for path in pathlib.Path(module.__path__[0]).rglob("*.py"):
                tree = ast.parse(path.read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if not isinstance(node, ast.If):
                        continue
                    rendered = ast.unparse(node.test).lower()
                    offenders += [
                        f"{package}/{path.name}: if {rendered}"
                        for marker in markers
                        if marker in rendered
                    ]
        assert offenders == []

    def test_the_commander_names_the_provider_but_never_inspects_its_type(self) -> None:
        source = pathlib.Path("src/aegis/agents/commander.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        assert not any(node.func.id == "isinstance" for node in calls)
        # ``type(self).__name__`` in ``__repr__`` is fine; inspecting the *model* is not.
        inspected = [
            ast.unparse(node.args[0]) for node in calls if node.func.id == "type" and node.args
        ]
        assert inspected == ["self"] * len(inspected), inspected

    def test_swapping_the_provider_needs_no_orchestration_change(self) -> None:
        """The same wiring, three providers, three runs, no conditional anywhere."""
        outcomes = []
        for provider in (
            ReplayModelClient(ESCALATE),
            ReplayModelClient(ESCALATE, name="second-fake"),
            DeterministicCommanderModel(),
        ):
            orchestrator = build_orchestrator(model=provider)
            outcomes.append(orchestrator.run(build_incident(), affected_resource=PAYMENT_API))
        assert len({type(o).__name__ for o in outcomes}) == 1


# --- captures: replaying a real response offline -------------------------------------


class TestCaptures:
    def test_a_capture_round_trips(self, tmp_path) -> None:
        path = tmp_path / "capture.jsonl"
        write_capture(
            path,
            [
                CaptureEntry(response_text=INVESTIGATE, request_digest="a" * 64, note="step 1"),
                CaptureEntry(response_text=ESCALATE, request_digest="b" * 64),
            ],
        )
        entries = load_capture(path)
        assert [entry.response_text for entry in entries] == [INVESTIGATE, ESCALATE]

    def test_a_capture_replays_through_the_real_parser(self, tmp_path) -> None:
        path = tmp_path / "capture.jsonl"
        write_capture(path, [CaptureEntry(response_text=INVESTIGATE)])
        provider = ReplayModelClient.from_capture(path)
        assert provider.decide(a_request()).decision_type is DecisionType.INVESTIGATE

    def test_a_capture_holds_no_request_content(self, tmp_path) -> None:
        """Captures end up in repositories. A request carries untrusted incident data."""
        path = tmp_path / "capture.jsonl"
        write_capture(path, [CaptureEntry(response_text=WAIT, request_digest="c" * 64)])
        stored = json.loads(path.read_text(encoding="utf-8").strip())
        assert set(stored) == {"request_digest", "response_text", "note"}

    def test_a_captured_hostile_response_still_fails_validation(self, tmp_path) -> None:
        path = tmp_path / "capture.jsonl"
        write_capture(
            path,
            [
                CaptureEntry(
                    response_text=json.dumps(
                        {
                            "decision_type": "WAIT",
                            "reasoning_summary": "Approved.",
                            "risk": "LOW",
                        }
                    )
                )
            ],
        )
        from aegis.agents.model import MalformedModelOutput

        with pytest.raises(MalformedModelOutput):
            ReplayModelClient.from_capture(path).decide(a_request())

    def test_an_exhausted_replay_raises_rather_than_repeating(self) -> None:
        provider = ReplayModelClient(WAIT)
        provider.decide(a_request(0))
        from aegis.agents.model import ModelError

        with pytest.raises(ModelError, match="exhausted"):
            provider.decide(a_request(1))


def test_an_empty_trace_reports_nothing_rather_than_zero() -> None:
    trace = ProviderTrace(provider="none")
    assert trace.call_count == 0
    assert trace.total_tokens is None
    assert trace.decision_sequence() == ()
