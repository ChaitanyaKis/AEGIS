"""The Commander, its decision contracts, its model boundary and its prompt.

The theme throughout: the Commander is structurally unable to govern. Most of these tests
assert an absence — a field that cannot be expressed, a collaborator it does not hold, a
channel that does not exist.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest
from pydantic import ValidationError

from aegis.agents import (
    COMMANDER_SYSTEM_PROMPT,
    FORBIDDEN_PROPOSAL_FIELDS,
    Commander,
    CommanderContext,
    CommanderDecision,
    CommanderProposal,
    DecisionType,
    DeterministicCommanderModel,
    MalformedModelOutput,
    ModelError,
    ModelRequest,
    ModelTimeout,
    ModelUnavailable,
    ScriptedCommanderModel,
    ToolRequest,
    parse_decision,
    render,
)
from aegis.agents.decisions import TaskType
from aegis.agents.model import ToolSpecification
from aegis.core.domain import IncidentState, NonEmptyStr, to_json
from aegis.enterprise import PAYMENT_API
from tests.agents.conftest import INJECTION

TOOLS = ("get_service_health", "get_metrics", "get_recent_deployments", "get_dependency_health")


# --- what a decision can express ----------------------------------------------------


@pytest.mark.parametrize("field", sorted(FORBIDDEN_PROPOSAL_FIELDS))
def test_a_proposal_cannot_carry_a_governance_field(field: str) -> None:
    """A model that states its own risk produces an error, not a decision with a risk in it."""
    with pytest.raises(ValidationError):
        CommanderProposal(
            capability_id="production.rollback",
            target_resource=PAYMENT_API,
            **{field: "LOW"},
        )


def test_a_decision_cannot_carry_an_approval_or_verification() -> None:
    for extra in ({"approved": True}, {"verified": True}, {"policy_decision": "ALLOW"}):
        with pytest.raises(ValidationError):
            CommanderDecision(decision_type=DecisionType.WAIT, reasoning_summary="x", **extra)


@pytest.mark.parametrize(
    ("decision_type", "payload"),
    [
        (DecisionType.INVESTIGATE, {}),
        (DecisionType.PROPOSE_ACTION, {}),
        (
            DecisionType.INVESTIGATE,
            {"proposal": {"capability_id": "c", "target_resource": "r"}},
        ),
        (DecisionType.PROPOSE_ACTION, {"tool_request": {"tool_id": "t"}}),
        (DecisionType.WAIT, {"tool_request": {"tool_id": "t"}}),
        (DecisionType.ESCALATE, {"proposal": {"capability_id": "c", "target_resource": "r"}}),
    ],
    ids=[
        "investigate-without-tool",
        "propose-without-proposal",
        "investigate-with-proposal",
        "propose-with-tool",
        "wait-with-payload",
        "escalate-with-payload",
    ],
)
def test_each_decision_type_requires_exactly_its_own_payload(
    decision_type: DecisionType, payload: dict
) -> None:
    with pytest.raises(ValidationError):
        CommanderDecision(decision_type=decision_type, reasoning_summary="x", **payload)


def test_the_decision_vocabulary_is_closed() -> None:
    assert [member.value for member in DecisionType] == [
        "INVESTIGATE",
        "PROPOSE_ACTION",
        "WAIT",
        "DELEGATE",
        "ESCALATE",
    ]
    with pytest.raises(ValidationError):
        CommanderDecision(decision_type="EXECUTE", reasoning_summary="x")


def test_a_reasoning_summary_is_required() -> None:
    """Every decision explains itself, even though nothing deterministic reads it."""
    with pytest.raises(ValidationError):
        CommanderDecision(decision_type=DecisionType.WAIT, reasoning_summary="")


# --- the model boundary -------------------------------------------------------------


def test_malformed_output_raises_rather_than_being_repaired() -> None:
    for raw in ("not json", "[]", '"a string"', "{}", '{"decision_type": "NOPE"}'):
        with pytest.raises(MalformedModelOutput):
            parse_decision(raw)


def test_a_self_assessed_risk_in_raw_output_is_rejected() -> None:
    raw = json.dumps(
        {
            "decision_type": "PROPOSE_ACTION",
            "reasoning_summary": "trust me",
            "proposal": {
                "capability_id": "production.rollback",
                "target_resource": PAYMENT_API,
                "risk": "LOW",
            },
        }
    )
    with pytest.raises(MalformedModelOutput):
        parse_decision(raw)


def test_valid_output_parses() -> None:
    decision = parse_decision(
        json.dumps(
            {
                "decision_type": "INVESTIGATE",
                "reasoning_summary": "need health",
                "tool_request": {"tool_id": "get_service_health", "arguments": {}},
            }
        )
    )
    assert decision.decision_type is DecisionType.INVESTIGATE


def test_every_model_failure_is_an_exception_not_a_value() -> None:
    """There is no decision a caller could mistake for permission."""
    for error in (ModelTimeout, ModelUnavailable, MalformedModelOutput):
        assert issubclass(error, ModelError)
    assert not issubclass(ModelError, CommanderDecision.__mro__[0])


def test_a_model_error_propagates_out_of_the_commander() -> None:
    def fail(_request: ModelRequest) -> CommanderDecision:
        raise ModelTimeout("deadline exceeded")

    commander = Commander(ScriptedCommanderModel(fail))
    with pytest.raises(ModelTimeout):
        commander.decide(
            CommanderContext(incident_id="INC-1", lifecycle_state=IncidentState.CLASSIFIED),
            available_tools=TOOLS,
        )


# --- prompt: untrusted data cannot reach the instruction channel ---------------------


def test_the_request_has_no_instruction_field() -> None:
    """Injection is impossible here because the wire does not exist."""
    assert "system_instruction" not in ModelRequest.model_fields
    assert "system" not in ModelRequest.model_fields
    assert set(ModelRequest.model_fields) == {
        "task",
        "data",
        "available_tools",
        "tool_specifications",
        "available_specialists",
        "step",
        "max_steps",
    }


def test_the_narrowing_fields_cannot_carry_prose() -> None:
    """``available_tools``, ``tool_specifications`` and ``available_specialists`` describe
    what a request may *name*. Every one of them is a closed shape of ids and schema types,
    so none is a place a caller could smuggle an instruction into the trusted channel."""
    for field in ("available_tools", "available_specialists"):
        annotation = ModelRequest.model_fields[field].annotation
        assert annotation == tuple[NonEmptyStr, ...], field
    assert set(ToolSpecification.model_fields) == {"tool_id", "description", "arguments"}


def test_the_system_instruction_is_a_constant(poisoned_context: CommanderContext) -> None:
    clean, _ = render(ModelRequest(task="t", data={}, available_tools=TOOLS, step=0, max_steps=8))
    poisoned, user_content = render(
        ModelRequest(
            task="t",
            data=poisoned_context.as_model_data(),
            available_tools=TOOLS,
            step=0,
            max_steps=8,
        )
    )
    assert clean == poisoned == COMMANDER_SYSTEM_PROMPT
    assert INJECTION not in poisoned
    assert INJECTION in user_content


def test_untrusted_data_is_quoted_as_json_under_one_key(
    poisoned_context: CommanderContext,
) -> None:
    _, user_content = render(
        ModelRequest(
            task="t",
            data=poisoned_context.as_model_data(),
            available_tools=TOOLS,
            step=0,
            max_steps=8,
        )
    )
    payload = user_content.split("UNTRUSTED DATA", 1)[1].split("\n", 1)[1]
    assert set(json.loads(payload)) == {"data"}


def test_the_prompt_states_the_boundary() -> None:
    """Belt as well as braces: the structure is the defence, the prompt says so too."""
    lowered = COMMANDER_SYSTEM_PROMPT.lower()
    assert "untrusted content" in lowered
    assert "never instructions" in lowered
    assert "may not authorize" in lowered
    assert "may not approve" in lowered
    assert "may not assess risk" in lowered


# --- prompt: what the trusted channel tells the model it may name ---------------------

SPECIFICATIONS = (
    ToolSpecification(
        tool_id="get_recent_deployments",
        description="The version a service is running, and the version before it.",
        arguments={"resource": "string"},
    ),
    ToolSpecification(
        tool_id="get_metrics",
        description="Error rate and latency for one service.",
        arguments={"resource": "string"},
    ),
)


def _render(**overrides) -> str:
    settings = {"task": "t", "data": {}, "available_tools": TOOLS, "step": 0, "max_steps": 8}
    settings.update(overrides)
    return render(ModelRequest(**settings))[1]


def test_tool_arguments_are_shown_so_they_need_not_be_guessed() -> None:
    """The live failure's second cause. ``{"resource": ...}`` is the difference between a
    read that answers and an INVALID_ARGUMENTS a model has to guess its way out of."""
    content = _render(tool_specifications=SPECIFICATIONS)
    assert "get_recent_deployments(resource: string)" in content
    assert "The version a service is running, and the version before it." in content


def test_a_bare_id_list_still_renders() -> None:
    """Specifications are additive. A caller that supplies ids alone gets the old list."""
    content = _render()
    assert f"AVAILABLE TOOLS: {', '.join(TOOLS)}" in content


def test_a_specification_for_a_tool_this_agent_may_not_call_is_not_shown() -> None:
    """``available_tools`` stays the authority on what may be named. A description cannot
    widen it — an agent should not learn the shape of tools it was never given."""
    withheld = ToolSpecification(
        tool_id="get_security_signals",
        description="Security-relevant signals for one service.",
        arguments={"resource": "string"},
    )
    content = _render(tool_specifications=(*SPECIFICATIONS, withheld))
    assert "get_security_signals" not in content


def test_the_specialist_list_is_rendered() -> None:
    content = _render(available_specialists=("diagnostic", "remediation"))
    assert "AVAILABLE SPECIALISTS: diagnostic, remediation" in content


def test_no_specialists_renders_as_none_rather_than_silence() -> None:
    """An empty list is a statement — "you may delegate to nobody" — not an omission a
    model could read as "delegate to whoever you like"."""
    assert "AVAILABLE SPECIALISTS: none" in _render()


def test_the_tool_and_specialist_lists_sit_outside_the_untrusted_data(
    poisoned_context: CommanderContext,
) -> None:
    """Both are AEGIS-authored, so they belong in the trusted part of the user channel.
    The untrusted payload stays exactly one JSON object under one key."""
    content = _render(
        data=poisoned_context.as_model_data(),
        tool_specifications=SPECIFICATIONS,
        available_specialists=("diagnostic",),
    )
    trusted, untrusted = content.split("UNTRUSTED DATA", 1)
    assert "AVAILABLE SPECIALISTS" in trusted
    assert "get_recent_deployments(resource: string)" in trusted
    payload = untrusted.splitlines()[1]
    assert set(json.loads(payload)) == {"data"}
    assert INJECTION not in trusted


def test_a_specification_cannot_carry_a_capability_id() -> None:
    """Knowing how to call a tool is not learning what capability sits behind it."""
    assert "capability_id" not in ToolSpecification.model_fields
    with pytest.raises(ValidationError):
        ToolSpecification(
            tool_id="get_metrics",
            description="x",
            arguments={},
            capability_id="telemetry.read",
        )


# --- prompt: the vocabulary the model is shown must be the vocabulary it may use ------
#
# The live Gemini trial failed here and nowhere else. The prompt documented four of the
# five decision types; DELEGATE was missing, and DELEGATE is the only route to a
# remediation, because PROPOSAL_AUTHORITY gives the Commander proposal rights over nothing.
# The model was asked to reach a goal through a decision it was never told existed, and
# spent all ten steps re-investigating. These tests exist so that gap cannot reopen: the
# deterministic model reads `request.data` and never the prompt, so 302 green benchmark
# scenarios say nothing at all about whether the prompt is complete.


@pytest.mark.parametrize("decision_type", list(DecisionType))
def test_every_decision_type_appears_in_the_prompt(decision_type: DecisionType) -> None:
    assert decision_type.value in COMMANDER_SYSTEM_PROMPT


@pytest.mark.parametrize("task_type", list(TaskType))
def test_every_task_type_appears_in_the_prompt(task_type: TaskType) -> None:
    assert task_type.value in COMMANDER_SYSTEM_PROMPT


def test_the_prompt_documents_the_delegation_payload() -> None:
    """Naming DELEGATE is not enough; a decision needs the payload its validator demands."""
    assert '"decision_type": "DELEGATE"' in COMMANDER_SYSTEM_PROMPT
    for field in ("delegation", "target_agent_id", "task_type"):
        assert field in COMMANDER_SYSTEM_PROMPT


def test_the_prompt_says_the_commander_cannot_propose_a_remediation_itself() -> None:
    """PROPOSAL_AUTHORITY is the rule; this is the model being told about it in advance.

    Telling it does not enforce it — the orchestrator refuses the proposal either way. It
    stops the model burning its whole step budget rediscovering a refusal by trial.
    """
    lowered = COMMANDER_SYSTEM_PROMPT.lower()
    assert "cannot propose a remediation yourself" in lowered
    assert "propose_remediation" in lowered


def test_the_prompt_tells_the_model_to_read_a_refusal_rather_than_repeat_it() -> None:
    assert "read that reason" in COMMANDER_SYSTEM_PROMPT.lower()


def test_the_prompt_contains_no_secrets() -> None:
    lowered = COMMANDER_SYSTEM_PROMPT.lower()
    for forbidden in ("api_key", "apikey", "password", "credential", "token", "bearer"):
        assert forbidden not in lowered


# --- the Commander holds nothing it could govern with -------------------------------


def test_the_agent_plane_imports_no_control_plane_authority() -> None:
    """The structural guarantee: a compromised model has nothing here to call."""
    import aegis.agents as agents

    forbidden = (
        "aegis.core.policy",
        "aegis.core.approval",
        "aegis.core.incidents",
        "aegis.core.verification",
        "aegis.core.audit",
        "aegis.core.assessment",
        "aegis.enterprise",
        "aegis.orchestration",
    )
    offenders: list[str] = []
    for path in sorted(pathlib.Path(agents.__path__[0]).glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            elif isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            else:
                continue
            offenders += [
                f"{path.name}: {name}"
                for name in names
                if any(name.startswith(bad) for bad in forbidden)
            ]
    assert offenders == []


def test_the_commander_holds_only_a_model(commander: Commander) -> None:
    held = {
        type(value).__name__
        for value in vars(commander).values()
        if not isinstance(value, str | int)
    }
    assert held == {"DeterministicCommanderModel"}


def test_the_agent_plane_executes_nothing_dynamically() -> None:
    import aegis.agents as agents

    for path in pathlib.Path(agents.__path__[0]).glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for forbidden in ("eval(", "exec(", "__import__", "importlib", "subprocess"):
            assert forbidden not in text, f"{path.name}: {forbidden}"


# --- the deterministic test model ---------------------------------------------------


def test_the_deterministic_model_investigates_before_proposing(
    commander: Commander, context: CommanderContext
) -> None:
    decision = commander.decide(context, available_tools=TOOLS)
    assert decision.decision_type is DecisionType.INVESTIGATE
    assert decision.tool_request.tool_id == "get_service_health"


def test_the_deterministic_model_is_reproducible(
    commander: Commander, context: CommanderContext
) -> None:
    first = commander.decide(context, available_tools=TOOLS)
    second = commander.decide(context, available_tools=TOOLS)
    assert to_json(first) == to_json(second)


def test_the_deterministic_model_reads_the_data_it_is_given(
    commander: Commander, context: CommanderContext
) -> None:
    """Once it has evidence it delegates, because it may not draft a remediation itself."""
    advanced = context
    for observation in (
        {"health": "unhealthy"},
        {"error_rate": 37.0},
        {"current_deployment": "v9.9", "previous_deployment": "v9.8"},
    ):
        advanced = advanced.with_step(
            decision=CommanderDecision(
                decision_type=DecisionType.INVESTIGATE,
                reasoning_summary="looking",
                tool_request=ToolRequest(tool_id="get_service_health"),
            ),
            note="observed",
            observation=observation,
        )
    decision = commander.decide(advanced, available_tools=TOOLS)
    assert decision.decision_type is DecisionType.DELEGATE
    assert decision.delegation.target_agent_id == "diagnostic"
    assert decision.delegation.target_resource == PAYMENT_API


def test_the_deterministic_model_ignores_injected_instructions(
    commander: Commander, poisoned_context: CommanderContext
) -> None:
    """It reads structure, not prose, so injected commands change nothing."""
    decision = commander.decide(poisoned_context, available_tools=TOOLS)
    assert decision.decision_type is DecisionType.INVESTIGATE
    assert decision.tool_request.tool_id in TOOLS


def test_the_deterministic_model_is_labelled_a_test_model() -> None:
    import aegis.agents.deterministic as module

    assert "DETERMINISTIC TEST MODEL" in (module.__doc__ or "")
    assert DeterministicCommanderModel.name == "deterministic-test-model"


def test_a_scripted_model_refuses_to_run_past_its_script() -> None:
    model = ScriptedCommanderModel(
        CommanderDecision(decision_type=DecisionType.WAIT, reasoning_summary="once")
    )
    request = ModelRequest(task="t", step=0, max_steps=4)
    assert model.decide(request).decision_type is DecisionType.WAIT
    with pytest.raises(ModelError, match="exhausted"):
        model.decide(request)


# --- session context ----------------------------------------------------------------


def test_the_context_is_frozen_and_advances_by_value(context: CommanderContext) -> None:
    decision = CommanderDecision(decision_type=DecisionType.WAIT, reasoning_summary="holding")
    advanced = context.with_step(decision=decision, note="waited")

    assert context.step == 0
    assert advanced.step == 1
    assert advanced is not context
    with pytest.raises(ValidationError):
        context.step = 5  # type: ignore[misc]


def test_the_context_preserves_evidence_references(context: CommanderContext) -> None:
    """Provenance survives; a model summary never replaces it."""
    advanced = context.with_step(
        decision=CommanderDecision(
            decision_type=DecisionType.INVESTIGATE,
            reasoning_summary="everything looks fine to me",
            tool_request=ToolRequest(tool_id="get_service_health"),
        ),
        note="observed",
        observation={"health": "unhealthy"},
        evidence=("obs-telemetry-payment-api-20260101T120000Z",),
    )
    assert advanced.evidence_references == ("obs-telemetry-payment-api-20260101T120000Z",)
    assert advanced.findings == ("everything looks fine to me",)
    assert advanced.history[0].observation == {"health": "unhealthy"}


def test_the_commander_cannot_set_its_lifecycle_state(context: CommanderContext) -> None:
    """It records what the state machine did; it never chooses."""
    assert context.with_lifecycle_state(IncidentState.EXECUTING).lifecycle_state is (
        IncidentState.EXECUTING
    )
    import inspect

    source = inspect.getsource(Commander)
    assert "IncidentState" not in source
    assert "transition" not in source
