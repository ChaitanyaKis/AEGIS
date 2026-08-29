"""The governed tool boundary: exact lookup, schema checks, and policy in front of reads."""

from __future__ import annotations

import ast
import pathlib

import pytest

from aegis.core.domain import PolicyDecisionType
from aegis.core.policy import PolicyEngine, PolicyRule
from aegis.enterprise import (
    CUSTOMER_DATABASE,
    ORDER_SERVICE,
    PAYMENT_API,
    EnterpriseWorld,
    FailureType,
    ServiceHealth,
)
from aegis.orchestration import (
    READ_TOOLS,
    ToolKind,
    ToolOutcome,
    ToolRegistry,
)
from aegis.orchestration.tools import GovernedToolbox
from tests.fleet import COMMANDER, build_registry, fixed_clock

HEALTH = {"resource": PAYMENT_API}


# --- the registry -------------------------------------------------------------------


def test_the_registry_is_exact(toolbox: GovernedToolbox) -> None:
    registry = toolbox.registry
    assert registry.get("get_service_health") is not None
    for near_miss in ("get_service", "GET_SERVICE_HEALTH", "get_service_health ", ""):
        assert registry.get(near_miss) is None


def test_every_tool_declares_its_contract() -> None:
    for tool in READ_TOOLS:
        assert tool.tool_id and tool.capability_id and tool.description
        if tool.kind is ToolKind.READ:
            assert tool.input_schema == {"resource": "string"}
            assert tool.output_schema


def test_read_tools_are_what_the_commander_sees() -> None:
    """The Commander sees its four investigation tools, not every tool that exists."""
    from tests.orchestration.conftest import build_orchestrator

    commander_tools = build_orchestrator().toolbox.available_tool_ids()
    assert commander_tools == (
        "get_dependency_health",
        "get_metrics",
        "get_recent_deployments",
        "get_service_health",
    )
    assert "propose_rollback" not in commander_tools
    assert "get_security_signals" not in commander_tools


def test_an_unpermitted_tool_does_not_exist_for_that_agent(toolbox: GovernedToolbox) -> None:
    """Not a denial: an agent should not learn the shape of capabilities it never had."""
    from aegis.orchestration.orchestrator import COMMANDER_TOOLS

    restricted = GovernedToolbox(
        toolbox.registry,
        PolicyEngine(build_registry(), clock=fixed_clock),
        EnterpriseWorld(),
        COMMANDER,
        allowed_tools=COMMANDER_TOOLS,
        clock=fixed_clock,
    )
    result = restricted.invoke("get_security_signals", HEALTH)
    assert result.outcome is ToolOutcome.UNKNOWN_TOOL


def test_duplicate_tool_ids_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate tool"):
        ToolRegistry((READ_TOOLS[0], READ_TOOLS[0]))


def test_the_boundary_executes_nothing_dynamically() -> None:
    """A tool id is a dictionary key, never a path to a callable."""
    import aegis.orchestration as orchestration

    for path in pathlib.Path(orchestration.__path__[0]).glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for forbidden in ("eval(", "exec(", "__import__", "importlib", "subprocess", "getattr("):
            assert forbidden not in text, f"{path.name}: {forbidden}"
        ast.parse(text)


# --- unknown and malformed calls ----------------------------------------------------


@pytest.mark.parametrize(
    "tool_id", ["disable_policy", "export_customer_data", "", "get_service_healt"]
)
def test_an_unknown_tool_cannot_execute(toolbox: GovernedToolbox, tool_id: str) -> None:
    result = toolbox.invoke(tool_id, HEALTH)
    assert result.outcome is ToolOutcome.UNKNOWN_TOOL
    assert result.data == {}


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"resource": ""},
        {"resource": 42},
        {"resource": True},
        {"service": PAYMENT_API},
        {"resource": PAYMENT_API, "extra": "x"},
    ],
    ids=["missing", "empty", "wrong-type", "bool-not-string", "wrong-name", "unexpected"],
)
def test_malformed_arguments_cannot_execute(toolbox: GovernedToolbox, arguments: dict) -> None:
    result = toolbox.invoke("get_service_health", arguments)
    assert result.outcome is ToolOutcome.INVALID_ARGUMENTS
    assert result.data == {}


def test_a_propose_tool_cannot_be_invoked_as_a_read(toolbox: GovernedToolbox) -> None:
    """Proposing is a decision type, not a tool call that acts."""
    result = toolbox.invoke("propose_rollback", {"target_version": "v4.7"})
    assert result.outcome is ToolOutcome.INVALID_ARGUMENTS
    assert "PROPOSE" in result.detail


# --- reads are governed -------------------------------------------------------------


def test_an_allowed_read_returns_data_and_provenance(toolbox: GovernedToolbox) -> None:
    result = toolbox.invoke("get_service_health", HEALTH)
    assert result.outcome is ToolOutcome.OK
    assert result.data == {"health": "unhealthy"}
    assert result.evidence
    assert all(ref.startswith("obs-") for ref in result.evidence)


def test_reads_reflect_the_world(toolbox: GovernedToolbox, world: EnterpriseWorld) -> None:
    assert toolbox.invoke("get_metrics", HEALTH).data == {"error_rate": 37.0}
    world.rollback(PAYMENT_API, "v4.7")
    assert toolbox.invoke("get_metrics", HEALTH).data == {"error_rate": 0.7}


def test_the_deployment_tool_names_the_previous_version(toolbox: GovernedToolbox) -> None:
    result = toolbox.invoke("get_recent_deployments", HEALTH)
    assert result.data == {"current_deployment": "v4.8", "previous_deployment": "v4.7"}


def test_dependency_health_reports_the_neighbourhood(toolbox: GovernedToolbox) -> None:
    result = toolbox.invoke("get_dependency_health", HEALTH)
    assert result.outcome is ToolOutcome.OK
    assert "service:order-service" in result.data["dependents"]
    assert "db:payment" in result.data["dependencies"]


def test_out_of_scope_neighbours_are_marked_not_permitted(
    toolbox: GovernedToolbox,
) -> None:
    """ "Not shown" must stay distinguishable from "healthy"."""
    result = toolbox.invoke("get_dependency_health", HEALTH)
    assert result.data["dependencies"]["db:payment"] == "not_permitted"


def test_a_read_outside_capability_scope_is_denied(toolbox: GovernedToolbox) -> None:
    """telemetry.read is scoped to payment-api and order-service, and nothing else."""
    result = toolbox.invoke("get_service_health", {"resource": CUSTOMER_DATABASE})
    assert result.outcome is ToolOutcome.DENIED
    assert result.policy_reference == PolicyRule.RESOURCE_OUT_OF_SCOPE.value
    assert result.data == {}


def test_a_read_the_agent_may_not_perform_is_denied(world: EnterpriseWorld) -> None:
    """business-impact does not hold deployment.read; the tool is refused, not adapted.

    Diagnostic does hold it — ``claude.md`` section 7 has it correlate deployments — so the
    agent that genuinely lacks the grant is the one that demonstrates the refusal.
    """
    from tests.fleet import BUSINESS_IMPACT

    toolbox = GovernedToolbox(
        ToolRegistry(),
        PolicyEngine(build_registry(), clock=fixed_clock),
        world,
        BUSINESS_IMPACT,
        clock=fixed_clock,
    )
    result = toolbox.invoke("get_recent_deployments", HEALTH)
    assert result.outcome is ToolOutcome.DENIED
    assert result.policy_reference == PolicyRule.CAPABILITY_NOT_HELD.value


def test_every_read_asks_policy(toolbox: GovernedToolbox) -> None:
    """Not "reads are low risk so we skip the check" — the check happens every time."""
    decision = toolbox.authorize_read(toolbox.registry.get("get_service_health"), PAYMENT_API)
    assert decision.decision is PolicyDecisionType.ALLOW
    denied = toolbox.authorize_read(toolbox.registry.get("get_service_health"), CUSTOMER_DATABASE)
    assert denied.decision is PolicyDecisionType.DENY


def test_a_denial_is_structured_data_not_an_exception(toolbox: GovernedToolbox) -> None:
    """The Commander can read and report a refusal rather than crashing or guessing."""
    result = toolbox.invoke("get_service_health", {"resource": CUSTOMER_DATABASE})
    assert result.outcome is ToolOutcome.DENIED
    assert result.policy_reference
    assert "DENY" in result.detail


def test_an_undeclared_resource_is_unavailable(toolbox: GovernedToolbox) -> None:
    result = toolbox.invoke("get_service_health", {"resource": ORDER_SERVICE})
    assert result.outcome is ToolOutcome.OK  # in scope and declared
    denied = toolbox.invoke("get_service_health", {"resource": "service:ghost"})
    assert denied.outcome is ToolOutcome.DENIED  # out of scope before it is unknown


# --- tool failure is never evidence -------------------------------------------------


def test_a_dark_telemetry_source_is_unavailable_not_healthy(
    toolbox: GovernedToolbox, world: EnterpriseWorld
) -> None:
    world.inject_failure(FailureType.VERIFICATION_FAILURE)
    result = toolbox.invoke("get_service_health", HEALTH)
    assert result.outcome is ToolOutcome.UNAVAILABLE
    assert result.data == {}
    assert "health" not in result.data


def test_an_unavailable_read_carries_no_data(
    toolbox: GovernedToolbox, world: EnterpriseWorld
) -> None:
    world.inject_failure(FailureType.VERIFICATION_FAILURE)
    assert toolbox.invoke("get_metrics", HEALTH).outcome is ToolOutcome.UNAVAILABLE
    # The deployment feed is still up, so that read still answers.
    assert toolbox.invoke("get_recent_deployments", HEALTH).outcome is ToolOutcome.OK


def test_execution_layer_failures_do_not_change_reads(
    toolbox: GovernedToolbox, world: EnterpriseWorld
) -> None:
    baseline = toolbox.invoke("get_service_health", HEALTH).data
    for failure in (FailureType.TOOL_TIMEOUT, FailureType.TOOL_500):
        world.clear_failures()
        world.inject_failure(failure)
        assert toolbox.invoke("get_service_health", HEALTH).data == baseline


def test_reads_never_change_the_world(toolbox: GovernedToolbox, world: EnterpriseWorld) -> None:
    before = world.snapshot().resources
    for tool_id in toolbox.available_tool_ids():
        toolbox.invoke(tool_id, HEALTH)
    assert world.snapshot().resources == before
    assert world.state(PAYMENT_API).health is ServiceHealth.UNHEALTHY


def test_reads_are_reproducible(toolbox: GovernedToolbox) -> None:
    first = toolbox.invoke("get_service_health", HEALTH)
    second = toolbox.invoke("get_service_health", HEALTH)
    assert first.data == second.data
    assert first.evidence == second.evidence


# --- what the toolbox tells an agent about its tools ---------------------------------
#
# Added after the first live Gemini run: the model was given tool *ids* and nothing else,
# had to guess that the argument was `resource`, and could not learn otherwise because a
# refusal came back as a bare outcome code. Describing a tool grants nothing — the read
# still builds an Action and still asks policy — but a caller that cannot call correctly
# spends its whole step budget finding that out.


def test_a_specification_is_offered_for_every_available_tool(toolbox: GovernedToolbox) -> None:
    specifications = toolbox.available_tool_specifications()
    assert tuple(s.tool_id for s in specifications) == toolbox.available_tool_ids()


def test_a_specification_carries_the_registry_schema_rather_than_a_copy(
    toolbox: GovernedToolbox,
) -> None:
    """Projected from the ToolDefinition the registry holds, so the argument names shown
    to an agent are the same ones ``validate_arguments`` enforces."""
    for specification in toolbox.available_tool_specifications():
        declared = toolbox.registry.get(specification.tool_id)
        assert dict(specification.arguments) == dict(declared.input_schema)
        assert specification.description == declared.description


def test_a_specification_never_names_the_capability_behind_the_tool(
    toolbox: GovernedToolbox,
) -> None:
    """An agent should not learn the shape of capabilities from a tool listing."""
    for specification in toolbox.available_tool_specifications():
        assert "capability_id" not in specification.model_dump()
        assert ".read" not in str(specification.model_dump())


def test_an_unpermitted_tool_gets_no_specification(world: EnterpriseWorld) -> None:
    """The narrowing is the same one ``available_tool_ids`` applies. A description cannot
    reveal a tool the agent was not given."""
    restricted = GovernedToolbox(
        ToolRegistry(),
        PolicyEngine(build_registry(), clock=fixed_clock),
        world,
        COMMANDER,
        allowed_tools=frozenset({"get_service_health"}),
        clock=fixed_clock,
    )
    assert [s.tool_id for s in restricted.available_tool_specifications()] == ["get_service_health"]


def test_following_a_specification_never_produces_invalid_arguments(
    toolbox: GovernedToolbox,
) -> None:
    """The end-to-end claim, and exactly as far as it goes.

    A caller that passes what the specification declares gets past argument validation --
    the failure the live run could not escape. It does **not** get past policy: an agent
    reading a tool it does not hold the capability for is still DENIED, which is the whole
    point of describing a tool rather than granting one.
    """
    for specification in toolbox.available_tool_specifications():
        arguments = {name: PAYMENT_API for name in specification.arguments}
        result = toolbox.invoke(specification.tool_id, arguments)
        assert result.outcome is not ToolOutcome.INVALID_ARGUMENTS, specification.tool_id
        assert result.outcome in {ToolOutcome.OK, ToolOutcome.DENIED}, specification.tool_id


def test_a_specification_does_not_make_a_read_permitted(toolbox: GovernedToolbox) -> None:
    """Knowing how to call `get_security_signals` is not holding `security.read`."""
    result = toolbox.invoke("get_security_signals", {"resource": PAYMENT_API})
    assert result.outcome is ToolOutcome.DENIED
    assert "does not hold capability" in result.detail


def test_a_refused_call_says_what_was_wrong(toolbox: GovernedToolbox) -> None:
    """``detail`` is the part a caller can act on. An outcome code alone says that
    something is wrong and not what, which is how a retry loop starts."""
    missing = toolbox.invoke("get_recent_deployments", {})
    assert missing.outcome is ToolOutcome.INVALID_ARGUMENTS
    assert "resource" in missing.detail

    unscoped = toolbox.invoke("get_recent_deployments", {"resource": "payment-api"})
    assert unscoped.outcome is ToolOutcome.DENIED
    assert "payment-api" in unscoped.detail
