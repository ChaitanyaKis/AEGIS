"""The governed toolbox — policy in front of every read.

The Commander and the specialists never touch the world, the executor, the policy engine
or the audit store. They name a tool id and get structured data back. Everything between
those two points happens here:

    agent -> tool id -> capability -> PolicyEngine -> ALLOW/DENY -> ObservationSource

The tool *contracts* live in :mod:`aegis.tools` precisely so that the agent plane can use
them without importing this module and, through it, the control plane.

Reads are authorized, not merely allowed by convention: each read builds a real ``Action``
and asks the real policy engine. A denial comes back as structured data an agent can
report, and denials are not something it can retry its way past.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime

from pydantic import JsonValue

from aegis.agents.model import ToolSpecification
from aegis.core.dependencies import DependencyGraph, UnknownResourceError
from aegis.core.domain import Action, Agent, PolicyDecisionType, utc_now
from aegis.core.policy import PolicyEngine
from aegis.enterprise import EnterpriseWorld, ObservationSource
from aegis.tools.contracts import (
    READ_TOOLS,
    ToolDefinition,
    ToolKind,
    ToolOutcome,
    ToolRegistry,
    ToolResult,
)

__all__ = [
    "READ_TOOLS",
    "GovernedToolbox",
    "ToolDefinition",
    "ToolKind",
    "ToolOutcome",
    "ToolRegistry",
    "ToolResult",
]


class GovernedToolbox:
    """Runs read tools, with policy in front of every one.

    Args:
        registry: The tools that exist.
        policy_engine: Asked about every read, before any observation is made.
        world: The simulated enterprise.
        agent: The control-plane record the reads are attributed to.
        graph: Dependency topology, for ``get_dependency_health``.
        allowed_tools: The subset of tool ids this agent may name. ``None`` means every
            read tool. A tool outside the set does not exist as far as this agent is
            concerned — naming it yields ``UNKNOWN_TOOL``, not a denial, because an agent
            should not learn the shape of capabilities it was never given.
        clock: Observation time. Injectable so runs stay reproducible.

    The Commander holds no reference to this object's collaborators — it calls
    :meth:`invoke` with a tool id and receives a :class:`ToolResult`.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        policy_engine: PolicyEngine,
        world: EnterpriseWorld,
        agent: Agent,
        *,
        graph: DependencyGraph | None = None,
        allowed_tools: frozenset[str] | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._registry = registry
        self._allowed_tools = allowed_tools
        self._policy = policy_engine
        self._world = world
        self._agent = agent
        self._graph = graph if graph is not None else world.dependency_graph()
        self._observations = ObservationSource(world)
        self._clock = clock
        self._call_counter = 0

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    def available_tool_ids(self) -> tuple[str, ...]:
        """What this agent may ask for. Read tools only; proposals are a decision type."""
        return tuple(
            tool_id for tool_id in self._registry.ids(kind=ToolKind.READ) if self._permits(tool_id)
        )

    def available_tool_specifications(self) -> tuple[ToolSpecification, ...]:
        """The same tools, described well enough to call correctly.

        Purpose and argument names, taken from each registered
        :class:`~aegis.tools.contracts.ToolDefinition` rather than restated, so there is no
        second copy of a schema to drift from the one :meth:`invoke` enforces.

        ``capability_id`` is deliberately left out. :meth:`available_tool_ids` withholds
        tools outside ``allowed_tools`` precisely so an agent does not learn the shape of
        capabilities it was never given, and naming the capability behind a tool it *may*
        call would give that away by another route. Knowing how to call a tool is not
        permission to: every call still builds an ``Action`` and asks the policy engine.
        """
        specifications = []
        for tool_id in self.available_tool_ids():
            tool = self._registry.get(tool_id)
            if tool is None:  # pragma: no cover - ids() only yields registered tools
                continue
            specifications.append(
                ToolSpecification(
                    tool_id=tool.tool_id,
                    description=tool.description,
                    arguments=dict(tool.input_schema),
                )
            )
        return tuple(specifications)

    def _permits(self, tool_id: str) -> bool:
        return self._allowed_tools is None or tool_id in self._allowed_tools

    def invoke(self, tool_id: str, arguments: Mapping[str, JsonValue]) -> ToolResult:
        """Run one read tool under governance.

        Every outcome is a value, not an exception, so the Commander always receives
        structured data it can reason about — including when it is refused.
        """
        tool = self._registry.get(tool_id)
        if tool is not None and not self._permits(tool.tool_id):
            tool = None
        if tool is None:
            return ToolResult(
                tool_id=tool_id or "<empty>",
                outcome=ToolOutcome.UNKNOWN_TOOL,
                detail=(
                    f"no tool {tool_id!r} is registered; available: "
                    f"{', '.join(self.available_tool_ids())}"
                ),
            )
        if tool.kind is not ToolKind.READ:
            return ToolResult(
                tool_id=tool.tool_id,
                outcome=ToolOutcome.INVALID_ARGUMENTS,
                detail=(
                    f"{tool.tool_id} is a {tool.kind} tool and cannot be invoked as a read; "
                    f"propose it with a PROPOSE_ACTION decision instead"
                ),
            )

        problem = self._registry.validate_arguments(tool, arguments)
        if problem is not None:
            return ToolResult(
                tool_id=tool.tool_id,
                outcome=ToolOutcome.INVALID_ARGUMENTS,
                detail=f"{tool.tool_id}: {problem}",
            )

        resource = str(arguments["resource"])
        decision = self._authorize(tool, resource)
        if decision.decision is not PolicyDecisionType.ALLOW:
            return ToolResult(
                tool_id=tool.tool_id,
                outcome=ToolOutcome.DENIED,
                detail=f"{decision.decision}: {decision.reason}",
                policy_reference=decision.policy_reference,
            )

        return self._read(tool, resource)

    def authorize_read(self, tool: ToolDefinition, resource: str):
        """The policy decision for one read. Exposed so tests can assert it was asked."""
        return self._authorize(tool, resource)

    def _authorize(self, tool: ToolDefinition, resource: str):
        """Build a real action for the read and put it to the real policy engine."""
        self._call_counter += 1
        probe = Action(
            action_id=f"read-{self._call_counter:04d}",
            incident_id="INC-TOOL-READ",
            requesting_agent=self._agent.agent_id,
            capability=tool.capability_id,
            target_resource=resource,
        )
        return self._policy.evaluate(probe, self._agent)

    def _read(self, tool: ToolDefinition, resource: str) -> ToolResult:
        """Observe the world, once the read has been authorized."""
        if not self._world.contains(resource):
            return ToolResult(
                tool_id=tool.tool_id,
                outcome=ToolOutcome.UNAVAILABLE,
                detail=f"resource {resource!r} is not declared in this enterprise",
            )

        observations = self._observations.observe(resource, at=self._clock())
        values: dict[str, JsonValue] = {}
        for observation in observations:
            values.update(observation.values)
        evidence = tuple(observation.observation_id for observation in observations)

        if tool.tool_id == "get_service_health":
            data = _require(values, "health")
        elif tool.tool_id == "get_metrics":
            data = _require(values, "error_rate")
        elif tool.tool_id == "get_recent_deployments":
            data = self._deployments(resource, values)
        else:
            data = self._dependency_health(resource)
            evidence = ()

        if data is None:
            return ToolResult(
                tool_id=tool.tool_id,
                outcome=ToolOutcome.UNAVAILABLE,
                detail=(
                    f"{tool.tool_id}: no usable observation for {resource!r}; the source "
                    f"reported nothing for the requested attribute"
                ),
                evidence=evidence,
            )

        return ToolResult(
            tool_id=tool.tool_id,
            outcome=ToolOutcome.OK,
            data=data,
            evidence=evidence,
            detail=f"{tool.tool_id} observed {resource}",
        )

    def _deployments(self, resource: str, values: Mapping[str, JsonValue]) -> dict | None:
        """Current version, plus the previous declared one if there is exactly one."""
        current = values.get("deployment")
        if not isinstance(current, str):
            return None
        definition = self._world.definition(resource)
        others = [
            profile.version for profile in definition.deployments if profile.version != current
        ]
        data: dict[str, JsonValue] = {"current_deployment": current}
        if len(others) == 1:
            data["previous_deployment"] = others[0]
        return data

    def _dependency_health(self, resource: str) -> dict:
        """Topology around a resource, with health for each neighbour policy permits.

        Neighbours outside the capability's scope are reported as ``not_permitted`` rather
        than silently omitted — an agent should be able to tell "healthy" from "not shown".
        """
        try:
            dependencies = self._graph.dependencies(resource)
            dependents = self._graph.dependents(resource)
        except UnknownResourceError:
            return {"dependencies": {}, "dependents": {}}

        tool = self._registry.get("get_service_health")
        assert tool is not None  # registered above

        def health_of(neighbour: str) -> JsonValue:
            decision = self._authorize(tool, neighbour)
            if decision.decision is not PolicyDecisionType.ALLOW:
                return "not_permitted"
            if not self._world.contains(neighbour):
                return "unknown"
            return self._world.state(neighbour).health.value

        return {
            "dependencies": {name: health_of(name) for name in dependencies},
            "dependents": {name: health_of(name) for name in dependents},
        }

    def __repr__(self) -> str:
        return f"{type(self).__name__}(registry={self._registry!r})"


def _require(values: Mapping[str, JsonValue], key: str) -> dict[str, JsonValue] | None:
    """One attribute, or ``None`` when the source did not report it."""
    if key not in values:
        return None
    return {key: values[key]}
