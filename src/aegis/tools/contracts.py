"""Tool contracts: what a tool is, what calling one produces, and the registry.

Deliberately free of any control-plane import. The agent plane needs these types to name
tools and read results, and it must not be able to reach the policy engine, the executor
or the audit store while doing so — so the contracts live here and the *governed* toolbox
that enforces policy lives in :mod:`aegis.orchestration.tools`.

Three properties make the boundary hold:

* **The registry is closed and matched exactly.** A tool id is a dictionary key, never an
  attribute name, a module path or anything that becomes a callable. There is no
  ``getattr``, no dynamic import and no ``eval`` anywhere here, so an invented tool name
  can only produce ``UNKNOWN_TOOL``.
* **Arguments are checked against a declared schema** before anything runs. A malformed
  call is refused, not coerced.
* **Proposal tools do not act.** A PROPOSE tool exists so that a capability is
  *proposable* and declares the arguments a proposal must carry. Nothing here executes a
  remediation.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, Field, JsonValue, model_validator

from aegis.core.domain import DomainModel, EvidenceRef, NonEmptyStr

__all__ = [
    "READ_TOOLS",
    "ToolDefinition",
    "ToolKind",
    "ToolOutcome",
    "ToolRegistry",
    "ToolResult",
]


def _sorted_data(value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    return dict(sorted(value.items()))


_Data = Annotated[Mapping[str, JsonValue], AfterValidator(_sorted_data)]


class ToolKind(StrEnum):
    """What invoking a tool does."""

    READ = "READ"
    """Gathers information. Authorized, then executed against the observation source."""

    PROPOSE = "PROPOSE"
    """Makes a capability proposable. Invoking it never acts; it declares a shape."""


class ToolOutcome(StrEnum):
    """The result of a tool call. Only ``OK`` carries data."""

    OK = "OK"
    DENIED = "DENIED"
    """Policy refused. Structured, so the Commander can report it rather than guess."""

    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    INVALID_ARGUMENTS = "INVALID_ARGUMENTS"
    UNAVAILABLE = "UNAVAILABLE"
    """The underlying source could not answer. Never evidence of anything being well."""


class ToolDefinition(DomainModel):
    """One registered tool.

    ``input_schema`` maps argument name to the JSON type it must have; every declared
    argument is required. Anything else in the call is rejected.
    """

    tool_id: NonEmptyStr
    kind: ToolKind
    capability_id: NonEmptyStr
    """The capability this tool exercises. Policy is asked about this, not the tool id."""

    description: NonEmptyStr
    input_schema: Mapping[str, str] = Field(default_factory=dict)
    output_schema: tuple[NonEmptyStr, ...] = Field(default_factory=tuple)

    @model_validator(mode="after")
    def _schema_types_are_known(self) -> ToolDefinition:
        unknown = set(self.input_schema.values()) - set(_TYPES)
        if unknown:
            raise ValueError(f"{self.tool_id}: unknown argument types {sorted(unknown)}")
        return self


_TYPES: Mapping[str, type | tuple[type, ...]] = {
    "string": str,
    "number": (int, float),
    "boolean": bool,
}


class ToolResult(DomainModel):
    """What a tool call produced.

    ``data`` is untrusted content — a measurement of the world, never an instruction. It
    is handed to the Commander as data and to nothing else as authority.
    """

    tool_id: NonEmptyStr
    outcome: ToolOutcome
    data: _Data = Field(default_factory=dict)
    evidence: tuple[EvidenceRef, ...] = Field(default_factory=tuple)
    """Ids of the observations behind ``data``, so provenance survives the summary."""

    detail: NonEmptyStr
    policy_reference: NonEmptyStr | None = None
    """Rule that refused, when the outcome is DENIED."""

    @property
    def ok(self) -> bool:
        return self.outcome is ToolOutcome.OK


READ_TOOLS: tuple[ToolDefinition, ...] = (
    ToolDefinition(
        tool_id="get_service_health",
        kind=ToolKind.READ,
        capability_id="telemetry.read",
        description="Current health of one service.",
        input_schema={"resource": "string"},
        output_schema=("health",),
    ),
    ToolDefinition(
        tool_id="get_metrics",
        kind=ToolKind.READ,
        capability_id="telemetry.read",
        description="Current error rate of one service.",
        input_schema={"resource": "string"},
        output_schema=("error_rate",),
    ),
    ToolDefinition(
        tool_id="get_recent_deployments",
        kind=ToolKind.READ,
        capability_id="deployment.read",
        description="The version a service is running, and the version before it.",
        input_schema={"resource": "string"},
        output_schema=("current_deployment", "previous_deployment"),
    ),
    ToolDefinition(
        tool_id="get_dependency_health",
        kind=ToolKind.READ,
        capability_id="telemetry.read",
        description="Health of the resources a service depends on and that depend on it.",
        input_schema={"resource": "string"},
        output_schema=("dependencies", "dependents"),
    ),
    ToolDefinition(
        tool_id="get_security_signals",
        kind=ToolKind.READ,
        capability_id="security.read",
        description="Security-relevant signals for one service.",
        input_schema={"resource": "string"},
        output_schema=("health", "error_rate"),
    ),
    ToolDefinition(
        tool_id="propose_rollback",
        kind=ToolKind.PROPOSE,
        capability_id="production.rollback",
        description=(
            "Propose rolling a service back to a previous version. Creates a proposal for "
            "the control plane to assess and authorize; performs no rollback."
        ),
        input_schema={"target_version": "string"},
    ),
)
"""Every tool the Commander may name. Adding one is a code change with tests."""


class ToolRegistry:
    """Exact-match lookup over a fixed set of tools.

    No fuzzy matching, no prefix matching, no fallback. A miss is a miss.
    """

    def __init__(self, tools: tuple[ToolDefinition, ...] = READ_TOOLS) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        for tool in tools:
            if tool.tool_id in self._tools:
                raise ValueError(f"duplicate tool: {tool.tool_id!r}")
            self._tools[tool.tool_id] = tool

    def get(self, tool_id: str) -> ToolDefinition | None:
        """The tool with this exact id, or ``None``."""
        return self._tools.get(tool_id)

    def proposable(self, capability_id: str) -> ToolDefinition | None:
        """The PROPOSE tool for a capability, or ``None`` if it is not proposable."""
        for tool in self._tools.values():
            if tool.kind is ToolKind.PROPOSE and tool.capability_id == capability_id:
                return tool
        return None

    def ids(self, *, kind: ToolKind | None = None) -> tuple[str, ...]:
        """Tool ids, sorted, optionally of one kind."""
        return tuple(
            sorted(
                tool_id
                for tool_id, tool in self._tools.items()
                if kind is None or tool.kind is kind
            )
        )

    def validate_arguments(
        self, tool: ToolDefinition, arguments: Mapping[str, JsonValue]
    ) -> str | None:
        """Check a call against a tool's schema. Returns a reason, or ``None`` if valid."""
        missing = set(tool.input_schema) - set(arguments)
        if missing:
            return f"missing required argument(s): {', '.join(sorted(missing))}"
        unexpected = set(arguments) - set(tool.input_schema)
        if unexpected:
            return f"unexpected argument(s): {', '.join(sorted(unexpected))}"
        for name, type_name in tool.input_schema.items():
            expected = _TYPES[type_name]
            value = arguments[name]
            if type_name == "number" and isinstance(value, bool):
                return f"{name!r} must be {type_name}"
            if not isinstance(value, expected):
                return f"{name!r} must be {type_name}"
            if type_name == "string" and not value:
                return f"{name!r} must not be empty"
        return None

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, tool_id: object) -> bool:
        return tool_id in self._tools

    def __repr__(self) -> str:
        return f"{type(self).__name__}({len(self._tools)} tools)"
