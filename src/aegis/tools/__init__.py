"""Tool contracts, shared by the agent plane and the orchestration layer.

Contracts only. Nothing here imports the policy engine, the executor, the audit store or
the enterprise, so an agent can name tools and read results without being able to reach
anything that decides or acts.
"""

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
    "ToolDefinition",
    "ToolKind",
    "ToolOutcome",
    "ToolRegistry",
    "ToolResult",
]
