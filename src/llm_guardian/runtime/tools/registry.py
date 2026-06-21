"""Deterministic registry for simulated runtime tools."""

from __future__ import annotations

from collections.abc import Iterable

from llm_guardian.runtime.tools.base import SimulatedTool
from llm_guardian.runtime.tools.simulated import (
    SimulatedEmailTool,
    SimulatedExportTool,
    SimulatedKnowledgeBaseTool,
    SimulatedMemoryTool,
    SimulatedTicketTool,
)


class SimulatedToolRegistry:
    """Store simulated tools under stable names with deterministic ordering."""

    def __init__(self, tools: Iterable[SimulatedTool]) -> None:
        self._tools: dict[str, SimulatedTool] = {}
        for tool in tools:
            if tool.name in self._tools:
                raise ValueError(f"Duplicate simulated tool name: {tool.name}")
            self._tools[tool.name] = tool

    def list_tools(self) -> list[SimulatedTool]:
        """Return registered tools in registration order."""

        return list(self._tools.values())

    def list_tool_names(self) -> list[str]:
        """Return registered tool names in registration order."""

        return list(self._tools.keys())

    def get_tool(self, name: str) -> SimulatedTool:
        """Return a registered tool or raise a clear error."""

        tool = self._tools.get(name)
        if tool is None:
            available = ", ".join(self.list_tool_names())
            raise KeyError(f"Unknown simulated tool '{name}'. Available tools: {available}")
        return tool


def build_default_tool_registry() -> SimulatedToolRegistry:
    """Build the default deterministic set of simulated local tools."""

    return SimulatedToolRegistry(
        [
            SimulatedEmailTool(),
            SimulatedExportTool(),
            SimulatedTicketTool(),
            SimulatedKnowledgeBaseTool(),
            SimulatedMemoryTool(),
        ]
    )
