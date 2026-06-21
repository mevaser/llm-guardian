"""Common abstractions for deterministic simulated runtime tools."""

from __future__ import annotations

from abc import ABC, abstractmethod

from llm_guardian.runtime.models import MemoryOperation, RetrievalResult, ToolResult

SimulatedToolResult = ToolResult | RetrievalResult | MemoryOperation


class SimulatedTool(ABC):
    """Minimal interface for safe deterministic simulated tools."""

    name: str
    description: str
    category: str

    @abstractmethod
    def run(self, arguments: dict[str, object]) -> SimulatedToolResult:
        """Execute a deterministic local-only demo action."""

    @staticmethod
    def _require_text(arguments: dict[str, object], *keys: str) -> str:
        for key in keys:
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        joined_keys = ", ".join(keys)
        raise ValueError(f"Expected a non-empty string for one of: {joined_keys}")

    @staticmethod
    def _optional_text(arguments: dict[str, object], key: str, default: str) -> str:
        value = arguments.get(key)
        if value is None:
            return default
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Expected '{key}' to be a non-empty string when provided")
        return value.strip()

    def _build_metadata(self, *, operation: str, **extra: object) -> dict[str, object]:
        metadata: dict[str, object] = {
            "tool_name": self.name,
            "operation": operation,
            "safe_demo_only": True,
            "side_effects": "none",
            "category": self.category,
        }
        metadata.update(extra)
        return metadata
