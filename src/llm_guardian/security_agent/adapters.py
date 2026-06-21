"""Local target adapters for the central security agent."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import Field

from llm_guardian.models import TraceEvent
from llm_guardian.models import StrictBaseModel
from llm_guardian.targets.base import TargetAgent


class AdapterExecutionResult(StrictBaseModel):
    prompt: str
    response: str
    trace: list[TraceEvent] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    tool_results: list[dict[str, Any]] = Field(default_factory=list)
    memory_operations: list[dict[str, Any]] = Field(default_factory=list)
    retrieval_operations: list[dict[str, Any]] = Field(default_factory=list)
    state_changes: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


@runtime_checkable
class TargetAdapter(Protocol):
    target_name: str

    def execute(self, prompt: str, attack_id: str | None = None) -> AdapterExecutionResult:
        """Execute one local deterministic prompt against a target."""


class LocalTargetAdapter:
    """Wrap a local in-process target agent for security-agent execution."""

    def __init__(self, target: TargetAgent) -> None:
        self._target = target
        self.target_name = target.name

    def execute(self, prompt: str, attack_id: str | None = None) -> AdapterExecutionResult:
        response = self._target.invoke(prompt)
        metadata: dict[str, Any] = {
            "target_name": self._target.name,
            "target_description": self._target.description,
            "attack_id": attack_id,
            "execution_mode": "local_in_process",
            "target_metadata": dict(response.metadata),
        }
        return AdapterExecutionResult(
            prompt=prompt,
            response=response.content,
            trace=list(response.trace),
            metadata=metadata,
            tool_calls=list(response.tool_calls),
            memory_operations=[
                {"operation_type": "memory_update", "memory_value": memory_value}
                for memory_value in response.memory_updates
            ],
        )
