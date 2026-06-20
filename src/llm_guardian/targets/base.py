"""Shared contract for local target agents."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from llm_guardian.models import TargetResponse


@runtime_checkable
class TargetAgent(Protocol):
    name: str
    description: str

    def invoke(self, prompt: str) -> TargetResponse:
        """Return a deterministic local response for the provided prompt."""
