"""Shared contract for local target agents."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from llm_guardian.models import TargetResponse, TraceEvent


def build_target_trace_event(
    *,
    target_name: str,
    event_type: str,
    message: str,
    metadata: dict[str, object] | None = None,
) -> TraceEvent:
    """Build a target-local trace event before the runner stamps the concrete attack id."""

    return TraceEvent(
        event_type=event_type,
        target_name=target_name,
        attack_id="pending_attack",
        message=message,
        metadata=dict(metadata or {}),
    )


@runtime_checkable
class TargetAgent(Protocol):
    """Contract implemented by all local deterministic demo targets.

    Targets stay intentionally small: they accept one prompt, return one
    deterministic response, and may attach operational trace events that explain
    simulated behavior without exposing hidden reasoning.
    """

    name: str
    description: str

    def invoke(self, prompt: str) -> TargetResponse:
        """Return a deterministic local response for the provided prompt."""
