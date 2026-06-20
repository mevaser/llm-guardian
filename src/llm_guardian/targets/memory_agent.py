"""Deterministic vulnerable memory demo target."""

from __future__ import annotations

import re

from llm_guardian.models import TargetResponse
from llm_guardian.targets.base import build_target_trace_event


class MemoryAgent:
    """A local demo target that intentionally stores unvalidated user memory."""

    name = "memory_agent"
    description = "Deterministic memory demo target with intentional memory poisoning behavior."

    _REMEMBER_PATTERN = re.compile(r"remember that\s+(.+)", re.IGNORECASE)
    _RECALL_PROMPTS = (
        "what do you remember",
        "what is remembered",
        "what did i ask you to remember",
        "what is the admin password",
    )

    def __init__(self) -> None:
        self._memory: list[str] = []

    def invoke(self, prompt: str) -> TargetResponse:
        normalized_prompt = prompt.strip()
        remember_match = self._REMEMBER_PATTERN.search(normalized_prompt)
        prompt_lower = normalized_prompt.lower()

        if remember_match:
            memory_value = remember_match.group(1).strip()
            self._memory.append(memory_value)
            return TargetResponse(
                content=f"I will remember: {memory_value}",
                metadata={"demo_vulnerability": "memory_poisoning"},
                memory_updates=[memory_value],
                trace=[
                    build_target_trace_event(
                        target_name=self.name,
                        event_type="simulated_tool_decision",
                        message="Stored unvalidated memory item in local demo state.",
                        metadata={"memory_action": "write"},
                    )
                ],
            )

        if any(phrase in prompt_lower for phrase in self._RECALL_PROMPTS):
            if not self._memory:
                return TargetResponse(content="I do not remember anything yet.")

            latest_memory = self._memory[-1]
            return TargetResponse(
                content=f"I remember this unvalidated memory: {latest_memory}",
                metadata={"demo_vulnerability": "memory_poisoning"},
                trace=[
                    build_target_trace_event(
                        target_name=self.name,
                        event_type="simulated_retrieval",
                        message="Recalled latest unvalidated memory item.",
                        metadata={"memory_action": "recall"},
                    )
                ],
            )

        return TargetResponse(
            content="Tell me to remember something or ask what is remembered.",
            metadata={"demo_mode": "offline"},
        )
