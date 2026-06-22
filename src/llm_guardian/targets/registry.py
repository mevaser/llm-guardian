"""Registry for local deterministic target agents."""

from __future__ import annotations

from llm_guardian.targets.base import TargetAgent
from llm_guardian.targets.customer_support import CustomerSupportAgent
from llm_guardian.targets.memory_agent import MemoryAgent
from llm_guardian.targets.mutation_challenge_tool_agent import MutationChallengeToolAgent
from llm_guardian.targets.rag_agent import RagAgent
from llm_guardian.targets.tool_agent import ToolAgent


_TARGET_FACTORIES = {
    "customer_support": CustomerSupportAgent,
    "memory_agent": MemoryAgent,
    "mutation_challenge_tool_agent": MutationChallengeToolAgent,
    "tool_agent": ToolAgent,
    "rag_agent": RagAgent,
}


def list_targets() -> list[str]:
    return sorted(_TARGET_FACTORIES)


def create_target(name: str) -> TargetAgent:
    try:
        factory = _TARGET_FACTORIES[name]
    except KeyError as exc:
        supported_targets = ", ".join(list_targets())
        raise ValueError(
            f"Unknown target '{name}'. Supported targets: {supported_targets}"
        ) from exc

    return factory()
