"""Registry for local deterministic target agents."""

from __future__ import annotations

from llm_guardian.targets.base import TargetAgent
from llm_guardian.targets.customer_support import CustomerSupportAgent
from llm_guardian.targets.memory_agent import MemoryAgent


_TARGET_FACTORIES = {
    "customer_support": CustomerSupportAgent,
    "memory_agent": MemoryAgent,
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
