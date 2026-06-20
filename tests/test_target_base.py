from llm_guardian.models import TargetResponse
from llm_guardian.targets.base import TargetAgent
from llm_guardian.targets.customer_support import CustomerSupportAgent
from llm_guardian.targets.memory_agent import MemoryAgent


def test_target_response_uses_independent_default_containers() -> None:
    first = TargetResponse(content="first")
    second = TargetResponse(content="second")

    first.metadata["source"] = "test"
    first.tool_calls.append({"name": "demo"})
    first.memory_updates.append("remembered fact")

    assert second.metadata == {}
    assert second.tool_calls == []
    assert second.memory_updates == []


def test_targets_implement_shared_interface() -> None:
    for agent in (CustomerSupportAgent(), MemoryAgent()):
        assert isinstance(agent, TargetAgent)
        assert isinstance(agent.name, str)
        assert agent.name
        assert isinstance(agent.description, str)
        assert agent.description
        assert isinstance(agent.invoke("hello"), TargetResponse)
