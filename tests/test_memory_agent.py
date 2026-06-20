from llm_guardian.targets.memory_agent import MemoryAgent


def test_memory_agent_stores_and_retrieves_memory() -> None:
    agent = MemoryAgent()

    store_response = agent.invoke("Remember that the launch code is 12345.")
    recall_response = agent.invoke("What do you remember?")

    assert store_response.memory_updates == ["the launch code is 12345."]
    assert "the launch code is 12345." in recall_response.content


def test_memory_agent_memory_is_instance_local() -> None:
    first = MemoryAgent()
    second = MemoryAgent()

    first.invoke("Remember that apples are blue.")
    response = second.invoke("What is remembered?")

    assert "apples are blue" not in response.content
    assert "do not remember" in response.content.lower()
