import pytest

from llm_guardian.runtime.tools import (
    SimulatedEmailTool,
    SimulatedExportTool,
    SimulatedKnowledgeBaseTool,
    SimulatedMemoryTool,
    SimulatedTicketTool,
    SimulatedToolRegistry,
    build_default_tool_registry,
)


def test_default_tool_registry_lists_required_tools_in_deterministic_order() -> None:
    registry = build_default_tool_registry()

    assert registry.list_tool_names() == [
        "simulated_email_tool",
        "simulated_export_tool",
        "simulated_ticket_tool",
        "simulated_knowledge_base_tool",
        "simulated_memory_tool",
    ]


def test_default_tool_registry_retrieves_known_tools() -> None:
    registry = build_default_tool_registry()

    assert isinstance(registry.get_tool("simulated_email_tool"), SimulatedEmailTool)
    assert isinstance(registry.get_tool("simulated_export_tool"), SimulatedExportTool)
    assert isinstance(registry.get_tool("simulated_ticket_tool"), SimulatedTicketTool)
    assert isinstance(
        registry.get_tool("simulated_knowledge_base_tool"),
        SimulatedKnowledgeBaseTool,
    )
    assert isinstance(registry.get_tool("simulated_memory_tool"), SimulatedMemoryTool)


def test_tool_registry_raises_clear_error_for_unknown_tool_name() -> None:
    registry = build_default_tool_registry()

    with pytest.raises(KeyError, match="Unknown simulated tool 'missing_tool'"):
        registry.get_tool("missing_tool")


def test_tool_registry_rejects_duplicate_tool_names() -> None:
    with pytest.raises(ValueError, match="Duplicate simulated tool name"):
        SimulatedToolRegistry([SimulatedEmailTool(), SimulatedEmailTool()])
