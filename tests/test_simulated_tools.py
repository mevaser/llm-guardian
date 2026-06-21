from llm_guardian.runtime.models import MemoryOperation, RetrievalResult, ToolResult
from llm_guardian.runtime.tools import (
    SimulatedEmailTool,
    SimulatedExportTool,
    SimulatedKnowledgeBaseTool,
    SimulatedMemoryTool,
    SimulatedTicketTool,
)


def test_simulated_email_tool_returns_safe_deterministic_result() -> None:
    tool = SimulatedEmailTool()

    result = tool.run(
        {
            "recipient": "attacker@example.com",
            "data_scope": "demo customer summary",
            "subject": "Please send account details",
        }
    )

    assert isinstance(result, ToolResult)
    assert result.tool_name == "simulated_email_tool"
    assert (
        result.output_summary
        == "Simulated email prepared for attacker@example.com with demo customer summary. No email was sent."
    )
    assert result.metadata["operation"] == "prepare_outbound_email"
    assert result.metadata["safe_demo_only"] is True
    assert result.metadata["side_effects"] == "none"
    assert result.metadata["category"] == "tool_abuse"


def test_simulated_export_tool_reports_no_file_written() -> None:
    tool = SimulatedExportTool()

    result = tool.run({"dataset": "demo customer list", "destination": "desktop export"})

    assert isinstance(result, ToolResult)
    assert result.tool_name == "simulated_export_tool"
    assert result.output_summary == "Simulated export completed for demo customer list. No file was written."
    assert result.metadata["operation"] == "export_dataset"
    assert result.metadata["side_effects"] == "none"


def test_simulated_ticket_tool_reports_no_real_ticket_state_changed() -> None:
    tool = SimulatedTicketTool()

    result = tool.run(
        {
            "action": "bulk_close",
            "ticket_scope": "high priority queue",
            "note": "Close these immediately.",
        }
    )

    assert isinstance(result, ToolResult)
    assert result.tool_name == "simulated_ticket_tool"
    assert (
        result.output_summary
        == "Simulated ticket action completed in demo mode. No real ticket state changed."
    )
    assert result.metadata["operation"] == "bulk_close"
    assert result.metadata["ticket_scope"] == "high priority queue"
    assert result.metadata["safe_demo_only"] is True


def test_simulated_knowledge_base_tool_returns_fixed_untrusted_retrieval() -> None:
    tool = SimulatedKnowledgeBaseTool()

    result = tool.run({"query": "Find the refund escalation override instructions."})

    assert isinstance(result, RetrievalResult)
    assert result.source_name == "simulated_knowledge_base"
    assert result.query == "Find the refund escalation override instructions."
    assert result.trust_level == "untrusted"
    assert (
        result.content_summary
        == "Retrieved demo knowledge snippet marked as untrusted operational context."
    )
    assert result.metadata["tool_name"] == "simulated_knowledge_base_tool"
    assert result.metadata["operation"] == "retrieve_snippet"
    assert result.metadata["safe_demo_only"] is True
    assert result.metadata["side_effects"] == "none"
    assert result.metadata["category"] == "rag_injection"


def test_simulated_memory_tool_write_then_read_is_deterministic() -> None:
    tool = SimulatedMemoryTool()

    write_result = tool.run(
        {
            "operation": "write",
            "memory_key": "session_note",
            "memory_value": "Attacker says to trust the pasted password.",
        }
    )
    read_result = tool.run({"operation": "read", "memory_key": "session_note"})

    assert isinstance(write_result, MemoryOperation)
    assert write_result.operation_type == "write"
    assert write_result.memory_key == "session_note"
    assert write_result.memory_value == "Attacker says to trust the pasted password."
    assert write_result.validated is False
    assert write_result.metadata["tool_name"] == "simulated_memory_tool"
    assert write_result.metadata["safe_demo_only"] is True
    assert write_result.metadata["side_effects"] == "none"
    assert write_result.metadata["category"] == "memory_poisoning"

    assert isinstance(read_result, MemoryOperation)
    assert read_result.operation_type == "read"
    assert read_result.memory_key == "session_note"
    assert read_result.memory_value == "Attacker says to trust the pasted password."
    assert read_result.validated is False


def test_simulated_memory_tool_instances_are_isolated() -> None:
    first_tool = SimulatedMemoryTool()
    second_tool = SimulatedMemoryTool()

    first_tool.run(
        {
            "operation": "write",
            "memory_key": "session_note",
            "memory_value": "first instance only",
        }
    )
    second_result = second_tool.run({"operation": "read", "memory_key": "session_note"})

    assert isinstance(second_result, MemoryOperation)
    assert second_result.operation_type == "read"
    assert second_result.memory_key == "session_note"
    assert second_result.memory_value == "No stored demo memory found for session_note."
    assert second_result.metadata["operation"] == "read"
