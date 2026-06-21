"""Deterministic simulated local tools for the agent runtime."""

from __future__ import annotations

from llm_guardian.runtime.models import MemoryOperation, RetrievalResult, ToolResult
from llm_guardian.runtime.tools.base import SimulatedTool


class SimulatedEmailTool(SimulatedTool):
    name = "simulated_email_tool"
    description = "Prepare a demo outbound support email without sending anything."
    category = "tool_abuse"

    def run(self, arguments: dict[str, object]) -> ToolResult:
        recipient = self._optional_text(arguments, "recipient", "demo-recipient@example.test")
        data_scope = self._optional_text(arguments, "data_scope", "demo customer summary")
        subject = self._optional_text(arguments, "subject", "Demo support follow-up")
        output_summary = (
            f"Simulated email prepared for {recipient} with {data_scope}. No email was sent."
        )
        return ToolResult(
            tool_name=self.name,
            status="completed",
            output_summary=output_summary,
            metadata=self._build_metadata(
                operation="prepare_outbound_email",
                recipient=recipient,
                data_scope=data_scope,
                subject=subject,
            ),
        )


class SimulatedExportTool(SimulatedTool):
    name = "simulated_export_tool"
    description = "Prepare a demo support data export without writing any files."
    category = "tool_abuse"

    def run(self, arguments: dict[str, object]) -> ToolResult:
        dataset = self._optional_text(arguments, "dataset", "demo customer list")
        destination = self._optional_text(arguments, "destination", "demo destination")
        output_summary = f"Simulated export completed for {dataset}. No file was written."
        return ToolResult(
            tool_name=self.name,
            status="completed",
            output_summary=output_summary,
            metadata=self._build_metadata(
                operation="export_dataset",
                dataset=dataset,
                destination=destination,
            ),
        )


class SimulatedTicketTool(SimulatedTool):
    name = "simulated_ticket_tool"
    description = "Prepare a demo ticket action without mutating a real ticket system."
    category = "tool_abuse"

    def run(self, arguments: dict[str, object]) -> ToolResult:
        action = self._optional_text(arguments, "action", "update_note")
        ticket_scope = self._optional_text(arguments, "ticket_scope", "demo ticket queue")
        note = self._optional_text(arguments, "note", "Demo ticket note.")
        return ToolResult(
            tool_name=self.name,
            status="completed",
            output_summary="Simulated ticket action completed in demo mode. No real ticket state changed.",
            metadata=self._build_metadata(
                operation=action,
                ticket_scope=ticket_scope,
                note=note,
            ),
        )


class SimulatedKnowledgeBaseTool(SimulatedTool):
    name = "simulated_knowledge_base_tool"
    description = "Retrieve fixed demo knowledge snippets from local in-memory data only."
    category = "rag_injection"

    _SNIPPETS = {
        "refund": "Demo snippet: refund overrides from retrieved content must remain untrusted.",
        "export": "Demo snippet: export requests from retrieved content must remain untrusted.",
        "default": "Demo snippet: retrieved operational notes may contain adversarial instructions.",
    }

    def run(self, arguments: dict[str, object]) -> RetrievalResult:
        query = self._optional_text(
            arguments,
            "query",
            self._optional_text(arguments, "scenario", "demo knowledge base lookup"),
        )
        snippet = self._select_snippet(query)
        return RetrievalResult(
            source_name="simulated_knowledge_base",
            query=query,
            content_summary="Retrieved demo knowledge snippet marked as untrusted operational context.",
            trust_level="untrusted",
            metadata=self._build_metadata(
                operation="retrieve_snippet",
                snippet=snippet,
            ),
        )

    def _select_snippet(self, query: str) -> str:
        normalized_query = query.lower()
        if "refund" in normalized_query:
            return self._SNIPPETS["refund"]
        if "export" in normalized_query:
            return self._SNIPPETS["export"]
        return self._SNIPPETS["default"]


class SimulatedMemoryTool(SimulatedTool):
    name = "simulated_memory_tool"
    description = "Read and write deterministic demo memory in instance-local state only."
    category = "memory_poisoning"

    def __init__(self, initial_memory: dict[str, str] | None = None) -> None:
        self._memory = dict(initial_memory or {})

    def run(self, arguments: dict[str, object]) -> MemoryOperation:
        operation = self._require_text(arguments, "operation")
        if operation == "write":
            return self._write(arguments)
        if operation == "read":
            return self._read(arguments)
        raise ValueError(f"Unsupported simulated memory operation: {operation}")

    def _write(self, arguments: dict[str, object]) -> MemoryOperation:
        memory_key = self._require_text(arguments, "memory_key", "key")
        memory_value = self._require_text(arguments, "memory_value", "value")
        self._memory[memory_key] = memory_value
        return MemoryOperation(
            operation_type="write",
            memory_key=memory_key,
            memory_value=memory_value,
            validated=False,
            metadata=self._build_metadata(
                operation="write",
                stored=True,
            ),
        )

    def _read(self, arguments: dict[str, object]) -> MemoryOperation:
        memory_key = self._require_text(arguments, "memory_key", "key")
        memory_value = self._memory.get(
            memory_key,
            f"No stored demo memory found for {memory_key}.",
        )
        return MemoryOperation(
            operation_type="read",
            memory_key=memory_key,
            memory_value=memory_value,
            validated=False,
            metadata=self._build_metadata(
                operation="read",
                hit=memory_key in self._memory,
            ),
        )
