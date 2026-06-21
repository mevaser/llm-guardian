"""Deterministic vulnerable tool-use demo target."""

from __future__ import annotations

from llm_guardian.models import TargetResponse
from llm_guardian.runtime.models import AgentDecision, MemoryOperation, PolicyDecision, RetrievalResult, ToolCall, ToolResult
from llm_guardian.runtime.runtime import AgentRuntime


class ToolAgent:
    """A local demo target that simulates risky tool execution through the runtime.

    The agent stays compatible with the shared target interface while routing
    prompts through the deterministic runtime, policy engine, and simulated
    local tools. No real tools or external systems are ever called.
    """

    name = "tool_agent"
    description = "Deterministic tool-use demo target with intentional simulated tool abuse."

    def __init__(self) -> None:
        self._runtime = AgentRuntime(
            target_name=self.name,
            final_response_builder=self._build_support_response,
        )

    def invoke(self, prompt: str) -> TargetResponse:
        run_result = self._runtime.run(prompt)
        decision = run_result.decision
        policy_decision = run_result.policy_decisions[0] if run_result.policy_decisions else None
        tool_result = run_result.tool_results[0] if run_result.tool_results else None

        metadata: dict[str, object] = {
            "runtime_mode": "agent_runtime",
            "demo_mode": "offline",
            "external_calls_made": run_result.runtime_metadata["external_calls_made"],
        }
        if decision is not None:
            metadata.update(
                {
                    "action_type": decision.action_type,
                    "action_name": decision.action_name,
                    "risk_flags": list(decision.risk_flags),
                }
            )
        if policy_decision is not None:
            metadata["policy_decision"] = policy_decision.decision
        if tool_result is not None:
            metadata.update(
                {
                    "demo_vulnerability": "tool_abuse_simulation",
                    "tool_name": tool_result.tool_name,
                    "safe_demo_only": tool_result.metadata.get("safe_demo_only", True),
                    "side_effects": tool_result.metadata.get("side_effects", "none"),
                }
            )

        return TargetResponse(
            content=run_result.final_response,
            metadata=metadata,
            tool_calls=[tool_call.model_dump(mode="json") for tool_call in run_result.tool_calls],
            trace=run_result.trace_events,
        )

    @staticmethod
    def _build_support_response(
        prompt: str,
        decision: AgentDecision,
        policy_decision: PolicyDecision,
        tool_calls: list[ToolCall],
        tool_results: list[ToolResult],
        retrieval_results: list[RetrievalResult],
        memory_operations: list[MemoryOperation],
    ) -> str:
        del policy_decision, tool_calls, retrieval_results, memory_operations

        if decision.action_type == "tool_action":
            response_text = decision.action_arguments.get("response_text")
            if isinstance(response_text, str) and response_text.strip():
                return response_text
            if tool_results:
                return tool_results[-1].output_summary

        prompt_lower = prompt.strip().lower()
        if decision.action_type == "policy_sensitive_action":
            return (
                "Support workflow: I can help with local support procedures, but I cannot disclose "
                "protected internal guidance in this demo."
            )
        if "refund" in prompt_lower:
            return (
                "Support workflow: Refund requests require approval review and status confirmation "
                "inside this local demo."
            )
        if "account" in prompt_lower or "customer" in prompt_lower:
            return (
                "Support workflow: I can describe account and customer support steps for this local "
                "demo without taking any action."
            )
        return (
            "Support workflow: I can explain local support procedures and available options "
            "without changing any external state."
        )
