"""Minimal deterministic runtime loop for local agent execution."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Callable

from llm_guardian.models import TraceEvent
from llm_guardian.runtime.models import (
    AgentRunResult,
    AgentDecision,
    MemoryOperation,
    PolicyDecision,
    RetrievalResult,
    ToolCall,
    ToolResult,
)
from llm_guardian.runtime.planner import RuleBasedPlanner
from llm_guardian.runtime.policy import PolicyEngine
from llm_guardian.runtime.tools import SimulatedToolRegistry, build_default_tool_registry

FinalResponseBuilder = Callable[
    [str, AgentDecision, PolicyDecision, list[ToolCall], list[ToolResult], list[RetrievalResult], list[MemoryOperation]],
    str,
]


class AgentRuntime:
    """Run a prompt through a deterministic planner and policy engine."""

    def __init__(
        self,
        *,
        target_name: str,
        planner: RuleBasedPlanner | None = None,
        policy_engine: PolicyEngine | None = None,
        tool_registry: SimulatedToolRegistry | None = None,
        final_response_builder: FinalResponseBuilder | None = None,
    ) -> None:
        self._target_name = target_name
        self._planner = planner or RuleBasedPlanner()
        self._policy_engine = policy_engine or PolicyEngine()
        self._tool_registry = tool_registry or build_default_tool_registry()
        self._final_response_builder = final_response_builder

    def run(self, prompt: str, attack_id: str | None = None) -> AgentRunResult:
        """Execute the runtime core loop without calling external systems."""

        runtime_attack_id = attack_id or "runtime_ad_hoc"
        decision = self._planner.plan(prompt)
        policy_decision = self._policy_engine.evaluate(decision)
        tool_calls: list[ToolCall] = []
        tool_results: list[ToolResult] = []
        retrieval_results: list[RetrievalResult] = []
        memory_operations: list[MemoryOperation] = []
        trace_events = [
            self._build_trace_event(
                attack_id=runtime_attack_id,
                event_type="agent_started",
                message="Started deterministic agent runtime execution.",
            ),
            self._build_trace_event(
                attack_id=runtime_attack_id,
                event_type="planner_decision",
                message="Planner selected a deterministic action classification.",
                metadata={
                    "action_type": decision.action_type,
                    "action_name": decision.action_name,
                    "risk_flags": list(decision.risk_flags),
                },
            ),
            self._build_trace_event(
                attack_id=runtime_attack_id,
                event_type="policy_decision",
                message=policy_decision.reason_summary,
                metadata={
                    "decision": policy_decision.decision,
                    "severity": policy_decision.severity,
                    "applies_to": policy_decision.applies_to,
                    **policy_decision.metadata,
                },
            ),
        ]

        if decision.action_type == "tool_action":
            tool_call = ToolCall(
                tool_name=decision.action_name or "simulated_tool_execution",
                arguments={**decision.action_arguments},
                allowed_by_policy=policy_decision.decision == "approved",
            )
            tool_calls.append(tool_call)
            trace_events.append(
                self._build_trace_event(
                    attack_id=runtime_attack_id,
                    event_type="action_selected",
                    message="Runtime selected a simulated tool action.",
                    metadata={
                        "action_type": decision.action_type,
                        "action_name": decision.action_name,
                        "tool_name": tool_call.tool_name,
                        "risk_flags": list(decision.risk_flags),
                    },
                )
            )
            if tool_call.allowed_by_policy:
                trace_events.append(
                    self._build_trace_event(
                        attack_id=runtime_attack_id,
                        event_type="tool_called",
                        message="Called a simulated local tool with demo-only arguments.",
                        metadata={
                            "tool_name": tool_call.tool_name,
                            "safe_demo_only": True,
                            "side_effects": "none",
                        },
                    )
                )
                tool_result = self._run_simulated_tool(tool_call)
                tool_results.append(tool_result)
                trace_events.append(
                    self._build_trace_event(
                        attack_id=runtime_attack_id,
                        event_type="observation_received",
                        message="Received a simulated tool observation from the runtime.",
                        metadata={
                            "tool_name": tool_result.tool_name,
                            "status": tool_result.status,
                            "safe_demo_only": tool_result.metadata.get("safe_demo_only", True),
                            "side_effects": tool_result.metadata.get("side_effects", "none"),
                        },
                    )
                )
        elif decision.action_type == "retrieval_action":
            retrieval_results.append(
                RetrievalResult(
                    source_name="simulated_knowledge_base",
                    query=prompt,
                    content_summary="Retrieval execution is deferred in the runtime core slice.",
                    trust_level="unverified",
                    metadata={"mode": "placeholder"},
                )
            )
            trace_events.extend(
                [
                    self._build_trace_event(
                        attack_id=runtime_attack_id,
                        event_type="action_selected",
                        message="Runtime selected a deterministic retrieval action.",
                        metadata={"action_type": decision.action_type, "action_name": decision.action_name},
                    ),
                    self._build_trace_event(
                        attack_id=runtime_attack_id,
                        event_type="observation_received",
                        message="Received a placeholder retrieval observation from the runtime.",
                        metadata={"source_name": "simulated_knowledge_base", "trust_level": "unverified"},
                    ),
                ]
            )
        elif decision.action_type == "memory_action":
            memory_operations.append(
                MemoryOperation(
                    operation_type=decision.action_name or "memory_action",
                    memory_key="runtime_memory_placeholder",
                    memory_value=prompt if "memory_store" == decision.action_name else None,
                    validated=False,
                    metadata={"mode": "placeholder"},
                )
            )
            trace_events.extend(
                [
                    self._build_trace_event(
                        attack_id=runtime_attack_id,
                        event_type="action_selected",
                        message="Runtime selected a deterministic memory action.",
                        metadata={"action_type": decision.action_type, "action_name": decision.action_name},
                    ),
                    self._build_trace_event(
                        attack_id=runtime_attack_id,
                        event_type="observation_received",
                        message="Received a placeholder memory observation from the runtime.",
                        metadata={"operation_type": decision.action_name or "memory_action"},
                    ),
                ]
            )

        final_response = self._build_final_response(
            prompt=prompt,
            decision=decision,
            policy_decision=policy_decision,
            tool_calls=tool_calls,
            tool_results=tool_results,
            retrieval_results=retrieval_results,
            memory_operations=memory_operations,
        )
        trace_events.append(
            self._build_trace_event(
                attack_id=runtime_attack_id,
                event_type="final_response",
                message="Runtime produced a deterministic final response.",
                metadata={
                    "action_type": decision.action_type,
                    "action_name": decision.action_name,
                    "tool_name": tool_calls[0].tool_name if tool_calls else None,
                },
            )
        )

        return AgentRunResult(
            final_response=final_response,
            trace_events=trace_events,
            decision=decision,
            policy_decisions=[policy_decision],
            tool_calls=tool_calls,
            tool_results=tool_results,
            retrieval_results=retrieval_results,
            memory_operations=memory_operations,
            runtime_metadata={
                "target_name": self._target_name,
                "attack_id": runtime_attack_id,
                "external_calls_made": False,
            },
        )

    def _build_trace_event(
        self,
        *,
        attack_id: str,
        event_type: str,
        message: str,
        metadata: dict[str, object] | None = None,
    ) -> TraceEvent:
        return TraceEvent(
            event_type=event_type,
            timestamp=datetime.now(UTC),
            target_name=self._target_name,
            attack_id=attack_id,
            message=message,
            metadata=dict(metadata or {}),
        )

    def _run_simulated_tool(self, tool_call: ToolCall) -> ToolResult:
        tool = self._tool_registry.get_tool(tool_call.tool_name)
        result = tool.run(tool_call.arguments)
        if not isinstance(result, ToolResult):
            raise TypeError(
                f"Runtime expected a ToolResult from '{tool_call.tool_name}' during tool_action execution."
            )
        return result

    def _build_final_response(
        self,
        *,
        prompt: str,
        decision: AgentDecision,
        policy_decision: PolicyDecision,
        tool_calls: list[ToolCall],
        tool_results: list[ToolResult],
        retrieval_results: list[RetrievalResult],
        memory_operations: list[MemoryOperation],
    ) -> str:
        if self._final_response_builder is not None:
            return self._final_response_builder(
                prompt,
                decision,
                policy_decision,
                tool_calls,
                tool_results,
                retrieval_results,
                memory_operations,
            )

        if decision.action_type == "tool_action":
            if tool_results:
                return tool_results[-1].output_summary
            return "Selected a simulated tool action without calling external systems."
        if decision.action_type == "retrieval_action":
            return "Selected a simulated retrieval action without performing live retrieval."
        if decision.action_type == "memory_action":
            return "Selected a simulated memory action without persisting external state."
        if decision.action_type == "policy_sensitive_action":
            return "Flagged the prompt as policy-sensitive and returned a deterministic safe response."
        return "Produced a deterministic normal response."
