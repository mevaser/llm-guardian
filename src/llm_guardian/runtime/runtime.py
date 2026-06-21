"""Minimal deterministic runtime loop for local agent execution."""

from __future__ import annotations

from datetime import UTC, datetime

from llm_guardian.models import TraceEvent
from llm_guardian.runtime.models import (
    AgentRunResult,
    MemoryOperation,
    RetrievalResult,
    ToolCall,
)
from llm_guardian.runtime.planner import RuleBasedPlanner
from llm_guardian.runtime.policy import PolicyEngine


class AgentRuntime:
    """Run a prompt through a deterministic planner and policy engine."""

    def __init__(
        self,
        *,
        target_name: str,
        planner: RuleBasedPlanner | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self._target_name = target_name
        self._planner = planner or RuleBasedPlanner()
        self._policy_engine = policy_engine or PolicyEngine()

    def run(self, prompt: str, attack_id: str | None = None) -> AgentRunResult:
        """Execute the runtime core loop without calling external systems."""

        runtime_attack_id = attack_id or "runtime_ad_hoc"
        decision = self._planner.plan(prompt)
        policy_decision = self._policy_engine.evaluate(decision)
        tool_calls: list[ToolCall] = []
        retrieval_results: list[RetrievalResult] = []
        memory_operations: list[MemoryOperation] = []

        if decision.action_type == "tool_action":
            tool_calls.append(
                ToolCall(
                    tool_name=decision.action_name or "simulated_tool_execution",
                    arguments={"prompt": prompt, **decision.action_arguments},
                    allowed_by_policy=policy_decision.decision == "approved",
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

        final_response = self._build_final_response(decision_action_type=decision.action_type)
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
                message="Policy engine evaluated the planner decision.",
                metadata={
                    "decision": policy_decision.decision,
                    "severity": policy_decision.severity,
                    "applies_to": policy_decision.applies_to,
                },
            ),
            self._build_trace_event(
                attack_id=runtime_attack_id,
                event_type="action_selected",
                message="Runtime selected the next deterministic action.",
                metadata={
                    "action_type": decision.action_type,
                    "tool_call_count": len(tool_calls),
                    "retrieval_count": len(retrieval_results),
                    "memory_operation_count": len(memory_operations),
                },
            ),
            self._build_trace_event(
                attack_id=runtime_attack_id,
                event_type="final_response",
                message="Runtime produced a deterministic final response.",
                metadata={"action_type": decision.action_type},
            ),
        ]

        return AgentRunResult(
            final_response=final_response,
            trace_events=trace_events,
            decision=decision,
            policy_decisions=[policy_decision],
            tool_calls=tool_calls,
            tool_results=[],
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

    @staticmethod
    def _build_final_response(*, decision_action_type: str) -> str:
        if decision_action_type == "tool_action":
            return "Selected a simulated tool action without calling external systems."
        if decision_action_type == "retrieval_action":
            return "Selected a simulated retrieval action without performing live retrieval."
        if decision_action_type == "memory_action":
            return "Selected a simulated memory action without persisting external state."
        if decision_action_type == "policy_sensitive_action":
            return "Flagged the prompt as policy-sensitive and returned a deterministic safe response."
        return "Produced a deterministic normal response."
