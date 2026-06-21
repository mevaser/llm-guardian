from llm_guardian.models import TraceEvent
from llm_guardian.runtime.models import (
    AgentDecision,
    AgentRunResult,
    MemoryOperation,
    PolicyDecision,
    RetrievalResult,
    ToolCall,
    ToolResult,
)


def test_runtime_models_can_be_instantiated() -> None:
    decision = AgentDecision(
        action_type="tool_action",
        action_name="simulated_email_tool",
        action_arguments={"recipient": "ops@example.test"},
        reason_summary="Detected tool-oriented keywords in the prompt.",
        risk_flags=["external_side_effect_request"],
    )
    tool_call = ToolCall(
        tool_name="simulated_email_tool",
        arguments={"recipient": "ops@example.test"},
        allowed_by_policy=True,
    )
    tool_result = ToolResult(
        tool_name="simulated_email_tool",
        status="deferred",
        output_summary="Tool execution is deferred in the runtime core slice.",
        metadata={"mode": "placeholder"},
    )
    retrieval_result = RetrievalResult(
        source_name="simulated_knowledge_base",
        query="Search the knowledge base for refund rules.",
        content_summary="Retrieval execution is deferred in the runtime core slice.",
        trust_level="unverified",
        metadata={"mode": "placeholder"},
    )
    memory_operation = MemoryOperation(
        operation_type="remember",
        memory_key="session_note",
        memory_value="The customer prefers email replies.",
        validated=False,
        metadata={"mode": "placeholder"},
    )
    policy_decision = PolicyDecision(
        decision="approved",
        reason_summary="Tool actions are allowed in vulnerable demo mode.",
        applies_to="tool_action",
        severity="medium",
        metadata={"vulnerable_demo_mode": True},
    )
    trace_event = TraceEvent(
        event_type="planner_decision",
        target_name="tool_agent",
        attack_id="TA-001",
        message="Planner selected a tool-oriented action.",
        metadata={"action_type": "tool_action"},
    )

    run_result = AgentRunResult(
        final_response="Selected a simulated tool action without calling external systems.",
        trace_events=[trace_event],
        decision=decision,
        policy_decisions=[policy_decision],
        tool_calls=[tool_call],
        tool_results=[tool_result],
        retrieval_results=[retrieval_result],
        memory_operations=[memory_operation],
        runtime_metadata={"target_name": "tool_agent"},
    )

    assert run_result.decision == decision
    assert run_result.trace_events[0].event_type == "planner_decision"
    assert isinstance(run_result.trace_events[0], TraceEvent)
    assert run_result.tool_calls[0].allowed_by_policy is True
    assert run_result.tool_results[0].status == "deferred"
    assert run_result.retrieval_results[0].trust_level == "unverified"
    assert run_result.memory_operations[0].operation_type == "remember"
    assert run_result.policy_decisions[0].decision == "approved"


def test_runtime_model_defaults_use_independent_containers() -> None:
    first_decision = AgentDecision(action_type="normal_response", reason_summary="Respond normally.")
    second_decision = AgentDecision(action_type="normal_response", reason_summary="Respond normally.")
    first_result = AgentRunResult(final_response="First response.")
    second_result = AgentRunResult(final_response="Second response.")

    first_decision.action_arguments["audience"] = "first"
    first_decision.risk_flags.append("first-flag")
    first_result.tool_calls.append(ToolCall(tool_name="simulated_tool", arguments={}))
    first_result.runtime_metadata["mode"] = "first"

    assert second_decision.action_arguments == {}
    assert second_decision.risk_flags == []
    assert second_result.tool_calls == []
    assert second_result.runtime_metadata == {}
