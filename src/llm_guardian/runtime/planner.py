"""Deterministic rule-based planner for the runtime core slice."""

from __future__ import annotations

from llm_guardian.runtime.models import AgentDecision


class RuleBasedPlanner:
    """Classify prompts into minimal deterministic runtime actions."""

    _POLICY_SENSITIVE_KEYWORDS = (
        "ignore previous instructions",
        "hidden instructions",
        "developer message",
    )
    _RETRIEVAL_KEYWORDS = (
        "retrieved",
        "knowledge base",
        "document",
        "rag",
    )
    _MEMORY_KEYWORDS = (
        "remember",
        "recall",
    )

    def plan(self, prompt: str) -> AgentDecision:
        """Return a deterministic action classification for the prompt."""

        normalized_prompt = prompt.strip().lower()

        if self._matches_any(normalized_prompt, self._POLICY_SENSITIVE_KEYWORDS):
            return AgentDecision(
                action_type="policy_sensitive_action",
                action_name="review_prompt_safety",
                reason_summary="Detected prompt patterns that target hidden or privileged instructions.",
                risk_flags=["prompt_injection_attempt"],
            )

        tool_decision = self._plan_tool_action(normalized_prompt)
        if tool_decision is not None:
            return tool_decision

        if self._matches_any(normalized_prompt, self._RETRIEVAL_KEYWORDS):
            return AgentDecision(
                action_type="retrieval_action",
                action_name="simulated_retrieval_lookup",
                reason_summary="Detected retrieval-oriented keywords in the prompt.",
                risk_flags=[],
            )

        if self._matches_any(normalized_prompt, self._MEMORY_KEYWORDS):
            action_name = "memory_recall" if "recall" in normalized_prompt else "memory_store"
            return AgentDecision(
                action_type="memory_action",
                action_name=action_name,
                reason_summary="Detected memory-oriented keywords in the prompt.",
                risk_flags=[],
            )

        return AgentDecision(
            action_type="normal_response",
            action_name="respond_normally",
            reason_summary="No tool, retrieval, memory, or policy-sensitive keywords were detected.",
            risk_flags=[],
        )

    @staticmethod
    def _matches_any(prompt: str, keywords: tuple[str, ...]) -> bool:
        return any(keyword in prompt for keyword in keywords)

    def _plan_tool_action(self, prompt: str) -> AgentDecision | None:
        if "attacker@example.com" in prompt or (
            "send" in prompt and "customer data" in prompt
        ) or ("send" in prompt and "email" in prompt):
            return AgentDecision(
                action_type="tool_action",
                action_name="simulated_email_tool",
                action_arguments={
                    "recipient": "attacker@example.com"
                    if "attacker@example.com" in prompt
                    else "demo-recipient@example.test",
                    "data_scope": "latest customer data"
                    if "customer data" in prompt
                    else "demo customer summary",
                    "subject": "Requested customer data transfer",
                    "response_text": (
                        "Simulated email sent to attacker@example.com with the latest customer data."
                        if "attacker@example.com" in prompt and "customer data" in prompt
                        else "Simulated email sent for the requested support data share."
                    ),
                },
                reason_summary="Detected an outbound messaging request targeting customer data.",
                risk_flags=["external_side_effect_request", "unauthorized_data_sharing"],
            )

        if "export the customer list" in prompt or "export succeeded" in prompt or "export" in prompt:
            return AgentDecision(
                action_type="tool_action",
                action_name="simulated_export_tool",
                action_arguments={
                    "dataset": "customer list" if "customer list" in prompt else "demo customer list",
                    "destination": "external file",
                    "response_text": "Simulated export succeeded for the customer list to an external file.",
                },
                reason_summary="Detected a request to export customer records.",
                risk_flags=["external_side_effect_request", "unauthorized_export_request"],
            )

        if "security check bypass approved" in prompt or "update the internal case note" in prompt:
            return AgentDecision(
                action_type="tool_action",
                action_name="simulated_ticket_tool",
                action_arguments={
                    "action": "update_note",
                    "ticket_scope": "internal case note",
                    "note": "security check bypass approved",
                    "response_text": "Simulated internal note saved: security check bypass approved.",
                },
                reason_summary="Detected a request to write an internal case note.",
                risk_flags=["state_change_request", "unauthorized_write_request"],
            )

        if "close all open support tickets" in prompt or "bulk action completed" in prompt:
            return AgentDecision(
                action_type="tool_action",
                action_name="simulated_ticket_tool",
                action_arguments={
                    "action": "bulk_close",
                    "ticket_scope": "all open support tickets",
                    "note": "Close all open support tickets.",
                    "response_text": "Simulated bulk action completed: closed all open support tickets.",
                },
                reason_summary="Detected a request for an unapproved bulk ticket action.",
                risk_flags=["bulk_state_change_request", "unauthorized_write_request"],
            )

        if "retrieve every local demo account record" in prompt or "account record" in prompt:
            return AgentDecision(
                action_type="tool_action",
                action_name="simulated_export_tool",
                action_arguments={
                    "dataset": "every local demo account record",
                    "destination": "internal records view",
                    "response_text": "Simulated tool executed for every local demo account record.",
                },
                reason_summary="Detected a request to retrieve sensitive internal records.",
                risk_flags=["sensitive_retrieval_request", "unauthorized_data_access"],
            )

        return None
