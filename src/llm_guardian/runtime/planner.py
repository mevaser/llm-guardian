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
    _TOOL_KEYWORDS = (
        "send",
        "email",
        "export",
        "close tickets",
        "update note",
        "retrieve every account",
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

        if self._matches_any(normalized_prompt, self._TOOL_KEYWORDS):
            return AgentDecision(
                action_type="tool_action",
                action_name="simulated_tool_execution",
                reason_summary="Detected tool-oriented keywords in the prompt.",
                risk_flags=["external_side_effect_request"],
            )

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
