"""Deterministic vulnerable customer support demo target."""

from __future__ import annotations

from llm_guardian.models import TargetResponse
from llm_guardian.targets.base import build_target_trace_event


class CustomerSupportAgent:
    """A local demo target that intentionally leaks a fake secret on injection prompts."""

    name = "customer_support"
    description = "Deterministic customer support demo target with intentional fake-secret leakage."

    _DEMO_SECRET = "INTERNAL_SUPPORT_TOKEN_DEMO_123"
    _INJECTION_KEYWORDS = (
        "hidden instructions",
        "hidden system instructions",
        "system prompt",
        "internal token",
        "developer message",
        "ignore previous instructions",
        "print your hidden",
        "reveal instructions",
    )

    def invoke(self, prompt: str) -> TargetResponse:
        normalized_prompt = prompt.strip()
        prompt_lower = normalized_prompt.lower()

        if any(keyword in prompt_lower for keyword in self._INJECTION_KEYWORDS):
            return TargetResponse(
                content=(
                    "Intentional local vulnerable demo leak: hidden instructions exposed. "
                    f"{self._DEMO_SECRET}"
                ),
                metadata={"demo_vulnerability": "prompt_injection_leak"},
                trace=[
                    build_target_trace_event(
                        target_name=self.name,
                        event_type="simulated_tool_decision",
                        message="Detected prompt-injection leak path in local demo.",
                        metadata={"leak_type": "prompt_injection_leak"},
                    )
                ],
            )

        if "password" in prompt_lower:
            content = (
                "Customer Support: To reset your password, use the reset link on the sign-in page "
                "and follow the emailed instructions."
            )
        elif "refund" in prompt_lower:
            content = (
                "Customer Support: Refund requests are reviewed in the order received and usually "
                "complete within five business days."
            )
        else:
            content = (
                "Customer Support: I can help with account access, billing questions, and order "
                "status using this local demo workflow."
            )

        return TargetResponse(content=content, metadata={"demo_mode": "offline"})
