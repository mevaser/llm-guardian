"""Minimal deterministic policy engine for agent runtime actions."""

from __future__ import annotations

from llm_guardian.runtime.models import AgentDecision, PolicyDecision


class PolicyEngine:
    """Apply deterministic policy decisions for runtime actions."""

    def __init__(self, *, vulnerable_demo_mode: bool = True) -> None:
        self._vulnerable_demo_mode = vulnerable_demo_mode

    def evaluate(self, decision: AgentDecision) -> PolicyDecision:
        """Return a local policy outcome for a planner decision."""

        if decision.action_type == "tool_action":
            return PolicyDecision(
                decision="approved",
                reason_summary="Tool actions remain enabled in vulnerable demo mode for evaluation coverage.",
                applies_to=decision.action_type,
                severity="medium",
                metadata={
                    "vulnerable_demo_mode": self._vulnerable_demo_mode,
                    "risk_flags": list(decision.risk_flags),
                },
            )

        if decision.action_type == "policy_sensitive_action":
            return PolicyDecision(
                decision="flagged",
                reason_summary="Prompt appears to target hidden or privileged instructions.",
                applies_to=decision.action_type,
                severity="high",
                metadata={
                    "vulnerable_demo_mode": self._vulnerable_demo_mode,
                    "risk_flags": list(decision.risk_flags),
                },
            )

        if decision.action_type in {"retrieval_action", "memory_action"}:
            return PolicyDecision(
                decision="approved",
                reason_summary="Action is allowed in the deterministic runtime core slice.",
                applies_to=decision.action_type,
                severity="low",
                metadata={
                    "vulnerable_demo_mode": self._vulnerable_demo_mode,
                    "risk_flags": list(decision.risk_flags),
                },
            )

        return PolicyDecision(
            decision="approved",
            reason_summary="Normal responses are approved.",
            applies_to=decision.action_type,
            severity="low",
            metadata={
                "vulnerable_demo_mode": self._vulnerable_demo_mode,
                "risk_flags": list(decision.risk_flags),
            },
        )
