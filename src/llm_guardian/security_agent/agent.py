"""Deterministic orchestration loop for the central security agent."""

from __future__ import annotations

from typing import Any

from llm_guardian.security_agent.adapters import TargetAdapter
from llm_guardian.security_agent.executor import AttackExecutor
from llm_guardian.security_agent.models import (
    AttackAttempt,
    SecurityAgentResult,
    SecurityTestObjective,
    TargetProfile,
)
from llm_guardian.security_agent.planner import AttackPlanner


class SecurityAgent:
    """Coordinate deterministic planning and execution for one local security test run."""

    def __init__(
        self,
        planner: AttackPlanner | None = None,
        executor: AttackExecutor | None = None,
    ) -> None:
        self._planner = planner or AttackPlanner()
        self._executor = executor or AttackExecutor()

    def run(
        self,
        target_profile: TargetProfile,
        objective: SecurityTestObjective,
        attacks: list[object],
        target_adapter: TargetAdapter,
    ) -> SecurityAgentResult:
        """Run one deterministic local security-agent loop without retries or mutation."""

        plan = self._planner.plan(
            target_profile=target_profile,
            objective=objective,
            attack_library=attacks,
        )
        attempts = self._executor.execute(
            plan=plan,
            adapter=target_adapter,
            attack_library=attacks,
        )
        findings = self._build_findings(attempts)
        risk_summary = self._build_risk_summary(attempts)
        summary = self._build_summary(
            target_profile=target_profile,
            objective=objective,
            risk_summary=risk_summary,
        )

        return SecurityAgentResult(
            target_profile=target_profile,
            objective=objective,
            attempts=attempts,
            findings=findings,
            summary=summary,
            risk_summary=risk_summary,
        )

    @staticmethod
    def _build_findings(attempts: list[AttackAttempt]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for attempt in attempts:
            if attempt.success is not True:
                continue
            findings.append(
                {
                    "attack_id": attempt.attack_id,
                    "success": True,
                    "evidence": list(attempt.evidence),
                    "prompt": attempt.prompt,
                    "response_excerpt": SecurityAgent._build_response_excerpt(attempt.response),
                }
            )
        return findings

    @staticmethod
    def _build_response_excerpt(response: str | None, max_length: int = 160) -> str:
        if response is None:
            return ""
        if len(response) <= max_length:
            return response
        return f"{response[: max_length - 3]}..."

    @staticmethod
    def _build_risk_summary(attempts: list[AttackAttempt]) -> dict[str, int | float]:
        total_attempts = len(attempts)
        successful_attempts = sum(1 for attempt in attempts if attempt.success is True)
        failed_attempts = sum(1 for attempt in attempts if attempt.success is False)
        skipped_or_unknown_attempts = sum(1 for attempt in attempts if attempt.success is None)
        success_rate = round(successful_attempts / total_attempts, 4) if total_attempts else 0.0

        return {
            "total_attempts": total_attempts,
            "successful_attempts": successful_attempts,
            "failed_attempts": failed_attempts,
            "skipped_or_unknown_attempts": skipped_or_unknown_attempts,
            "success_rate": success_rate,
        }

    @staticmethod
    def _build_summary(
        *,
        target_profile: TargetProfile,
        objective: SecurityTestObjective,
        risk_summary: dict[str, int | float],
    ) -> str:
        return (
            f"Executed {risk_summary['total_attempts']} attacks for goal '{objective.goal}' "
            f"against target_type '{target_profile.target_type}'. "
            f"Successes: {risk_summary['successful_attempts']}; "
            f"failures: {risk_summary['failed_attempts']}; "
            f"skipped_or_unknown: {risk_summary['skipped_or_unknown_attempts']}; "
            f"success_rate: {float(risk_summary['success_rate']):.2f}."
        )
