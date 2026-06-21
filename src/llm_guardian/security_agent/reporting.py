"""JSON and Markdown reporting helpers for security-agent results."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from llm_guardian.security_agent.findings import SecurityFindingBuilder
from llm_guardian.security_agent.models import SecurityAgentResult, SecurityFinding


class SecurityAgentJsonReportBuilder:
    """Build a JSON-compatible report payload from a SecurityAgentResult."""

    def __init__(self, *, finding_builder: SecurityFindingBuilder | None = None) -> None:
        self._finding_builder = finding_builder or SecurityFindingBuilder()

    def build(
        self,
        *,
        result: SecurityAgentResult,
        attack_library: Iterable[object],
    ) -> dict[str, Any]:
        findings = self._resolve_findings(result=result, attack_library=attack_library)
        mutation_strategies_used = self._ordered_unique(
            mutation.mutation_type for mutation in result.prompt_mutations
        )

        return {
            "target_profile": result.target_profile.model_dump(mode="json"),
            "objective": result.objective.model_dump(mode="json"),
            "attack_plan": result.attack_plan.model_dump(mode="json") if result.attack_plan is not None else None,
            "summary": {
                "objective": result.objective.goal,
                "total_attempts": result.risk_summary.get("total_attempts", len(result.attempts)),
                "successful_attempts": result.risk_summary.get(
                    "successful_attempts",
                    sum(1 for attempt in result.attempts if attempt.success is True),
                ),
                "failed_attempts": result.risk_summary.get(
                    "failed_attempts",
                    sum(1 for attempt in result.attempts if attempt.success is False),
                ),
                "skipped_or_unknown_attempts": result.risk_summary.get(
                    "skipped_or_unknown_attempts",
                    sum(1 for attempt in result.attempts if attempt.success is None),
                ),
                "success_rate": result.risk_summary.get("success_rate", 0.0),
                "mutation_strategies_used": mutation_strategies_used,
                "finding_count": len(findings),
            },
            "findings": [finding.model_dump(mode="json") for finding in findings],
            "attempt_history": [attempt.model_dump(mode="json") for attempt in result.attempts],
            "prompt_mutations": [mutation.model_dump(mode="json") for mutation in result.prompt_mutations],
            "risk_summary": dict(result.risk_summary),
            "narrative_summary": result.summary,
        }

    def _resolve_findings(
        self,
        *,
        result: SecurityAgentResult,
        attack_library: Iterable[object],
    ) -> list[SecurityFinding]:
        if result.findings:
            return list(result.findings)
        return self._finding_builder.build(
            attempts=result.attempts,
            prompt_mutations=result.prompt_mutations,
            attack_library=attack_library,
            target_profile=result.target_profile,
            attack_plan=result.attack_plan,
        )

    @staticmethod
    def _ordered_unique(values: Iterable[str]) -> list[str]:
        unique_values: list[str] = []
        for value in values:
            if value not in unique_values:
                unique_values.append(value)
        return unique_values


class SecurityAgentMarkdownReportBuilder:
    """Render a deterministic Markdown report for security-agent results."""

    def __init__(self, *, json_builder: SecurityAgentJsonReportBuilder | None = None) -> None:
        self._json_builder = json_builder or SecurityAgentJsonReportBuilder()

    def build(
        self,
        *,
        result: SecurityAgentResult,
        attack_library: Iterable[object],
    ) -> str:
        payload = self._json_builder.build(result=result, attack_library=attack_library)
        summary = payload["summary"]
        findings = payload["findings"]

        lines = [
            "# LLM Guardian Security Agent Report",
            "",
            "## Target Profile",
            "",
            f"- Target name: `{payload['target_profile']['metadata'].get('target_name', 'unknown')}`",
            f"- Target type: `{payload['target_profile']['target_type']}`",
            f"- Authorization scope: `{payload['target_profile']['authorization_scope']}`",
            "",
            "## Objective",
            "",
            f"- Goal: {payload['objective']['goal']}",
            f"- Allowed categories: {', '.join(payload['objective']['allowed_categories']) or 'none'}",
            f"- Safety mode: `{payload['objective']['safety_mode']}`",
            "",
            "## Summary",
            "",
            f"- Total attempts: {summary['total_attempts']}",
            f"- Successful attempts: {summary['successful_attempts']}",
            f"- Failed attempts: {summary['failed_attempts']}",
            f"- Skipped or unknown attempts: {summary['skipped_or_unknown_attempts']}",
            f"- Success rate: {summary['success_rate']:.4f}",
            f"- Mutation strategies used: {self._render_mutation_strategies(summary['mutation_strategies_used'])}",
            f"- Findings: {summary['finding_count']}",
            "",
            "## Findings",
            "",
        ]

        if findings:
            for finding in findings:
                lines.extend(
                    [
                        f"### {finding['finding_id']} - {finding['attack_name']}",
                        "",
                        f"- Attack ID: `{finding['attack_id']}`",
                        f"- Category: `{finding['category']}`",
                        f"- Severity: `{finding['severity']}`",
                        f"- Successful attempt IDs: {', '.join(f'`{item}`' for item in finding['successful_attempt_ids'])}",
                        f"- Mutation strategies: {self._render_mutation_strategies(finding['mutation_strategies'])}",
                        f"- Recommendation: {finding['recommendation']}",
                        f"- Evidence summary: {finding['evidence_summary']}",
                        "",
                    ]
                )
        else:
            lines.extend(["No successful findings were generated.", ""])

        lines.extend(["## Attempt History", ""])
        for attempt in payload["attempt_history"]:
            lines.extend(
                [
                    f"### {attempt.get('attempt_id') or self._build_attempt_id(attempt)}",
                    "",
                    f"- Attack ID: `{attempt['attack_id']}`",
                    f"- Attempt index: {attempt['attempt_index']}",
                    f"- Success: `{str(attempt['success']).lower()}`",
                    f"- Mutation strategy: `{attempt['mutation_strategy'] or 'none'}`",
                    f"- Prompt: `{attempt['prompt']}`",
                    f"- Evidence count: {len(attempt['evidence'])}",
                    "",
                ]
            )

        return "\n".join(lines)

    @staticmethod
    def _render_mutation_strategies(strategies: list[str]) -> str:
        if not strategies:
            return "none"
        return ", ".join(f"`{strategy}`" for strategy in strategies)

    @staticmethod
    def _build_attempt_id(attempt: dict[str, Any]) -> str:
        return f"{attempt['attack_id']}-attempt-{attempt['attempt_index']}"
