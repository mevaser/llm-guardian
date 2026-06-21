"""Deterministic local attack execution for the central security agent."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from llm_guardian.evaluators.deterministic import DeterministicEvaluator
from llm_guardian.models import AttackCase, AttackResult, Severity, TargetResponse
from llm_guardian.security_agent.adapters import TargetAdapter
from llm_guardian.security_agent.models import AttackAttempt, AttackPlan


class AttackExecutor:
    """Execute planned attacks through a local target adapter."""

    def __init__(self, evaluator: DeterministicEvaluator | None = None) -> None:
        self._evaluator = evaluator or DeterministicEvaluator()

    def execute(
        self,
        *,
        plan: AttackPlan,
        adapter: TargetAdapter,
        attack_library: Iterable[object],
    ) -> list[AttackAttempt]:
        metadata_by_id = self._index_attack_metadata(attack_library)
        max_total_attempts = self._resolve_max_total_attempts(plan)
        attempts: list[AttackAttempt] = []

        for attack_id in plan.selected_attack_ids[:max_total_attempts]:
            metadata = metadata_by_id.get(attack_id)
            attempts.append(
                self.execute_attempt(
                    attack_id=attack_id,
                    metadata=metadata,
                    adapter=adapter,
                )
            )

        return attempts

    def execute_attempt(
        self,
        *,
        attack_id: str,
        metadata: object | None,
        adapter: TargetAdapter,
        prompt_override: str | None = None,
        attempt_index: int = 1,
        mutation_strategy: str | None = None,
        source_prompt: str | None = None,
        mutation_reason_summary: str | None = None,
    ) -> AttackAttempt:
        if metadata is None:
            return self._build_skipped_attempt(attack_id=attack_id, reason="attack metadata was not found")

        prompt = prompt_override if prompt_override is not None else self._read_text_value(metadata, "prompt")
        if prompt is None or not prompt.strip():
            return self._build_skipped_attempt(attack_id=attack_id, reason="attack prompt metadata was missing")

        normalized_prompt = prompt.strip()
        execution_result = adapter.execute(normalized_prompt, attack_id=attack_id)
        attack_case, evaluation_skip_reason = self._build_attack_case(metadata=metadata, prompt=normalized_prompt)

        if attack_case is None:
            return AttackAttempt(
                attack_id=attack_id,
                attempt_index=attempt_index,
                prompt=normalized_prompt,
                mutation_strategy=mutation_strategy,
                source_prompt=source_prompt,
                mutation_reason_summary=mutation_reason_summary,
                response=execution_result.response,
                trace=execution_result.trace,
                success=None,
                evidence=[f"Evaluation skipped because {evaluation_skip_reason}."],
            )

        evaluation_result = self._evaluator.evaluate(
            target_name=adapter.target_name,
            attack=attack_case,
            response=TargetResponse(
                content=execution_result.response,
                metadata=execution_result.metadata,
                trace=execution_result.trace,
            ),
        )
        return self._build_attempt_from_evaluation(
            evaluation_result,
            attempt_index=attempt_index,
            mutation_strategy=mutation_strategy,
            source_prompt=source_prompt,
            mutation_reason_summary=mutation_reason_summary,
        )

    @staticmethod
    def _resolve_max_total_attempts(plan: AttackPlan) -> int:
        budget_value = plan.budget.get("max_total_attempts")
        if isinstance(budget_value, int) and budget_value >= 1:
            return budget_value
        return plan.objective.max_total_attempts

    @staticmethod
    def _index_attack_metadata(attack_library: Iterable[object]) -> dict[str, object]:
        indexed: dict[str, object] = {}
        for entry in attack_library:
            attack_id = AttackExecutor._read_text_value(entry, "id") or AttackExecutor._read_text_value(
                entry, "attack_id"
            )
            if attack_id is None or not attack_id.strip():
                continue
            normalized_attack_id = attack_id.strip()
            if normalized_attack_id not in indexed:
                indexed[normalized_attack_id] = entry
        return indexed

    @staticmethod
    def _read_text_value(entry: object, key: str) -> str | None:
        if isinstance(entry, dict):
            value = entry.get(key)
        else:
            value = getattr(entry, key, None)

        if value is None:
            return None
        if hasattr(value, "value"):
            value = value.value
        if not isinstance(value, str):
            value = str(value)
        return value

    @staticmethod
    def _read_indicator_values(entry: object, *keys: str) -> list[str]:
        for key in keys:
            if isinstance(entry, dict):
                value = entry.get(key)
            else:
                value = getattr(entry, key, None)

            if value is None:
                continue
            if isinstance(value, list):
                return [str(item).strip() for item in value if str(item).strip()]
            return [str(value).strip()] if str(value).strip() else []
        return []

    @staticmethod
    def _build_attack_case(metadata: object, prompt: str) -> tuple[AttackCase | None, str | None]:
        attack_id = AttackExecutor._read_text_value(metadata, "id") or AttackExecutor._read_text_value(
            metadata, "attack_id"
        )
        category = AttackExecutor._read_text_value(metadata, "category")
        if category is None or not category.strip():
            return None, "attack metadata is missing a non-empty category"
        if attack_id is None or not attack_id.strip():
            return None, "attack metadata is missing a non-empty id"

        title = AttackExecutor._read_text_value(metadata, "title") or attack_id.strip()
        recommendation = (
            AttackExecutor._read_text_value(metadata, "recommendation")
            or "Review the local target behavior and harden the affected control path."
        )
        severity = AttackExecutor._read_text_value(metadata, "severity") or Severity.LOW.value

        try:
            attack_case = AttackCase(
                id=attack_id.strip(),
                category=category.strip(),
                severity=severity.strip(),
                title=title.strip(),
                prompt=prompt,
                success_indicators=AttackExecutor._read_indicator_values(
                    metadata,
                    "success_indicators",
                    "indicators",
                ),
                failure_indicators=AttackExecutor._read_indicator_values(
                    metadata,
                    "failure_indicators",
                ),
                recommendation=recommendation.strip(),
            )
        except Exception as exc:
            return None, f"attack metadata could not be adapted for deterministic evaluation ({exc})"

        return attack_case, None

    @staticmethod
    def _build_attempt_from_evaluation(
        result: AttackResult,
        *,
        attempt_index: int = 1,
        mutation_strategy: str | None = None,
        source_prompt: str | None = None,
        mutation_reason_summary: str | None = None,
    ) -> AttackAttempt:
        return AttackAttempt(
            attack_id=result.attack_id,
            attempt_id=f"{result.attack_id}-attempt-{attempt_index}",
            attempt_index=attempt_index,
            prompt=result.prompt,
            mutation_strategy=mutation_strategy,
            source_prompt=source_prompt,
            mutation_reason_summary=mutation_reason_summary,
            response=result.response,
            trace=result.trace,
            success=result.success,
            evidence=result.evidence,
        )

    @staticmethod
    def _build_skipped_attempt(*, attack_id: str, reason: str) -> AttackAttempt:
        return AttackAttempt(
            attack_id=attack_id,
            attempt_id=f"{attack_id}-attempt-1",
            attempt_index=1,
            prompt=f"Execution skipped for attack_id='{attack_id}'.",
            mutation_strategy=None,
            response=None,
            trace=[],
            success=None,
            evidence=[f"Execution skipped because {reason} for attack_id='{attack_id}'."],
        )
