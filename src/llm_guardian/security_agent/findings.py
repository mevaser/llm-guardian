"""Deterministic finding aggregation for the security agent path."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from llm_guardian.models import Severity
from llm_guardian.security_agent.models import (
    AttackAttempt,
    AttackPlan,
    PromptMutation,
    SecurityFinding,
    TargetProfile,
)


class SecurityFindingBuilder:
    """Convert successful security-agent attempts into stable structured findings."""

    def build(
        self,
        *,
        attempts: list[AttackAttempt],
        prompt_mutations: list[PromptMutation],
        attack_library: Iterable[object],
        target_profile: TargetProfile,
        attack_plan: AttackPlan | None = None,
    ) -> list[SecurityFinding]:
        metadata_by_id = self._index_attack_metadata(attack_library)
        mutations_by_attack = self._group_prompt_mutations(prompt_mutations)
        successful_attempts_by_attack: dict[str, list[AttackAttempt]] = {}

        for attempt in attempts:
            if not self._attempt_was_successful(attempt):
                continue
            successful_attempts_by_attack.setdefault(attempt.attack_id, []).append(attempt)

        findings: list[SecurityFinding] = []
        for attack_id, successful_attempts in successful_attempts_by_attack.items():
            metadata = metadata_by_id.get(attack_id, {})
            mutation_records = mutations_by_attack.get(attack_id, [])
            attack_name = self._read_text_value(metadata, "title") or attack_id
            category = self._read_text_value(metadata, "category") or self._infer_category(
                attack_plan=attack_plan,
                attack_id=attack_id,
            )
            severity = self._read_text_value(metadata, "severity") or Severity.LOW.value
            recommendation = (
                self._read_text_value(metadata, "recommendation")
                or "Review the local target behavior and harden the affected control path."
            )

            findings.append(
                SecurityFinding(
                    finding_id=f"finding-{attack_id.lower()}",
                    attack_id=attack_id,
                    attack_name=attack_name,
                    category=category,
                    severity=severity,
                    target_name=self._resolve_target_name(target_profile),
                    target_type=target_profile.target_type,
                    evidence_summary=self._build_evidence_summary(
                        successful_attempts=successful_attempts,
                        mutation_records=mutation_records,
                    ),
                    successful_attempt_ids=[
                        attempt.attempt_id or self._build_attempt_id(attack_id, attempt.attempt_index)
                        for attempt in successful_attempts
                    ],
                    mutation_strategies=self._ordered_unique(
                        [
                            attempt.mutation_strategy
                            for attempt in successful_attempts
                            if attempt.mutation_strategy is not None
                        ]
                        + [
                            mutation.mutation_type
                            for mutation in mutation_records
                            if mutation.mutation_type
                        ]
                    ),
                    source_prompts=self._ordered_unique(
                        [
                            attempt.source_prompt
                            for attempt in successful_attempts
                            if attempt.source_prompt is not None
                        ]
                    ),
                    recommendation=recommendation,
                    response_excerpt=self._build_response_excerpt(successful_attempts[-1].response),
                )
            )

        return findings

    @staticmethod
    def _index_attack_metadata(attack_library: Iterable[object]) -> dict[str, object]:
        indexed: dict[str, object] = {}
        for entry in attack_library:
            attack_id = SecurityFindingBuilder._read_text_value(
                entry, "id"
            ) or SecurityFindingBuilder._read_text_value(entry, "attack_id")
            if attack_id is None or not attack_id.strip():
                continue
            normalized_attack_id = attack_id.strip()
            if normalized_attack_id not in indexed:
                indexed[normalized_attack_id] = entry
        return indexed

    @staticmethod
    def _group_prompt_mutations(
        prompt_mutations: list[PromptMutation],
    ) -> dict[str, list[PromptMutation]]:
        grouped: dict[str, list[PromptMutation]] = {}
        for mutation in prompt_mutations:
            grouped.setdefault(mutation.source_attack_id, []).append(mutation)
        return grouped

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
        return value.strip() if value.strip() else None

    @staticmethod
    def _resolve_target_name(target_profile: TargetProfile) -> str | None:
        for key in ("target_name", "target_id", "name", "id"):
            value = target_profile.metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    @staticmethod
    def _build_attempt_id(attack_id: str, attempt_index: int) -> str:
        return f"{attack_id}-attempt-{attempt_index}"

    @staticmethod
    def _ordered_unique(values: Iterable[str | None]) -> list[str]:
        unique_values: list[str] = []
        for value in values:
            if value is None:
                continue
            if value not in unique_values:
                unique_values.append(value)
        return unique_values

    @staticmethod
    def _build_response_excerpt(response: str | None, max_length: int = 160) -> str:
        if response is None:
            return ""
        if len(response) <= max_length:
            return response
        return f"{response[: max_length - 3]}..."

    def _build_evidence_summary(
        self,
        *,
        successful_attempts: list[AttackAttempt],
        mutation_records: list[PromptMutation],
    ) -> str:
        summary_parts = self._ordered_unique(
            [
                evidence_item
                for attempt in successful_attempts
                for evidence_item in attempt.evidence
            ]
            + [
                attempt.mutation_reason_summary
                for attempt in successful_attempts
                if attempt.mutation_reason_summary is not None
            ]
            + [
                mutation.reason_summary
                for mutation in mutation_records
            ]
        )
        return "; ".join(summary_parts) if summary_parts else "Successful attack evidence captured."

    @staticmethod
    def _infer_category(*, attack_plan: AttackPlan | None, attack_id: str) -> str:
        if attack_plan is not None and attack_plan.selected_categories:
            return attack_plan.selected_categories[0]
        prefix_map = {
            "PI-": "prompt_injection",
            "JB-": "jailbreak",
            "TA-": "tool_abuse",
            "RI-": "rag_injection",
            "MP-": "memory_poisoning",
        }
        for prefix, category in prefix_map.items():
            if attack_id.upper().startswith(prefix):
                return category
        return "prompt_injection"

    @staticmethod
    def _attempt_was_successful(attempt: AttackAttempt) -> bool:
        if attempt.verdict is not None:
            return attempt.verdict.status == "success" and attempt.verdict.success is True
        return attempt.success is True
