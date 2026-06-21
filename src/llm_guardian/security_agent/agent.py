"""Deterministic orchestration loop for the central security agent."""

from __future__ import annotations

from collections.abc import Iterable

from llm_guardian.security_agent.adapters import TargetAdapter
from llm_guardian.security_agent.executor import AttackExecutor
from llm_guardian.security_agent.findings import SecurityFindingBuilder
from llm_guardian.security_agent.models import (
    AttackAttempt,
    AttackPlan,
    AttackCampaign,
    PromptMutation,
    SecurityAgentResult,
    SecurityTestObjective,
    TargetProfile,
    ThreatModel,
)
from llm_guardian.security_agent.mutator import PromptMutator
from llm_guardian.security_agent.planner import AttackPlanner


class SecurityAgent:
    """Coordinate deterministic planning and execution for one local security test run."""

    def __init__(
        self,
        planner: AttackPlanner | None = None,
        executor: AttackExecutor | None = None,
        mutator: PromptMutator | None = None,
        finding_builder: SecurityFindingBuilder | None = None,
        max_mutations_per_attack: int = 0,
    ) -> None:
        self._planner = planner or AttackPlanner()
        self._executor = executor or AttackExecutor()
        self._mutator = mutator or PromptMutator()
        self._finding_builder = finding_builder or SecurityFindingBuilder()
        self._max_mutations_per_attack = max(max_mutations_per_attack, 0)

    def run(
        self,
        target_profile: TargetProfile,
        objective: SecurityTestObjective,
        attacks: list[object],
        target_adapter: TargetAdapter,
    ) -> SecurityAgentResult:
        """Run one deterministic local security-agent loop with optional bounded mutation retries."""

        threat_model = self._planner.build_threat_model(
            target_profile=target_profile,
            objective=objective,
        )
        attack_campaign = self._planner.create_campaign(
            threat_model=threat_model,
            target_profile=target_profile,
            objective=objective,
            attack_library=attacks,
            max_mutations_per_attack=self._max_mutations_per_attack,
        )
        plan = attack_campaign.attack_plan
        attempts, prompt_mutations = self._execute_with_optional_mutations(
            plan=plan,
            attack_library=attacks,
            target_adapter=target_adapter,
        )
        findings = self._finding_builder.build(
            attempts=attempts,
            prompt_mutations=prompt_mutations,
            attack_library=attacks,
            target_profile=target_profile,
            attack_plan=plan,
        )
        risk_summary = self._build_risk_summary(attempts)
        summary = self._build_summary(
            target_profile=target_profile,
            objective=objective,
            risk_summary=risk_summary,
        )

        return SecurityAgentResult(
            target_profile=target_profile,
            objective=objective,
            attack_plan=plan,
            threat_model=threat_model,
            attack_campaign=attack_campaign,
            attempts=attempts,
            findings=findings,
            prompt_mutations=prompt_mutations,
            summary=summary,
            risk_summary=risk_summary,
        )

    def _execute_with_optional_mutations(
        self,
        *,
        plan: AttackPlan,
        attack_library: Iterable[object],
        target_adapter: TargetAdapter,
    ) -> tuple[list[AttackAttempt], list[PromptMutation]]:
        metadata_by_id = self._index_attack_metadata(attack_library)
        attempts: list[AttackAttempt] = []
        prompt_mutations: list[PromptMutation] = []
        max_total_attempts = plan.objective.max_total_attempts

        for attack_id in plan.selected_attack_ids:
            if len(attempts) >= max_total_attempts:
                break

            metadata = metadata_by_id.get(attack_id)
            original_attempt = self._executor.execute_attempt(
                attack_id=attack_id,
                metadata=metadata,
                adapter=target_adapter,
                attempt_index=1,
            )
            attempts.append(original_attempt)

            if original_attempt.success is True:
                continue

            if metadata is None:
                continue

            allowed_mutations = min(
                self._max_mutations_per_attack,
                max(plan.objective.max_attempts_per_attack - 1, 0),
            )
            if allowed_mutations <= 0:
                continue

            mutation_strategies = self._ordered_mutation_strategies(metadata)
            if not mutation_strategies:
                continue

            current_attempt = original_attempt
            for strategy in mutation_strategies[:allowed_mutations]:
                if len(attempts) >= max_total_attempts:
                    break

                mutation = self._mutator.mutate(
                    attack_id=attack_id,
                    prompt=current_attempt.prompt,
                    category=self._read_attack_value(metadata, "category"),
                    failed_evidence=current_attempt.evidence,
                    strategy=strategy,
                )
                prompt_mutations.append(mutation)
                mutated_attempt = self._executor.execute_attempt(
                    attack_id=attack_id,
                    metadata=metadata,
                    adapter=target_adapter,
                    prompt_override=mutation.mutated_prompt,
                    attempt_index=current_attempt.attempt_index + 1,
                    mutation_strategy=mutation.mutation_type,
                    source_prompt=mutation.source_prompt,
                    mutation_reason_summary=mutation.reason_summary,
                )
                attempts.append(mutated_attempt)
                if mutated_attempt.success is True:
                    break
                current_attempt = mutated_attempt

        return attempts, prompt_mutations

    @staticmethod
    def _build_risk_summary(attempts: list[AttackAttempt]) -> dict[str, int | float]:
        total_attempts = len(attempts)
        successful_attempts = sum(1 for attempt in attempts if SecurityAgent._attempt_success(attempt) is True)
        failed_attempts = sum(1 for attempt in attempts if SecurityAgent._attempt_success(attempt) is False)
        skipped_or_unknown_attempts = sum(1 for attempt in attempts if SecurityAgent._attempt_success(attempt) is None)
        success_rate = round(successful_attempts / total_attempts, 4) if total_attempts else 0.0

        return {
            "total_attempts": total_attempts,
            "successful_attempts": successful_attempts,
            "failed_attempts": failed_attempts,
            "skipped_or_unknown_attempts": skipped_or_unknown_attempts,
            "success_rate": success_rate,
        }

    @staticmethod
    def _attempt_success(attempt: AttackAttempt) -> bool | None:
        if attempt.verdict is not None:
            return attempt.verdict.success
        return attempt.success

    @staticmethod
    def _ordered_mutation_strategies(metadata: object) -> list[str]:
        category = SecurityAgent._read_attack_value(metadata, "category")
        default_strategy_by_category = {
            "rag_injection": "retrieved_document_wrapper",
            "memory_poisoning": "memory_note_wrapper",
            "tool_abuse": "indirect_framing",
            "prompt_injection": "quoted_instruction",
            "jailbreak": "role_framing",
        }
        ordered_strategies = [
            default_strategy_by_category.get(
                category.strip().lower() if category and category.strip() else "",
                "rephrase_instruction",
            ),
            "rephrase_instruction",
            "indirect_framing",
            "role_framing",
            "urgency_framing",
            "formatting_noise",
            "quoted_instruction",
            "retrieved_document_wrapper",
            "memory_note_wrapper",
        ]
        unique_strategies: list[str] = []
        for strategy in ordered_strategies:
            if strategy not in unique_strategies:
                unique_strategies.append(strategy)
        return unique_strategies

    @staticmethod
    def _index_attack_metadata(attack_library: Iterable[object]) -> dict[str, object]:
        indexed: dict[str, object] = {}
        for entry in attack_library:
            attack_id = SecurityAgent._read_attack_value(entry, "id") or SecurityAgent._read_attack_value(
                entry, "attack_id"
            )
            if attack_id is None or not attack_id.strip():
                continue
            normalized_attack_id = attack_id.strip()
            if normalized_attack_id not in indexed:
                indexed[normalized_attack_id] = entry
        return indexed

    @staticmethod
    def _read_attack_value(entry: object, key: str) -> str | None:
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
