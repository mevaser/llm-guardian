"""Offline scan runner for local deterministic targets."""

from __future__ import annotations

from collections.abc import Iterable

from llm_guardian.evaluators.deterministic import DeterministicEvaluator
from llm_guardian.models import AttackCase, ScanReport, ScanSummary, TargetResponse
from llm_guardian.targets.base import TargetAgent


class ScanRunner:
    """Run attacks against a single target instance and build a scan report."""

    def __init__(
        self,
        *,
        target: TargetAgent,
        evaluator: DeterministicEvaluator | None = None,
    ) -> None:
        self._target = target
        self._evaluator = evaluator or DeterministicEvaluator()

    def run(self, attacks: Iterable[AttackCase]) -> ScanReport:
        results = [self._run_attack(attack) for attack in attacks]
        total_attacks = len(results)
        successful_attacks = sum(1 for result in results if result.success)
        risk_score = round((successful_attacks / total_attacks) * 10, 2) if total_attacks else 0.0

        return ScanReport(
            summary=ScanSummary(
                target_name=self._target.name,
                total_attacks=total_attacks,
                successful_attacks=successful_attacks,
                risk_score=risk_score,
            ),
            results=results,
        )

    def _run_attack(self, attack: AttackCase):
        response = self._target.invoke(attack.prompt)
        final_response = response

        if attack.follow_up_prompt:
            follow_up_response = self._target.invoke(attack.follow_up_prompt)
            final_response = self._combine_responses(initial=response, follow_up=follow_up_response)

        return self._evaluator.evaluate(
            target_name=self._target.name,
            attack=attack,
            response=final_response,
        )

    @staticmethod
    def _combine_responses(*, initial: TargetResponse, follow_up: TargetResponse) -> TargetResponse:
        combined_content = "\n".join([initial.content, follow_up.content])
        combined_metadata = {**initial.metadata, **follow_up.metadata}
        combined_tool_calls = [*initial.tool_calls, *follow_up.tool_calls]
        combined_memory_updates = [*initial.memory_updates, *follow_up.memory_updates]
        return TargetResponse(
            content=combined_content,
            metadata=combined_metadata,
            tool_calls=combined_tool_calls,
            memory_updates=combined_memory_updates,
        )
