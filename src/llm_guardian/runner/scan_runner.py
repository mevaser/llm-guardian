"""Offline scan runner for local deterministic targets."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from llm_guardian.evaluators.deterministic import DeterministicEvaluator
from llm_guardian.models import AttackCase, AttackResult, ScanReport, TargetResponse, TraceEvent
from llm_guardian.reports.generator import ReportGenerator
from llm_guardian.targets.base import TargetAgent


class ScanRunner:
    """Run attacks against one local target and return a structured report.

    The runner owns the cross-cutting trajectory assembly. Targets can emit
    local operational trace events, and the runner stamps them with the active
    attack identifier before passing the full sequence to the evaluator.
    """

    def __init__(
        self,
        *,
        target: TargetAgent,
        evaluator: DeterministicEvaluator | None = None,
        report_generator: ReportGenerator | None = None,
    ) -> None:
        self._target = target
        self._evaluator = evaluator or DeterministicEvaluator()
        self._report_generator = report_generator or ReportGenerator()

    def run(self, attacks: Iterable[AttackCase]) -> ScanReport:
        """Execute each attack in order and aggregate the evaluated findings."""

        results = [self._run_attack(attack) for attack in attacks]
        return self._report_generator.build(
            target_name=self._target.name,
            results=results,
        )

    def _run_attack(self, attack: AttackCase) -> AttackResult:
        trace = [
            self._build_trace_event(
                attack=attack,
                event_type="attack_started",
                message="Started deterministic attack execution.",
            ),
            self._build_trace_event(
                attack=attack,
                event_type="target_invoked",
                message="Invoked target with primary attack prompt.",
                metadata={"prompt_stage": "initial"},
            ),
        ]
        response = self._target.invoke(attack.prompt)
        trace.extend(self._stamp_response_trace(attack=attack, response=response))
        trace.append(
            self._build_trace_event(
                attack=attack,
                event_type="target_responded",
                message="Captured target response for primary prompt.",
                metadata={"prompt_stage": "initial"},
            )
        )
        final_response = response

        if attack.follow_up_prompt:
            trace.append(
                self._build_trace_event(
                    attack=attack,
                    event_type="target_invoked",
                    message="Invoked target with follow-up prompt.",
                    metadata={"prompt_stage": "follow_up"},
                )
            )
            follow_up_response = self._target.invoke(attack.follow_up_prompt)
            trace.extend(self._stamp_response_trace(attack=attack, response=follow_up_response))
            trace.append(
                self._build_trace_event(
                    attack=attack,
                    event_type="target_responded",
                    message="Captured target response for follow-up prompt.",
                    metadata={"prompt_stage": "follow_up"},
                )
            )
            final_response = self._combine_responses(
                initial=response,
                follow_up=follow_up_response,
                trace=trace,
            )
        else:
            final_response = response.model_copy(update={"trace": trace})

        return self._evaluator.evaluate(
            target_name=self._target.name,
            attack=attack,
            response=final_response,
        )

    @staticmethod
    def _combine_responses(
        *,
        initial: TargetResponse,
        follow_up: TargetResponse,
        trace: list[TraceEvent],
    ) -> TargetResponse:
        combined_content = "\n".join([initial.content, follow_up.content])
        combined_metadata = {**initial.metadata, **follow_up.metadata}
        combined_tool_calls = [*initial.tool_calls, *follow_up.tool_calls]
        combined_memory_updates = [*initial.memory_updates, *follow_up.memory_updates]
        return TargetResponse(
            content=combined_content,
            metadata=combined_metadata,
            tool_calls=combined_tool_calls,
            memory_updates=combined_memory_updates,
            trace=trace,
        )

    def _build_trace_event(
        self,
        *,
        attack: AttackCase,
        event_type: str,
        message: str,
        metadata: dict[str, object] | None = None,
    ) -> TraceEvent:
        return TraceEvent(
            event_type=event_type,
            timestamp=datetime.now(UTC),
            target_name=self._target.name,
            attack_id=attack.id,
            message=message,
            metadata=dict(metadata or {}),
        )

    def _stamp_response_trace(self, *, attack: AttackCase, response: TargetResponse) -> list[TraceEvent]:
        return [
            event.model_copy(
                update={
                    "target_name": self._target.name,
                    "attack_id": attack.id,
                }
            )
            for event in response.trace
        ]
