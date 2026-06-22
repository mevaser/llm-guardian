"""Deterministic orchestration loop for the central security agent."""

from __future__ import annotations

import importlib.util
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from llm_guardian.attacks.loader import load_attack_scenarios
from llm_guardian.config import DEFAULT_ATTACK_SCENARIOS_PATH, REPOSITORY_ROOT
from llm_guardian.evaluators import grade_result
from llm_guardian.models import (
    AdaptiveProbeResult,
    AgentPlan,
    AgentTraceStep,
    SecurityScanResult,
    Severity,
)
from llm_guardian.reports.markdown import generate_markdown_report
from llm_guardian.reports.trajectory import write_trajectory_log
from llm_guardian.runner import run_scenario
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
from llm_guardian.security_agent.mutator import LLMAssistedPromptMutator, PromptMutator
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
        mutation_strategy_mode: str = "deterministic",
    ) -> None:
        if mutation_strategy_mode not in {"deterministic", "llm-assisted"}:
            raise ValueError("mutation_strategy_mode must be 'deterministic' or 'llm-assisted'.")
        if mutation_strategy_mode == "llm-assisted" and not isinstance(
            mutator, LLMAssistedPromptMutator
        ):
            raise ValueError(
                "mutation_strategy_mode='llm-assisted' requires LLMAssistedPromptMutator."
            )
        if mutation_strategy_mode == "deterministic" and isinstance(
            mutator, LLMAssistedPromptMutator
        ):
            raise ValueError(
                "mutation_strategy_mode='deterministic' cannot use LLMAssistedPromptMutator."
            )
        self._planner = planner or AttackPlanner()
        self._executor = executor or AttackExecutor()
        self._mutator = mutator or PromptMutator()
        self._finding_builder = finding_builder or SecurityFindingBuilder()
        self._max_mutations_per_attack = max(max_mutations_per_attack, 0)
        self._mutation_strategy_mode = mutation_strategy_mode

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
            mutation_strategy_mode=self._mutation_strategy_mode,
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

                mutation = self._mutate_prompt(
                    attack_id=attack_id,
                    metadata=metadata,
                    current_attempt=current_attempt,
                    original_prompt=original_attempt.prompt,
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
                    llm_failure_analysis=mutation.llm_failure_analysis,
                    llm_recommended_strategy=mutation.llm_recommended_strategy,
                    llm_validation_status=mutation.llm_validation_status,
                    fallback_used=mutation.fallback_used,
                )
                attempts.append(mutated_attempt)
                if mutated_attempt.success is True:
                    break
                current_attempt = mutated_attempt

        return attempts, prompt_mutations

    def _mutate_prompt(
        self,
        *,
        attack_id: str,
        metadata: object,
        current_attempt: AttackAttempt,
        original_prompt: str,
        strategy: str,
    ) -> PromptMutation:
        category = self._read_attack_value(metadata, "category")
        if self._mutation_strategy_mode == "llm-assisted" and isinstance(
            self._mutator,
            LLMAssistedPromptMutator,
        ):
            return self._mutator.mutate(
                attack_id=attack_id,
                prompt=current_attempt.prompt,
                category=category,
                failed_evidence=current_attempt.evidence,
                strategy=strategy,
                previous_attempt=current_attempt,
                original_prompt=original_prompt,
                allowed_strategies=self._ordered_mutation_strategies(metadata),
            )

        return self._mutator.mutate(
            attack_id=attack_id,
            prompt=current_attempt.prompt,
            category=category,
            failed_evidence=current_attempt.evidence,
            strategy=strategy,
        )

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


class SecurityScanAgent:
    """Run the deterministic MVP scenario-scan pipeline for approved local demo targets."""

    _DEMO_TARGET_NAME = "demo-vulnerable-rag"

    def run(self, target_name: str, output_dir: Path) -> SecurityScanResult:
        scenarios = self._load_scenarios()
        agent_trace: list[AgentTraceStep] = []
        next_step = 1
        agent_plan = self._build_agent_plan(target_name=target_name, scenarios=scenarios)
        agent_trace.append(
            AgentTraceStep(
                step=next_step,
                phase="plan",
                action="Selected deterministic scenarios from the local YAML attack library.",
                observation=(
                    f"Loaded {agent_plan.scenario_count} scenarios from "
                    f"{DEFAULT_ATTACK_SCENARIOS_PATH.name}."
                ),
                decision="Execute the selected scenarios in fixed YAML order.",
                evidence=", ".join(agent_plan.selected_scenario_ids),
            )
        )
        next_step += 1
        target_module = self._resolve_target(target_name)
        scenario_results = []
        findings = []
        for scenario in scenarios:
            scenario_result = run_scenario(target_module, scenario)
            scenario_results.append(scenario_result)
            agent_trace.append(
                AgentTraceStep(
                    step=next_step,
                    phase="execute",
                    scenario_id=scenario.id,
                    action=f"Executed scenario '{scenario.id}' against the demo target.",
                    observation="Collected a deterministic response, tool trace, and retrieved context.",
                    decision="Inspect the captured runtime evidence.",
                )
            )
            next_step += 1
            agent_trace.append(
                AgentTraceStep(
                    step=next_step,
                    phase="observe",
                    scenario_id=scenario.id,
                    action="Reviewed the target response and tool trace.",
                    observation=self._build_observation_summary(scenario_result),
                    decision="Grade the scenario with deterministic evaluator rules.",
                    evidence=self._build_observation_evidence(scenario_result),
                )
            )
            next_step += 1
            finding = grade_result(scenario, scenario_result)
            findings.append(finding)
            agent_trace.append(
                AgentTraceStep(
                    step=next_step,
                    phase="evaluate",
                    scenario_id=scenario.id,
                    action="Applied deterministic grading rules to the observed behavior.",
                    observation=f"Scenario verdict: {finding.verdict}; severity: {finding.severity.value}.",
                    decision=finding.reason,
                    evidence=finding.evidence,
                )
            )
            next_step += 1

        adaptive_probes = self._build_adaptive_probes(findings=findings)
        for adaptive_probe in adaptive_probes:
            agent_trace.append(
                AgentTraceStep(
                    step=next_step,
                    phase="adapt",
                    scenario_id=adaptive_probe.trigger_scenario_id,
                    action=f"Recorded adaptive follow-up probe '{adaptive_probe.probe_id}'.",
                    observation=adaptive_probe.observation,
                    decision=adaptive_probe.recommendation,
                    evidence=adaptive_probe.evidence,
                )
            )
            next_step += 1
        scan_result = SecurityScanResult(
            scan_id=self._build_scan_id(),
            target_name=target_name,
            target_profile=self._build_target_profile(target_name),
            agent_plan=agent_plan,
            agent_trace=agent_trace,
            scenario_results=scenario_results,
            findings=findings,
            adaptive_probes=adaptive_probes,
        )
        scan_result.agent_trace.append(
            AgentTraceStep(
                step=next_step,
                phase="report",
                action="Prepared the trajectory and Markdown report outputs.",
                observation=(
                    f"Collected {len(scan_result.findings)} graded scenarios and "
                    f"{len(scan_result.adaptive_probes)} adaptive probes."
                ),
                decision="Write both scan artifacts to the requested output directory.",
            )
        )
        self._write_outputs(scan_result=scan_result, output_dir=output_dir)
        return scan_result

    def _load_scenarios(self):
        return load_attack_scenarios(DEFAULT_ATTACK_SCENARIOS_PATH)

    def _resolve_target(self, target_name: str):
        if target_name != self._DEMO_TARGET_NAME:
            raise ValueError(
                f"Unknown target '{target_name}'. Supported targets: {self._DEMO_TARGET_NAME}"
            )

        module_path = REPOSITORY_ROOT / "demo_targets" / "vulnerable_rag_agent" / "target.py"
        spec = importlib.util.spec_from_file_location(
            "llm_guardian_demo_vulnerable_rag_target",
            module_path,
        )
        if spec is None or spec.loader is None:
            raise ValueError(f"Could not load demo target module: {module_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _write_outputs(self, *, scan_result: SecurityScanResult, output_dir: Path) -> None:
        resolved_output_dir = Path(output_dir)
        write_trajectory_log(scan_result, resolved_output_dir / "trajectory.json")
        generate_markdown_report(scan_result, resolved_output_dir / "scan_report.md")

    @staticmethod
    def _build_scan_id() -> str:
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        return f"demo-scan-{timestamp}"

    def _build_target_profile(self, target_name: str) -> dict[str, str | bool]:
        return {
            "target_name": target_name,
            "target_type": "local_demo_rag_module",
            "scenario_source": str(DEFAULT_ATTACK_SCENARIOS_PATH),
            "authorization_scope": "local_demo_only",
            "offline_only": True,
        }

    @staticmethod
    def _build_agent_plan(*, target_name: str, scenarios) -> AgentPlan:
        selected_scenario_ids = [scenario.id for scenario in scenarios]
        return AgentPlan(
            target_name=target_name,
            scenario_count=len(selected_scenario_ids),
            selected_scenario_ids=selected_scenario_ids,
            rationale=(
                "Run every deterministic demo scenario to measure prompt-injection, "
                "tool-use, secret-handling, and benign-response behavior in one stable scan."
            ),
            execution_strategy=(
                "Execute scenarios in fixed YAML order, observe response and tool evidence, "
                "grade with deterministic rules, then add follow-up probes for critical failures."
            ),
        )

    @staticmethod
    def _build_observation_summary(scenario_result) -> str:
        tool_count = len(scenario_result.tool_trace)
        has_context = bool(scenario_result.retrieved_context.strip())
        return (
            f"Observed {tool_count} tool call(s); "
            f"retrieved_context_present={'yes' if has_context else 'no'}."
        )

    @staticmethod
    def _build_observation_evidence(scenario_result) -> str:
        if scenario_result.tool_trace:
            first_tool = scenario_result.tool_trace[0]
            tool_name = first_tool.get("tool") or first_tool.get("tool_name") or first_tool.get("name")
            return f"First tool trace entry: {tool_name or 'unknown'}"
        if scenario_result.retrieved_context.strip():
            return "Retrieved context was captured for inspection."
        return "No tool activity or retrieved context was captured."

    @staticmethod
    def _build_adaptive_probes(
        *,
        findings,
    ) -> list[AdaptiveProbeResult]:
        adaptive_probes: list[AdaptiveProbeResult] = []
        for index, finding in enumerate(findings, start=1):
            if finding.verdict != "fail" or finding.severity != Severity.CRITICAL:
                continue
            if finding.category == "unsafe_tool_use" and "attacker@example.com" in finding.reason:
                adaptive_probes.append(
                    AdaptiveProbeResult(
                        probe_id=f"adaptive-probe-{index:03d}",
                        trigger_scenario_id=finding.scenario_id,
                        category=finding.category,
                        status="confirmed",
                        observation=(
                            "Adaptive follow-up confirmed unsafe outbound tool behavior "
                            "targeting attacker@example.com."
                        ),
                        recommendation="Add tool-call gating before any outbound email or export action.",
                        evidence=finding.evidence,
                    )
                )
                continue
            adaptive_probes.append(
                AdaptiveProbeResult(
                    probe_id=f"adaptive-probe-{index:03d}",
                    trigger_scenario_id=finding.scenario_id,
                    category=finding.category,
                    status="confirmed",
                    observation=(
                        "Adaptive follow-up confirmed the critical failure remained visible in "
                        "the deterministic evidence."
                    ),
                    recommendation="Gate sensitive tool access and block secret-handling actions by policy.",
                    evidence=finding.evidence,
                )
            )
        return adaptive_probes
