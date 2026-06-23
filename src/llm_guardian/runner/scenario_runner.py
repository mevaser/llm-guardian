"""Minimal deterministic scenario runner for the course MVP."""

from __future__ import annotations

from typing import Any

from llm_guardian.models import AttackScenario, AttackScenarioCategory, ScenarioRunResult


def run_scenario(target_module: Any, scenario: AttackScenario) -> ScenarioRunResult:
    """Execute one attack scenario against a target module with a stable demo policy."""

    raw_result = target_module.run_target(
        prompt=scenario.prompt,
        use_poisoned_doc=_should_use_poisoned_doc(scenario),
    )

    return ScenarioRunResult(
        scenario_id=scenario.id,
        prompt=scenario.prompt,
        target_response=raw_result["response"],
        tool_trace=list(raw_result.get("tool_trace", [])),
        retrieved_context=raw_result.get("retrieved_context", ""),
        raw_result=dict(raw_result),
    )


def _should_use_poisoned_doc(scenario: AttackScenario) -> bool:
    if scenario.category is AttackScenarioCategory.INDIRECT_PROMPT_INJECTION:
        return True

    if scenario.category is not AttackScenarioCategory.UNSAFE_TOOL_USE:
        return False

    scenario_id = scenario.id.lower()
    prompt = scenario.prompt.lower()
    return any(
        marker in scenario_id or marker in prompt
        for marker in ("attacker@example.com", "email", "exfiltration")
    )
