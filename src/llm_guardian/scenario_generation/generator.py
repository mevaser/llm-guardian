"""Scenario generation workflow with deterministic validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from llm_guardian.models import (
    AttackScenario,
    GeneratedScenarioBatch,
    ScenarioGenerationRequest,
    ScenarioGenerationResult,
)
from llm_guardian.scenario_generation.providers import ScenarioLLMProvider


def generate_attack_scenarios(
    target_name: str,
    target_profile_summary: str,
    provider: ScenarioLLMProvider,
    count: int = 2,
) -> ScenarioGenerationResult:
    request = ScenarioGenerationRequest(
        target_name=target_name,
        target_profile_summary=target_profile_summary,
        count=count,
    )
    raw_output = provider.generate_scenarios(request)
    validation_errors: list[str] = []
    parsed_scenarios: list[AttackScenario] = []
    accepted_scenarios: list[AttackScenario] = []
    rejected_scenarios: list[dict[str, Any]] = []

    try:
        payload = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        return ScenarioGenerationResult(
            raw_output=raw_output,
            parsed_scenarios=[],
            accepted_scenarios=[],
            rejected_scenarios=[],
            validation_errors=[f"Provider returned invalid JSON: {exc}"],
        )

    scenario_items = payload.get("scenarios", [])
    if not isinstance(scenario_items, list):
        return ScenarioGenerationResult(
            raw_output=raw_output,
            parsed_scenarios=[],
            accepted_scenarios=[],
            rejected_scenarios=[],
            validation_errors=["Provider JSON must define a top-level 'scenarios' list."],
        )

    seen_ids: set[str] = set()
    for index, item in enumerate(scenario_items, start=1):
        normalized_item = dict(item) if isinstance(item, dict) else {"raw_item": item}
        scenario_id = normalized_item.get("id")
        if isinstance(scenario_id, str) and scenario_id.strip():
            normalized_item["id"] = _normalize_generated_id(scenario_id)
        try:
            scenario = AttackScenario.model_validate(normalized_item)
            parsed_scenarios.append(scenario)
            _validate_generated_scenario(scenario, seen_ids=seen_ids)
        except (ValidationError, ValueError) as exc:
            validation_errors.append(f"Scenario {index}: {exc}")
            rejected_scenarios.append(normalized_item)
            if isinstance(normalized_item.get("id"), str) and normalized_item["id"].strip():
                seen_ids.add(normalized_item["id"])
            continue

        seen_ids.add(scenario.id)
        accepted_scenarios.append(scenario)

    return ScenarioGenerationResult(
        raw_output=raw_output,
        parsed_scenarios=parsed_scenarios,
        accepted_scenarios=accepted_scenarios,
        rejected_scenarios=rejected_scenarios,
        validation_errors=validation_errors,
    )


def build_generated_scenario_batch(
    *,
    target_name: str,
    target_profile_summary: str,
    provider_name: str,
    model_name: str,
    result: ScenarioGenerationResult,
    generation_notes: str = "",
) -> GeneratedScenarioBatch:
    return GeneratedScenarioBatch(
        target_name=target_name,
        target_profile_summary=target_profile_summary,
        generated_scenarios=result.accepted_scenarios,
        provider=provider_name,
        model=model_name,
        generation_notes=generation_notes,
    )


def write_generated_scenarios_yaml(scenarios: list[AttackScenario], output_path: Path) -> Path:
    payload = {"scenarios": [scenario.model_dump(mode="json") for scenario in scenarios]}
    resolved_output_path = Path(output_path)
    resolved_output_path.parent.mkdir(parents=True, exist_ok=True)
    resolved_output_path.write_text(
        yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return resolved_output_path


def _normalize_generated_id(raw_id: str) -> str:
    stripped_id = raw_id.strip()
    if stripped_id.startswith("generated-"):
        return stripped_id
    return f"generated-{stripped_id}"


def _validate_generated_scenario(scenario: AttackScenario, *, seen_ids: set[str]) -> None:
    if scenario.id in seen_ids:
        raise ValueError(f"Duplicate generated scenario id: {scenario.id}")
    if not scenario.prompt.strip():
        raise ValueError(f"Generated scenario '{scenario.id}' has an empty prompt.")
    if not scenario.failure_conditions:
        raise ValueError(
            f"Generated scenario '{scenario.id}' must define deterministic failure_conditions."
        )
