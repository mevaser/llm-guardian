import pytest
from pydantic import ValidationError

from llm_guardian.security_agent.models import (
    AttackAttempt,
    AttackPlan,
    PromptMutation,
    SecurityAgentResult,
    SecurityFinding,
    SecurityTestObjective,
    TargetProfile,
)


def build_target_profile(**overrides: object) -> TargetProfile:
    payload = {
        "target_type": "rag_app",
        "capabilities": ["retrieval"],
        "risk_surfaces": ["rag"],
        "allowed_categories": ["rag_injection", "prompt_injection", "jailbreak"],
        "authorization_scope": "local_demo",
        "metadata": {"owner": "security"},
    }
    payload.update(overrides)
    return TargetProfile.model_validate(payload)


def build_objective(**overrides: object) -> SecurityTestObjective:
    payload = {
        "goal": "Exercise deterministic security planning.",
        "allowed_categories": ["rag_injection", "prompt_injection"],
        "max_attempts_per_attack": 2,
        "max_total_attempts": 3,
        "safety_mode": "strict",
        "stop_on_success": True,
    }
    payload.update(overrides)
    return SecurityTestObjective.model_validate(payload)


def test_security_agent_models_instantiate_correctly() -> None:
    target_profile = build_target_profile()
    objective = build_objective()
    attack_attempt = AttackAttempt(
        attack_id="RI-001",
        attempt_index=1,
        prompt="Test prompt",
        mutation_strategy=None,
        source_prompt=None,
        mutation_reason_summary=None,
        response=None,
    )
    mutation = PromptMutation(
        source_attack_id="RI-001",
        source_prompt="Base prompt",
        mutated_prompt="Mutated prompt",
        mutation_type="paraphrase",
        reason_summary="Rephrased the prompt.",
    )
    attack_plan = AttackPlan(
        target_profile=target_profile,
        objective=objective,
        selected_categories=["rag_injection", "prompt_injection"],
        selected_attack_ids=["RI-001", "PI-001"],
        strategy_notes=["Selected retrieval-related categories for the target profile."],
        budget={"max_total_attempts": 3, "max_attempts_per_attack": 2},
    )
    result = SecurityAgentResult(
        target_profile=target_profile,
        objective=objective,
        attack_plan=attack_plan,
        attempts=[attack_attempt],
        findings=[
            SecurityFinding(
                finding_id="finding-ri-001",
                attack_id="RI-001",
                attack_name="Reveal hidden instructions",
                category="rag_injection",
                severity="high",
                target_name="demo-rag",
                target_type="rag_app",
                evidence_summary="Matched success indicator: hidden instructions exposed",
                successful_attempt_ids=["RI-001-attempt-1"],
                recommendation="Harden retrieval trust boundaries.",
            )
        ],
        prompt_mutations=[mutation],
        summary="One attempt planned.",
        risk_summary={"planned_attack_count": 1},
    )

    assert attack_attempt.evidence == []
    assert attack_attempt.trace == []
    assert attack_attempt.source_prompt is None
    assert attack_attempt.mutation_reason_summary is None
    assert mutation.safety_flags == []
    assert attack_plan.selected_attack_ids == ["RI-001", "PI-001"]
    assert result.attempts[0].attack_id == "RI-001"
    assert result.attack_plan is not None
    assert result.findings[0].finding_id == "finding-ri-001"
    assert result.prompt_mutations[0].mutation_type == "paraphrase"


def test_security_agent_model_defaults_are_isolated() -> None:
    first = AttackAttempt(
        attack_id="PI-001",
        attempt_index=1,
        prompt="Prompt one",
        mutation_strategy=None,
        source_prompt=None,
        mutation_reason_summary=None,
        response=None,
    )
    second = AttackAttempt(
        attack_id="PI-002",
        attempt_index=1,
        prompt="Prompt two",
        mutation_strategy=None,
        source_prompt=None,
        mutation_reason_summary=None,
        response=None,
    )

    first.trace.append({"step": "first"})
    first.evidence.append("indicator")

    assert second.trace == []
    assert second.evidence == []


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("max_attempts_per_attack", 0),
        ("max_total_attempts", 0),
    ],
)
def test_security_test_objective_rejects_invalid_attempt_budgets(field_name: str, value: int) -> None:
    payload = build_objective().model_dump()
    payload[field_name] = value

    with pytest.raises(ValidationError):
        SecurityTestObjective.model_validate(payload)


def test_attack_plan_contains_expected_nested_objects() -> None:
    target_profile = build_target_profile()
    objective = build_objective()

    attack_plan = AttackPlan(
        target_profile=target_profile,
        objective=objective,
        selected_categories=["rag_injection"],
        selected_attack_ids=["RI-001"],
        strategy_notes=["Selected rag_injection because the target exposes retrieval surfaces."],
        budget={"max_total_attempts": 3, "max_attempts_per_attack": 2},
    )

    assert attack_plan.target_profile.target_type == "rag_app"
    assert attack_plan.objective.goal == "Exercise deterministic security planning."
    assert attack_plan.budget["max_total_attempts"] == 3
