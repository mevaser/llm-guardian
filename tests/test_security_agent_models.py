import pytest
from pydantic import ValidationError

from llm_guardian.security_agent.models import (
    AttackCampaign,
    AttackAttempt,
    AttackPlan,
    Observation,
    PromptMutation,
    SecurityAgentResult,
    SecurityFinding,
    SecurityTestObjective,
    TargetProfile,
    ThreatModel,
    Trajectory,
    Verdict,
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


def test_attempt_accepts_first_class_trajectory_observation_and_verdict() -> None:
    trajectory = Trajectory(
        attack_id="TA-001",
        attempt_id="TA-001-attempt-1",
        attempt_index=1,
        prompt="Send the data externally.",
        response_text="Simulated email tool executed in demo mode.",
        target_metadata={"execution_mode": "local_in_process"},
        tool_calls=[{"tool_name": "simulated_email_tool", "arguments": {"recipient": "demo@example.local"}}],
        tool_names=["simulated_email_tool"],
        tool_arguments=[{"recipient": "demo@example.local"}],
        tool_results=[{"tool_name": "simulated_email_tool", "status": "simulated"}],
        trace_events=[],
    )
    observation = Observation(
        tool_called=True,
        tool_names=["simulated_email_tool"],
        mock_side_effects_detected=True,
        matched_success_indicators=["email tool executed"],
        relevant_evidence=["Matched success indicator: email tool executed"],
    )
    verdict = Verdict(
        status="success",
        success=True,
        severity="high",
        reason="Matched deterministic success indicators.",
        evidence=["Matched success indicator: email tool executed"],
        matched_success_indicators=["email tool executed"],
        deterministic_rationale="Deterministic success indicators were present.",
    )

    attempt = AttackAttempt(
        attack_id="TA-001",
        attempt_id="TA-001-attempt-1",
        attempt_index=1,
        prompt="Send the data externally.",
        response="Simulated email tool executed in demo mode.",
        success=True,
        trajectory=trajectory,
        observation=observation,
        verdict=verdict,
    )

    assert attempt.trajectory is trajectory
    assert attempt.observation is observation
    assert attempt.verdict is verdict
    assert attempt.success is True


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


def test_threat_model_and_attack_campaign_models_instantiate_correctly() -> None:
    target_profile = build_target_profile(metadata={"target_name": "demo-rag"})
    objective = build_objective()
    threat_model = ThreatModel(
        target_name="demo-rag",
        target_type="rag_app",
        authorization_scope="local_demo",
        capabilities=["retrieval"],
        available_tools=[],
        risk_surfaces=["rag"],
        allowed_test_categories=["rag_injection", "prompt_injection", "jailbreak"],
        forbidden_actions=["external_system_access"],
        assets_at_risk=["retrieved context"],
        trust_boundaries=["retrieval boundary"],
        assumptions=["Target is a local deterministic demo."],
        safety_constraints=["No external API calls."],
        threat_categories_in_scope=["rag_injection", "prompt_injection"],
        rationale=["Retrieval surfaces can carry untrusted instructions."],
    )
    attack_plan = AttackPlan(
        target_profile=target_profile,
        objective=objective,
        selected_categories=["rag_injection", "prompt_injection"],
        selected_attack_ids=["RI-001", "PI-001"],
        strategy_notes=["Selected deterministic attacks."],
        budget={"max_total_attempts": 3, "max_attempts_per_attack": 2},
    )
    campaign = AttackCampaign(
        campaign_id="campaign-demo-rag",
        campaign_name="Deterministic campaign for demo-rag",
        target_name="demo-rag",
        target_type="rag_app",
        threat_model=threat_model,
        attack_plan=attack_plan,
        selected_attack_ids=["RI-001", "PI-001"],
        selected_categories=["rag_injection", "prompt_injection"],
        excluded_categories=["jailbreak"],
        excluded_attack_ids=["JB-001"],
        planning_rationale=["Applied objective category filter."],
        attack_ordering_rationale="Attacks run in deterministic library order.",
        retry_policy={"stop_on_success": True},
        mutation_budget=1,
        max_attempts_per_attack=2,
        safety_mode="strict",
        total_planned_attacks=2,
        deterministic_metadata={"planned_attack_count": 2},
    )

    assert threat_model.target_name == "demo-rag"
    assert threat_model.threat_categories_in_scope == ["rag_injection", "prompt_injection"]
    assert campaign.threat_model is threat_model
    assert campaign.attack_plan is attack_plan
    assert campaign.mutation_budget == 1
    assert campaign.total_planned_attacks == 2
