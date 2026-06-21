from llm_guardian.security_agent.models import SecurityTestObjective, TargetProfile
from llm_guardian.security_agent.planner import AttackPlanner


def build_target_profile(
    *,
    target_type: str,
    capabilities: list[str] | None = None,
    risk_surfaces: list[str] | None = None,
    allowed_categories: list[str] | None = None,
) -> TargetProfile:
    return TargetProfile(
        target_type=target_type,
        capabilities=capabilities or [],
        risk_surfaces=risk_surfaces or [],
        allowed_categories=allowed_categories or [],
        authorization_scope="local_demo",
        metadata={},
    )


def build_objective(
    *,
    allowed_categories: list[str] | None = None,
    max_total_attempts: int = 10,
) -> SecurityTestObjective:
    return SecurityTestObjective(
        goal="Exercise the deterministic planner.",
        allowed_categories=allowed_categories or [],
        max_attempts_per_attack=2,
        max_total_attempts=max_total_attempts,
        safety_mode="strict",
        stop_on_success=True,
    )


def test_rag_app_selects_expected_categories() -> None:
    planner = AttackPlanner()
    attack_metadata = [
        {"id": "RI-001", "category": "rag_injection"},
        {"id": "PI-001", "category": "prompt_injection"},
        {"id": "JB-001", "category": "jailbreak"},
    ]

    plan = planner.plan(
        target_profile=build_target_profile(target_type="rag_app"),
        objective=build_objective(),
        attack_library=attack_metadata,
    )

    assert plan.selected_categories == ["rag_injection", "prompt_injection", "jailbreak"]


def test_tool_using_agent_selects_expected_categories() -> None:
    planner = AttackPlanner()
    attack_metadata = [
        {"id": "TA-001", "category": "tool_abuse"},
        {"id": "PI-001", "category": "prompt_injection"},
        {"id": "JB-001", "category": "jailbreak"},
    ]

    plan = planner.plan(
        target_profile=build_target_profile(target_type="tool_using_agent"),
        objective=build_objective(),
        attack_library=attack_metadata,
    )

    assert plan.selected_categories == ["tool_abuse", "prompt_injection", "jailbreak"]


def test_memory_agent_selects_expected_categories() -> None:
    planner = AttackPlanner()
    attack_metadata = [
        {"id": "MP-001", "category": "memory_poisoning"},
        {"id": "PI-001", "category": "prompt_injection"},
        {"id": "JB-001", "category": "jailbreak"},
    ]

    plan = planner.plan(
        target_profile=build_target_profile(target_type="memory_agent"),
        objective=build_objective(),
        attack_library=attack_metadata,
    )

    assert plan.selected_categories == ["memory_poisoning", "prompt_injection", "jailbreak"]


def test_generic_chatbot_selects_expected_categories_only() -> None:
    planner = AttackPlanner()
    attack_metadata = [
        {"id": "PI-001", "category": "prompt_injection"},
        {"id": "JB-001", "category": "jailbreak"},
        {"id": "RI-001", "category": "rag_injection"},
    ]

    plan = planner.plan(
        target_profile=build_target_profile(target_type="generic_chatbot"),
        objective=build_objective(),
        attack_library=attack_metadata,
    )

    assert plan.selected_categories == ["prompt_injection", "jailbreak"]


def test_allowed_categories_filter_selected_categories() -> None:
    planner = AttackPlanner()
    attack_metadata = [
        {"id": "RI-001", "category": "rag_injection"},
        {"id": "PI-001", "category": "prompt_injection"},
        {"id": "JB-001", "category": "jailbreak"},
    ]

    plan = planner.plan(
        target_profile=build_target_profile(target_type="rag_app"),
        objective=build_objective(allowed_categories=["prompt_injection"]),
        attack_library=attack_metadata,
    )

    assert plan.selected_categories == ["prompt_injection"]
    assert plan.selected_attack_ids == ["PI-001"]


def test_max_total_attempts_limits_selected_attack_ids() -> None:
    planner = AttackPlanner()
    attack_metadata = [
        {"id": "PI-001", "category": "prompt_injection"},
        {"id": "PI-002", "category": "prompt_injection"},
        {"id": "JB-001", "category": "jailbreak"},
    ]

    plan = planner.plan(
        target_profile=build_target_profile(target_type="generic_chatbot"),
        objective=build_objective(max_total_attempts=2),
        attack_library=attack_metadata,
    )

    assert plan.selected_attack_ids == ["PI-001", "PI-002"]


def test_attack_planner_is_deterministic() -> None:
    planner = AttackPlanner()
    attack_metadata = [
        {"id": "TA-001", "category": "tool_abuse"},
        {"id": "PI-001", "category": "prompt_injection"},
        {"id": "JB-001", "category": "jailbreak"},
    ]
    target_profile = build_target_profile(target_type="tool_using_agent", capabilities=["tools"])
    objective = build_objective()

    first = planner.plan(
        target_profile=target_profile,
        objective=objective,
        attack_library=attack_metadata,
    )
    second = planner.plan(
        target_profile=target_profile,
        objective=objective,
        attack_library=attack_metadata,
    )

    assert first == second


def test_attack_planner_reads_simple_dict_attack_metadata() -> None:
    planner = AttackPlanner()
    attack_metadata = [
        {"attack_id": "TA-001", "category": "tool_abuse"},
        {"attack_id": "PI-001", "category": "prompt_injection"},
        {"attack_id": "JB-001", "category": "jailbreak"},
    ]

    plan = planner.plan(
        target_profile=build_target_profile(target_type="tool_using_agent", capabilities=["tools"]),
        objective=build_objective(),
        attack_library=attack_metadata,
    )

    assert plan.selected_attack_ids == ["TA-001", "PI-001", "JB-001"]


def test_attack_planner_ignores_categories_not_present_in_attack_metadata() -> None:
    planner = AttackPlanner()
    attack_metadata = [
        {"id": "PI-001", "category": "prompt_injection"},
    ]

    plan = planner.plan(
        target_profile=build_target_profile(target_type="rag_app", capabilities=["retrieval"]),
        objective=build_objective(),
        attack_library=attack_metadata,
    )

    assert plan.selected_categories == ["prompt_injection"]
    assert plan.selected_attack_ids == ["PI-001"]


def test_attack_planner_includes_strategy_notes_for_selection_reasons() -> None:
    planner = AttackPlanner()
    attack_metadata = [
        {"id": "RI-001", "category": "rag_injection"},
        {"id": "PI-001", "category": "prompt_injection"},
        {"id": "JB-001", "category": "jailbreak"},
    ]

    plan = planner.plan(
        target_profile=build_target_profile(
            target_type="generic_chatbot",
            capabilities=["retrieval"],
            risk_surfaces=["rag"],
        ),
        objective=build_objective(),
        attack_library=attack_metadata,
    )

    assert any("target type" in note.lower() for note in plan.strategy_notes)
    assert any("capabilities" in note.lower() or "risk surfaces" in note.lower() for note in plan.strategy_notes)
