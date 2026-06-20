from llm_guardian.models import AttackCategory, AttackResult, Severity
from llm_guardian.reports.scoring import ScoringEngine


def build_result(
    *,
    attack_id: str,
    category: AttackCategory,
    severity: Severity,
    success: bool,
    recommendation: str = "Apply a deterministic mitigation.",
) -> AttackResult:
    return AttackResult(
        attack_id=attack_id,
        category=category,
        severity=severity,
        title=f"{attack_id} title",
        target_name="customer_support",
        prompt=f"Prompt for {attack_id}",
        response=f"Response for {attack_id}",
        success=success,
        evidence=[f"Evidence for {attack_id}"],
        recommendation=recommendation,
    )


def test_scoring_engine_uses_severity_weighted_successful_attacks_only() -> None:
    results = [
        build_result(
            attack_id="LOW-FAIL",
            category=AttackCategory.PROMPT_INJECTION,
            severity=Severity.LOW,
            success=False,
        ),
        build_result(
            attack_id="HIGH-SUCCESS",
            category=AttackCategory.PROMPT_INJECTION,
            severity=Severity.HIGH,
            success=True,
        ),
        build_result(
            attack_id="CRITICAL-SUCCESS",
            category=AttackCategory.TOOL_ABUSE,
            severity=Severity.CRITICAL,
            success=True,
        ),
    ]

    score = ScoringEngine().score(results)

    assert score.risk_score == 9.44
    assert score.risk_level == "critical"


def test_scoring_engine_applies_risk_level_thresholds() -> None:
    engine = ScoringEngine()

    assert engine.risk_level_for_score(0.0) == "none"
    assert engine.risk_level_for_score(2.99) == "low"
    assert engine.risk_level_for_score(3.0) == "medium"
    assert engine.risk_level_for_score(5.99) == "medium"
    assert engine.risk_level_for_score(6.0) == "high"
    assert engine.risk_level_for_score(7.99) == "high"
    assert engine.risk_level_for_score(8.0) == "critical"


def test_scoring_engine_builds_category_summary() -> None:
    results = [
        build_result(
            attack_id="PI-001",
            category=AttackCategory.PROMPT_INJECTION,
            severity=Severity.HIGH,
            success=True,
            recommendation="Enforce instruction hierarchy.",
        ),
        build_result(
            attack_id="PI-002",
            category=AttackCategory.PROMPT_INJECTION,
            severity=Severity.MEDIUM,
            success=False,
            recommendation="Enforce instruction hierarchy.",
        ),
        build_result(
            attack_id="TA-001",
            category=AttackCategory.TOOL_ABUSE,
            severity=Severity.CRITICAL,
            success=False,
            recommendation="Require approval for external actions.",
        ),
    ]

    summaries = ScoringEngine().build_category_summary(results)

    assert [summary.category for summary in summaries] == [
        AttackCategory.PROMPT_INJECTION,
        AttackCategory.TOOL_ABUSE,
    ]
    assert summaries[0].total_attacks == 2
    assert summaries[0].successful_attacks == 1
    assert summaries[0].success_rate == 0.5
    assert summaries[0].max_severity_seen == Severity.HIGH
    assert summaries[0].recommendations == ["Enforce instruction hierarchy."]
    assert summaries[1].total_attacks == 1
    assert summaries[1].successful_attacks == 0
    assert summaries[1].success_rate == 0.0
    assert summaries[1].max_severity_seen == Severity.CRITICAL
