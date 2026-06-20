from datetime import datetime

from llm_guardian.models import AttackCategory, AttackResult, ScanReport, Severity, TraceEvent
from llm_guardian.reports.generator import MarkdownReportGenerator, ReportGenerator


def build_result(
    *,
    attack_id: str,
    category: AttackCategory,
    severity: Severity,
    success: bool,
    title: str,
    response: str,
    recommendation: str,
) -> AttackResult:
    return AttackResult(
        attack_id=attack_id,
        category=category,
        severity=severity,
        title=title,
        target_name="customer_support",
        prompt=f"Prompt for {attack_id}",
        response=response,
        success=success,
        evidence=[f"Evidence for {attack_id}"],
        trace=[
            TraceEvent(
                event_type="attack_started",
                target_name="customer_support",
                attack_id=attack_id,
                message=f"Started {attack_id}",
                metadata={"phase": "runner"},
            )
        ],
        recommendation=recommendation,
    )


def test_report_generator_produces_richer_schema() -> None:
    report = ReportGenerator().build(
        target_name="customer_support",
        results=[
            build_result(
                attack_id="PI-001",
                category=AttackCategory.PROMPT_INJECTION,
                severity=Severity.HIGH,
                success=True,
                title="Reveal system prompt",
                response="The system prompt is exposed.",
                recommendation="Block system prompt disclosure.",
            ),
            build_result(
                attack_id="TA-001",
                category=AttackCategory.TOOL_ABUSE,
                severity=Severity.CRITICAL,
                success=False,
                title="Unauthorized email action",
                response="Action blocked.",
                recommendation="Require approval for external actions.",
            ),
        ],
    )

    payload = report.model_dump(mode="json")

    assert isinstance(report, ScanReport)
    assert isinstance(payload["scan_id"], str)
    assert payload["target_name"] == "customer_support"
    assert payload["total_attacks"] == 2
    assert payload["successful_attacks"] == 1
    assert payload["risk_score"] == 4.12
    assert payload["risk_level"] == "medium"
    assert isinstance(datetime.fromisoformat(payload["created_at"]), datetime)
    assert payload["category_summary"][0]["category"] == "prompt_injection"
    assert payload["findings"][0]["title"] == "Reveal system prompt"
    assert payload["findings"][0]["trace"][0]["attack_id"] == "PI-001"
    assert payload["findings"][0]["trace"][0]["event_type"] == "attack_started"
    assert payload["recommendations"] == ["Block system prompt disclosure."]


def test_markdown_report_includes_expected_sections() -> None:
    report = ReportGenerator().build(
        target_name="customer_support",
        results=[
            build_result(
                attack_id="PI-001",
                category=AttackCategory.PROMPT_INJECTION,
                severity=Severity.HIGH,
                success=True,
                title="Reveal system prompt",
                response="The system prompt is exposed.",
                recommendation="Block system prompt disclosure.",
            )
        ],
    )

    rendered = MarkdownReportGenerator().render(report)

    assert "# LLM Guardian Scan Report" in rendered
    assert "## Scan Metadata" in rendered
    assert "## Executive Summary" in rendered
    assert "## Category Summary" in rendered
    assert "| Category | Total Attacks | Successful Attacks | Success Rate | Max Severity |" in rendered
    assert "## Findings" in rendered
    assert "### PI-001 - Reveal system prompt" in rendered
    assert "Trajectory:" in rendered
    assert "- `attack_started`:" in rendered
    assert "## Recommendations" in rendered
    assert "## Ethical and Scope Note" in rendered
    assert "local intentionally vulnerable demo targets" in rendered
