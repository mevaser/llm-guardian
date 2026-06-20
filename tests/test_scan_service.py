import json

from llm_guardian.attacks.loader import load_attack_library
from llm_guardian.config import DEFAULT_ATTACK_LIBRARY_PATH
from llm_guardian.models import AttackCategory, ScanReport
from llm_guardian.runner.scan_service import (
    render_report_json,
    render_report_markdown,
    run_offline_scan,
)


def test_run_offline_scan_without_category_filter_uses_full_library() -> None:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)

    report = run_offline_scan(target_name="customer_support")

    assert report.total_attacks == len(library.attacks)
    assert len(report.findings) == len(library.attacks)


def test_run_offline_scan_filters_categories_before_execution() -> None:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)
    expected_tool_attacks = [
        attack for attack in library.attacks if attack.category is AttackCategory.TOOL_ABUSE
    ]

    report = run_offline_scan(target_name="tool_agent", categories=[AttackCategory.TOOL_ABUSE])

    assert report.target_name == "tool_agent"
    assert report.total_attacks == len(expected_tool_attacks)
    assert report.category_summary[0].category is AttackCategory.TOOL_ABUSE
    assert all(finding.category is AttackCategory.TOOL_ABUSE for finding in report.findings)


def test_render_report_json_serializes_scan_report() -> None:
    report = run_offline_scan(target_name="customer_support", categories=["prompt_injection"])

    payload = json.loads(render_report_json(report))

    assert ScanReport.model_validate(payload) == report


def test_render_report_markdown_uses_existing_report_generator() -> None:
    report = run_offline_scan(target_name="customer_support", categories=["prompt_injection"])

    rendered = render_report_markdown(report)

    assert "# LLM Guardian Scan Report" in rendered
    assert f"Target: `{report.target_name}`" in rendered
