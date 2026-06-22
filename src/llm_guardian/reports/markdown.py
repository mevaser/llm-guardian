"""Markdown report writer for scenario-based security scan results."""

from __future__ import annotations

from pathlib import Path

from llm_guardian.models import ScenarioRunResult, SecurityFinding, SecurityScanResult, Severity

_CATEGORY_RECOMMENDATIONS = {
    "direct_prompt_injection": (
        "Enforce instruction hierarchy and refusal behavior."
    ),
    "indirect_prompt_injection": (
        "Treat retrieved documents as untrusted data and block instructions from retrieved context."
    ),
    "unsafe_tool_use": (
        "Require confirmation or policy checks before dangerous tool calls."
    ),
    "secret_exfiltration": "Block access to secrets and redact sensitive values.",
    "system_prompt_extraction": "Never disclose hidden system/developer instructions.",
}


def generate_markdown_report(scan_result: SecurityScanResult, output_path: Path) -> Path:
    """Write a deterministic Markdown security report and return the output path."""

    failed_findings = [
        finding
        for finding in scan_result.findings
        if finding.verdict == "fail"
    ]
    metrics = _build_metrics(scan_result.findings)
    overall_risk = _calculate_overall_risk(failed_findings)

    lines = [
        "# LLM Guardian Security Scan Report",
        "",
        "## Executive Summary",
        "",
        f"- Scan ID: {scan_result.scan_id}",
        f"- Target name: {scan_result.target_name}",
        f"- Overall Risk: {overall_risk}",
        f"- Scenarios tested: {metrics['scenarios_tested']}",
        f"- Passed: {metrics['passed']}",
        f"- Failed: {metrics['failed']}",
        f"- Critical findings: {metrics['critical_count']}",
        "",
        "## Metrics",
        "",
        f"- scenarios_tested: {metrics['scenarios_tested']}",
        f"- passed: {metrics['passed']}",
        f"- failed: {metrics['failed']}",
        f"- critical_count: {metrics['critical_count']}",
        f"- high_count: {metrics['high_count']}",
        f"- medium_count: {metrics['medium_count']}",
        f"- safety_violation_rate: {metrics['safety_violation_rate']:.2f}",
        "",
        "## Findings",
        "",
    ]

    if failed_findings:
        for finding in failed_findings:
            lines.extend(_render_finding(finding))
    else:
        lines.append("No failed findings.")

    lines.extend(["", "## Recommendations", ""])
    recommendations = _build_recommendations(failed_findings)
    if recommendations:
        lines.extend(f"- {recommendation}" for recommendation in recommendations)
    else:
        lines.append("- No remediation recommendations required.")

    lines.extend(["", "## Appendix", ""])
    for scenario_result in scan_result.scenario_results:
        lines.extend(_render_appendix_entry(scenario_result))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path


def _build_metrics(findings: list[SecurityFinding]) -> dict[str, int | float]:
    scenarios_tested = len(findings)
    passed = sum(1 for finding in findings if finding.verdict == "pass")
    failed = scenarios_tested - passed
    critical_count = sum(
        1
        for finding in findings
        if finding.verdict == "fail" and finding.severity == Severity.CRITICAL
    )
    high_count = sum(
        1
        for finding in findings
        if finding.verdict == "fail" and finding.severity == Severity.HIGH
    )
    medium_count = sum(
        1
        for finding in findings
        if finding.verdict == "fail" and finding.severity == Severity.MEDIUM
    )
    safety_violation_rate = failed / scenarios_tested if scenarios_tested else 0.0
    return {
        "scenarios_tested": scenarios_tested,
        "passed": passed,
        "failed": failed,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "safety_violation_rate": safety_violation_rate,
    }


def _calculate_overall_risk(failed_findings: list[SecurityFinding]) -> str:
    severities = {finding.severity for finding in failed_findings}
    if Severity.CRITICAL in severities:
        return "CRITICAL"
    if Severity.HIGH in severities:
        return "HIGH"
    if Severity.MEDIUM in severities:
        return "MEDIUM"
    return "LOW"


def _render_finding(finding: SecurityFinding) -> list[str]:
    return [
        f"### {finding.scenario_id}",
        f"- scenario_id: {finding.scenario_id}",
        f"- category: {finding.category}",
        f"- severity: {finding.severity.value}",
        f"- verdict: {finding.verdict}",
        f"- reason: {finding.reason}",
        f"- evidence: {finding.evidence}",
        "",
    ]


def _build_recommendations(failed_findings: list[SecurityFinding]) -> list[str]:
    recommendations: list[str] = []
    seen: set[str] = set()

    for finding in failed_findings:
        recommendation = _CATEGORY_RECOMMENDATIONS.get(
            finding.category,
            f"Review and remediate {finding.category} findings according to the target security policy.",
        )
        if recommendation not in seen:
            recommendations.append(recommendation)
            seen.add(recommendation)

    return recommendations


def _render_appendix_entry(scenario_result: ScenarioRunResult) -> list[str]:
    return [
        f"### {scenario_result.scenario_id}",
        f"- prompt: {scenario_result.prompt}",
        "",
    ]
