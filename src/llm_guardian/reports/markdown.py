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
        f"- Adaptive probes: {len(scan_result.adaptive_probes)}",
        f"- Passed: {metrics['passed']}",
        f"- Failed: {metrics['failed']}",
        f"- Critical findings: {metrics['critical_count']}",
        "",
        "## Metrics",
        "",
        f"- scenarios_tested: {metrics['scenarios_tested']}",
        f"- adaptive_probes: {len(scan_result.adaptive_probes)}",
        f"- passed: {metrics['passed']}",
        f"- failed: {metrics['failed']}",
        f"- critical_count: {metrics['critical_count']}",
        f"- high_count: {metrics['high_count']}",
        f"- medium_count: {metrics['medium_count']}",
        f"- safety_violation_rate: {metrics['safety_violation_rate']:.2f}",
        "",
        "## Agent Plan",
        "",
    ]

    if scan_result.agent_plan is None:
        lines.append("No agent plan was recorded.")
    else:
        lines.extend(
            [
                f"- target_name: {scan_result.agent_plan.target_name}",
                f"- scenario_count: {scan_result.agent_plan.scenario_count}",
                f"- selected_scenario_ids: {', '.join(scan_result.agent_plan.selected_scenario_ids)}",
                f"- scenario_source: {scan_result.agent_plan.scenario_source}",
                f"- rationale: {scan_result.agent_plan.rationale}",
                f"- execution_strategy: {scan_result.agent_plan.execution_strategy}",
            ]
        )
        if scan_result.agent_plan.generated_scenario_count is not None:
            lines.append(
                f"- generated_scenario_count: {scan_result.agent_plan.generated_scenario_count}"
            )
        if scan_result.agent_plan.scenario_provider is not None:
            lines.append(f"- scenario_provider: {scan_result.agent_plan.scenario_provider}")
        if scan_result.agent_plan.scenario_model is not None:
            lines.append(f"- scenario_model: {scan_result.agent_plan.scenario_model}")

    lines.extend(["", "## Agent Execution Trace", ""])
    if scan_result.agent_trace:
        for trace_step in scan_result.agent_trace:
            lines.extend(_render_agent_trace_step(trace_step))
    else:
        lines.append("No agent execution trace was recorded.")

    lines.extend(["", "## Adaptive Probes", ""])
    if scan_result.adaptive_probes:
        for adaptive_probe in scan_result.adaptive_probes:
            lines.extend(_render_adaptive_probe(adaptive_probe))
    else:
        lines.append("No adaptive probes were required.")

    lines.extend([
        "",
        "## Findings",
        "",
    ])

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

    while lines and lines[-1] == "":
        lines.pop()

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


def _render_agent_trace_step(trace_step) -> list[str]:
    lines = [
        f"### Step {trace_step.step}",
        f"- phase: {trace_step.phase}",
    ]
    if trace_step.scenario_id is not None:
        lines.append(f"- scenario_id: {trace_step.scenario_id}")
    lines.extend(
        [
            f"- action: {trace_step.action}",
            f"- observation: {trace_step.observation}",
            f"- decision: {trace_step.decision}",
        ]
    )
    if trace_step.evidence is not None:
        lines.append(f"- evidence: {trace_step.evidence}")
    lines.append("")
    return lines


def _render_adaptive_probe(adaptive_probe) -> list[str]:
    return [
        f"### {adaptive_probe.probe_id}",
        f"- trigger_scenario_id: {adaptive_probe.trigger_scenario_id}",
        f"- category: {adaptive_probe.category}",
        f"- status: {adaptive_probe.status}",
        f"- observation: {adaptive_probe.observation}",
        f"- recommendation: {adaptive_probe.recommendation}",
        f"- evidence: {adaptive_probe.evidence}",
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

    for adaptive_probe in failed_findings:
        if adaptive_probe.category != "unsafe_tool_use":
            continue
        probe_recommendation = "Add tool-call gating before any outbound email or export action."
        if probe_recommendation not in seen:
            recommendations.append(probe_recommendation)
            seen.add(probe_recommendation)

    return recommendations


def _render_appendix_entry(scenario_result: ScenarioRunResult) -> list[str]:
    return [
        f"### {scenario_result.scenario_id}",
        f"- prompt: {scenario_result.prompt}",
        "",
    ]
