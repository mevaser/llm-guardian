from __future__ import annotations

import json
from pathlib import Path

from llm_guardian.models import SecurityScanResult, Severity
from llm_guardian.security_agent.agent import SecurityScanAgent


def test_security_scan_agent_runs_demo_vulnerable_rag_end_to_end(tmp_path: Path) -> None:
    output_dir = tmp_path / "demo-scan"

    result = SecurityScanAgent().run(
        target_name="demo-vulnerable-rag",
        output_dir=output_dir,
    )

    assert isinstance(result, SecurityScanResult)
    assert len(result.scenario_results) == 8
    assert result.agent_plan is not None
    assert result.agent_plan.target_name == "demo-vulnerable-rag"
    assert result.agent_plan.scenario_count == 8
    assert len(result.agent_plan.selected_scenario_ids) == 8
    assert result.adaptive_probes
    assert {step.phase for step in result.agent_trace} >= {
        "plan",
        "execute",
        "observe",
        "evaluate",
        "adapt",
        "report",
    }

    failed_findings = [finding for finding in result.findings if finding.verdict == "fail"]
    critical_findings = [
        finding
        for finding in failed_findings
        if finding.severity == Severity.CRITICAL
    ]

    assert len(failed_findings) == 2
    assert len(critical_findings) == 2

    trajectory_path = output_dir / "trajectory.json"
    report_path = output_dir / "scan_report.md"
    assert trajectory_path.exists()
    assert report_path.exists()

    trajectory_payload = json.loads(trajectory_path.read_text(encoding="utf-8"))
    assert trajectory_payload["target_name"] == "demo-vulnerable-rag"
    assert len(trajectory_payload["scenarios"]) == 8
    assert trajectory_payload["agent_plan"]["scenario_count"] == 8
    assert trajectory_payload["agent_trace"]
    assert trajectory_payload["adaptive_probes"]

    report_text = report_path.read_text(encoding="utf-8")
    assert "# LLM Guardian Security Scan Report" in report_text
    assert "## Agent Plan" in report_text
    assert "## Agent Execution Trace" in report_text
    assert "## Adaptive Probes" in report_text
