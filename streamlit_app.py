"""Root Streamlit entrypoint for the SecurityScanAgent demo workflow."""

from __future__ import annotations

import json
from pathlib import Path

from llm_guardian.models import SecurityScanResult, Severity
from llm_guardian.security_agent.agent import SecurityScanAgent

try:
    import streamlit as st
except ImportError as exc:  # pragma: no cover - exercised by environment smoke check instead
    raise RuntimeError(
        "Streamlit is required to run this UI. Install the project dependencies first."
    ) from exc


DEFAULT_TARGET = "demo-vulnerable-rag"
DEFAULT_OUTPUT_DIR = Path("reports") / "streamlit_scan"


def run_streamlit_scan(target_name: str, output_dir: Path) -> SecurityScanResult:
    """Run the same SecurityScanAgent workflow used by the CLI."""

    agent = SecurityScanAgent()
    return agent.run(target_name=target_name, output_dir=output_dir)


def _build_summary_metrics(scan_result: SecurityScanResult) -> dict[str, int | str]:
    passed = sum(1 for finding in scan_result.findings if finding.verdict == "pass")
    failed = len(scan_result.findings) - passed
    critical = sum(
        1
        for finding in scan_result.findings
        if finding.verdict == "fail" and finding.severity == Severity.CRITICAL
    )
    overall_risk = _calculate_overall_risk(scan_result)
    return {
        "Target": scan_result.target_name,
        "Scenarios tested": len(scan_result.findings),
        "Adaptive probes": len(scan_result.adaptive_probes),
        "Passed": passed,
        "Failed": failed,
        "Critical": critical,
        "Overall Risk": overall_risk,
    }


def _calculate_overall_risk(scan_result: SecurityScanResult) -> str:
    failed_severities = {
        finding.severity
        for finding in scan_result.findings
        if finding.verdict == "fail"
    }
    if Severity.CRITICAL in failed_severities:
        return "CRITICAL"
    if Severity.HIGH in failed_severities:
        return "HIGH"
    if Severity.MEDIUM in failed_severities:
        return "MEDIUM"
    return "LOW"


def _build_trace_rows(scan_result: SecurityScanResult) -> list[dict[str, str | int | None]]:
    return [
        {
            "step": trace_step.step,
            "phase": trace_step.phase,
            "scenario_id": trace_step.scenario_id,
            "action": trace_step.action,
            "observation": trace_step.observation,
            "decision": trace_step.decision,
            "evidence": trace_step.evidence,
        }
        for trace_step in scan_result.agent_trace
    ]


def _build_failed_findings_rows(scan_result: SecurityScanResult) -> list[dict[str, str]]:
    return [
        {
            "scenario_id": finding.scenario_id,
            "category": finding.category,
            "severity": finding.severity.value,
            "verdict": finding.verdict,
            "reason": finding.reason,
            "evidence": finding.evidence,
        }
        for finding in scan_result.findings
        if finding.verdict == "fail"
    ]


def _build_adaptive_probe_rows(scan_result: SecurityScanResult) -> list[dict[str, str]]:
    return [
        {
            "probe_id": adaptive_probe.probe_id,
            "source_scenario_id": adaptive_probe.trigger_scenario_id,
            "trigger": adaptive_probe.category,
            "action": "record_adaptive_follow_up_probe",
            "observation": adaptive_probe.observation,
            "decision": adaptive_probe.status,
            "recommendation": adaptive_probe.recommendation,
        }
        for adaptive_probe in scan_result.adaptive_probes
    ]


def _read_output_artifacts(output_dir: Path) -> tuple[dict[str, object], str]:
    trajectory_path = output_dir / "trajectory.json"
    report_path = output_dir / "scan_report.md"
    trajectory_payload = json.loads(trajectory_path.read_text(encoding="utf-8"))
    report_markdown = report_path.read_text(encoding="utf-8")
    return trajectory_payload, report_markdown


def main() -> None:
    st.set_page_config(
        page_title="LLM Guardian - AI Agent Security Evaluator",
        layout="wide",
    )
    st.title("LLM Guardian — AI Agent Security Evaluator")
    st.write(
        "SecurityScanAgent is the deterministic security evaluator used by the CLI and this "
        "Streamlit UI. The app runs the same agent workflow, then displays the resulting plan, "
        "trace, findings, adaptive probes, trajectory JSON, and Markdown report."
    )

    selected_target = st.selectbox("Target", options=[DEFAULT_TARGET], index=0)
    output_dir_input = st.text_input("Output directory", value=str(DEFAULT_OUTPUT_DIR))

    if st.button("Run Security Scan", type="primary"):
        output_dir = Path(output_dir_input)
        with st.spinner("Running SecurityScanAgent..."):
            scan_result = run_streamlit_scan(
                target_name=selected_target,
                output_dir=output_dir,
            )
            trajectory_payload, report_markdown = _read_output_artifacts(output_dir)

        summary_metrics = _build_summary_metrics(scan_result)
        metric_columns = st.columns(7)
        metric_labels = list(summary_metrics)
        for index, label in enumerate(metric_labels):
            metric_columns[index].metric(label, str(summary_metrics[label]))

        tabs = st.tabs(
            [
                "Executive Summary",
                "Agent Plan",
                "Agent Trace",
                "Findings",
                "Adaptive Probes",
                "Trajectory JSON",
                "Markdown Report",
            ]
        )

        with tabs[0]:
            st.subheader("Executive Summary")
            for label, value in summary_metrics.items():
                st.write(f"**{label}:** {value}")

        with tabs[1]:
            st.subheader("Agent Plan")
            if scan_result.agent_plan is None:
                st.info("No agent plan was recorded.")
            else:
                st.write(f"**target_name:** {scan_result.agent_plan.target_name}")
                st.write(f"**scenario_count:** {scan_result.agent_plan.scenario_count}")
                st.write(
                    "**selected_scenario_ids:** "
                    + ", ".join(scan_result.agent_plan.selected_scenario_ids)
                )
                st.write(f"**rationale:** {scan_result.agent_plan.rationale}")
                st.write(
                    f"**execution_strategy:** {scan_result.agent_plan.execution_strategy}"
                )

        with tabs[2]:
            st.subheader("Agent Trace")
            st.dataframe(_build_trace_rows(scan_result), use_container_width=True, hide_index=True)

        with tabs[3]:
            st.subheader("Findings")
            st.dataframe(
                _build_failed_findings_rows(scan_result),
                use_container_width=True,
                hide_index=True,
            )

        with tabs[4]:
            st.subheader("Adaptive Probes")
            st.dataframe(
                _build_adaptive_probe_rows(scan_result),
                use_container_width=True,
                hide_index=True,
            )

        with tabs[5]:
            st.subheader("Trajectory JSON")
            st.json(trajectory_payload)

        with tabs[6]:
            st.subheader("Markdown Report")
            st.markdown(report_markdown)


if __name__ == "__main__":
    main()
