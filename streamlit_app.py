"""Root Streamlit entrypoint for the SecurityScanAgent demo workflow."""

from __future__ import annotations

import json
from pathlib import Path

from llm_guardian.env import load_local_dotenv
from llm_guardian.models import SecurityScanResult, Severity
from llm_guardian.scenario_generation import (
    FakeScenarioLLMProvider,
    GroqScenarioLLMProvider,
    ProviderConfigurationError,
    build_target_profile_summary,
    generate_attack_scenarios,
    write_generated_scenarios_yaml,
)
from llm_guardian.security_agent.agent import SecurityScanAgent

load_local_dotenv()

try:
    import streamlit as st
except ImportError as exc:  # pragma: no cover - exercised by environment smoke check instead
    raise RuntimeError(
        "Streamlit is required to run this UI. Install the project dependencies first."
    ) from exc


DEFAULT_TARGET = "demo-vulnerable-rag"
DEFAULT_OUTPUT_DIR = Path("reports") / "streamlit_scan"
DEFAULT_GENERATED_SCENARIOS_PATH = (
    Path("reports") / "streamlit_generated" / "generated_attack_scenarios.yaml"
)


def run_streamlit_scenario_generation(
    target_name: str,
    count: int,
    provider_name: str,
    output_path: Path,
    api_key: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
):
    """Generate optional attack scenarios for the Streamlit demo."""

    if provider_name == "fake":
        provider = FakeScenarioLLMProvider()
    elif provider_name == "groq":
        provider = GroqScenarioLLMProvider(
            api_key=api_key,
            model=model or "llama-3.3-70b-versatile",
            base_url=base_url or "https://api.groq.com/openai/v1",
        )
    else:
        raise ValueError(f"Unsupported scenario provider '{provider_name}'.")

    result = generate_attack_scenarios(
        target_name=target_name,
        target_profile_summary=build_target_profile_summary(target_name),
        provider=provider,
        count=count,
    )
    provider_model = "fake-deterministic" if provider_name == "fake" else provider.model
    write_generated_scenarios_yaml(
        result.accepted_scenarios,
        output_path,
        metadata={
            "target_name": target_name,
            "provider": provider_name,
            "model": provider_model,
            "requested_count": count,
            "accepted_count": len(result.accepted_scenarios),
        },
    )
    return result


def run_streamlit_scan(
    target_name: str,
    output_dir: Path,
    scenario_file: Path | None = None,
) -> SecurityScanResult:
    """Run the same SecurityScanAgent workflow used by the CLI."""

    agent = SecurityScanAgent()
    if scenario_file is None:
        return agent.run(target_name=target_name, output_dir=output_dir)
    return agent.run(
        target_name=target_name,
        output_dir=output_dir,
        scenario_file=scenario_file,
    )


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

    st.session_state.setdefault("generated_scenarios_result", None)
    st.session_state.setdefault("latest_streamlit_scan_result", None)
    st.session_state.setdefault("latest_streamlit_trajectory_payload", None)
    st.session_state.setdefault("latest_streamlit_report_markdown", None)

    generator_tab, scan_tab = st.tabs(["Scenario Generator", "Security Scan"])

    with generator_tab:
        generator_target = st.selectbox("Target", options=[DEFAULT_TARGET], index=0, key="generator_target")
        generator_columns = st.columns(3)
        with generator_columns[0]:
            scenario_count = int(
                st.number_input("Scenario count", min_value=1, value=2, step=1, key="scenario_count")
            )
        with generator_columns[1]:
            provider_name = st.selectbox(
                "Provider",
                options=["fake", "groq"],
                index=0,
                key="scenario_provider",
            )
        with generator_columns[2]:
            generated_output_path = st.text_input(
                "Generated scenario file",
                value=str(DEFAULT_GENERATED_SCENARIOS_PATH),
                key="generated_output_path",
            )
        groq_api_key = ""
        groq_model = "llama-3.3-70b-versatile"
        groq_base_url = "https://api.groq.com/openai/v1"
        if provider_name == "groq":
            st.caption("API key is used only for this run and is not saved.")
            groq_api_key = st.text_input("Groq API key", type="password", key="groq_api_key")
            groq_model = st.text_input(
                "Groq model",
                value="llama-3.3-70b-versatile",
                key="groq_model",
            )
            groq_base_url = st.text_input(
                "Groq base URL",
                value="https://api.groq.com/openai/v1",
                key="groq_base_url",
            )

        if st.button("Generate Scenarios", type="primary"):
            try:
                with st.spinner("Generating optional attack scenarios..."):
                    result = run_streamlit_scenario_generation(
                        target_name=generator_target,
                        count=scenario_count,
                        provider_name=provider_name,
                        output_path=Path(generated_output_path),
                        api_key=groq_api_key,
                        model=groq_model,
                        base_url=groq_base_url,
                    )
                st.session_state["generated_scenarios_result"] = result
                st.success(f"Saved {len(result.accepted_scenarios)} scenarios to {generated_output_path}")
            except (ProviderConfigurationError, RuntimeError, ValueError) as exc:
                st.error(str(exc))

        generated_result = st.session_state["generated_scenarios_result"]
        if generated_result is not None:
            st.caption(
                "Generated scenarios are target-aware for the selected demo target and can be run from the Security Scan tab."
            )
            st.subheader("Accepted Scenarios")
            st.dataframe(
                [scenario.model_dump(mode="python") for scenario in generated_result.accepted_scenarios],
                use_container_width=True,
                hide_index=True,
            )
            if generated_result.rejected_scenarios:
                st.subheader("Rejected Scenarios")
                st.dataframe(
                    generated_result.rejected_scenarios,
                    use_container_width=True,
                    hide_index=True,
                )
            if generated_result.validation_errors:
                st.subheader("Validation Errors")
                for error in generated_result.validation_errors:
                    st.write(f"- {error}")

    with scan_tab:
        selected_target = st.selectbox("Target", options=[DEFAULT_TARGET], index=0, key="scan_target")
        output_dir_input = st.text_input("Output directory", value=str(DEFAULT_OUTPUT_DIR), key="scan_output_dir")
        scenario_source_mode = st.radio(
            "Scenario source",
            options=("use default scenarios", "use generated scenarios if available"),
            index=0,
            key="scenario_source_mode",
        )

        if st.button("Run Security Scan", type="primary", key="run_scan"):
            output_dir = Path(output_dir_input)
            scenario_file = None
            if scenario_source_mode == "use generated scenarios if available":
                candidate_path = Path(st.session_state.get("generated_output_path", str(DEFAULT_GENERATED_SCENARIOS_PATH)))
                if candidate_path.exists():
                    scenario_file = candidate_path

            with st.spinner("Running SecurityScanAgent..."):
                scan_result = run_streamlit_scan(
                    target_name=selected_target,
                    output_dir=output_dir,
                    scenario_file=scenario_file,
                )
                trajectory_payload, report_markdown = _read_output_artifacts(output_dir)

            st.session_state["latest_streamlit_scan_result"] = scan_result
            st.session_state["latest_streamlit_trajectory_payload"] = trajectory_payload
            st.session_state["latest_streamlit_report_markdown"] = report_markdown

        scan_result = st.session_state["latest_streamlit_scan_result"]
        trajectory_payload = st.session_state["latest_streamlit_trajectory_payload"]
        report_markdown = st.session_state["latest_streamlit_report_markdown"]
        if scan_result is None or trajectory_payload is None or report_markdown is None:
            st.info("Run a scan to view the plan, trace, findings, and generated artifacts.")
            return

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
                st.write(f"**scenario_source:** {scan_result.agent_plan.scenario_source}")
                if scan_result.agent_plan.generated_scenario_count is not None:
                    st.write(
                        f"**generated_scenario_count:** {scan_result.agent_plan.generated_scenario_count}"
                    )
                if scan_result.agent_plan.scenario_provider is not None:
                    st.write(f"**scenario_provider:** {scan_result.agent_plan.scenario_provider}")
                if scan_result.agent_plan.scenario_model is not None:
                    st.write(f"**scenario_model:** {scan_result.agent_plan.scenario_model}")
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
