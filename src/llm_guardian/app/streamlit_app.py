"""Streamlit dashboard for offline LLM Guardian scans."""

from __future__ import annotations

from llm_guardian.attacks.loader import load_attack_library
from llm_guardian.app.security_agent_demo import (
    DEFAULT_MAX_ATTEMPTS_PER_ATTACK,
    DEFAULT_MAX_TOTAL_ATTEMPTS,
    DEFAULT_SECURITY_AGENT_CATEGORY,
    DEFAULT_SECURITY_AGENT_TARGET,
    SecurityAgentDemoData,
    build_attempt_timeline_rows,
    build_security_agent_findings_rows,
    get_default_max_mutations_per_attack,
    run_security_agent_demo_scan,
)
from llm_guardian.app.streamlit_state import (
    LATEST_SCAN_JSON_EXPORT_KEY,
    LATEST_SCAN_MARKDOWN_EXPORT_KEY,
    LATEST_SCAN_REPORT_KEY,
    ensure_session_state,
    store_scan_state,
)
from llm_guardian.config import DEFAULT_ATTACK_LIBRARY_PATH
from llm_guardian.models import AttackResult, ScanReport
from llm_guardian.runner.scan_service import run_offline_scan
from llm_guardian.targets.registry import list_targets

try:
    import streamlit as st
except ImportError as exc:  # pragma: no cover - guarded by optional dependency install
    raise RuntimeError(
        "Streamlit is required to run the dashboard. Install the optional UI dependency first."
    ) from exc


DASHBOARD_TABS = ("Baseline Scan", "Security Agent Demo")


def _load_category_options() -> list[str]:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)
    return sorted({attack.category.value for attack in library.attacks})


def _build_category_rows(report: ScanReport) -> list[dict[str, object]]:
    return [
        {
            "Category": summary.category.value,
            "Total attacks": summary.total_attacks,
            "Successful attacks": summary.successful_attacks,
            "Success rate": f"{summary.success_rate:.0%}",
            "Max severity": summary.max_severity_seen.value,
        }
        for summary in report.category_summary
    ]


def _build_findings_rows(report: ScanReport) -> list[dict[str, object]]:
    return [
        {
            "Attack ID": finding.attack_id,
            "Category": finding.category.value,
            "Severity": finding.severity.value,
            "Success": finding.success,
            "Title": finding.title or "",
            "Response snippet": _response_snippet(finding.response),
        }
        for finding in report.findings
    ]


def _response_snippet(response: str, *, limit: int = 120) -> str:
    compact = " ".join(response.split())
    if len(compact) <= limit:
        return compact
    return f"{compact[: limit - 3]}..."


def _render_finding_details(finding: AttackResult) -> None:
    expander_title = (
        f"{finding.attack_id} | {finding.category.value} | {finding.severity.value} | "
        f"{finding.title or 'Untitled finding'}"
    )
    with st.expander(expander_title):
        st.write(f"**Attack ID:** `{finding.attack_id}`")
        st.write(f"**Category:** `{finding.category.value}`")
        st.write(f"**Severity:** `{finding.severity.value}`")
        st.write(f"**Title:** {finding.title or 'Untitled finding'}")
        st.write("**Prompt:**")
        st.code(finding.prompt, language="text")
        st.write("**Response:**")
        st.code(finding.response, language="text")
        st.write("**Evidence:**")
        if finding.evidence:
            for item in finding.evidence:
                st.write(f"- {item}")
        else:
            st.write("- No evidence captured.")
        st.write("**Trajectory:**")
        if finding.trace:
            for event in finding.trace:
                st.write(
                    f"- `{event.event_type}` | `{event.timestamp.isoformat()}` | {event.message}"
                )
        else:
            st.write("- No trace events captured.")
        st.write(f"**Recommendation:** {finding.recommendation}")


def _render_report(report: ScanReport) -> None:
    st.subheader("Scan Metadata")
    metadata_left, metadata_right = st.columns(2)
    with metadata_left:
        st.write(f"**Target name:** `{report.target_name}`")
        st.write(f"**Risk level:** `{report.risk_level.value}`")
    with metadata_right:
        st.write(f"**Total attacks:** {report.total_attacks}")
        st.write(f"**Successful attacks:** {report.successful_attacks}")

    metrics = st.columns(2)
    metrics[0].metric("Risk score", f"{report.risk_score:.2f}/10.00")
    metrics[1].metric("Risk level", report.risk_level.value)

    st.subheader("Category Summary")
    st.dataframe(_build_category_rows(report), use_container_width=True, hide_index=True)

    st.subheader("Findings")
    st.dataframe(_build_findings_rows(report), use_container_width=True, hide_index=True)

    st.subheader("Finding Details")
    for finding in report.findings:
        _render_finding_details(finding)


def _render_baseline_scan_view(targets: list[str], category_options: list[str]) -> None:
    st.subheader("Baseline Scan")
    control_left, control_right = st.columns(2)
    with control_left:
        target_name = st.selectbox("Target agent", options=targets, index=0, key="baseline_target")
    with control_right:
        selected_categories = st.multiselect(
            "Attack categories",
            options=category_options,
            help="Leave empty to scan all categories.",
            key="baseline_categories",
        )
    run_requested = st.button("Run baseline scan", type="primary", key="baseline_run")

    if run_requested:
        with st.spinner("Running deterministic offline scan..."):
            report = run_offline_scan(
                target_name=target_name,
                categories=selected_categories or None,
            )
        store_scan_state(st.session_state, report)

    report = st.session_state[LATEST_SCAN_REPORT_KEY]
    if report is None:
        st.info("Select a target and optional category filter, then run a scan.")
        return

    _render_report(report)

    json_report = st.session_state[LATEST_SCAN_JSON_EXPORT_KEY]
    markdown_report = st.session_state[LATEST_SCAN_MARKDOWN_EXPORT_KEY]

    download_columns = st.columns(2)
    download_columns[0].download_button(
        "Download JSON report",
        data=json_report,
        file_name=f"{report.scan_id}.json",
        mime="application/json",
        use_container_width=True,
    )
    download_columns[1].download_button(
        "Download Markdown report",
        data=markdown_report,
        file_name=f"{report.scan_id}.md",
        mime="text/markdown",
        use_container_width=True,
    )


def _render_security_agent_demo_view(targets: list[str], category_options: list[str]) -> None:
    st.subheader("Security Agent Demo")
    target_index = (
        targets.index(DEFAULT_SECURITY_AGENT_TARGET)
        if DEFAULT_SECURITY_AGENT_TARGET in targets
        else 0
    )
    default_categories = (
        [DEFAULT_SECURITY_AGENT_CATEGORY]
        if DEFAULT_SECURITY_AGENT_CATEGORY in category_options
        else []
    )

    first_row = st.columns(2)
    with first_row[0]:
        target_name = st.selectbox(
            "Target agent",
            options=targets,
            index=target_index,
            key="security_agent_target",
        )
    with first_row[1]:
        selected_categories = st.multiselect(
            "Attack categories",
            options=category_options,
            default=default_categories,
            key="security_agent_categories",
        )

    default_max_mutations_per_attack = get_default_max_mutations_per_attack(target_name)
    last_target_name = st.session_state.get("security_agent_mutation_target_name")
    if last_target_name != target_name:
        st.session_state["security_agent_max_mutations_per_attack"] = (
            default_max_mutations_per_attack
        )
        st.session_state["security_agent_mutation_target_name"] = target_name

    second_row = st.columns(4)
    with second_row[0]:
        max_total_attempts = st.number_input(
            "Max total attempts",
            min_value=1,
            value=DEFAULT_MAX_TOTAL_ATTEMPTS,
            step=1,
            key="security_agent_max_total_attempts",
        )
    with second_row[1]:
        max_attempts_per_attack = st.number_input(
            "Max attempts per attack",
            min_value=1,
            value=DEFAULT_MAX_ATTEMPTS_PER_ATTACK,
            step=1,
            key="security_agent_max_attempts_per_attack",
        )
    with second_row[2]:
        max_mutations_per_attack = st.number_input(
            "Max mutations per attack",
            min_value=0,
            value=st.session_state["security_agent_max_mutations_per_attack"],
            step=1,
            key="security_agent_max_mutations_per_attack",
        )
    with second_row[3]:
        mutation_strategy_mode = st.selectbox(
            "Mutation strategy mode",
            options=("deterministic", "llm-assisted"),
            index=0,
            key="security_agent_mutation_strategy_mode",
        )

    llm_provider = "fake"
    llm_model = None
    llm_timeout_seconds = 30
    if mutation_strategy_mode == "llm-assisted":
        provider_row = st.columns(3)
        with provider_row[0]:
            llm_provider = st.selectbox(
                "LLM provider",
                options=("fake", "ollama"),
                index=0,
                key="security_agent_llm_provider",
            )
        with provider_row[1]:
            if llm_provider == "ollama":
                llm_model = st.text_input(
                    "Ollama model",
                    value="",
                    placeholder="qwen2.5:7b-instruct",
                    key="security_agent_llm_model",
                )
        with provider_row[2]:
            if llm_provider == "ollama":
                llm_timeout_seconds = int(
                    st.number_input(
                        "LLM timeout (seconds)",
                        min_value=1,
                        value=30,
                        step=1,
                        key="security_agent_llm_timeout_seconds",
                    )
                )

    if st.button("Run Security Agent demo", type="primary", key="security_agent_run"):
        with st.spinner(f"Running {mutation_strategy_mode} SecurityAgent scan..."):
            try:
                st.session_state["security_agent_demo_data"] = run_security_agent_demo_scan(
                    target_name=target_name,
                    categories=selected_categories or [DEFAULT_SECURITY_AGENT_CATEGORY],
                    max_total_attempts=int(max_total_attempts),
                    max_attempts_per_attack=int(max_attempts_per_attack),
                    max_mutations_per_attack=int(max_mutations_per_attack),
                    mutation_strategy_mode=mutation_strategy_mode,
                    llm_provider=llm_provider,
                    llm_model=llm_model,
                    llm_timeout_seconds=llm_timeout_seconds,
                )
            except ValueError as exc:
                st.error(str(exc))

    demo_data = st.session_state.get("security_agent_demo_data")
    if demo_data is None:
        st.info(
            "Run the demo to view the SecurityAgent threat model, campaign, attempts, "
            "and findings."
        )
        return

    _render_security_agent_demo_result(demo_data)


def _render_security_agent_demo_result(demo_data: SecurityAgentDemoData) -> None:
    payload = demo_data.payload
    summary = payload["summary"]
    metric_columns = st.columns(7)
    metric_columns[0].metric("Total attempts", summary["total_attempts"])
    metric_columns[1].metric("Successful", summary["successful_attempts"])
    metric_columns[2].metric("Failed", summary["failed_attempts"])
    metric_columns[3].metric("Skipped/unknown", summary["skipped_or_unknown_attempts"])
    metric_columns[4].metric("Success rate", f"{float(summary['success_rate']):.0%}")
    metric_columns[5].metric("Findings", summary["finding_count"])
    metric_columns[6].metric(
        "Mutations",
        ", ".join(summary["mutation_strategies_used"]) or "none",
    )

    _render_mapping_section(
        "Target Profile",
        payload["target_profile"],
        [
            "target_name",
            "target_type",
            "authorization_scope",
            "safety_mode",
            "available_tools",
            "forbidden_actions",
        ],
    )
    _render_mapping_section(
        "Threat Model",
        payload["threat_model"] or {},
        [
            "assets_at_risk",
            "trust_boundaries",
            "safety_constraints",
            "threat_categories_in_scope",
            "rationale",
        ],
    )
    _render_mapping_section(
        "Attack Campaign",
        payload["attack_campaign"] or {},
        [
            "campaign_id",
            "selected_categories",
            "selected_attack_ids",
            "total_planned_attacks",
            "mutation_budget",
            "retry_policy",
            "planning_rationale",
            "attack_ordering_rationale",
        ],
    )

    st.subheader("Attempt Timeline")
    st.dataframe(build_attempt_timeline_rows(payload), use_container_width=True, hide_index=True)

    st.subheader("Attempt Detail")
    for attempt in payload["attempt_history"]:
        _render_security_agent_attempt_detail(attempt)

    st.subheader("Findings")
    st.dataframe(
        build_security_agent_findings_rows(payload),
        use_container_width=True,
        hide_index=True,
    )

    download_columns = st.columns(2)
    download_columns[0].download_button(
        "Download SecurityAgent JSON",
        data=demo_data.json_report,
        file_name="security-agent-demo.json",
        mime="application/json",
        use_container_width=True,
    )
    download_columns[1].download_button(
        "Download SecurityAgent Markdown",
        data=demo_data.markdown_report,
        file_name="security-agent-demo.md",
        mime="text/markdown",
        use_container_width=True,
    )


def _render_mapping_section(title: str, mapping: dict[str, object], keys: list[str]) -> None:
    st.subheader(title)
    for key in keys:
        value = mapping.get(key)
        label = key.replace("_", " ").title()
        if isinstance(value, list):
            st.write(f"**{label}:** {', '.join(str(item) for item in value) or 'none'}")
        elif isinstance(value, dict):
            st.write(f"**{label}:**")
            st.json(value)
        else:
            st.write(f"**{label}:** `{value}`")


def _render_security_agent_attempt_detail(attempt: dict[str, object]) -> None:
    attempt_id = attempt.get("attempt_id") or (
        f"{attempt.get('attack_id')}-attempt-{attempt.get('attempt_index')}"
    )
    verdict = attempt.get("verdict")
    status = verdict.get("status", "unknown") if isinstance(verdict, dict) else "unknown"
    title = (
        f"{attempt.get('attack_id')} attempt {attempt.get('attempt_index')} | "
        f"{status} | {attempt.get('mutation_strategy') or 'none'}"
    )
    with st.expander(title):
        st.write(f"**Attempt ID:** `{attempt_id}`")
        st.write("**Prompt:**")
        st.code(str(attempt.get("prompt") or ""), language="text")
        st.write("**Response:**")
        st.code(str(attempt.get("response") or ""), language="text")

        trajectory = attempt.get("trajectory")
        st.write("**Trajectory:**")
        if isinstance(trajectory, dict):
            st.write(f"Tool names: `{', '.join(trajectory.get('tool_names', [])) or 'none'}`")
            st.json(
                {
                    "tool_calls": trajectory.get("tool_calls", []),
                    "tool_results": trajectory.get("tool_results", []),
                    "mutation_lineage": trajectory.get("mutation_lineage", {}),
                }
            )
        else:
            st.write("No trajectory captured.")

        st.write("**Observation:**")
        st.json(attempt.get("observation") or {})
        if attempt.get("llm_validation_status") is not None:
            st.write("**LLM mutation:**")
            st.json(
                {
                    "failure_analysis": attempt.get("llm_failure_analysis"),
                    "recommended_strategy": attempt.get("llm_recommended_strategy"),
                    "validation_status": attempt.get("llm_validation_status"),
                    "fallback_used": attempt.get("fallback_used"),
                }
            )
        st.write("**Verdict:**")
        st.json(attempt.get("verdict") or {})
        st.write("**Evidence:**")
        evidence = attempt.get("evidence")
        if isinstance(evidence, list) and evidence:
            for item in evidence:
                st.write(f"- {item}")
        else:
            st.write("- No evidence captured.")


def main() -> None:
    st.set_page_config(page_title="LLM Guardian Dashboard", layout="wide")
    st.title("LLM Guardian")
    st.caption("Offline dashboard for controlled local red-team scans.")
    st.warning(
        "This demo scans only local intentionally vulnerable targets. "
        "It does not test real third-party systems."
    )
    st.info(
        "Looking for Wizard Lab Agent Runs? "
        "Open [http://127.0.0.1:8000/admin](http://127.0.0.1:8000/admin) to view the Wizard Leak Lab Admin Dashboard."
    )
    ensure_session_state(st.session_state)

    targets = list_targets()
    category_options = _load_category_options()

    baseline_tab, security_agent_tab = st.tabs(list(DASHBOARD_TABS))
    with baseline_tab:
        _render_baseline_scan_view(targets, category_options)
    with security_agent_tab:
        _render_security_agent_demo_view(targets, category_options)


if __name__ == "__main__":
    main()
