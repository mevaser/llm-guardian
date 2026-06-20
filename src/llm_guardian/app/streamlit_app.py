"""Streamlit dashboard for offline LLM Guardian scans."""

from __future__ import annotations

from llm_guardian.attacks.loader import load_attack_library
from llm_guardian.config import DEFAULT_ATTACK_LIBRARY_PATH
from llm_guardian.models import AttackResult, ScanReport
from llm_guardian.runner.scan_service import (
    render_report_json,
    render_report_markdown,
    run_offline_scan,
)
from llm_guardian.targets.registry import list_targets

try:
    import streamlit as st
except ImportError as exc:  # pragma: no cover - guarded by optional dependency install
    raise RuntimeError(
        "Streamlit is required to run the dashboard. Install the optional UI dependency first."
    ) from exc


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


def main() -> None:
    st.set_page_config(page_title="LLM Guardian Dashboard", layout="wide")
    st.title("LLM Guardian")
    st.caption("Offline dashboard for controlled local red-team scans.")
    st.warning(
        "This demo scans only local intentionally vulnerable targets. "
        "It does not test real third-party systems."
    )

    targets = list_targets()
    category_options = _load_category_options()

    with st.sidebar:
        st.header("Scan Controls")
        target_name = st.selectbox("Target agent", options=targets, index=0)
        selected_categories = st.multiselect(
            "Attack categories",
            options=category_options,
            help="Leave empty to scan all categories.",
        )
        run_requested = st.button("Run scan", type="primary", use_container_width=True)

    if not run_requested:
        st.info("Select a target and optional category filter, then run a scan.")
        return

    with st.spinner("Running deterministic offline scan..."):
        report = run_offline_scan(
            target_name=target_name,
            categories=selected_categories or None,
        )

    _render_report(report)

    json_report = render_report_json(report)
    markdown_report = render_report_markdown(report)

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


if __name__ == "__main__":
    main()
