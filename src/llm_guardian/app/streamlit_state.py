"""Streamlit-independent state helpers for persisted dashboard scan results."""

from __future__ import annotations

from collections.abc import MutableMapping

from llm_guardian.models import ScanReport
from llm_guardian.runner.scan_service import render_report_json, render_report_markdown


LATEST_SCAN_REPORT_KEY = "latest_scan_report"
LATEST_SCAN_JSON_EXPORT_KEY = "latest_scan_json_export"
LATEST_SCAN_MARKDOWN_EXPORT_KEY = "latest_scan_markdown_export"


def ensure_session_state(state: MutableMapping[str, object]) -> None:
    """Initialize the small set of persisted dashboard values."""

    state.setdefault(LATEST_SCAN_REPORT_KEY, None)
    state.setdefault(LATEST_SCAN_JSON_EXPORT_KEY, None)
    state.setdefault(LATEST_SCAN_MARKDOWN_EXPORT_KEY, None)


def store_scan_state(state: MutableMapping[str, object], report: ScanReport) -> None:
    """Persist the latest report plus its export payloads for rerun-safe downloads."""

    state[LATEST_SCAN_REPORT_KEY] = report
    state[LATEST_SCAN_JSON_EXPORT_KEY] = render_report_json(report)
    state[LATEST_SCAN_MARKDOWN_EXPORT_KEY] = render_report_markdown(report)
