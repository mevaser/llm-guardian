import importlib

import pytest

from llm_guardian.app.streamlit_state import (
    LATEST_SCAN_JSON_EXPORT_KEY,
    LATEST_SCAN_MARKDOWN_EXPORT_KEY,
    LATEST_SCAN_REPORT_KEY,
    ensure_session_state,
    store_scan_state,
)
from llm_guardian.runner.scan_service import (
    render_report_json,
    render_report_markdown,
    run_offline_scan,
)


def test_streamlit_app_module_imports_when_streamlit_is_available() -> None:
    pytest.importorskip("streamlit")

    module = importlib.import_module("llm_guardian.app.streamlit_app")

    assert hasattr(module, "main")


def test_store_scan_state_persists_report_and_export_payloads() -> None:
    report = run_offline_scan(target_name="tool_agent", categories=["tool_abuse"])
    state: dict[str, object] = {}

    ensure_session_state(state)
    store_scan_state(state, report)

    assert state[LATEST_SCAN_REPORT_KEY] == report
    assert state[LATEST_SCAN_JSON_EXPORT_KEY] == render_report_json(report)
    assert state[LATEST_SCAN_MARKDOWN_EXPORT_KEY] == render_report_markdown(report)
