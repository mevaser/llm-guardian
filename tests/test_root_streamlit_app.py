from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path

import pytest

from llm_guardian.models import SecurityScanResult


@pytest.fixture
def root_streamlit_app_module(monkeypatch: pytest.MonkeyPatch):
    fake_streamlit = types.ModuleType("streamlit")
    monkeypatch.setitem(sys.modules, "streamlit", fake_streamlit)
    sys.modules.pop("streamlit_app", None)
    return importlib.import_module("streamlit_app")


def test_root_streamlit_app_imports_successfully(root_streamlit_app_module) -> None:
    assert hasattr(root_streamlit_app_module, "main")
    assert hasattr(root_streamlit_app_module, "run_streamlit_scan")


def test_importing_root_streamlit_app_does_not_execute_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    call_counter = {"count": 0}

    class FakeSecurityScanAgent:
        def __init__(self) -> None:
            call_counter["count"] += 1

        def run(self, *, target_name: str, output_dir: Path) -> object:
            return {"target_name": target_name, "output_dir": str(output_dir)}

    fake_streamlit = types.ModuleType("streamlit")
    monkeypatch.setitem(sys.modules, "streamlit", fake_streamlit)
    monkeypatch.setattr(
        "llm_guardian.security_agent.agent.SecurityScanAgent",
        FakeSecurityScanAgent,
    )
    sys.modules.pop("streamlit_app", None)

    importlib.import_module("streamlit_app")

    assert call_counter["count"] == 0


def test_run_streamlit_scan_uses_security_scan_agent(
    monkeypatch: pytest.MonkeyPatch,
    root_streamlit_app_module,
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}
    expected_result = SecurityScanResult(
        scan_id="streamlit-test-scan",
        target_name="demo-vulnerable-rag",
        scenario_results=[],
        findings=[],
    )

    class FakeSecurityScanAgent:
        def run(self, *, target_name: str, output_dir: Path) -> SecurityScanResult:
            captured["target_name"] = target_name
            captured["output_dir"] = output_dir
            return expected_result

    monkeypatch.setattr(root_streamlit_app_module, "SecurityScanAgent", FakeSecurityScanAgent)

    result = root_streamlit_app_module.run_streamlit_scan(
        "demo-vulnerable-rag",
        tmp_path / "reports",
    )

    assert captured["target_name"] == "demo-vulnerable-rag"
    assert captured["output_dir"] == tmp_path / "reports"
    assert result is expected_result


def test_run_streamlit_scan_returns_security_scan_result_and_writes_artifacts(tmp_path: Path) -> None:
    streamlit_app_module = importlib.import_module("streamlit_app")
    output_dir = tmp_path / "streamlit-scan"

    result = streamlit_app_module.run_streamlit_scan(
        "demo-vulnerable-rag",
        output_dir,
    )

    assert isinstance(result, SecurityScanResult)
    assert (output_dir / "scan_report.md").exists()
    assert (output_dir / "trajectory.json").exists()
