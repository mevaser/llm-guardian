from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path

import pytest
import yaml

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


def test_run_streamlit_scenario_generation_uses_fake_provider_and_writes_yaml(
    root_streamlit_app_module,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "generated_attack_scenarios.yaml"

    result = root_streamlit_app_module.run_streamlit_scenario_generation(
        target_name="demo-vulnerable-rag",
        count=2,
        provider_name="fake",
        output_path=output_path,
    )

    assert len(result.accepted_scenarios) == 2
    assert result.rejected_scenarios == []
    assert output_path.exists()
    payload = yaml.safe_load(output_path.read_text(encoding="utf-8"))
    assert payload["metadata"]["target_name"] == "demo-vulnerable-rag"
    assert payload["metadata"]["provider"] == "fake"
    assert payload["metadata"]["model"] == "fake-deterministic"
    assert payload["metadata"]["requested_count"] == 2
    assert payload["metadata"]["accepted_count"] == 2
    assert "generated-" in payload["scenarios"][0]["id"]


def test_run_streamlit_scenario_generation_requires_groq_key(
    root_streamlit_app_module,
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="GROQ_API_KEY is required for provider=groq"):
        root_streamlit_app_module.run_streamlit_scenario_generation(
            target_name="demo-vulnerable-rag",
            count=2,
            provider_name="groq",
            output_path=tmp_path / "generated_attack_scenarios.yaml",
            api_key="",
        )
