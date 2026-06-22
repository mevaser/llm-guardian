import json
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = REPOSITORY_ROOT / "examples" / "demo_scan"


def test_demo_scan_example_artifacts_exist_with_required_content() -> None:
    readme_path = EXAMPLES_DIR / "README.md"
    report_path = EXAMPLES_DIR / "scan_report.md"
    trajectory_path = EXAMPLES_DIR / "trajectory.json"

    assert readme_path.exists()
    assert report_path.exists()
    assert trajectory_path.exists()

    readme_text = readme_path.read_text(encoding="utf-8")
    assert "deterministic sample output" in readme_text
    assert "python -m llm_guardian.cli agent-scan --target demo-vulnerable-rag --output-dir reports/demo_scan" in readme_text
    assert "scan_report.md is the human-readable report" in readme_text
    assert "trajectory.json is the machine-readable evidence log" in readme_text
    assert "No real emails are sent." in readme_text
    assert "No real secrets are read." in readme_text

    report_text = report_path.read_text(encoding="utf-8")
    assert "- Overall Risk: CRITICAL" in report_text
    assert "- Scenarios tested: 8" in report_text
    assert "- Failed: 2" in report_text
    assert "category: unsafe_tool_use" in report_text
    assert "severity: critical" in report_text

    trajectory_payload = json.loads(trajectory_path.read_text(encoding="utf-8"))
    assert trajectory_payload["scan_id"]
    assert trajectory_payload["target_name"] == "demo-vulnerable-rag"
    assert trajectory_payload["target_profile"]["target_name"] == "demo-vulnerable-rag"
    assert isinstance(trajectory_payload["scenarios"], list)
    assert len(trajectory_payload["scenarios"]) == 8
    assert all("verdict" in scenario for scenario in trajectory_payload["scenarios"])
    assert all("evidence" in scenario for scenario in trajectory_payload["scenarios"])
    assert any(
        scenario["verdict"] == "fail" and scenario["severity"] == "critical"
        for scenario in trajectory_payload["scenarios"]
    )
