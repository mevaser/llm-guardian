import json
import os
import subprocess
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "llm_guardian.cli", *args],
        cwd=REPOSITORY_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_cli_validate_attacks_exits_successfully() -> None:
    result = run_cli("validate-attacks")

    assert result.returncode == 0
    assert "Attack library valid" in result.stdout


def test_cli_list_attacks_prints_attack_metadata() -> None:
    result = run_cli("list-attacks")

    assert result.returncode == 0
    assert "PI-001" in result.stdout
    assert "prompt_injection" in result.stdout
    assert "Reveal hidden system instructions" in result.stdout


def test_cli_scan_writes_json_output(tmp_path: Path) -> None:
    output = tmp_path / "report.json"

    result = run_cli("scan", "--target", "customer_support", "--offline", "--output", str(output))

    assert result.returncode == 0
    assert output.exists()
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["target_name"] == "customer_support"
    assert report["total_attacks"] >= 20
    assert report["risk_level"] in {"low", "medium", "high", "critical"}
    assert "risk score" in result.stdout.lower()


def test_cli_scan_writes_markdown_output(tmp_path: Path) -> None:
    json_output = tmp_path / "report.json"
    markdown_output = tmp_path / "report.md"

    result = run_cli(
        "scan",
        "--target",
        "customer_support",
        "--offline",
        "--output",
        str(json_output),
        "--markdown-output",
        str(markdown_output),
    )

    assert result.returncode == 0
    assert json_output.exists()
    assert markdown_output.exists()
    assert "# LLM Guardian Scan Report" in markdown_output.read_text(encoding="utf-8")


def test_cli_list_targets_includes_tool_and_rag_agents() -> None:
    result = run_cli("list-targets")

    assert result.returncode == 0
    assert result.stdout.splitlines() == [
        "customer_support",
        "memory_agent",
        "rag_agent",
        "tool_agent",
    ]


def test_cli_scan_and_validate_report_for_tool_agent(tmp_path: Path) -> None:
    report_path = tmp_path / "tool-report.json"
    markdown_path = tmp_path / "tool-report.md"

    scan_result = run_cli(
        "scan",
        "--target",
        "tool_agent",
        "--offline",
        "--output",
        str(report_path),
        "--markdown-output",
        str(markdown_path),
    )

    assert scan_result.returncode == 0
    assert report_path.exists()
    assert markdown_path.exists()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["target_name"] == "tool_agent"

    validate_result = run_cli("validate-report", str(report_path))

    assert validate_result.returncode == 0
    assert "valid scan report" in validate_result.stdout.lower()


def test_cli_scan_and_validate_report_for_rag_agent(tmp_path: Path) -> None:
    report_path = tmp_path / "rag-report.json"
    markdown_path = tmp_path / "rag-report.md"

    scan_result = run_cli(
        "scan",
        "--target",
        "rag_agent",
        "--offline",
        "--output",
        str(report_path),
        "--markdown-output",
        str(markdown_path),
    )

    assert scan_result.returncode == 0
    assert report_path.exists()
    assert markdown_path.exists()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["target_name"] == "rag_agent"

    validate_result = run_cli("validate-report", str(report_path))

    assert validate_result.returncode == 0
    assert "valid scan report" in validate_result.stdout.lower()


def test_cli_scan_rejects_missing_offline_flag() -> None:
    result = run_cli("scan", "--target", "customer_support")

    assert result.returncode == 2
    assert "--offline" in result.stderr


def test_cli_scan_rejects_invalid_target() -> None:
    result = run_cli("scan", "--target", "unknown-target", "--offline")

    assert result.returncode == 1
    assert "Unknown target 'unknown-target'" in result.stderr


def test_cli_validate_report_accepts_generated_json_report(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    scan_result = run_cli("scan", "--target", "customer_support", "--offline", "--output", str(report_path))

    assert scan_result.returncode == 0

    result = run_cli("validate-report", str(report_path))

    assert result.returncode == 0
    assert "valid scan report" in result.stdout.lower()


def test_cli_validate_report_rejects_legacy_summary_shape(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "target_name": "customer_support",
                    "total_attacks": 1,
                    "successful_attacks": 1,
                    "risk_score": 10.0,
                },
                "results": [],
            }
        ),
        encoding="utf-8",
    )

    result = run_cli("validate-report", str(report_path))

    assert result.returncode == 1
    assert "invalid report" in result.stderr.lower()
