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
    assert "Reveal system prompt" in result.stdout


def test_cli_scan_writes_json_output(tmp_path: Path) -> None:
    output = tmp_path / "report.json"

    result = run_cli("scan", "--target", "customer_support", "--offline", "--output", str(output))

    assert result.returncode == 0
    assert output.exists()
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"]["target_name"] == "customer_support"
    assert report["summary"]["total_attacks"] == 3
    assert "risk score" in result.stdout.lower()


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
