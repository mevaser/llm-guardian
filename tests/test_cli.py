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


def test_cli_scan_writes_placeholder_report(tmp_path: Path) -> None:
    output = tmp_path / "report.json"

    result = run_cli("scan", "--target", "customer_support", "--offline", "--output", str(output))

    assert result.returncode == 0
    assert output.exists()
    assert "not_implemented" in output.read_text(encoding="utf-8")


def test_cli_validate_report_accepts_placeholder_report(tmp_path: Path) -> None:
    path = tmp_path / "placeholder.json"
    path.write_text('{"status": "not_implemented"}', encoding="utf-8")

    result = run_cli("validate-report", str(path))

    assert result.returncode == 0
    assert "valid placeholder" in result.stdout
