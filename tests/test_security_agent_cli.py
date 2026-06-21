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


def normalize_agent_scan_payload(payload: dict[str, object]) -> dict[str, object]:
    normalized = json.loads(json.dumps(payload))
    for attempt in normalized.get("attempt_history", []):
        for trace_event in attempt.get("trace", []):
            trace_event.pop("timestamp", None)
        trajectory = attempt.get("trajectory")
        if isinstance(trajectory, dict):
            for trace_event in trajectory.get("trace_events", []):
                trace_event.pop("timestamp", None)
    return normalized


def test_agent_scan_json_stdout_is_serializable() -> None:
    result = run_cli("agent-scan", "--target", "customer_support", "--output-format", "json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["target_profile"]["target_name"] == "customer_support"
    assert payload["target_profile"]["metadata"]["target_name"] == "customer_support"
    assert payload["target_profile"]["authorization_scope"] == "local_demo_only"
    assert payload["summary"]["objective"] == "Run a deterministic local security-agent scan."
    assert isinstance(payload["attempt_history"], list)
    assert result.stderr == ""


def test_agent_scan_markdown_stdout_is_deterministic() -> None:
    first = run_cli(
        "agent-scan",
        "--target",
        "tool_agent",
        "--category",
        "tool_abuse",
        "--max-total-attempts",
        "2",
        "--output-format",
        "markdown",
    )
    second = run_cli(
        "agent-scan",
        "--target",
        "tool_agent",
        "--category",
        "tool_abuse",
        "--max-total-attempts",
        "2",
        "--output-format",
        "markdown",
    )

    assert first.returncode == 0
    assert second.returncode == 0
    assert first.stdout == second.stdout
    assert "# LLM Guardian Security Agent Report" in first.stdout
    assert "- Target name: `tool_agent`" in first.stdout
    assert "## Attempt History" in first.stdout


def test_agent_scan_writes_json_output_file_without_stdout_noise(tmp_path: Path) -> None:
    output_path = tmp_path / "agent-report.json"

    result = run_cli(
        "agent-scan",
        "--target",
        "rag_agent",
        "--category",
        "rag_injection",
        "--output-format",
        "json",
        "--output-file",
        str(output_path),
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert output_path.exists()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["target_profile"]["metadata"]["target_name"] == "rag_agent"


def test_agent_scan_creates_missing_output_directory(tmp_path: Path) -> None:
    output_path = tmp_path / "nested" / "reports" / "agent-report.md"

    result = run_cli(
        "agent-scan",
        "--target",
        "tool_agent",
        "--category",
        "tool_abuse",
        "--output-format",
        "markdown",
        "--output-file",
        str(output_path),
    )

    assert result.returncode == 0
    assert output_path.exists()
    assert "# LLM Guardian Security Agent Report" in output_path.read_text(encoding="utf-8")


def test_agent_scan_rejects_invalid_target_name() -> None:
    result = run_cli("agent-scan", "--target", "unknown-target", "--output-format", "json")

    assert result.returncode == 1
    assert "Unknown target 'unknown-target'" in result.stderr


def test_agent_scan_mutation_budget_changes_attempt_history() -> None:
    baseline = run_cli(
        "agent-scan",
        "--target",
        "customer_support",
        "--category",
        "jailbreak",
        "--max-total-attempts",
        "2",
        "--max-attempts-per-attack",
        "2",
        "--max-mutations-per-attack",
        "0",
        "--output-format",
        "json",
    )
    mutated = run_cli(
        "agent-scan",
        "--target",
        "customer_support",
        "--category",
        "jailbreak",
        "--max-total-attempts",
        "2",
        "--max-attempts-per-attack",
        "2",
        "--max-mutations-per-attack",
        "1",
        "--output-format",
        "json",
    )

    assert baseline.returncode == 0
    assert mutated.returncode == 0

    baseline_payload = json.loads(baseline.stdout)
    mutated_payload = json.loads(mutated.stdout)

    assert baseline_payload["prompt_mutations"] == []
    assert mutated_payload["prompt_mutations"] != []
    assert all(attempt["attempt_index"] == 1 for attempt in baseline_payload["attempt_history"])
    assert any(attempt["attempt_index"] == 2 for attempt in mutated_payload["attempt_history"])


def test_agent_scan_repeated_json_runs_remain_deterministic() -> None:
    first = run_cli(
        "agent-scan",
        "--target",
        "tool_agent",
        "--category",
        "tool_abuse",
        "--max-total-attempts",
        "2",
        "--output-format",
        "json",
    )
    second = run_cli(
        "agent-scan",
        "--target",
        "tool_agent",
        "--category",
        "tool_abuse",
        "--max-total-attempts",
        "2",
        "--output-format",
        "json",
    )

    assert first.returncode == 0
    assert second.returncode == 0
    assert normalize_agent_scan_payload(json.loads(first.stdout)) == normalize_agent_scan_payload(
        json.loads(second.stdout)
    )


def test_agent_scan_uses_yaml_target_profile_contract() -> None:
    result = run_cli(
        "agent-scan",
        "--target",
        "tool_agent",
        "--category",
        "tool_abuse",
        "--max-total-attempts",
        "2",
        "--output-format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)

    assert payload["target_profile"]["target_name"] == "tool_agent"
    assert payload["target_profile"]["available_tools"] == [
        "simulated_email_tool",
        "simulated_export_tool",
        "simulated_ticket_tool",
    ]
    assert payload["target_profile"]["forbidden_actions"] == [
        "external_system_access",
        "credential_extraction",
        "real_side_effects",
        "third_party_target_testing",
        "send_external_email",
        "export_customer_data",
    ]
    assert payload["threat_model"]["available_tools"] == payload["target_profile"]["available_tools"]
    assert payload["threat_model"]["forbidden_actions"] == payload["target_profile"]["forbidden_actions"]
    assert payload["attack_campaign"]["target_name"] == "tool_agent"
    assert payload["attack_campaign"]["selected_categories"] == ["tool_abuse"]


def test_agent_scan_rejects_invalid_target_profile_file(tmp_path: Path) -> None:
    profile_path = tmp_path / "profiles.yaml"
    profile_path.write_text(
        """
targets:
  - id: customer_support
    target_name: customer_support
""",
        encoding="utf-8",
    )

    result = run_cli(
        "agent-scan",
        "--target",
        "customer_support",
        "--target-profile",
        str(profile_path),
        "--output-format",
        "json",
    )

    assert result.returncode == 1
    assert "Invalid target profile for target 'customer_support'" in result.stderr
    assert str(profile_path) in result.stderr
    assert "target_type" in result.stderr


def test_baseline_scan_command_behavior_remains_unchanged() -> None:
    result = run_cli("scan", "--target", "customer_support", "--offline")

    assert result.returncode == 0
    assert "Target: customer_support" in result.stdout
    assert "Risk score:" in result.stdout
    assert "LLM Guardian Security Agent Report" not in result.stdout
