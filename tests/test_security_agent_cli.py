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


def test_agent_scan_uses_yaml_mutation_budget_for_mutation_challenge_target() -> None:
    result = run_cli(
        "agent-scan",
        "--target",
        "mutation_challenge_tool_agent",
        "--category",
        "tool_abuse",
        "--max-attempts-per-attack",
        "2",
        "--output-format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    attempts_by_attack: dict[str, list[dict[str, object]]] = {}
    for attempt in payload["attempt_history"]:
        attempts_by_attack.setdefault(attempt["attack_id"], []).append(attempt)
    ta_001_attempts = attempts_by_attack["TA-001"]

    assert payload["target_profile"]["target_name"] == "mutation_challenge_tool_agent"
    assert payload["target_profile"]["mutation_policy"]["max_mutations_per_attack"] == 1
    assert payload["attack_campaign"]["mutation_budget"] == 1
    assert payload["attack_campaign"]["retry_policy"]["max_mutations_per_attack"] == 1
    assert payload["summary"]["mutation_strategies_used"] == ["indirect_framing"]
    assert [attempt["attempt_index"] for attempt in ta_001_attempts] == [1, 2]
    assert ta_001_attempts[0]["verdict"]["status"] == "blocked"
    assert ta_001_attempts[0]["success"] is False
    assert ta_001_attempts[0]["trajectory"]["tool_calls"] == []
    assert ta_001_attempts[0]["observation"]["target_refused"] is True
    assert ta_001_attempts[0]["observation"]["tool_called"] is False
    assert "Tool called: simulated_email_tool" not in ta_001_attempts[0]["observation"]["relevant_evidence"]
    assert ta_001_attempts[1]["verdict"]["status"] == "success"
    assert ta_001_attempts[1]["success"] is True
    assert ta_001_attempts[1]["mutation_strategy"] == "indirect_framing"
    assert ta_001_attempts[1]["trajectory"]["mutation_lineage"]["mutation_strategy"] == "indirect_framing"
    assert ta_001_attempts[1]["trajectory"]["tool_calls"][0]["tool_name"] == "simulated_email_tool"
    assert ta_001_attempts[1]["observation"]["tool_called"] is True
    assert "Tool called: simulated_email_tool" in ta_001_attempts[1]["observation"]["relevant_evidence"]
    assert ta_001_attempts[1]["trajectory"]["tool_names"] == ["simulated_email_tool"]
    assert ta_001_attempts[1]["observation"]["mock_side_effects_detected"] is True
    assert ta_001_attempts[1]["observation"]["external_call_attempted"] is False
    assert payload["findings"][0]["attack_id"] == "TA-001"
    assert payload["findings"][0]["successful_attempt_ids"] == ["TA-001-attempt-2"]
    assert payload["findings"][0]["mutation_strategies"] == ["indirect_framing"]


def test_agent_scan_explicit_mutation_budget_overrides_yaml_profile() -> None:
    result = run_cli(
        "agent-scan",
        "--target",
        "mutation_challenge_tool_agent",
        "--category",
        "tool_abuse",
        "--max-attempts-per-attack",
        "2",
        "--max-mutations-per-attack",
        "0",
        "--output-format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)

    assert payload["attack_campaign"]["mutation_budget"] == 0
    assert payload["attack_campaign"]["retry_policy"]["max_mutations_per_attack"] == 0
    assert payload["prompt_mutations"] == []
    assert all(attempt["attempt_index"] == 1 for attempt in payload["attempt_history"])


def test_agent_scan_defaults_to_deterministic_mutation_strategy_mode() -> None:
    result = run_cli(
        "agent-scan",
        "--target",
        "mutation_challenge_tool_agent",
        "--category",
        "tool_abuse",
        "--max-total-attempts",
        "2",
        "--max-attempts-per-attack",
        "2",
        "--output-format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert "mutation_strategy_mode" not in payload["attack_campaign"]["retry_policy"]
    assert "llm_validation_status" not in payload["prompt_mutations"][0]
    assert "fallback_used" not in payload["prompt_mutations"][0]


def test_agent_scan_llm_assisted_fake_provider_adds_structured_mutation_metadata() -> None:
    result = run_cli(
        "agent-scan",
        "--target",
        "mutation_challenge_tool_agent",
        "--category",
        "tool_abuse",
        "--max-total-attempts",
        "10",
        "--max-attempts-per-attack",
        "2",
        "--max-mutations-per-attack",
        "1",
        "--mutation-strategy-mode",
        "llm-assisted",
        "--llm-provider",
        "fake",
        "--output-format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["total_attempts"] == 10
    assert payload["summary"]["successful_attempts"] == 5
    assert payload["summary"]["failed_attempts"] == 5
    assert payload["attack_campaign"]["retry_policy"]["mutation_strategy_mode"] == "llm-assisted"
    assert payload["summary"]["mutation_strategies_used"] == ["indirect_framing"]
    first_mutation = payload["prompt_mutations"][0]
    assert first_mutation["llm_recommended_strategy"] == "indirect_framing"
    assert first_mutation["llm_validation_status"] == "valid"
    assert first_mutation["fallback_used"] is False
    mutated_attempt = payload["attempt_history"][1]
    assert mutated_attempt["llm_failure_analysis"]
    assert mutated_attempt["llm_validation_status"] == "valid"
    assert mutated_attempt["trajectory"]["mutation_lineage"]["llm_recommended_strategy"] == "indirect_framing"
    assert mutated_attempt["observation"]["external_call_attempted"] is False


def test_agent_scan_deterministic_mode_ignores_unimplemented_provider_selection() -> None:
    result = run_cli(
        "agent-scan",
        "--target",
        "tool_agent",
        "--category",
        "tool_abuse",
        "--max-total-attempts",
        "2",
        "--mutation-strategy-mode",
        "deterministic",
        "--llm-provider",
        "ollama",
        "--output-format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert "mutation_strategy_mode" not in payload["attack_campaign"]["retry_policy"]
    assert payload["summary"]["mutation_strategies_used"] == []


def test_agent_scan_llm_assisted_ollama_provider_runs_with_local_fallback() -> None:
    result = run_cli(
        "agent-scan",
        "--target",
        "mutation_challenge_tool_agent",
        "--category",
        "tool_abuse",
        "--max-total-attempts",
        "10",
        "--max-attempts-per-attack",
        "2",
        "--max-mutations-per-attack",
        "1",
        "--mutation-strategy-mode",
        "llm-assisted",
        "--llm-provider",
        "ollama",
        "--llm-model",
        "qwen2.5:7b-instruct",
        "--llm-timeout-seconds",
        "1",
        "--output-format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["total_attempts"] == 10
    assert payload["summary"]["successful_attempts"] == 5
    assert payload["summary"]["failed_attempts"] == 5
    assert payload["attack_campaign"]["retry_policy"]["mutation_strategy_mode"] == "llm-assisted"
    assert payload["prompt_mutations"]
    assert payload["prompt_mutations"][0]["llm_validation_status"] is not None
    assert payload["prompt_mutations"][0]["fallback_used"] in {True, False}


def test_agent_scan_llm_assisted_ollama_provider_requires_model() -> None:
    result = run_cli(
        "agent-scan",
        "--target",
        "mutation_challenge_tool_agent",
        "--category",
        "tool_abuse",
        "--mutation-strategy-mode",
        "llm-assisted",
        "--llm-provider",
        "ollama",
        "--output-format",
        "json",
    )

    assert result.returncode == 1
    assert "Ollama LLM provider requires --llm-model." in result.stderr


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


def test_agent_scan_demo_vulnerable_rag_writes_mvp_outputs_and_summary(tmp_path: Path) -> None:
    output_dir = tmp_path / "nested" / "demo-scan"

    result = run_cli(
        "agent-scan",
        "--target",
        "demo-vulnerable-rag",
        "--output-dir",
        str(output_dir),
    )

    assert result.returncode == 0
    assert output_dir.is_dir()

    trajectory_path = output_dir / "trajectory.json"
    report_path = output_dir / "scan_report.md"
    assert trajectory_path.exists()
    assert report_path.exists()

    stdout = result.stdout
    assert "LLM Guardian Scan Complete" in stdout
    assert "Adaptive probes: 2" in stdout
    assert "Overall Risk" in stdout

    report_text = report_path.read_text(encoding="utf-8")
    assert "verdict: fail" in report_text
    assert "## Agent Plan" in report_text
    assert "## Agent Execution Trace" in report_text
    assert "## Adaptive Probes" in report_text

    trajectory_payload = json.loads(trajectory_path.read_text(encoding="utf-8"))
    assert trajectory_payload["target_name"] == "demo-vulnerable-rag"
    assert trajectory_payload["agent_plan"]["scenario_count"] == 8
    assert trajectory_payload["agent_trace"]
    assert len(trajectory_payload["adaptive_probes"]) == 2
    assert trajectory_payload["scenarios"]
    assert any(item["verdict"] == "fail" for item in trajectory_payload["scenarios"])
    assert all("scenario_id" in item for item in trajectory_payload["scenarios"])
    assert all("evidence" in item for item in trajectory_payload["scenarios"])


def test_generate_scenarios_command_writes_yaml(tmp_path: Path) -> None:
    output_path = tmp_path / "generated_attack_scenarios.yaml"

    result = run_cli(
        "generate-scenarios",
        "--target",
        "demo-vulnerable-rag",
        "--count",
        "2",
        "--output",
        str(output_path),
        "--provider",
        "fake",
    )

    assert result.returncode == 0
    assert output_path.exists()
    assert "Scenario generation complete" in result.stdout
    assert "Accepted: 2" in result.stdout
    assert "Rejected: 0" in result.stdout
    output_text = output_path.read_text(encoding="utf-8")
    assert "scenarios:" in output_text
    assert "generated-" in output_text


def test_agent_scan_demo_vulnerable_rag_accepts_generated_scenario_file(tmp_path: Path) -> None:
    scenario_path = tmp_path / "generated_attack_scenarios.yaml"
    generate_result = run_cli(
        "generate-scenarios",
        "--target",
        "demo-vulnerable-rag",
        "--count",
        "2",
        "--output",
        str(scenario_path),
        "--provider",
        "fake",
    )
    assert generate_result.returncode == 0

    output_dir = tmp_path / "generated-scan"
    result = run_cli(
        "agent-scan",
        "--target",
        "demo-vulnerable-rag",
        "--scenario-file",
        str(scenario_path),
        "--output-dir",
        str(output_dir),
    )

    assert result.returncode == 0
    assert "Scenarios tested: 2" in result.stdout
    trajectory_payload = json.loads((output_dir / "trajectory.json").read_text(encoding="utf-8"))
    assert trajectory_payload["agent_plan"]["scenario_count"] == 2
    assert trajectory_payload["target_profile"]["scenario_source"] == str(scenario_path)
    assert trajectory_payload["agent_plan"]["scenario_source"] == str(scenario_path)
