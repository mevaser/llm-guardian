import importlib
import inspect

import pytest

from llm_guardian.app import streamlit_app
from llm_guardian.app.security_agent_demo import (
    DEFAULT_MAX_ATTEMPTS_PER_ATTACK,
    DEFAULT_MAX_TOTAL_ATTEMPTS,
    DEFAULT_SECURITY_AGENT_CATEGORY,
    DEFAULT_SECURITY_AGENT_TARGET,
    build_attempt_timeline_rows,
    build_security_agent_findings_rows,
    get_default_max_mutations_per_attack,
    run_security_agent_demo_scan,
)
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
    assert module.DASHBOARD_TABS == ("Baseline Scan", "Security Agent Demo")


def test_run_security_agent_demo_scan_signature_accepts_streamlit_llm_kwargs() -> None:
    parameters = inspect.signature(run_security_agent_demo_scan).parameters

    assert "mutation_strategy_mode" in parameters
    assert parameters["mutation_strategy_mode"].default == "deterministic"
    assert "llm_provider" in parameters
    assert parameters["llm_provider"].default == "fake"
    assert "llm_model" in parameters
    assert parameters["llm_model"].default is None
    assert "llm_timeout_seconds" in parameters
    assert parameters["llm_timeout_seconds"].default == 30


def test_streamlit_app_and_security_agent_demo_stay_api_compatible() -> None:
    helper_parameters = inspect.signature(run_security_agent_demo_scan).parameters
    caller_source = inspect.getsource(streamlit_app._render_security_agent_demo_view)

    for parameter_name in (
        "mutation_strategy_mode",
        "llm_provider",
        "llm_model",
        "llm_timeout_seconds",
    ):
        assert parameter_name in helper_parameters
        assert f"{parameter_name}={parameter_name}" in caller_source


def test_store_scan_state_persists_report_and_export_payloads() -> None:
    report = run_offline_scan(target_name="tool_agent", categories=["tool_abuse"])
    state: dict[str, object] = {}

    ensure_session_state(state)
    store_scan_state(state, report)

    assert state[LATEST_SCAN_REPORT_KEY] == report
    assert state[LATEST_SCAN_JSON_EXPORT_KEY] == render_report_json(report)
    assert state[LATEST_SCAN_MARKDOWN_EXPORT_KEY] == render_report_markdown(report)


def test_security_agent_demo_scan_prepares_mutation_retry_payload() -> None:
    demo_data = run_security_agent_demo_scan()
    payload = demo_data.payload

    assert payload["target_profile"]["target_name"] == "mutation_challenge_tool_agent"
    assert payload["summary"]["total_attempts"] == 10
    assert payload["summary"]["failed_attempts"] == 5
    assert payload["summary"]["successful_attempts"] == 5
    assert payload["summary"]["skipped_or_unknown_attempts"] == 0
    assert payload["summary"]["mutation_strategies_used"] == ["indirect_framing"]
    assert payload["threat_model"]["threat_categories_in_scope"] == ["tool_abuse"]
    assert payload["attack_campaign"]["selected_categories"] == ["tool_abuse"]
    assert payload["attack_campaign"]["mutation_budget"] == 1
    assert payload["attack_campaign"]["retry_policy"]["max_mutations_per_attack"] == 1
    ta_001_attempt_1 = payload["attempt_history"][0]
    ta_001_attempt_2 = payload["attempt_history"][1]

    assert ta_001_attempt_1["attack_id"] == "TA-001"
    assert ta_001_attempt_1["verdict"]["status"] == "blocked"
    assert ta_001_attempt_1["trajectory"]["tool_calls"] == []
    assert ta_001_attempt_1["observation"]["tool_called"] is False
    assert "Tool called: simulated_email_tool" not in ta_001_attempt_1["observation"]["relevant_evidence"]
    assert ta_001_attempt_2["attack_id"] == "TA-001"
    assert ta_001_attempt_2["verdict"]["status"] == "success"
    assert ta_001_attempt_2["trajectory"]["tool_calls"][0]["tool_name"] == "simulated_email_tool"
    assert ta_001_attempt_2["observation"]["tool_called"] is True
    assert "Tool called: simulated_email_tool" in ta_001_attempt_2["observation"]["relevant_evidence"]

    timeline_rows = build_attempt_timeline_rows(payload)
    assert timeline_rows[0]["Attack ID"] == "TA-001"
    assert timeline_rows[0]["Attempt index"] == 1
    assert timeline_rows[0]["Verdict"] == "blocked"
    assert timeline_rows[0]["Success"] is False
    assert timeline_rows[1]["Attack ID"] == "TA-001"
    assert timeline_rows[1]["Attempt index"] == 2
    assert timeline_rows[1]["Verdict"] == "success"
    assert timeline_rows[1]["Success"] is True
    assert timeline_rows[1]["Mutation strategy"] == "indirect_framing"
    assert timeline_rows[2]["Attack ID"] == "TA-002"
    assert timeline_rows[2]["Attempt index"] == 1
    assert timeline_rows[2]["Verdict"] == "blocked"
    assert timeline_rows[3]["Attack ID"] == "TA-002"
    assert timeline_rows[3]["Attempt index"] == 2
    assert timeline_rows[3]["Verdict"] == "success"
    assert timeline_rows[3]["Mutation strategy"] == "indirect_framing"

    finding_rows = build_security_agent_findings_rows(payload)
    assert len(finding_rows) == 5
    assert finding_rows[0]["Successful attempt IDs"] == "TA-001-attempt-2"
    assert finding_rows[0]["Mutation strategies"] == "indirect_framing"
    assert "TA-001-attempt-2" in demo_data.json_report
    assert "## Attempt History" in demo_data.markdown_report


def test_security_agent_demo_scan_uses_yaml_mutation_policy_by_default() -> None:
    assert get_default_max_mutations_per_attack("mutation_challenge_tool_agent") == 1
    assert get_default_max_mutations_per_attack("tool_agent") == 0

    payload = run_security_agent_demo_scan(target_name="tool_agent").payload

    assert payload["attack_campaign"]["mutation_budget"] == 0
    assert payload["attack_campaign"]["retry_policy"]["max_mutations_per_attack"] == 0
    assert "mutation_strategy_mode" not in payload["attack_campaign"]["retry_policy"]
    assert payload["prompt_mutations"] == []


def test_security_agent_demo_scan_explicit_override_beats_yaml_mutation_policy() -> None:
    payload = run_security_agent_demo_scan(
        target_name="mutation_challenge_tool_agent",
        max_mutations_per_attack=0,
    ).payload

    assert payload["attack_campaign"]["mutation_budget"] == 0
    assert payload["attack_campaign"]["retry_policy"]["max_mutations_per_attack"] == 0
    assert "mutation_strategy_mode" not in payload["attack_campaign"]["retry_policy"]
    assert payload["prompt_mutations"] == []


def test_security_agent_demo_scan_supports_llm_assisted_fake_mode() -> None:
    payload = run_security_agent_demo_scan(
        mutation_strategy_mode="llm-assisted",
        llm_provider="fake",
    ).payload

    assert payload["attack_campaign"]["retry_policy"]["mutation_strategy_mode"] == "llm-assisted"
    assert payload["prompt_mutations"][0]["llm_validation_status"] == "valid"
    assert payload["prompt_mutations"][0]["fallback_used"] is False
    assert payload["attempt_history"][1]["llm_recommended_strategy"] == "indirect_framing"


def test_security_agent_demo_scan_supports_llm_assisted_ollama_mode() -> None:
    payload = run_security_agent_demo_scan(
        mutation_strategy_mode="llm-assisted",
        llm_provider="ollama",
        llm_model="qwen2.5:7b-instruct",
        llm_timeout_seconds=1,
    ).payload

    assert payload["attack_campaign"]["retry_policy"]["mutation_strategy_mode"] == "llm-assisted"
    assert payload["prompt_mutations"]
    assert payload["prompt_mutations"][0]["llm_validation_status"] is not None
    assert payload["prompt_mutations"][0]["fallback_used"] in {True, False}


def test_security_agent_demo_scan_ollama_mutator_wires_provider_model_and_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FakeOllamaLLMClient:
        def __init__(self, *, model: str, timeout_seconds: int) -> None:
            captured["model"] = model
            captured["timeout_seconds"] = timeout_seconds

    class FakeLLMAssistedPromptMutator:
        def __init__(self, *, llm_client: object) -> None:
            captured["llm_client"] = llm_client

    class FakeSecurityAgent:
        def __init__(self, *, max_mutations_per_attack: int, mutation_strategy_mode: str, mutator: object) -> None:
            captured["max_mutations_per_attack"] = max_mutations_per_attack
            captured["mutation_strategy_mode"] = mutation_strategy_mode
            captured["mutator"] = mutator

        def run(self, **_: object) -> object:
            return object()

    class FakeJsonReportBuilder:
        def build(self, **_: object) -> dict[str, object]:
            return {}

    class FakeMarkdownReportBuilder:
        def __init__(self, *, json_builder: object) -> None:
            captured["json_builder"] = json_builder

        def build(self, **_: object) -> str:
            return "report"

    monkeypatch.setattr(
        "llm_guardian.app.security_agent_demo.OllamaLLMClient",
        FakeOllamaLLMClient,
    )
    monkeypatch.setattr(
        "llm_guardian.app.security_agent_demo.LLMAssistedPromptMutator",
        FakeLLMAssistedPromptMutator,
    )
    monkeypatch.setattr(
        "llm_guardian.app.security_agent_demo.SecurityAgent",
        FakeSecurityAgent,
    )
    monkeypatch.setattr(
        "llm_guardian.app.security_agent_demo.SecurityAgentJsonReportBuilder",
        FakeJsonReportBuilder,
    )
    monkeypatch.setattr(
        "llm_guardian.app.security_agent_demo.SecurityAgentMarkdownReportBuilder",
        FakeMarkdownReportBuilder,
    )

    streamlit_app.run_security_agent_demo_scan(
        mutation_strategy_mode="llm-assisted",
        llm_provider="ollama",
        llm_model="qwen2.5:7b-instruct",
        llm_timeout_seconds=7,
        max_total_attempts=1,
        max_attempts_per_attack=1,
        categories=[DEFAULT_SECURITY_AGENT_CATEGORY],
        target_name=DEFAULT_SECURITY_AGENT_TARGET,
    )

    assert captured["mutation_strategy_mode"] == "llm-assisted"
    assert captured["model"] == "qwen2.5:7b-instruct"
    assert captured["timeout_seconds"] == 7
    assert isinstance(captured["llm_client"], FakeOllamaLLMClient)
    assert isinstance(captured["mutator"], FakeLLMAssistedPromptMutator)


def test_security_agent_demo_scan_deterministic_mutation_payload_omits_null_llm_metadata() -> None:
    payload = run_security_agent_demo_scan(
        target_name="mutation_challenge_tool_agent",
        max_total_attempts=2,
        max_attempts_per_attack=2,
        max_mutations_per_attack=1,
    ).payload

    assert "llm_failure_analysis" not in payload["attempt_history"][1]
    assert "llm_recommended_strategy" not in payload["attempt_history"][1]
    assert "llm_validation_status" not in payload["attempt_history"][1]
    assert "fallback_used" not in payload["attempt_history"][1]
    assert "llm_failure_analysis" not in payload["prompt_mutations"][0]
    assert "llm_recommended_strategy" not in payload["prompt_mutations"][0]
    assert "llm_validation_status" not in payload["prompt_mutations"][0]
    assert "fallback_used" not in payload["prompt_mutations"][0]
