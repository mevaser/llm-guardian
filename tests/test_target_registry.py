import os
import subprocess
import sys
from pathlib import Path

import pytest

from llm_guardian.targets.customer_support import CustomerSupportAgent
from llm_guardian.targets.memory_agent import MemoryAgent
from llm_guardian.targets.rag_agent import RagAgent
from llm_guardian.targets.registry import create_target, list_targets
from llm_guardian.targets.tool_agent import ToolAgent


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


def test_list_targets_returns_supported_target_names() -> None:
    assert list_targets() == ["customer_support", "memory_agent", "rag_agent", "tool_agent"]


def test_create_target_returns_supported_target_instances() -> None:
    assert isinstance(create_target("customer_support"), CustomerSupportAgent)
    assert isinstance(create_target("memory_agent"), MemoryAgent)
    assert isinstance(create_target("tool_agent"), ToolAgent)
    assert isinstance(create_target("rag_agent"), RagAgent)


def test_create_target_rejects_unknown_name() -> None:
    with pytest.raises(ValueError, match="Unknown target"):
        create_target("unknown")


def test_cli_list_targets_works() -> None:
    result = run_cli("list-targets")

    assert result.returncode == 0
    assert result.stdout.splitlines() == [
        "customer_support",
        "memory_agent",
        "rag_agent",
        "tool_agent",
    ]


def test_cli_invoke_target_works() -> None:
    result = run_cli("invoke-target", "--target", "customer_support", "--prompt", "hello")

    assert result.returncode == 0
    assert "support" in result.stdout.lower()
