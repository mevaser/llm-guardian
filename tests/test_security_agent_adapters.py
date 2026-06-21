from llm_guardian.models import TargetResponse, TraceEvent
from llm_guardian.security_agent.adapters import LocalTargetAdapter


class FakeTargetAgent:
    name = "fake_target"
    description = "Deterministic fake target for adapter tests."

    def invoke(self, prompt: str) -> TargetResponse:
        return TargetResponse(
            content=f"Handled: {prompt}",
            metadata={"demo_mode": "offline", "source": "fake_target"},
            trace=[
                TraceEvent(
                    event_type="target_invoked",
                    target_name=self.name,
                    attack_id="pending_attack",
                    message="Fake target handled the prompt.",
                    metadata={"prompt_length": len(prompt)},
                )
            ],
        )


def test_local_target_adapter_wraps_target_and_returns_execution_result() -> None:
    adapter = LocalTargetAdapter(FakeTargetAgent())

    result = adapter.execute(prompt="Test adapter prompt", attack_id="PI-001")

    assert result.prompt == "Test adapter prompt"
    assert result.response == "Handled: Test adapter prompt"
    assert len(result.trace) == 1
    assert result.trace[0].target_name == "fake_target"
    assert result.metadata["target_name"] == "fake_target"
    assert result.metadata["target_description"] == "Deterministic fake target for adapter tests."
    assert result.metadata["attack_id"] == "PI-001"
    assert result.metadata["target_metadata"] == {"demo_mode": "offline", "source": "fake_target"}
    assert result.metadata["execution_mode"] == "local_in_process"

