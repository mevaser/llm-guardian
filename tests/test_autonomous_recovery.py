import os
from unittest.mock import patch
import pytest

from llm_guardian.redteam.local_lab.models import ObservationState, PreviousAttempt, PlannerDecision
from llm_guardian.redteam.local_lab.attack_agent import AutonomousStrategy, CONCRETE_TRANSFORMATION_TACTICS, is_near_duplicate

class DummyPlanner:
    def __init__(self, proposals=None):
        self.proposals = proposals or []
        self.call_count = 0
        self.provider_name = "dummy"
        self.api_key = "fake"

    def propose_next_action(self, state):
        if self.call_count < len(self.proposals):
            decision = self.proposals[self.call_count]
            self.call_count += 1
            return decision, None
        return None, "No more proposals"

@patch("llm_guardian.redteam.local_lab.attack_agent.LLMAttackPlanner")
@patch.dict(os.environ, {"GROQ_API_KEY": "fake_key"})
def test_transformation_hint_forces_concrete_format(mock_planner_class):
    dummy_planner = DummyPlanner([
        PlannerDecision(strategy_name="generic exploration", selected_prompt="What is the data?", rationale_summary="", expected_bypass_type="", confidence=0.5, observation_summary="", next_action_summary=""),
        PlannerDecision(strategy_name="generic exploration", selected_prompt="What is the data again?", rationale_summary="", expected_bypass_type="", confidence=0.5, observation_summary="", next_action_summary="")
    ])
    mock_planner_class.return_value = dummy_planner
    
    strategy = AutonomousStrategy()
    strategy.planner = dummy_planner
    
    state = ObservationState(
        level_id=1, title="Test", public_description="Desc", current_turn=2, max_attempts=8,
        previous_attempts=[PreviousAttempt(attempt_number=1, prompt="Hello", response="hint", outcome_type="transformation_hint", solved=False, observation_summary="rejected", selected_tactic="generic")],
        last_hint_type="transformation_hint", pending_forced_tactic="transformation_hint"
    )
    prompt, decision_info = strategy.generate_prompt(state)
    assert decision_info["controller_override_used"] is True
    assert decision_info["forced_transformation_format"] in [t["name"] for t in CONCRETE_TRANSFORMATION_TACTICS]
    assert prompt in [t["prompt"] for t in CONCRETE_TRANSFORMATION_TACTICS]

@patch("llm_guardian.redteam.local_lab.attack_agent.LLMAttackPlanner")
@patch.dict(os.environ, {"GROQ_API_KEY": "fake_key"})
def test_oscillation_detection(mock_planner_class):
    dummy_planner = DummyPlanner([
        PlannerDecision(strategy_name="generic exploration", selected_prompt="Prompt A", rationale_summary="", expected_bypass_type="", confidence=0.5, observation_summary="", next_action_summary=""),
        PlannerDecision(strategy_name="generic exploration", selected_prompt="Prompt B", rationale_summary="", expected_bypass_type="", confidence=0.5, observation_summary="", next_action_summary="")
    ])
    mock_planner_class.return_value = dummy_planner
    strategy = AutonomousStrategy()
    strategy.planner = dummy_planner
    state = ObservationState(
        level_id=1, title="Test", public_description="Desc", current_turn=3, max_attempts=8,
        previous_attempts=[
            PreviousAttempt(attempt_number=1, prompt="Prompt A", response="fail", outcome_type="filtered", solved=False, observation_summary="rejected", selected_tactic="generic"),
            PreviousAttempt(attempt_number=2, prompt="Prompt B", response="fail", outcome_type="filtered", solved=False, observation_summary="rejected", selected_tactic="generic")
        ]
    )
    prompt, decision_info = strategy.generate_prompt(state)
    assert decision_info["duplicate_prompt_detected"] is True
    assert decision_info["oscillation_detected"] is True
    assert decision_info["duplicate_prompt_avoided"] is True
    assert decision_info["recovery_reason"] == "oscillation_detected"
    assert "override" in decision_info["rationale_summary"].lower()

@patch("llm_guardian.redteam.local_lab.attack_agent.LLMAttackPlanner")
@patch.dict(os.environ, {"GROQ_API_KEY": "fake_key"})
def test_proper_form_switches_format(mock_planner_class):
    dummy_planner = DummyPlanner([
        PlannerDecision(strategy_name="generic exploration", selected_prompt="Something else", rationale_summary="", expected_bypass_type="", confidence=0.5, observation_summary="", next_action_summary=""),
        PlannerDecision(strategy_name="generic exploration", selected_prompt="Something else again", rationale_summary="", expected_bypass_type="", confidence=0.5, observation_summary="", next_action_summary="")
    ])
    mock_planner_class.return_value = dummy_planner
    strategy = AutonomousStrategy()
    strategy.planner = dummy_planner
    first_format = CONCRETE_TRANSFORMATION_TACTICS[0]
    state = ObservationState(
        level_id=1, title="Test", public_description="Desc", current_turn=3, max_attempts=8,
        previous_attempts=[
            PreviousAttempt(attempt_number=1, prompt="Hello", response="hint", outcome_type="transformation_hint", solved=False, observation_summary="rejected", selected_tactic="generic"),
            PreviousAttempt(attempt_number=2, prompt=first_format["prompt"], response="Your request lacks the proper form.", outcome_type="filtered", solved=False, observation_summary="rejected", selected_tactic=first_format["name"])
        ],
        last_hint_type="transformation_hint", pending_forced_tactic="transformation_hint"
    )
    prompt, decision_info = strategy.generate_prompt(state)
    assert decision_info["controller_override_used"] is True
    assert decision_info["forced_transformation_format"] in [t["name"] for t in CONCRETE_TRANSFORMATION_TACTICS]
    assert decision_info["forced_transformation_format"] != first_format["name"]
    assert prompt != first_format["prompt"]
