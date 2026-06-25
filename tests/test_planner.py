import os
import json
import pytest
from unittest.mock import patch

from llm_guardian.redteam.local_lab.planner import LLMAttackPlanner
from llm_guardian.redteam.local_lab.models import PreviousAttempt

@pytest.fixture
def planner():
    # Make sure we don't accidentally hit Groq during init if something changes
    with patch.dict(os.environ, {"GROQ_API_KEY": "fake"}):
        return LLMAttackPlanner()

@pytest.fixture
def attempts():
    return [
        PreviousAttempt(
            attempt_number=1,
            prompt="Prompt 1",
            response="Secret 1",
            outcome_type="filtered",
            solved=False,
            observation_summary="failed",
            detected_hint_type="tool_hint",
            selected_tactic="test tactic 1",
            error_category="error 1",
            is_duplicate=False
        ),
        PreviousAttempt(
            attempt_number=2,
            prompt="Prompt 2",
            response="Secret 2",
            outcome_type="refusal",
            solved=False,
            observation_summary="failed",
            selected_tactic="test tactic 2",
        ),
        PreviousAttempt(
            attempt_number=3,
            prompt="Prompt 3",
            response="Secret 3",
            outcome_type="success",
            solved=True,
            observation_summary="success",
            selected_tactic="test tactic 3",
        ),
        PreviousAttempt(
            attempt_number=4,
            prompt="Prompt 4",
            response="Secret 4",
            outcome_type="filtered",
            solved=False,
            observation_summary="failed",
            selected_tactic="scripted",
        ),
        PreviousAttempt(
            attempt_number=5,
            prompt="Prompt 5",
            response="Secret 5",
            outcome_type="filtered",
            solved=False,
            observation_summary="failed",
            selected_tactic="test tactic 5",
        )
    ]

@patch.dict(os.environ, {"LLM_GUARDIAN_PLANNER_HISTORY_WINDOW": "2"})
def test_integer_history_window(planner, attempts):
    history_json = planner._format_history(attempts)
    history = json.loads(history_json)
    
    # Window is 2, so it should look at attempts [4, 5].
    # But attempt 4 is scripted, so it should be excluded!
    # So only attempt 5 is returned.
    assert len(history) == 1
    assert history[0]["attempt_number"] == 5

@patch.dict(os.environ, {"LLM_GUARDIAN_PLANNER_HISTORY_WINDOW": "all"})
def test_all_history_window(planner, attempts):
    history_json = planner._format_history(attempts)
    history = json.loads(history_json)
    
    # Should keep all except scripted (attempt 4) -> 4 items
    assert len(history) == 4
    
    # Attempt 3 is solved, so response should be excluded
    solved_entry = next(h for h in history if h["attempt_number"] == 3)
    assert "target_response" not in solved_entry
    assert solved_entry["target_response_summary"] == "success"

@patch.dict(os.environ, {"LLM_GUARDIAN_PLANNER_HISTORY_WINDOW": "invalid"})
def test_invalid_history_window_fallback(planner, attempts):
    history_json = planner._format_history(attempts)
    history = json.loads(history_json)
    
    # Fallback is 3. Last 3 attempts are [3, 4, 5].
    # Attempt 4 is scripted and excluded.
    # So we should have 2 attempts [3, 5].
    assert len(history) == 2
    assert history[0]["attempt_number"] == 3
    assert history[1]["attempt_number"] == 5

@patch.dict(os.environ, {"LLM_GUARDIAN_PLANNER_HISTORY_WINDOW": "all"})
def test_metadata_exposure(planner, attempts):
    history_json = planner._format_history(attempts)
    history = json.loads(history_json)
    
    # Attempt 1 should have rich context
    att1 = next(h for h in history if h["attempt_number"] == 1)
    assert att1["detected_hint_type"] == "tool_hint"
    assert att1["selected_tactic"] == "test tactic 1"
    assert att1["error_category"] == "error 1"
    assert "is_duplicate" not in att1 # False means we didn't add it
    assert att1["target_response"] == "Secret 1"
    
    # Attempt 3 solved, no response
    att3 = next(h for h in history if h["attempt_number"] == 3)
    assert "target_response" not in att3
    
    # Attempt 4 scripted, should not exist
    scripted_exists = any(h for h in history if h["attempt_number"] == 4)
    assert not scripted_exists

from llm_guardian.redteam.local_lab.models import ObservationState

@patch.dict(os.environ, {"LLM_GUARDIAN_PLANNER_PROVIDER": "gemini", "GEMINI_API_KEY": "fake_gemini_key", "LLM_GUARDIAN_PLANNER_STRUCTURED_OUTPUT": "true"})
def test_planner_provider_selection_gemini():
    planner = LLMAttackPlanner()
    assert planner.provider_name == "gemini"
    # Ensure google.genai was lazy loaded and handles mock nicely
    # We don't want to make real API calls, just verify provider selection

@patch.dict(os.environ, {"LLM_GUARDIAN_PLANNER_PROVIDER": "groq"})
def test_planner_provider_selection_groq():
    planner = LLMAttackPlanner()
    assert planner.provider_name == "groq"

@patch.dict(os.environ, {}, clear=True)
def test_planner_provider_selection_default():
    planner = LLMAttackPlanner()
    assert planner.provider_name == "groq"

@patch.dict(os.environ, {"LLM_GUARDIAN_PLANNER_PROVIDER": "gemini"}, clear=True)
def test_gemini_missing_key_handled_cleanly():
    planner = LLMAttackPlanner()
    # It shouldn't crash on init
    assert planner.provider_name == "gemini"
    
    state = ObservationState(
        level_id=1,
        title="Test",
        public_description="test desc",
        previous_attempts=[],
        current_turn=1,
        max_attempts=8
    )
    decision, error = planner.propose_next_action(state)
    assert decision is None
    assert error == "missing_gemini_api_key"

class DummyGeminiResponse:
    def __init__(self, text):
        self.text = text

class DummyGeminiModels:
    def __init__(self, text_to_return, exception_to_raise=None):
        self.text_to_return = text_to_return
        self.exception_to_raise = exception_to_raise
        
    def generate_content(self, model, contents, config):
        if self.exception_to_raise:
            raise self.exception_to_raise
        return DummyGeminiResponse(self.text_to_return)

class DummyGeminiClient:
    def __init__(self, text_to_return, exception_to_raise=None):
        self.models = DummyGeminiModels(text_to_return, exception_to_raise)

@patch.dict(os.environ, {"LLM_GUARDIAN_PLANNER_PROVIDER": "gemini", "GEMINI_API_KEY": "fake_key"})
def test_gemini_valid_json_parsing():
    planner = LLMAttackPlanner()
    planner.provider.client = DummyGeminiClient(json.dumps({
        "strategy_name": "Test Strategy",
        "rationale_summary": "Test rationale",
        "selected_prompt": "Test prompt",
        "expected_bypass_type": "obfuscation",
        "confidence": 0.9,
        "observation_summary": "observed",
        "next_action_summary": "next",
    }))
    
    state = ObservationState(
        level_id=1, title="Test", public_description="test desc",
        previous_attempts=[], current_turn=1, max_attempts=8
    )
    decision, error = planner.propose_next_action(state)
    assert error is None
    assert decision is not None
    assert decision.strategy_name == "Test Strategy"
    assert decision.selected_prompt == "Test prompt"

@patch.dict(os.environ, {"LLM_GUARDIAN_PLANNER_PROVIDER": "gemini", "GEMINI_API_KEY": "fake_key"})
def test_gemini_malformed_json_parsing():
    planner = LLMAttackPlanner()
    planner.provider.client = DummyGeminiClient("not json")
    
    state = ObservationState(
        level_id=1, title="Test", public_description="test desc",
        previous_attempts=[], current_turn=1, max_attempts=8
    )
    decision, error = planner.propose_next_action(state)
    assert decision is None
    assert error is not None
    assert "JSON parse error" in error

@patch.dict(os.environ, {"LLM_GUARDIAN_PLANNER_PROVIDER": "gemini", "GEMINI_API_KEY": "fake_key"})
def test_gemini_api_error_handling():
    from google.genai.errors import APIError
    planner = LLMAttackPlanner()
    planner.provider.client = DummyGeminiClient(
        "dummy", 
        exception_to_raise=APIError(500, {"error": {"message": "Mocked API Error"}})
    )
    
    state = ObservationState(
        level_id=1, title="Test", public_description="test desc",
        previous_attempts=[], current_turn=1, max_attempts=8
    )
    decision, error = planner.propose_next_action(state)
    assert decision is None
    assert error is not None
    assert "Gemini API Error" in error

