import pytest
import os
import json
from unittest.mock import patch, MagicMock
from urllib.error import URLError, HTTPError

from llm_guardian.redteam.local_lab.groq_composer import compose_response

@pytest.fixture
def mock_env():
    with patch.dict(os.environ, {"GROQ_API_KEY": "test-key"}):
        yield

def test_missing_api_key_fallback():
    with patch.dict(os.environ, {}, clear=True):
        resp, diagnostics = compose_response(
            level_id=1,
            level_title="Test",
            defense_description="None",
            user_prompt="Hello",
            intent="small_talk",
            outcome_type="safe_answer",
            deterministic_base_response="Deterministic fallback.",
            safe_state_summary={}
        )
        assert resp == "Deterministic fallback."
        assert diagnostics["fallback_reason"] == "missing_groq_api_key"

@patch("urllib.request.urlopen")
def test_safe_answer_with_api_key(mock_urlopen, mock_env):
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "choices": [{"message": {"content": "The weather is lovely here."}}]
    }).encode("utf-8")
    
    mock_response.getcode.return_value = 200
    mock_urlopen.return_value.__enter__.return_value = mock_response

    resp, diagnostics = compose_response(
        level_id=1,
        level_title="Test",
        defense_description="None",
        user_prompt="Hello",
        intent="small_talk",
        outcome_type="safe_answer",
        deterministic_base_response="Base.",
        safe_state_summary={}
    )
    
    assert resp == "The weather is lovely here."
    assert diagnostics["groq_http_status"] == 200
    assert diagnostics["fallback_reason"] is None
    
    # Assert headers and method
    req = mock_urlopen.call_args[0][0]
    assert req.method == "POST"
    assert req.headers.get("User-agent") == "llm-guardian-wizard-lab/0.1"
    assert req.headers.get("Accept") == "application/json"
    assert req.headers.get("Content-type") == "application/json"
    assert req.headers.get("Authorization") == "Bearer test-key"

@patch("urllib.request.urlopen")
def test_timeout_fallback(mock_urlopen, mock_env):
    mock_urlopen.side_effect = URLError(TimeoutError("Timeout"))
    
    resp, diagnostics = compose_response(
        level_id=1,
        level_title="Test",
        defense_description="None",
        user_prompt="Hello",
        intent="small_talk",
        outcome_type="success",
        deterministic_base_response="Base fallback.",
        safe_state_summary={}
    )
    
    assert resp == "Base fallback."
    assert diagnostics["fallback_reason"] == "timeout"

@patch("urllib.request.urlopen")
def test_http_401_fallback(mock_urlopen, mock_env):
    mock_urlopen.side_effect = HTTPError("url", 401, "Unauthorized", {}, None)
    
    resp, diagnostics = compose_response(
        level_id=1, level_title="T", defense_description="D",
        user_prompt="H", intent="I", outcome_type="O",
        deterministic_base_response="Base", safe_state_summary={}
    )
    
    assert resp == "Base"
    assert diagnostics["fallback_reason"] == "http_401_invalid_key"

@patch("urllib.request.urlopen")
def test_http_403_fallback(mock_urlopen, mock_env):
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"error": "Forbidden"}'
    mock_urlopen.side_effect = HTTPError("url", 403, "Forbidden", {}, mock_response)
    
    resp, diagnostics = compose_response(
        level_id=1, level_title="T", defense_description="D",
        user_prompt="H", intent="I", outcome_type="O",
        deterministic_base_response="Base", safe_state_summary={}
    )
    
    assert resp == "Base"
    assert diagnostics["fallback_reason"] == "http_403_forbidden"

@patch("urllib.request.urlopen")
def test_http_404_fallback(mock_urlopen, mock_env):
    mock_urlopen.side_effect = HTTPError("url", 404, "Not Found", {}, None)
    
    resp, diagnostics = compose_response(
        level_id=1, level_title="T", defense_description="D",
        user_prompt="H", intent="I", outcome_type="O",
        deterministic_base_response="Base", safe_state_summary={}
    )
    
    assert resp == "Base"
    assert diagnostics["fallback_reason"] == "http_404_model_not_found"

@patch("urllib.request.urlopen")
def test_http_429_fallback(mock_urlopen, mock_env):
    mock_urlopen.side_effect = HTTPError("url", 429, "Too Many Requests", {}, None)
    
    resp, diagnostics = compose_response(
        level_id=1, level_title="T", defense_description="D",
        user_prompt="H", intent="I", outcome_type="O",
        deterministic_base_response="Base", safe_state_summary={}
    )
    
    assert resp == "Base"
    assert diagnostics["fallback_reason"] == "http_429_rate_limit"
