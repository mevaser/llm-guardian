import os
import json
import tempfile
from pathlib import Path
from llm_guardian.redteam.local_lab.observability import Redactor, ObservabilityLogger

def test_redactor_strings():
    text1 = "Here is my key: gsk_1234567890123456789012345678"
    redacted1 = Redactor.redact_string(text1)
    assert "gsk_" not in redacted1
    assert "[REDACTED_GROQ_KEY]" in redacted1

    text2 = "Auth header: Authorization: Bearer some-secret-token"
    redacted2 = Redactor.redact_string(text2)
    assert "some-secret-token" not in redacted2
    assert "Authorization: [REDACTED]" in redacted2

    text3 = "Here is sk-abcdefghijklmnopqrstuvwxyz12345678901234 key"
    redacted3 = Redactor.redact_string(text3)
    assert "sk-" not in redacted3
    assert "[REDACTED_OPENAI_KEY]" in redacted3

    text4 = 'api_key="my_secret_123"'
    redacted4 = Redactor.redact_string(text4)
    assert "my_secret_123" not in redacted4
    assert "api_key=[REDACTED]" in redacted4
    
    text5 = "normal string with no secrets"
    assert Redactor.redact_string(text5) == text5

def test_redactor_dicts():
    data = {
        "headers": {
            "Authorization": "Bearer 123456"
        },
        "payload": {
            "key": "gsk_1234567890123456789012345678",
            "message": "hello"
        },
        "list_data": ["sk-abcdefghijklmnopqrstuvwxyz12345678901234"]
    }
    redacted = Redactor.redact_dict(data)
    assert "Bearer" in redacted["headers"]["Authorization"]
    assert "123456" not in redacted["headers"]["Authorization"]
    assert "[REDACTED_GROQ_KEY]" == redacted["payload"]["key"]
    assert "hello" == redacted["payload"]["message"]
    assert "[REDACTED_OPENAI_KEY]" == redacted["list_data"][0]

def test_observability_logger():
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = ObservabilityLogger(run_id="test_run", base_dir=tmpdir)
        
        # Check meta creation
        meta_path = Path(tmpdir) / "test_run" / "run_meta.json"
        assert meta_path.exists()
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
            assert meta["run_id"] == "test_run"
            assert meta["status"] == "running"

        # Check events
        logger.log_event("wizard_lab_api", "run_started", message="Run starting with secret gsk_1234567890123456789012345678")
        events_path = Path(tmpdir) / "test_run" / "events.jsonl"
        assert events_path.exists()
        with open(events_path, "r", encoding="utf-8") as f:
            event = json.loads(f.readline())
            assert event["component"] == "wizard_lab_api"
            assert "[REDACTED_GROQ_KEY]" in event["message"]
            assert "gsk_" not in event["message"]

        # Check trajectory
        logger.add_trajectory_attempt(1, "hello", "hi", True)
        trajectory_path = Path(tmpdir) / "test_run" / "trajectory.json"
        assert trajectory_path.exists()
        with open(trajectory_path, "r", encoding="utf-8") as f:
            traj = json.load(f)
            assert len(traj) == 1
            assert traj[0]["solved"] is True

        # Finish run
        logger.update_meta(levels_attempted=1, levels_solved=1, levels_failed=0)
        logger.finish_run()
        
        # Check report
        report_path = Path(tmpdir) / "test_run" / "report.md"
        assert report_path.exists()
        with open(report_path, "r", encoding="utf-8") as f:
            report_content = f.read()
            assert "test_run" in report_content
            assert "**Levels Solved:** 1" in report_content
            assert "✅ Yes" in report_content
