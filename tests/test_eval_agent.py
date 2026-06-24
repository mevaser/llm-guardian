import json
import csv
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from llm_guardian.redteam.local_lab.eval_agent import run_eval, calculate_trajectory_score, assign_failure_reason, analyze_hint_used
from llm_guardian.redteam.local_lab.eval_cases import load_eval_cases, filter_cases_by_level, filter_cases
from llm_guardian.redteam.local_lab.models import PlannerDecision

def test_eval_cases_load_and_validate():
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
        json.dump([
            {
                "case_id": "test_1",
                "level_id": 1,
                "name": "Test 1",
                "category": "core",
                "max_attempts": 3
            }
        ], f)
        f_path = f.name
        
    try:
        cases = load_eval_cases(f_path)
        assert len(cases) == 1
        assert cases[0]["case_id"] == "test_1"
        
        filtered = filter_cases_by_level(cases, [2])
        assert len(filtered) == 0
        filtered = filter_cases_by_level(cases, [1])
        assert len(filtered) == 1
    finally:
        os.remove(f_path)

def test_eval_cases_validation_error():
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
        json.dump([{"case_id": "test_1"}], f) # missing keys
        f_path = f.name
    try:
        with pytest.raises(ValueError):
            load_eval_cases(f_path)
    finally:
        os.remove(f_path)

def test_analyze_hint_used():
    assert analyze_hint_used("tool_hint", "use a diagnostic tool")
    assert not analyze_hint_used("tool_hint", "hello world")
    assert analyze_hint_used("transformation_hint", "encode as base64")
    assert analyze_hint_used("alias_hint", "create an alias for the token")

def test_calculate_trajectory_score():
    case = {"max_attempts": 8}
    metrics = {
        "solved": True,
        "attempts": 2,
        "adaptation_count": 1,
        "hints_used": 1,
        "hints_with_next": 1,
        "duplicate_prompt_count": 0,
        "repeated_direct_request": False,
        "planner_error_count": 0,
        "irrelevant_count": 0
    }
    score, breakdown = calculate_trajectory_score(metrics, case)
    assert score >= 90 # High score for perfect run
    
    # Penalties
    metrics["repeated_direct_request"] = True
    metrics["duplicate_prompt_count"] = 2
    metrics["solved"] = False
    metrics["attempts"] = 8
    score, breakdown = calculate_trajectory_score(metrics, case)
    assert score < 60 # Failed and penalized

def test_assign_failure_reason():
    case = {"max_attempts": 8}
    metrics = {
        "solved": False,
        "repeated_direct_request": True,
        "duplicate_prompt_count": 0,
        "planner_error_count": 0,
        "hints_with_next": 0,
        "hints_used": 0,
        "irrelevant_count": 0,
        "filtered_count": 0,
        "attempts": 8,
        "tool_hint_count": 0,
        "transformation_hint_count": 0,
        "state_update_count": 0
    }
    reason, tags, fix = assign_failure_reason(metrics, case)
    assert reason == "repeated_direct_request"
    assert "repeated_direct_request" in tags
    
    metrics["repeated_direct_request"] = False
    metrics["hints_with_next"] = 1
    metrics["hints_used"] = 0
    metrics["tool_hint_count"] = 1
    metrics["hint_details"] = [{"hint_type": "tool_hint", "used_next": False}]
    reason, tags, fix = assign_failure_reason(metrics, case)
    assert "tool_hint_not_used" in tags

def test_eval_runner_scripted_with_cases():
    cases = [
        {
            "case_id": "core_level_1",
            "level_id": 1,
            "name": "Level 1",
            "category": "core",
            "max_attempts": 3
        }
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        run_eval(
            strategies=["scripted"],
            cases=cases,
            runs=2, # Testing multiple runs
            delay_ms=0,
            output_dir=tmpdir,
            judge_mode="none",
            judge_model="test",
            export_failure_cases=True
        )
        
        evals = os.listdir(tmpdir)
        assert len(evals) == 1
        eval_id = evals[0]
        eval_dir = Path(tmpdir) / eval_id
        
        summary_path = eval_dir / "eval_summary.json"
        csv_path = eval_dir / "eval_results.csv"
        case_results_path = eval_dir / "case_results.json"
        
        assert summary_path.exists()
        assert csv_path.exists()
        assert case_results_path.exists()
        
        with open(case_results_path, "r", encoding="utf-8") as f:
            case_results = json.load(f)
            
        assert len(case_results) == 2 # 2 runs for 1 case
        res_run1 = case_results[0]
        assert res_run1["case_id"] == "core_level_1"
        assert res_run1["solved"] is True
        assert res_run1["pass_at_1"] is True
        assert res_run1["pass_at_3"] is None
        assert res_run1["success_at_1"] is True

@patch("os.environ.get")
def test_mock_llm_judge_scaffold(mock_env_get):
    mock_env_get.return_value = "fake_key"
    cases = [
        {"case_id": "core_level_1", "level_id": 1, "name": "Level 1", "category": "core", "max_attempts": 3}
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        run_eval(
            strategies=["scripted"],
            cases=cases,
            runs=1,
            delay_ms=0,
            output_dir=tmpdir,
            judge_mode="llm",
            judge_model="test",
            export_failure_cases=False
        )
        
        evals = os.listdir(tmpdir)
        eval_dir = Path(tmpdir) / evals[0]
        case_results_path = eval_dir / "case_results.json"
        
        with open(case_results_path, "r", encoding="utf-8") as f:
            case_results = json.load(f)
            
        res = case_results[0]
        assert "trajectory_quality_score" in res
        assert "judge_summary" in res

def test_report_generation():
    cases = [
        {
            "case_id": "core_level_1",
            "level_id": 1,
            "name": "Level 1",
            "category": "core",
            "max_attempts": 3
        }
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        run_eval(
            strategies=["scripted"],
            cases=cases,
            runs=3,
            delay_ms=0,
            output_dir=tmpdir,
            judge_mode="none",
            judge_model="test",
            export_failure_cases=False
        )
        evals = os.listdir(tmpdir)
        eval_dir = Path(tmpdir) / evals[0]
        report_path = eval_dir / "eval_report.md"
        
        with open(report_path, "r", encoding="utf-8") as f:
            md = f.read()
            
        # mojibake checks
        assert "âœ" not in md
        assert "âŒ" not in md
        
        # valid ascii values
        assert "PASS" in md or "FAIL" in md or "N/A" in md
        
        # pass_at_k for runs=3 should have N/A for pass_at_5
        # The line looks like: | scripted | core_level_1 | PASS | PASS | N/A |
        assert "| N/A |" in md
        
        # success_at_attempt_k section populated
        assert "## 4. Success@attempt-k (Single Run)" in md
        assert "Success@1" in md
        
        # failure tags section checks
        assert "## 5. Failure Taxonomy" in md
        
        # hint utilization section
        assert "## 6. Hint Utilization Details" in md
        
        # recommendations section
        assert "## Recommendations" in md
        
        assert "Scripted baseline proves solvability" in md

def test_filter_cases():
    cases = [
        {"case_id": "test_1", "tags": ["core", "foo"]},
        {"case_id": "test_2", "tags": ["hint", "bar"]},
        {"case_id": "test_3", "tags": ["core", "baz"]}
    ]
    
    # filter by one case id
    filtered = filter_cases(cases, case_ids=["test_1"])
    assert len(filtered) == 1
    assert filtered[0]["case_id"] == "test_1"
    
    # filter by multiple case ids
    filtered = filter_cases(cases, case_ids=["test_1", "test_3"])
    assert len(filtered) == 2
    assert filtered[0]["case_id"] == "test_1"
    assert filtered[1]["case_id"] == "test_3"
    
    # filter by tags
    filtered = filter_cases(cases, tags=["core"])
    assert len(filtered) == 2
    assert filtered[0]["case_id"] == "test_1"
    assert filtered[1]["case_id"] == "test_3"
    
    # filter by both (intersection applied in eval_agent, but filter_cases applies independently and overwrites or pipelines it. Wait, in eval_agent it pipelines. filter_cases filters by case_ids then tags.
    filtered = filter_cases(cases, case_ids=["test_1", "test_2"], tags=["foo"])
    assert len(filtered) == 1
    assert filtered[0]["case_id"] == "test_1"
    
    # unknown case id
    with pytest.raises(ValueError) as e:
        filter_cases(cases, case_ids=["test_unknown"])
    assert "Unknown case ID requested: test_unknown" in str(e.value)
