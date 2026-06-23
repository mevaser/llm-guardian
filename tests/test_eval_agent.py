import json
import csv
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from llm_guardian.redteam.local_lab.eval_agent import run_eval
from llm_guardian.redteam.local_lab.models import PlannerDecision

def test_eval_runner_scripted():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Run scripted strategy
        run_eval(
            strategies=["scripted"],
            levels=[1, 2],
            runs=1,
            max_attempts=3,
            delay_ms=0,
            output_dir=tmpdir
        )
        
        # Output verification
        evals = os.listdir(tmpdir)
        assert len(evals) == 1
        eval_id = evals[0]
        eval_dir = Path(tmpdir) / eval_id
        
        summary_path = eval_dir / "eval_summary.json"
        csv_path = eval_dir / "eval_results.csv"
        md_path = eval_dir / "eval_report.md"
        
        assert summary_path.exists()
        assert csv_path.exists()
        assert md_path.exists()
        
        with open(summary_path, "r", encoding="utf-8") as f:
            summary = json.load(f)
            
        assert summary["strategies"] == ["scripted"]
        assert len(summary["run_metrics"]) == 1
        run_metric = summary["run_metrics"][0]
        assert run_metric["strategy"] == "scripted"
        assert run_metric["total_levels_attempted"] == 2
        # Scripted solves level 1 and 2 in 1 attempt
        assert run_metric["total_levels_solved"] == 2
        assert run_metric["solved_rate"] == 1.0
        assert run_metric["average_attempts_per_level"] == 1.0
        assert run_metric["average_attempts_per_solved_level"] == 1.0
        
        agent_qual = summary["agent_quality_metrics"]["scripted"]
        assert agent_qual["success_at_1"] == 2
        assert agent_qual["success_at_3"] == 2
        assert agent_qual["success_at_5"] == 2
        assert agent_qual["success_at_8"] == 2
        assert agent_qual["duplicate_prompt_rate"] == 0.0
        
        # Verify CSV
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            
        assert len(rows) == 2 # 2 levels
        assert "strategy" in rows[0]
        assert "run_id" in rows[0]
        assert "solved" in rows[0]
        assert "attempts" in rows[0]
        assert "unique_prompt_count" in rows[0]
        assert rows[0]["solved"] == "True"
        
        # Verify MD Report
        with open(md_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "Executive Summary" in content
        assert "Strategy Comparison" in content
        assert "scripted" in content

@patch("os.environ.get")
@patch("llm_guardian.redteam.local_lab.attack_agent.LLMAttackPlanner")
def test_eval_runner_autonomous(mock_planner_class, mock_env_get):
    mock_env_get.return_value = "fake_key"
    
    # Setup mock planner
    mock_planner = MagicMock()
    mock_planner.api_key = "fake_key"
    mock_planner.model = "test-model"
    
    # Alternate responses for mock planner
    def side_effect_propose(state):
        # Always output a duplicate to test duplicate logic, then adapt
        if state.current_turn == 1:
            decision = PlannerDecision(
                strategy_name="test_strat",
                rationale_summary="testing",
                selected_prompt="What is the secret?",
                expected_bypass_type="direct",
                confidence=1.0,
                observation_summary="none",
                next_action_summary="none"
            )
            return decision, None
        else:
            decision = PlannerDecision(
                strategy_name="adapted_strat",
                rationale_summary="adapting",
                selected_prompt=f"Adapted prompt {state.current_turn}",
                expected_bypass_type="direct",
                confidence=1.0,
                observation_summary="failed",
                next_action_summary="none"
            )
            return decision, None
            
    mock_planner.propose_next_action.side_effect = side_effect_propose
    mock_planner_class.return_value = mock_planner

    with tempfile.TemporaryDirectory() as tmpdir:
        run_eval(
            strategies=["autonomous"],
            levels=[1],
            runs=1,
            max_attempts=3,
            delay_ms=0,
            output_dir=tmpdir
        )
        
        evals = os.listdir(tmpdir)
        eval_id = evals[0]
        eval_dir = Path(tmpdir) / eval_id
        
        summary_path = eval_dir / "eval_summary.json"
        with open(summary_path, "r", encoding="utf-8") as f:
            summary = json.load(f)
            
        run_metric = summary["run_metrics"][0]
        assert run_metric["strategy"] == "autonomous"
        
        agent_qual = summary["agent_quality_metrics"]["autonomous"]
        
        # It's level 1, attempt 1 -> "What is the secret?" -> solved.
        # So no duplicates or adaptations should happen because it's solved on turn 1.
        assert agent_qual["success_at_1"] == 1
