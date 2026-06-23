import tempfile
import json
from pathlib import Path

from llm_guardian.redteam.local_lab.attack_agent import AttackRunner, LocalLabAdapter, parse_levels

def test_parse_levels():
    assert parse_levels("1-3") == [1, 2, 3]
    assert parse_levels("1,3,5") == [1, 3, 5]
    assert parse_levels("1-2,5") == [1, 2, 5]

def test_scripted_attack_runner_solves_all():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = LocalLabAdapter()
        runner = AttackRunner(
            adapter=adapter,
            strategy_name="scripted",
            response_mode="deterministic",
            max_attempts=8,
            base_dir=tmpdir
        )
        
        levels = list(range(1, 9))
        runner.run_all(levels)
        
        # Verify logs
        meta_path = Path(tmpdir) / runner.logger.run_id / "run_meta.json"
        assert meta_path.exists()
        
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
            assert meta["levels_attempted"] == 8
            assert meta["levels_solved"] == 8
            assert meta["levels_failed"] == 0
            assert meta["strategy"] == "scripted"
            assert meta["status"] == "completed"

        trajectory_path = Path(tmpdir) / runner.logger.run_id / "trajectory.json"
        assert trajectory_path.exists()
        
        # Verify that all levels were solved
        with open(trajectory_path, "r", encoding="utf-8") as f:
            traj = json.load(f)
            # Find the final attempt for each level and verify solved=True
            level_status = {}
            for t in traj:
                if t["solved"]:
                    level_status[t["level_id"]] = True
            
            assert len(level_status) == 8
            for lvl in range(1, 9):
                assert level_status.get(lvl) is True
