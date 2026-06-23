import json
from pathlib import Path
from typing import List, Dict, Any, Optional

def load_eval_cases(file_path: str) -> List[Dict[str, Any]]:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Eval cases file not found: {file_path}")
        
    with open(path, "r", encoding="utf-8") as f:
        cases = json.load(f)
        
    if not isinstance(cases, list):
        raise ValueError("Eval cases must be a JSON array.")
        
    for idx, case in enumerate(cases):
        required_keys = {"case_id", "level_id", "name", "category", "max_attempts"}
        missing = required_keys - set(case.keys())
        if missing:
            raise ValueError(f"Case at index {idx} is missing required keys: {missing}")
            
    return cases

def filter_cases_by_level(cases: List[Dict[str, Any]], levels: List[int]) -> List[Dict[str, Any]]:
    return [c for c in cases if c["level_id"] in levels]
