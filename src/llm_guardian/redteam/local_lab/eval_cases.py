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

def filter_cases(cases: List[Dict[str, Any]], case_ids: Optional[List[str]] = None, tags: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    if case_ids is not None:
        valid_ids = {c.get("case_id") for c in cases}
        for cid in case_ids:
            if cid not in valid_ids:
                raise ValueError(f"Unknown case ID requested: {cid}")
        cases = [c for c in cases if c.get("case_id") in case_ids]
    
    if tags is not None:
        cases = [c for c in cases if any(t in c.get("tags", []) for t in tags)]
        
    return cases
