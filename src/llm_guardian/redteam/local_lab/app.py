import uuid
from typing import Dict, List
import uvicorn
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse, JSONResponse
from pathlib import Path

from llm_guardian.redteam.local_lab.models import (
    LevelInfo, SessionStart, SubmitRequest, SubmitResponse, SessionState, Attempt
)
from llm_guardian.redteam.local_lab.levels import LEVELS, evaluate_prompt
from llm_guardian.redteam.local_lab import groq_composer
from llm_guardian.redteam.local_lab.observability import Redactor
from pydantic import BaseModel
import logging
import os
import json
import subprocess

logger = logging.getLogger("llm_guardian.redteam.local_lab")

from llm_guardian.env import load_local_env
# Load .env file if it exists, without overriding existing environment variables
dotenv_loaded = load_local_env()

def is_duplicate_attempt(attempt: dict) -> bool:
    status = str(attempt.get("status", "")).lower()
    fallback_reason = str(attempt.get("fallback_reason", "")).lower()
    return (
        attempt.get("duplicate") is True
        or attempt.get("is_duplicate") is True
        or "duplicate" in status
        or "duplicate" in fallback_reason
    )

logger.info("Startup: local env loaded")
groq_key = os.environ.get("GROQ_API_KEY")
groq_key_present = bool(groq_key)
groq_key_length = len(groq_key) if groq_key_present else 0
logger.info(f"Startup: groq_key_present={groq_key_present}, groq_key_length={groq_key_length}")
logger.info(f"Startup: cwd={os.getcwd()}")

app = FastAPI(title="Wizard Leak Lab")

# In-memory session store
sessions: Dict[str, SessionState] = {}

# Mount static files
STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
def read_root():
    return FileResponse(str(STATIC_DIR / "index.html"))

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(content=b"", media_type="image/x-icon")

@app.get("/admin")
def read_admin():
    return FileResponse(str(STATIC_DIR / "admin.html"))

@app.get("/evals")
def read_evals():
    return FileResponse(str(STATIC_DIR / "evals.html"))

@app.get("/presentation")
def read_presentation():
    return FileResponse(str(STATIC_DIR / "presentation.html"))

@app.get("/api/levels", response_model=List[LevelInfo])
def get_levels():
    """Returns a list of all available levels."""
    return [
        LevelInfo(
            level_id=lvl.level_id,
            title=lvl.title,
            public_description=lvl.public_description,
            objective=lvl.objective,
            opening_message=lvl.opening_message
        ) for lvl in LEVELS.values()
    ]

@app.get("/api/debug/config")
def get_debug_config():
    """Returns safe diagnostic configuration."""
    groq_key = os.environ.get("GROQ_API_KEY")
    return {
        "groq_key_present": bool(groq_key),
        "groq_key_length": len(groq_key) if groq_key else 0,
        "cwd": os.getcwd(),
        "dotenv_loaded": dotenv_loaded,
        "groq_model": "llama-3.1-8b-instant"
    }

@app.post("/api/session/start", response_model=SessionStart)
def start_session(level_id: int):
    """Starts a new session for a specific level."""
    if level_id not in LEVELS:
        raise HTTPException(status_code=404, detail="Level not found")
        
    session_id = str(uuid.uuid4())
    lvl = LEVELS[level_id]
    
    sessions[session_id] = SessionState(
        session_id=session_id,
        level_id=level_id,
        attempts=[],
        state={},
        solved=False
    )
    
    return SessionStart(
        session_id=session_id,
        level_info=LevelInfo(
            level_id=lvl.level_id,
            title=lvl.title,
            public_description=lvl.public_description,
            objective=lvl.objective,
            opening_message=lvl.opening_message
        )
    )

@app.get("/api/session/{session_id}", response_model=SessionState)
def get_session(session_id: str):
    """Gets the state of a session."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    return sessions[session_id]

@app.post("/api/session/submit", response_model=SubmitResponse)
def submit_prompt(request: SubmitRequest):
    """Submits a prompt to the current level."""
    if request.session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
        
    session = sessions[request.session_id]
    level_id = session.level_id
    secret = LEVELS[level_id].secret
    
    # Evaluate prompt
    response_text, solved, filtered, intent, outcome_type = evaluate_prompt(session, request.prompt)
    fallback = False
    
    composer_used = False
    fallback_reason = None
    groq_http_status = None
    groq_error_type = None
    response_mode_used = "deterministic"
    
    should_call_groq = request.response_mode == "groq_live" and not solved
    
    logger.debug(f"Submit attempt: session_id={request.session_id}, level_id={level_id}, "
                 f"response_mode_requested={request.response_mode}, intent={intent}, "
                 f"outcome_type={outcome_type}, solved={solved}, filtered={filtered}, "
                 f"should_call_groq={should_call_groq}, prompt_length={len(request.prompt)}")
    
    if request.response_mode == "groq_live":
        if solved:
            # Do not send success/solved responses (which may contain transformed secrets) to Groq.
            pass
        else:
            composed, diagnostics = groq_composer.compose_response(
                level_id=level_id,
                level_title=LEVELS[level_id].title,
                defense_description=LEVELS[level_id].defense_description,
                user_prompt=request.prompt,
                intent=intent,
                outcome_type=outcome_type,
                deterministic_base_response=response_text,
                safe_state_summary=session.state
            )
            
            fallback_reason = diagnostics.get("fallback_reason")
            groq_http_status = diagnostics.get("groq_http_status")
            groq_error_type = diagnostics.get("groq_error_type")
            
            if fallback_reason:
                fallback = True
            else:
                composer_used = True
                response_mode_used = "groq_live"
                
            response_text = composed
            
    logger.debug(f"Submit completed: session_id={request.session_id}, composer_used={composer_used}, fallback_reason={fallback_reason}")
    
    # If the exact secret was found and solved is true, we mark it solved.
    # If filtered is true, solved must be false.
    if solved:
        session.solved = True
        
    # Record attempt
    attempt = Attempt(
        prompt=request.prompt,
        response=response_text,
        solved=solved
    )
    session.attempts.append(attempt)
    
    return SubmitResponse(
        response=response_text,
        solved=solved,
        filtered=filtered,
        fallback=fallback,
        response_mode_requested=request.response_mode,
        response_mode_used=response_mode_used,
        composer_used=composer_used,
        fallback_reason=fallback_reason,
        intent=intent,
        outcome_type=outcome_type,
        groq_http_status=groq_http_status,
        groq_error_type=groq_error_type
    )

RUNS_DIR = Path("reports/redteam/wizard_lab/runs")
EVALS_DIR = Path("reports/redteam/wizard_lab/evals")


class RunStartRequest(BaseModel):
    levels: str = "1-8"
    strategy: str = "autonomous"
    response_mode: str = "deterministic"
    max_attempts: int = 6
    delay_ms: int = 0
    planner_model: str = "llama-3.1-8b-instant"
    planner_temperature: float = 0.7

def run_agent_in_background(levels_str: str, strategy: str, response_mode: str, max_attempts: int, delay_ms: int, run_id: str, planner_model: str, planner_temperature: float, base_dir: str):
    logger.info(f"Starting background agent run {run_id}")
    try:
        from llm_guardian.redteam.local_lab.attack_agent import AttackRunner, parse_levels
        from llm_guardian.redteam.local_lab.adapters import LocalLabAdapter
        
        levels = parse_levels(levels_str)
        adapter = LocalLabAdapter()
        runner = AttackRunner(
            adapter=adapter,
            strategy_name=strategy,
            response_mode=response_mode,
            max_attempts=max_attempts,
            delay_ms=delay_ms,
            base_dir=base_dir,
            run_id=run_id,
            planner_model=planner_model,
            planner_temperature=planner_temperature
        )
        
        runner.run_all(levels)
    except Exception as e:
        logger.error(f"Background run {run_id} failed: {str(e)}")
        # Try to mark failed if possible
        meta_file = Path(base_dir) / run_id / "run_meta.json"
        if meta_file.exists():
            try:
                with open(meta_file, "r") as f:
                    meta = json.load(f)
                meta["status"] = "failed"
                with open(meta_file, "w") as f:
                    json.dump(meta, f)
            except Exception:
                pass

@app.post("/api/admin/runs/start")
def start_run(req: RunStartRequest, background_tasks: BackgroundTasks):
    provider = os.getenv("LLM_GUARDIAN_PLANNER_PROVIDER", "None").lower()
    
    if req.strategy == "autonomous":
        if provider == "gemini":
            if not os.getenv("GEMINI_API_KEY"):
                raise HTTPException(status_code=400, detail="Autonomous mode requires GEMINI_API_KEY when planner provider is gemini.")
        elif provider == "groq":
            if not groq_key_present:
                raise HTTPException(status_code=400, detail="Autonomous mode requires GROQ_API_KEY when planner provider is groq. Scripted baseline is still available.")
        else:
            raise HTTPException(status_code=400, detail=f"Autonomous mode requires a supported planner provider (gemini, groq). Configured: {provider}")
        
    run_id = str(uuid.uuid4())
    eval_id = f"eval_{run_id[:8]}"
    base_dir = EVALS_DIR / eval_id / "runs"
    run_dir = base_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize meta so frontend can poll immediately
    import datetime
    meta = {
        "run_id": run_id,
        "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "running",
        "strategy": req.strategy,
        "response_mode": req.response_mode,
        "levels_attempted": 0,
        "levels_solved": 0,
        "levels_failed": 0
    }
    with open(run_dir / "run_meta.json", "w") as f:
        json.dump(meta, f)
        
    background_tasks.add_task(
        run_agent_in_background,
        req.levels,
        req.strategy,
        req.response_mode,
        req.max_attempts,
        req.delay_ms,
        run_id,
        req.planner_model,
        req.planner_temperature,
        str(base_dir)
    )
    
    return {
        "message": "Run started in background.",
        "run_id": run_id,
        "eval_id": eval_id,
        "status": "running",
        "planner_provider": provider if provider != "none" else None,
        "output_dir": str(run_dir),
        "eval_dir": str(base_dir.parent),
        "run_dir": str(run_dir)
    }

import datetime

def _check_stale(meta: dict) -> dict:
    if meta.get("status") == "running" and meta.get("levels_attempted", 0) == 0:
        start_time_str = meta.get("start_time")
        if start_time_str:
            try:
                start_time = datetime.datetime.fromisoformat(start_time_str.replace("Z", "+00:00"))
                now = datetime.datetime.now(datetime.timezone.utc)
                if (now - start_time).total_seconds() > 60:
                    meta["status"] = "stale"
            except Exception:
                pass
    return meta

def _find_run_dir(run_id: str):
    import pathlib
    direct = RUNS_DIR / run_id
    if direct.exists():
        return direct
    if EVALS_DIR.exists():
        for eval_dir in EVALS_DIR.iterdir():
            if not eval_dir.is_dir(): continue
            possible = eval_dir / "runs" / run_id
            if possible.exists():
                return possible
    return None

@app.get("/api/admin/runs/{run_id}/status")
def get_run_status(run_id: str):
    run_dir = _find_run_dir(run_id)
    if not run_dir:
        raise HTTPException(status_code=404, detail="Run not found")
    meta_file = run_dir / "run_meta.json"
    if not meta_file.exists():
        raise HTTPException(status_code=404, detail="Run not found")
    with open(meta_file, "r", encoding="utf-8") as f:
        return _check_stale(json.load(f))

@app.get("/api/admin/runs")
def get_runs():
    if not RUNS_DIR.exists():
        return []
    runs = []
    for run_dir in RUNS_DIR.iterdir():
        if run_dir.is_dir():
            meta_file = run_dir / "run_meta.json"
            if meta_file.exists():
                with open(meta_file, "r", encoding="utf-8") as f:
                    runs.append(_check_stale(json.load(f)))
    runs.sort(key=lambda x: x.get("start_time", ""), reverse=True)
    return runs

@app.get("/api/admin/runs/{run_id}")
def get_run(run_id: str):
    run_dir = _find_run_dir(run_id)
    if not run_dir:
        raise HTTPException(status_code=404, detail="Run not found")
    meta_file = run_dir / "run_meta.json"
    if not meta_file.exists():
        raise HTTPException(status_code=404, detail="Run not found")
    with open(meta_file, "r", encoding="utf-8") as f:
        return _check_stale(json.load(f))

from fastapi.responses import PlainTextResponse, JSONResponse

@app.get("/api/admin/runs/{run_id}/latest-decision")
def get_latest_decision(run_id: str):
    if ".." in run_id or "/" in run_id or "\\\\" in run_id:
        raise HTTPException(status_code=400, detail="Invalid run_id")
    run_dir = _find_run_dir(run_id)
    if not run_dir:
        raise HTTPException(status_code=404, detail="Run not found")
        
    events_path = run_dir / "events.jsonl"
    if not events_path.exists():
        return JSONResponse({})
        
    latest_decision = None
    with open(events_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "agent_decision":
                        latest_decision = event
                except json.JSONDecodeError:
                    pass
                    
    if not latest_decision:
        return JSONResponse({})
        
    telemetry = latest_decision.get("telemetry", {})
    safe_decision = {
        "planner_provider": latest_decision.get("planner_provider", "gemini"),
        "planner_model": latest_decision.get("planner_model", "gemini-3.5-flash"),
        "strategy": latest_decision.get("strategy_name", "autonomous"),
        "level": latest_decision.get("level_id"),
        "attempt": latest_decision.get("attempt"),
        "tactic": latest_decision.get("tactic", "diagnostic_probe"),
        "prompt_selected": latest_decision.get("selected_prompt", ""),
        "rationale_summary": latest_decision.get("rationale_summary") or latest_decision.get("decision_reason", ""),
        "telemetry": {
            "planner_prompt_used": telemetry.get("planner_prompt_used", True),
            "controller_prompt_override": telemetry.get("controller_prompt_override", False),
            "planner_replan_requested": telemetry.get("planner_replan_requested", False),
            "planner_replan_reason": telemetry.get("planner_replan_reason", "none"),
            "duplicate_prompt_detected": telemetry.get("duplicate_prompt_detected", False),
            "invalid_planner_prompt_detected": telemetry.get("invalid_planner_prompt_detected", False),
            "planner_self_refusal_detected": telemetry.get("planner_self_refusal_detected", False),
            "clue_following_context_sent": telemetry.get("clue_following_context_sent", True),
            "hint_type": telemetry.get("hint_type", "none")
        }
    }
    
    return JSONResponse(Redactor.redact_dict(safe_decision))

@app.get("/api/admin/runs/{run_id}/{artifact}")
def get_run_artifact(run_id: str, artifact: str):
    valid_artifacts = ["events", "errors", "trajectory", "report"]
    if artifact not in valid_artifacts:
        raise HTTPException(status_code=400, detail="Invalid artifact")
    
    if ".." in run_id or "/" in run_id or "\\\\" in run_id:
        raise HTTPException(status_code=400, detail="Invalid run_id")
    run_dir = _find_run_dir(run_id)
    if not run_dir:
        raise HTTPException(status_code=404, detail="Run not found")
        
    if artifact == "report":
        file_path = run_dir / "report.md"
        if not file_path.exists():
            return PlainTextResponse("No report generated.")
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            return PlainTextResponse(Redactor.redact_string(content))
            
    elif artifact in ["events", "errors"]:
        file_path = run_dir / f"{artifact}.jsonl"
        if not file_path.exists():
            return []
        lines = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        lines.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return JSONResponse(Redactor.redact_dict({"data": lines})["data"])
        
    elif artifact == "trajectory":
        file_path = run_dir / "trajectory.json"
        if not file_path.exists():
            return []
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return JSONResponse(Redactor.redact_dict({"data": data})["data"])

def _build_metrics_from_runs(run_dirs: list[Path]) -> dict:
    if not run_dirs:
        return {}
        
    strategies = set()
    cases_evaluated = 0
    levels_solved = 0
    total_runtime = 0
    case_results = []
    
    for run_dir in run_dirs:
        if not run_dir.is_dir():
            continue
            
        meta_file = run_dir / "run_meta.json"
        traj_file = run_dir / "trajectory.json"
        
        if not meta_file.exists():
            continue
            
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            continue
            
        strategy = meta.get("strategy", "unknown")
        strategies.add(strategy)
        
        start_time_str = meta.get("start_time")
        end_time_str = meta.get("end_time")
        if start_time_str and end_time_str:
            try:
                start = datetime.datetime.fromisoformat(start_time_str.replace("Z", "+00:00"))
                end = datetime.datetime.fromisoformat(end_time_str.replace("Z", "+00:00"))
                total_runtime += (end - start).total_seconds()
            except Exception:
                pass
                
        run_levels_attempted = meta.get("levels_attempted", 1)
        run_levels_solved = meta.get("levels_solved", 0)
        cases_evaluated += run_levels_attempted
        levels_solved += run_levels_solved
        
        traj_data = []
        if traj_file.exists():
            try:
                with open(traj_file, "r", encoding="utf-8") as f:
                    traj_data = json.load(f)
            except Exception:
                pass
                
        has_level_ids = any("level_id" in t for t in traj_data)
        
        if has_level_ids:
            # Group by level_id
            level_groups = {}
            for t in traj_data:
                lvl = str(t.get("level_id", ""))
                if lvl not in level_groups:
                    level_groups[lvl] = []
                level_groups[lvl].append(t)
                
            for lvl, attempts_list in level_groups.items():
                first_solved_attempt = None
                wizard_prompt = "-"
                for i, t in enumerate(attempts_list):
                    if t.get("solved") is True and first_solved_attempt is None:
                        first_solved_attempt = t.get("attempt", i + 1)
                    if t.get("wizard_opening_prompt", "-") != "-":
                        wizard_prompt = t.get("wizard_opening_prompt")
                        
                case_result = {
                    "strategy": strategy,
                    "case_id": lvl,
                    "wizard_opening_prompt": wizard_prompt,
                    "solved": first_solved_attempt is not None,
                    "attempts": len(attempts_list),
                    "first_solved_attempt": first_solved_attempt,
                    "refusals": sum(1 for t in attempts_list if t.get("filtered") is True or str(t.get("outcome_type", "")).lower() == "refusal" or str(t.get("status", "")).lower() == "refused"),
                    "duplicates": sum(1 for t in attempts_list if is_duplicate_attempt(t)),
                    "main_failure_reason": None,
                    "run_id": meta.get("run_id"),
                    "success_at_1": first_solved_attempt is not None and first_solved_attempt <= 1,
                    "success_at_3": first_solved_attempt is not None and first_solved_attempt <= 3,
                    "success_at_5": first_solved_attempt is not None and first_solved_attempt <= 5,
                    "success_at_6": first_solved_attempt is not None and first_solved_attempt <= 6,
                }
                case_results.append(case_result)
        else:
            if run_levels_attempted == 1:
                # One case, legacy
                first_solved_attempt = None
                wizard_prompt = "-"
                for i, t in enumerate(traj_data):
                    if t.get("solved") is True and first_solved_attempt is None:
                        first_solved_attempt = t.get("attempt", i + 1)
                    if t.get("wizard_opening_prompt", "-") != "-":
                        wizard_prompt = t.get("wizard_opening_prompt")
                        
                case_result = {
                    "strategy": strategy,
                    "case_id": str(meta.get("current_level", "unknown")),
                    "wizard_opening_prompt": wizard_prompt,
                    "solved": meta.get("levels_solved", 0) > 0,
                    "attempts": meta.get("total_attempts", len(traj_data)),
                    "first_solved_attempt": first_solved_attempt,
                    "refusals": sum(1 for t in traj_data if t.get("filtered") is True or str(t.get("outcome_type", "")).lower() == "refusal" or str(t.get("status", "")).lower() == "refused"),
                    "duplicates": sum(1 for t in traj_data if is_duplicate_attempt(t)),
                    "main_failure_reason": meta.get("status") if meta.get("levels_failed", 0) > 0 else None,
                    "run_id": meta.get("run_id"),
                    "success_at_1": first_solved_attempt is not None and first_solved_attempt <= 1,
                    "success_at_3": first_solved_attempt is not None and first_solved_attempt <= 3,
                    "success_at_5": first_solved_attempt is not None and first_solved_attempt <= 5,
                    "success_at_6": first_solved_attempt is not None and first_solved_attempt <= 6,
                }
                case_results.append(case_result)
            else:
                # Multi-level run without level_id in trajectory
                case_result = {
                    "strategy": strategy,
                    "case_id": "Multi-level (Legacy)",
                    "solved": False,
                    "attempts": meta.get("total_attempts", len(traj_data)),
                    "first_solved_attempt": None,
                    "refusals": meta.get("refused_count", 0),
                    "duplicates": meta.get("duplicate_prompt_count", 0),
                    "main_failure_reason": "No level grouping available",
                    "run_id": meta.get("run_id"),
                    "success_at_1": False,
                    "success_at_3": False,
                    "success_at_5": False,
                    "success_at_6": False,
                }
                case_results.append(case_result)
        
    if not case_results and cases_evaluated == 0:
        return {}
        
    
    # Extract overall status from the last parsed meta, and total_attempts
    overall_status = "unknown"
    overall_attempts = 0
    for run_dir in run_dirs:
        meta_file = run_dir / "run_meta.json"
        if meta_file.exists():
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                    overall_status = meta.get("status", overall_status)
                    overall_attempts += meta.get("total_attempts", 0)
            except:
                pass

    return {
        "strategies": list(strategies),
        "status": overall_status,
        "total_attempts": overall_attempts,
        "cases_evaluated": cases_evaluated,
        "levels_solved": levels_solved,
        "runs_per_strategy": 1,
        "runtime_seconds": total_runtime,
        "case_results": case_results
    }

def _build_eval_fallback(eval_dir: Path) -> dict:
    runs_dir = eval_dir / "runs"
    if not runs_dir.exists() or not runs_dir.is_dir():
        return {}
    return _build_metrics_from_runs(list(runs_dir.iterdir()))

@app.get("/api/evals")
def get_evals(request: Request):
    include_debug = request.query_params.get("include_debug", "false").lower() == "true"
    view = request.query_params.get("view", "")
    show_all = include_debug or view == "all"

    if not EVALS_DIR.exists():
        return []
    evals = []
    if RUNS_DIR.exists():
        for run_dir in RUNS_DIR.iterdir():
            if run_dir.is_dir():
                eval_info = {"eval_id": f"admin_run_{run_dir.name[:8]}"}
                try:
                    eval_info["created_at"] = run_dir.stat().st_mtime
                except Exception:
                    eval_info["created_at"] = 0
                fallback = _build_metrics_from_runs([run_dir])
                eval_info.update(fallback)
                eval_info["eval_type"] = "Legacy Admin Run"
                if show_all:
                    evals.append(eval_info)
                    
    for eval_dir in EVALS_DIR.iterdir():
        if eval_dir.is_dir():
            eval_info = {"eval_id": eval_dir.name}
            try:
                eval_info["created_at"] = eval_dir.stat().st_mtime
            except Exception:
                eval_info["created_at"] = 0
                
            summary_file = eval_dir / "eval_summary.json"
            if summary_file.exists():
                try:
                    with open(summary_file, "r", encoding="utf-8") as f:
                        summary_data = json.load(f)
                        eval_info.update(summary_data)
                except Exception:
                    pass
            else:
                fallback = _build_eval_fallback(eval_dir)
                eval_info.update(fallback)
            
            cases_evaluated = eval_info.get("cases_evaluated", 0)
            status = eval_info.get("status", "unknown")
            strategies = eval_info.get("strategies", [])
            
            if status != "completed":
                eval_info["eval_type"] = "Partial / Running"
            elif "autonomous" in strategies and "scripted" in strategies:
                eval_info["eval_type"] = "Mixed Strategy Eval"
            elif strategies == ["scripted"]:
                eval_info["eval_type"] = "Scripted Baseline"
            elif cases_evaluated == 1:
                eval_info["eval_type"] = "Smoke / Single-Level Run"
            elif "autonomous" in strategies and cases_evaluated >= 8:
                eval_info["eval_type"] = "Core8 Benchmark"
            elif "autonomous" in strategies and 2 <= cases_evaluated < 8:
                eval_info["eval_type"] = "Autonomous Multi-Level Run"
            else:
                eval_info["eval_type"] = "Legacy Admin Run" if eval_dir.name.startswith("admin_run_") else "Unknown"

            eval_info["source"] = "legacy_admin_run" if str(eval_info["eval_id"]).startswith("admin_run_") else "eval_folder"
            eval_info["recommended_demo"] = (status == "completed" and strategies == ["autonomous"] and cases_evaluated >= 2)
            
            cases = eval_info.pop("case_results", [])
            eval_info["success_at_6_count"] = sum(1 for c in cases if c.get("success_at_6"))
            eval_info["success_at_6_total"] = len(cases)
            
            if cases_evaluated > 0 or show_all:
                evals.append(eval_info)
                
    evals.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return evals

@app.get("/api/evals/{eval_id}")
def get_eval(eval_id: str):
    if ".." in eval_id or "/" in eval_id or "\\" in eval_id:
        raise HTTPException(status_code=404, detail="Eval not found")
        
    eval_info = {"eval_id": eval_id}
    
    if eval_id.startswith("admin_run_"):
        short_id = eval_id.replace("admin_run_", "")
        run_dir = None
        if RUNS_DIR.exists():
            for d in RUNS_DIR.iterdir():
                if d.is_dir() and d.name.startswith(short_id):
                    run_dir = d
                    break
        if not run_dir:
            raise HTTPException(status_code=404, detail="Eval not found")
            
        fallback = _build_metrics_from_runs([run_dir])
        eval_info.update(fallback)
        return eval_info

    eval_dir = EVALS_DIR / eval_id
    if not eval_dir.exists():
        raise HTTPException(status_code=404, detail="Eval not found")
        
    summary_file = eval_dir / "eval_summary.json"
    
    fallback_used = False
    if summary_file.exists():
        try:
            with open(summary_file, "r", encoding="utf-8") as f:
                summary_data = json.load(f)
                eval_info.update(summary_data)
        except Exception:
            pass
            
    # Include case_results summary
    case_results_file = eval_dir / "case_results.json"
    if case_results_file.exists():
        try:
            with open(case_results_file, "r", encoding="utf-8") as f:
                cases = json.load(f)
                eval_info["case_results"] = cases
        except Exception:
            pass
    else:
        fallback = _build_eval_fallback(eval_dir)
        eval_info.update(fallback)
            
    failure_file = eval_dir / "failure_backlog.json"
    if failure_file.exists():
        try:
            with open(failure_file, "r", encoding="utf-8") as f:
                eval_info["failures"] = json.load(f)
        except Exception:
            pass

    return eval_info

@app.get("/api/evals/{eval_id}/{artifact}")
def get_eval_artifact(eval_id: str, artifact: str):
    valid_artifacts = ["eval_report", "case_results", "failure_backlog", "trajectory"]
    if artifact not in valid_artifacts:
        raise HTTPException(status_code=400, detail="Invalid artifact")
        
    if ".." in eval_id or "/" in eval_id or "\\" in eval_id:
        raise HTTPException(status_code=400, detail="Invalid eval_id")
        
    run_dir = None
    eval_dir = None
    
    if eval_id.startswith("admin_run_"):
        short_id = eval_id.replace("admin_run_", "")
        if RUNS_DIR.exists():
            for d in RUNS_DIR.iterdir():
                if d.is_dir() and d.name.startswith(short_id):
                    run_dir = d
                    break
        if not run_dir:
            raise HTTPException(status_code=404, detail="Eval not found")
    else:
        eval_dir = EVALS_DIR / eval_id
        if not eval_dir.exists():
            raise HTTPException(status_code=404, detail="Eval not found")
        
    if artifact == "eval_report":
        file_path = run_dir / "report.md" if run_dir else eval_dir / "eval_report.md"
        if file_path.exists():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    return PlainTextResponse(Redactor.redact_string(content))
            except Exception:
                return PlainTextResponse("Error reading report.")
        
        # Fallback dynamic markdown generation
        fallback = _build_eval_fallback(eval_dir) if eval_dir else _build_metrics_from_runs([run_dir])
        cases = fallback.get("case_results", [])
        lines = [f"# Eval Report: {eval_id}", ""]
        lines.append("## Summary Metrics")
        total = len(cases)
        solved = sum(1 for c in cases if c.get("solved"))
        strats = ", ".join(list(set(c.get("strategy", "unknown") for c in cases)))
        lines.append(f"- **Strategies**: {strats}")
        lines.append(f"- **Total Cases**: {total}")
        lines.append(f"- **Solved Rate**: {solved}/{total} ({(solved/total*100):.1f}%)\n" if total > 0 else "- **Solved Rate**: N/A\n")
        
        success1 = sum(1 for c in cases if c.get("success_at_1"))
        success3 = sum(1 for c in cases if c.get("success_at_3"))
        success5 = sum(1 for c in cases if c.get("success_at_5"))
        success6 = sum(1 for c in cases if c.get("success_at_6"))
        
        if total > 0:
            lines.append("### Success Rates")
            lines.append(f"- **Success@1**: {success1}/{total}")
            lines.append(f"- **Success@3**: {success3}/{total}")
            lines.append(f"- **Success@5**: {success5}/{total}")
            lines.append(f"- **Success@6**: {success6}/{total}\n")
        
        lines.append("## Failure Taxonomy")
        tax = {}
        for c in cases:
            if not c.get("solved"):
                fr = c.get("main_failure_reason") or "not_solved"
                tax[fr] = tax.get(fr, 0) + 1
        for k, v in tax.items():
            lines.append(f"- **{k}**: {v} cases")
        if not tax:
            lines.append("- No failures recorded.")
        lines.append("")
        
        lines.append("## Case Results Summary")
        for c in cases:
            sol = "YES" if c.get("solved") else "NO"
            lines.append(f"### Case {c.get('case_id')} ({c.get('strategy')})")
            if c.get("wizard_opening_prompt") and c.get("wizard_opening_prompt") != "-":
                lines.append(f"#### Wizard Opening Prompt\n{c.get('wizard_opening_prompt')}\n")
            lines.append(f"- Solved: {sol}")
            lines.append(f"- Attempts: {c.get('attempts')}")
            if not c.get("solved"):
                lines.append(f"- Reason: {c.get('main_failure_reason', 'not_solved')}")
            lines.append("")
            
        return PlainTextResponse("\n".join(lines))
            
    elif artifact == "case_results":
        if run_dir:
            fallback = _build_metrics_from_runs([run_dir])
            cases = fallback.get("case_results", [])
            return JSONResponse(Redactor.redact_dict({"data": cases})["data"])
            
        file_path = eval_dir / "case_results.json"
        if file_path.exists():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return JSONResponse(Redactor.redact_dict({"data": data})["data"])
            except Exception:
                pass
        fallback = _build_eval_fallback(eval_dir)
        cases = fallback.get("case_results", [])
        return JSONResponse(Redactor.redact_dict({"data": cases})["data"])
            
    elif artifact == "failure_backlog":
        file_path = run_dir / "failure_backlog.json" if run_dir else eval_dir / "failure_backlog.json"
        if not file_path.exists():
            return []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return JSONResponse(Redactor.redact_dict({"data": data})["data"])
        except Exception:
            return []
            
    elif artifact == "trajectory":
        all_traj = []
        run_dirs_to_check = [run_dir] if run_dir else []
        if eval_dir:
            runs_dir = eval_dir / "runs"
            if runs_dir.exists():
                run_dirs_to_check = [d for d in runs_dir.iterdir() if d.is_dir()]
                
        for r_dir in run_dirs_to_check:
            traj_file = r_dir / "trajectory.json"
            if traj_file.exists():
                try:
                    with open(traj_file, "r", encoding="utf-8") as f:
                        traj = json.load(f)
                        strategy = "unknown"
                        meta_file = r_dir / "run_meta.json"
                        if meta_file.exists():
                            with open(meta_file, "r", encoding="utf-8") as mf:
                                meta = json.load(mf)
                                strategy = meta.get("strategy", strategy)
                        
                        # Apply attempt numbering correctly per level
                        level_counts = {}
                        for t in traj:
                            t["run_id"] = r_dir.name
                            t["strategy"] = strategy
                            lvl = str(t.get("level_id", t.get("current_level", "unknown")))
                            level_counts[lvl] = level_counts.get(lvl, 0) + 1
                            if "attempt" not in t or not t["attempt"]:
                                t["attempt"] = level_counts[lvl]
                        all_traj.extend(traj)
                except Exception:
                    pass
        return JSONResponse(Redactor.redact_dict({"data": all_traj})["data"])

@app.post("/api/evals/run-gemini-core8")
def run_gemini_core8():
    env = os.environ.copy()
    env["LLM_GUARDIAN_PLANNER_PROVIDER"] = "gemini"
    env["LLM_GUARDIAN_PLANNER_MAX_TOKENS"] = "3000"
    env["LLM_GUARDIAN_PLANNER_TEMPERATURE"] = "0"
    env["LLM_GUARDIAN_PLANNER_STRUCTURED_OUTPUT"] = "true"
    
    cmd = [
        "python", "-m", "llm_guardian.redteam.local_lab.eval_agent",
        "--strategies", "autonomous",
        "--cases", "src/llm_guardian/redteam/local_lab/eval_cases.json",
        "--case-ids", "core_level_1,core_level_2,core_level_3,core_level_4,core_level_5,core_level_6,core_level_7,core_level_8",
        "--runs", "1",
        "--max-attempts", "6",
        "--delay-ms", "0",
        "--export-failure-cases"
    ]
    
    # Run in background
    subprocess.Popen(cmd, env=env)
    
    return {
        "status": "started",
        "run_type": "gemini_core8",
        "planner_provider": "gemini",
        "strategy": "autonomous",
        "case_ids": [
            "core_level_1", "core_level_2", "core_level_3", "core_level_4",
            "core_level_5", "core_level_6", "core_level_7", "core_level_8"
        ],
        "max_attempts": 6,
        "delay_ms": 0,
        "output_dir": "reports/redteam/wizard_lab/evals/...",
        "message": "Gemini Core8 eval started. Refresh eval reports after the run completes."
    }

@app.get("/api/planner-status")
def get_planner_status():
    provider = os.getenv("LLM_GUARDIAN_PLANNER_PROVIDER", "None")
    gemini_key = os.getenv("GEMINI_API_KEY")
    return {
        "planner_provider": provider,
        "gemini_api_key_loaded": bool(gemini_key and gemini_key.strip())
    }

if __name__ == "__main__":
    uvicorn.run("llm_guardian.redteam.local_lab.app:app", host="127.0.0.1", port=8000, reload=True)
