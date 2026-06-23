import uuid
from typing import Dict, List
import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
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

logger = logging.getLogger("llm_guardian.redteam.local_lab")

from dotenv import load_dotenv
# Load .env file if it exists, without overriding existing environment variables
dotenv_loaded = load_dotenv(override=False)

logger.info(f"Startup: dotenv_loaded={dotenv_loaded}")
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

@app.get("/admin")
def read_admin():
    return FileResponse(str(STATIC_DIR / "admin.html"))

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

class RunStartRequest(BaseModel):
    levels: str = "1-8"
    strategy: str = "autonomous"
    response_mode: str = "deterministic"
    max_attempts: int = 8
    delay_ms: int = 1000
    planner_model: str = "llama-3.1-8b-instant"
    planner_temperature: float = 0.7

def run_agent_in_background(levels_str: str, strategy: str, response_mode: str, max_attempts: int, delay_ms: int, run_id: str, planner_model: str, planner_temperature: float):
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
            base_dir=str(RUNS_DIR),
            run_id=run_id,
            planner_model=planner_model,
            planner_temperature=planner_temperature
        )
        
        runner.run_all(levels)
    except Exception as e:
        logger.error(f"Background run {run_id} failed: {str(e)}")
        # Try to mark failed if possible
        meta_file = RUNS_DIR / run_id / "run_meta.json"
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
    if req.strategy == "autonomous" and not groq_key_present:
        raise HTTPException(status_code=400, detail="Autonomous mode requires GROQ_API_KEY. Scripted baseline is still available.")
        
    run_id = str(uuid.uuid4())
    run_dir = RUNS_DIR / run_id
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
        req.planner_temperature
    )
    
    return {
        "run_id": run_id,
        "status": "running",
        "output_dir": str(run_dir),
        "message": "Run started in background."
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

@app.get("/api/admin/runs/{run_id}/status")
def get_run_status(run_id: str):
    meta_file = RUNS_DIR / run_id / "run_meta.json"
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
    meta_file = RUNS_DIR / run_id / "run_meta.json"
    if not meta_file.exists():
        raise HTTPException(status_code=404, detail="Run not found")
    with open(meta_file, "r", encoding="utf-8") as f:
        return _check_stale(json.load(f))

from fastapi.responses import PlainTextResponse, JSONResponse

@app.get("/api/admin/runs/{run_id}/{artifact}")
def get_run_artifact(run_id: str, artifact: str):
    valid_artifacts = ["events", "decisions", "errors", "trajectory", "report"]
    if artifact not in valid_artifacts:
        raise HTTPException(status_code=400, detail="Invalid artifact")
    
    run_dir = RUNS_DIR / run_id
    if not run_dir.exists() or ".." in run_id or "/" in run_id or "\\" in run_id:
        raise HTTPException(status_code=404, detail="Run not found")
        
    if artifact == "report":
        file_path = run_dir / "report.md"
        if not file_path.exists():
            return PlainTextResponse("No report generated.")
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            return PlainTextResponse(Redactor.redact_string(content))
            
    elif artifact in ["events", "decisions", "errors"]:
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

if __name__ == "__main__":
    uvicorn.run("llm_guardian.redteam.local_lab.app:app", host="127.0.0.1", port=8000, reload=True)
