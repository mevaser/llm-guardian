import uuid
from typing import Dict, List
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from llm_guardian.redteam.local_lab.models import (
    LevelInfo, SessionStart, SubmitRequest, SubmitResponse, SessionState, Attempt
)
from llm_guardian.redteam.local_lab.levels import LEVELS, evaluate_prompt
from llm_guardian.redteam.local_lab import groq_composer
import logging
import os

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

if __name__ == "__main__":
    uvicorn.run("llm_guardian.redteam.local_lab.app:app", host="127.0.0.1", port=8000, reload=True)
