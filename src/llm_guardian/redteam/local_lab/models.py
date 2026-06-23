from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class LevelInfo(BaseModel):
    level_id: int
    title: str
    public_description: str
    objective: str
    opening_message: str

class LevelDefinition(LevelInfo):
    secret: str
    defense_description: str

class SessionStart(BaseModel):
    session_id: str
    level_info: LevelInfo

class SubmitRequest(BaseModel):
    session_id: str
    prompt: str
    response_mode: str = "deterministic"

class SubmitResponse(BaseModel):
    response: str
    solved: bool
    filtered: bool = False
    fallback: bool = False
    response_mode_requested: str = "deterministic"
    response_mode_used: str = "deterministic"
    composer_used: bool = False
    fallback_reason: Optional[str] = None
    intent: str = "unknown"
    outcome_type: str = "unknown"
    groq_http_status: Optional[int] = None
    groq_error_type: Optional[str] = None

class Attempt(BaseModel):
    prompt: str
    response: str
    solved: bool

class SessionState(BaseModel):
    session_id: str
    level_id: int
    attempts: List[Attempt] = Field(default_factory=list)
    state: Dict[str, Any] = Field(default_factory=dict)
    solved: bool = False
