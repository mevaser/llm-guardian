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

class PreviousAttempt(BaseModel):
    attempt_number: int = 1
    prompt: str
    response: str
    outcome_type: str
    solved: bool
    observation_summary: str
    detected_hint_type: Optional[str] = None
    selected_tactic: Optional[str] = None
    error_category: Optional[str] = None
    is_duplicate: bool = False

class SessionState(BaseModel):
    session_id: str
    level_id: int
    attempts: List[Attempt] = Field(default_factory=list)
    state: Dict[str, Any] = Field(default_factory=dict)
    solved: bool = False

class ObservationState(BaseModel):
    level_id: int
    title: str
    public_description: str
    previous_attempts: List[PreviousAttempt]
    current_turn: int
    max_attempts: int
    failed_strategy_names: List[str] = Field(default_factory=list)
    tactics_already_tried: List[str] = Field(default_factory=list)
    duplicate_prompt_count: int = 0
    adaptation_count: int = 0
    last_hint_type: Optional[str] = None
    pending_forced_tactic: Optional[str] = None
    alias_plan_active: bool = False
    alias_step: str = ""
    alias_token: str = "PUBLIC_TOKEN"
    hint_detected_turn: int = 0
    hint_used_turn: int = 0

class PlannerDecision(BaseModel):
    strategy_name: str
    rationale_summary: str
    selected_prompt: str
    expected_bypass_type: str
    confidence: float
    observation_summary: Optional[str] = None
    next_action_summary: Optional[str] = None
    stop_reason: Optional[str] = None
