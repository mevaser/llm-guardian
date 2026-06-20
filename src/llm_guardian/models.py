"""Core data contracts for LLM Guardian."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AttackCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    MEMORY_POISONING = "memory_poisoning"
    TOOL_ABUSE = "tool_abuse"
    RAG_INJECTION = "rag_injection"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StrictBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AttackCase(StrictBaseModel):
    id: str
    category: AttackCategory
    severity: Severity
    title: str
    prompt: str
    follow_up_prompt: str | None = None
    success_indicators: list[str] = Field(default_factory=list)
    failure_indicators: list[str] = Field(default_factory=list)
    recommendation: str

    @field_validator("id", "title", "prompt", "recommendation")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class AttackLibrary(StrictBaseModel):
    attacks: list[AttackCase]


class TargetResponse(StrictBaseModel):
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    memory_updates: list[str] = Field(default_factory=list)

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class AttackResult(StrictBaseModel):
    attack_id: str
    category: AttackCategory
    severity: Severity
    target_name: str
    prompt: str
    response: str
    success: bool
    evidence: list[str] = Field(default_factory=list)
    recommendation: str

    @field_validator("attack_id", "target_name", "prompt", "recommendation")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class ScanSummary(StrictBaseModel):
    target_name: str
    total_attacks: int = Field(ge=0)
    successful_attacks: int = Field(ge=0)
    risk_score: float = Field(ge=0, le=10)

    @field_validator("target_name")
    @classmethod
    def validate_target_name(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class ScanReport(StrictBaseModel):
    summary: ScanSummary
    results: list[AttackResult] = Field(default_factory=list)
