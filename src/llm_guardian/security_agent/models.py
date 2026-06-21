"""Core models for the central security agent orchestration layer."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from llm_guardian.models import StrictBaseModel


class TargetProfile(StrictBaseModel):
    target_type: str
    capabilities: list[str] = Field(default_factory=list)
    risk_surfaces: list[str] = Field(default_factory=list)
    allowed_categories: list[str] = Field(default_factory=list)
    authorization_scope: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target_type", "authorization_scope")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class SecurityTestObjective(StrictBaseModel):
    goal: str
    allowed_categories: list[str] = Field(default_factory=list)
    max_attempts_per_attack: int = Field(ge=1)
    max_total_attempts: int = Field(ge=1)
    safety_mode: str
    stop_on_success: bool

    @field_validator("goal", "safety_mode")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class AttackPlan(StrictBaseModel):
    target_profile: TargetProfile
    objective: SecurityTestObjective
    selected_categories: list[str] = Field(default_factory=list)
    selected_attack_ids: list[str] = Field(default_factory=list)
    strategy_notes: list[str] = Field(default_factory=list)
    budget: dict[str, int] = Field(default_factory=dict)


class AttackAttempt(StrictBaseModel):
    attack_id: str
    attempt_index: int = Field(ge=1)
    prompt: str
    mutation_strategy: str | None = None
    source_prompt: str | None = None
    mutation_reason_summary: str | None = None
    response: str | None = None
    trace: list[Any] = Field(default_factory=list)
    success: bool | None = None
    evidence: list[str] = Field(default_factory=list)

    @field_validator("attack_id", "prompt")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("mutation_strategy", "source_prompt", "mutation_reason_summary", "response")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class PromptMutation(StrictBaseModel):
    source_attack_id: str
    source_prompt: str
    mutated_prompt: str
    mutation_type: str
    reason_summary: str
    safety_flags: list[str] = Field(default_factory=list)

    @field_validator(
        "source_attack_id",
        "source_prompt",
        "mutated_prompt",
        "mutation_type",
        "reason_summary",
    )
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class SecurityAgentResult(StrictBaseModel):
    target_profile: TargetProfile
    objective: SecurityTestObjective
    attempts: list[AttackAttempt] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    prompt_mutations: list[PromptMutation] = Field(default_factory=list)
    summary: str
    risk_summary: dict[str, Any] = Field(default_factory=dict)

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value
