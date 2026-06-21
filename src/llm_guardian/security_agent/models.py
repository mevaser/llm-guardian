"""Core models for the central security agent orchestration layer."""

from __future__ import annotations

from typing import Literal
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


class ThreatModel(StrictBaseModel):
    target_name: str
    target_type: str
    authorization_scope: str
    capabilities: list[str] = Field(default_factory=list)
    available_tools: list[str] = Field(default_factory=list)
    risk_surfaces: list[str] = Field(default_factory=list)
    allowed_test_categories: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=list)
    assets_at_risk: list[str] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    safety_constraints: list[str] = Field(default_factory=list)
    threat_categories_in_scope: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)

    @field_validator("target_name", "target_type", "authorization_scope")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class AttackCampaign(StrictBaseModel):
    campaign_id: str
    campaign_name: str
    target_name: str
    target_type: str
    threat_model: ThreatModel
    attack_plan: AttackPlan
    selected_attack_ids: list[str] = Field(default_factory=list)
    selected_categories: list[str] = Field(default_factory=list)
    excluded_categories: list[str] = Field(default_factory=list)
    excluded_attack_ids: list[str] = Field(default_factory=list)
    planning_rationale: list[str] = Field(default_factory=list)
    attack_ordering_rationale: str
    retry_policy: dict[str, Any] = Field(default_factory=dict)
    mutation_budget: int = Field(ge=0)
    max_attempts_per_attack: int = Field(ge=1)
    safety_mode: str
    total_planned_attacks: int = Field(ge=0)
    deterministic_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "campaign_id",
        "campaign_name",
        "target_name",
        "target_type",
        "attack_ordering_rationale",
        "safety_mode",
    )
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class Trajectory(StrictBaseModel):
    attack_id: str
    attempt_id: str | None = None
    attempt_index: int = Field(ge=1)
    prompt: str
    response_text: str | None = None
    target_metadata: dict[str, Any] = Field(default_factory=dict)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    tool_names: list[str] = Field(default_factory=list)
    tool_arguments: list[dict[str, Any]] = Field(default_factory=list)
    tool_results: list[dict[str, Any]] = Field(default_factory=list)
    memory_operations: list[dict[str, Any]] = Field(default_factory=list)
    retrieval_operations: list[dict[str, Any]] = Field(default_factory=list)
    state_changes: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    trace_events: list[Any] = Field(default_factory=list)
    mutation_lineage: dict[str, Any] = Field(default_factory=dict)

    @field_validator("attack_id", "prompt")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("attempt_id", "response_text")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class Observation(StrictBaseModel):
    target_refused: bool = False
    asked_for_confirmation: bool = False
    tool_called: bool = False
    tool_names: list[str] = Field(default_factory=list)
    unauthorized_tool_call_detected: bool = False
    sensitive_data_disclosed: bool = False
    external_call_attempted: bool = False
    mock_side_effects_detected: bool = False
    matched_success_indicators: list[str] = Field(default_factory=list)
    matched_failure_indicators: list[str] = Field(default_factory=list)
    errors_detected: list[str] = Field(default_factory=list)
    relevant_evidence: list[str] = Field(default_factory=list)


class Verdict(StrictBaseModel):
    status: Literal["success", "blocked", "failed", "skipped", "unknown"]
    success: bool | None = None
    severity: str | None = None
    reason: str
    evidence: list[str] = Field(default_factory=list)
    matched_success_indicators: list[str] = Field(default_factory=list)
    matched_failure_indicators: list[str] = Field(default_factory=list)
    deterministic_rationale: str
    confidence_label: Literal["high", "medium", "low"] = "medium"

    @field_validator("reason", "deterministic_rationale")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("severity")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class AttackAttempt(StrictBaseModel):
    attack_id: str
    attempt_id: str | None = None
    attempt_index: int = Field(ge=1)
    prompt: str
    mutation_strategy: str | None = None
    source_prompt: str | None = None
    mutation_reason_summary: str | None = None
    response: str | None = None
    trace: list[Any] = Field(default_factory=list)
    success: bool | None = None
    evidence: list[str] = Field(default_factory=list)
    trajectory: Trajectory | None = None
    observation: Observation | None = None
    verdict: Verdict | None = None

    @field_validator("attack_id", "prompt")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("attempt_id", "mutation_strategy", "source_prompt", "mutation_reason_summary", "response")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class SecurityFinding(StrictBaseModel):
    finding_id: str
    attack_id: str
    attack_name: str
    category: str
    severity: str
    target_name: str | None = None
    target_type: str | None = None
    evidence_summary: str
    successful_attempt_ids: list[str] = Field(default_factory=list)
    mutation_strategies: list[str] = Field(default_factory=list)
    source_prompts: list[str] = Field(default_factory=list)
    recommendation: str
    response_excerpt: str = ""

    @field_validator(
        "finding_id",
        "attack_id",
        "attack_name",
        "category",
        "severity",
        "evidence_summary",
        "recommendation",
    )
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("target_name", "target_type")
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
    attack_plan: AttackPlan | None = None
    threat_model: ThreatModel | None = None
    attack_campaign: AttackCampaign | None = None
    attempts: list[AttackAttempt] = Field(default_factory=list)
    findings: list[SecurityFinding] = Field(default_factory=list)
    prompt_mutations: list[PromptMutation] = Field(default_factory=list)
    summary: str
    risk_summary: dict[str, Any] = Field(default_factory=dict)

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value
