"""Core data contracts for deterministic agent runtime execution."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from llm_guardian.models import StrictBaseModel, TraceEvent


class AgentDecision(StrictBaseModel):
    action_type: str
    action_name: str | None = None
    action_arguments: dict[str, Any] = Field(default_factory=dict)
    reason_summary: str
    risk_flags: list[str] = Field(default_factory=list)

    @field_validator("action_type", "reason_summary")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("action_name")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class ToolCall(StrictBaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    allowed_by_policy: bool | None = None

    @field_validator("tool_name")
    @classmethod
    def validate_tool_name(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class ToolResult(StrictBaseModel):
    tool_name: str
    status: str
    output_summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tool_name", "status", "output_summary")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class RetrievalResult(StrictBaseModel):
    source_name: str
    query: str
    content_summary: str
    trust_level: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_name", "query", "content_summary", "trust_level")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class MemoryOperation(StrictBaseModel):
    operation_type: str
    memory_key: str
    memory_value: str | None = None
    validated: bool
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("operation_type", "memory_key")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("memory_value")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class PolicyDecision(StrictBaseModel):
    decision: str
    reason_summary: str
    applies_to: str | None = None
    severity: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("decision", "reason_summary")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("applies_to", "severity")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class AgentRunResult(StrictBaseModel):
    final_response: str
    trace_events: list[TraceEvent] = Field(default_factory=list)
    decision: AgentDecision | None = None
    policy_decisions: list[PolicyDecision] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    retrieval_results: list[RetrievalResult] = Field(default_factory=list)
    memory_operations: list[MemoryOperation] = Field(default_factory=list)
    runtime_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("final_response")
    @classmethod
    def validate_final_response(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value
