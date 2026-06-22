"""Core data contracts for LLM Guardian."""

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AttackCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    MEMORY_POISONING = "memory_poisoning"
    TOOL_ABUSE = "tool_abuse"
    RAG_INJECTION = "rag_injection"


class AttackScenarioCategory(str, Enum):
    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    UNSAFE_TOOL_USE = "unsafe_tool_use"
    SECRET_EXFILTRATION = "secret_exfiltration"
    BENIGN = "benign"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScenarioSeverity(str, Enum):
    NONE = "none"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    NONE = "none"
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


class AttackScenario(StrictBaseModel):
    id: str
    name: str
    category: AttackScenarioCategory
    prompt: str
    severity: ScenarioSeverity
    expected_secure_behavior: str
    failure_conditions: dict[str, Any]

    @field_validator("id", "name", "prompt", "expected_secure_behavior")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("failure_conditions")
    @classmethod
    def validate_failure_conditions(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not value:
            raise ValueError("must define at least one failure condition")
        return value


class AttackScenarioLibrary(StrictBaseModel):
    scenarios: list[AttackScenario]

    @field_validator("scenarios")
    @classmethod
    def validate_non_empty_scenarios(cls, value: list[AttackScenario]) -> list[AttackScenario]:
        if not value:
            raise ValueError("must define at least one scenario")
        return value

    @model_validator(mode="after")
    def validate_unique_ids(self) -> "AttackScenarioLibrary":
        seen_ids: set[str] = set()
        duplicate_ids: list[str] = []
        for scenario in self.scenarios:
            if scenario.id in seen_ids:
                duplicate_ids.append(scenario.id)
            seen_ids.add(scenario.id)
        if duplicate_ids:
            duplicate_id_list = ", ".join(sorted(set(duplicate_ids)))
            raise ValueError(f"Duplicate attack scenario id(s): {duplicate_id_list}")
        return self


class ScenarioRunResult(StrictBaseModel):
    """Raw execution record for one attack scenario against a local target module."""

    scenario_id: str
    prompt: str
    target_response: str
    tool_trace: list[dict[str, Any]] = Field(default_factory=list)
    retrieved_context: str = ""
    raw_result: dict[str, Any] = Field(default_factory=dict)

    @field_validator("scenario_id", "prompt", "target_response")
    @classmethod
    def validate_non_empty_run_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class SecurityFinding(StrictBaseModel):
    """Deterministic grading output for one scenario run."""

    scenario_id: str
    category: str
    verdict: Literal["pass", "fail"]
    severity: Severity
    reason: str
    evidence: str

    @field_validator("scenario_id", "category", "reason", "evidence")
    @classmethod
    def validate_non_empty_finding_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class TargetResponse(StrictBaseModel):
    """Deterministic target output plus optional operational trace data."""

    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    memory_updates: list[str] = Field(default_factory=list)
    trace: list["TraceEvent"] = Field(default_factory=list)

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class TraceEvent(StrictBaseModel):
    """A compact operational audit event for deterministic scan trajectories."""

    event_type: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target_name: str
    attack_id: str
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type", "target_name", "attack_id", "message")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class AttackResult(StrictBaseModel):
    """The evaluated outcome for one attack, including evidence and trajectory."""

    attack_id: str
    category: AttackCategory
    severity: Severity
    title: str | None = None
    target_name: str
    prompt: str
    response: str
    success: bool
    evidence: list[str] = Field(default_factory=list)
    trace: list[TraceEvent] = Field(default_factory=list)
    recommendation: str

    @field_validator("attack_id", "target_name", "prompt", "recommendation")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("title")
    @classmethod
    def validate_optional_title(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class ScanSummary(StrictBaseModel):
    target_name: str
    total_attacks: int = Field(ge=0)
    successful_attacks: int = Field(ge=0)
    risk_score: float = Field(ge=0, le=10)
    risk_level: RiskLevel

    @field_validator("target_name")
    @classmethod
    def validate_target_name(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class CategorySummary(StrictBaseModel):
    category: AttackCategory
    total_attacks: int = Field(ge=0)
    successful_attacks: int = Field(ge=0)
    success_rate: float = Field(ge=0, le=1)
    max_severity_seen: Severity
    recommendations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_counts(self) -> "CategorySummary":
        if self.successful_attacks > self.total_attacks:
            raise ValueError("successful_attacks cannot exceed total_attacks")
        return self


class ScanReport(StrictBaseModel):
    scan_id: str
    created_at: datetime
    target_name: str
    total_attacks: int = Field(ge=0)
    successful_attacks: int = Field(ge=0)
    risk_score: float = Field(ge=0, le=10)
    risk_level: RiskLevel
    category_summary: list[CategorySummary] = Field(default_factory=list)
    findings: list[AttackResult] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    @field_validator("scan_id", "target_name")
    @classmethod
    def validate_non_empty_report_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @model_validator(mode="after")
    def validate_counts(self) -> "ScanReport":
        if self.successful_attacks > self.total_attacks:
            raise ValueError("successful_attacks cannot exceed total_attacks")
        if len(self.findings) != self.total_attacks:
            raise ValueError("total_attacks must match the number of findings")
        if sum(1 for finding in self.findings if finding.success) != self.successful_attacks:
            raise ValueError("successful_attacks must match successful findings")
        return self

    @property
    def results(self) -> list[AttackResult]:
        return self.findings

    @property
    def summary(self) -> ScanSummary:
        return ScanSummary(
            target_name=self.target_name,
            total_attacks=self.total_attacks,
            successful_attacks=self.successful_attacks,
            risk_score=self.risk_score,
            risk_level=self.risk_level,
        )
