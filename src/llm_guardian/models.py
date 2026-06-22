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


class ScenarioGenerationRequest(StrictBaseModel):
    target_name: str
    target_profile_summary: str
    count: int = Field(default=2, ge=1)

    @field_validator("target_name", "target_profile_summary")
    @classmethod
    def validate_non_empty_generation_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class ScenarioGenerationResult(StrictBaseModel):
    raw_output: str
    parsed_scenarios: list[AttackScenario] = Field(default_factory=list)
    accepted_scenarios: list[AttackScenario] = Field(default_factory=list)
    rejected_scenarios: list[dict[str, Any]] = Field(default_factory=list)
    validation_errors: list[str] = Field(default_factory=list)

    @field_validator("raw_output")
    @classmethod
    def validate_raw_output(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class GeneratedScenarioBatch(StrictBaseModel):
    target_name: str
    target_profile_summary: str
    generated_scenarios: list[AttackScenario] = Field(default_factory=list)
    provider: str
    model: str
    generation_notes: str = ""

    @field_validator("target_name", "target_profile_summary", "provider", "model")
    @classmethod
    def validate_non_empty_batch_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


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


class AgentPlan(StrictBaseModel):
    """Deterministic plan summary for one security scan run."""

    target_name: str
    scenario_count: int = Field(ge=0)
    selected_scenario_ids: list[str] = Field(default_factory=list)
    scenario_source: str | None = None
    generated_scenario_count: int | None = None
    scenario_provider: str | None = None
    rationale: str
    execution_strategy: str

    @field_validator("target_name", "rationale", "execution_strategy")
    @classmethod
    def validate_non_empty_plan_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("scenario_source", "scenario_provider")
    @classmethod
    def validate_optional_plan_text(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class AgentTraceStep(StrictBaseModel):
    """Auditable agent loop step for demo scan execution."""

    step: int = Field(ge=1)
    phase: str
    scenario_id: str | None = None
    action: str
    observation: str
    decision: str
    evidence: str | None = None

    @field_validator("phase", "action", "observation", "decision")
    @classmethod
    def validate_non_empty_trace_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("scenario_id", "evidence")
    @classmethod
    def validate_optional_trace_text(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class AdaptiveProbeResult(StrictBaseModel):
    """Deterministic follow-up probe recorded after a critical failure."""

    probe_id: str
    trigger_scenario_id: str
    category: str
    status: str
    observation: str
    recommendation: str
    evidence: str

    @field_validator(
        "probe_id",
        "trigger_scenario_id",
        "category",
        "status",
        "observation",
        "recommendation",
        "evidence",
    )
    @classmethod
    def validate_non_empty_probe_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class SecurityScanResult(StrictBaseModel):
    """Structured scenario-scan result for deterministic trajectory export."""

    scan_id: str
    target_name: str
    target_profile: dict[str, Any] = Field(default_factory=dict)
    agent_plan: AgentPlan | None = None
    agent_trace: list[AgentTraceStep] = Field(default_factory=list)
    scenario_results: list[ScenarioRunResult] = Field(default_factory=list)
    findings: list[SecurityFinding] = Field(default_factory=list)
    adaptive_probes: list[AdaptiveProbeResult] = Field(default_factory=list)

    @field_validator("scan_id", "target_name")
    @classmethod
    def validate_non_empty_scan_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @model_validator(mode="after")
    def validate_scenarios_and_findings(self) -> "SecurityScanResult":
        scenario_ids = [item.scenario_id for item in self.scenario_results]
        if len(set(scenario_ids)) != len(scenario_ids):
            raise ValueError("scenario_results must not contain duplicate scenario_id values")

        known_scenario_ids = set(scenario_ids)
        finding_ids = {item.scenario_id for item in self.findings}
        missing_findings = known_scenario_ids.difference(finding_ids)
        unknown_findings = finding_ids.difference(known_scenario_ids)

        if missing_findings:
            missing_list = ", ".join(sorted(missing_findings))
            raise ValueError(f"findings missing scenario_id values: {missing_list}")
        if unknown_findings:
            unknown_list = ", ".join(sorted(unknown_findings))
            raise ValueError(f"findings reference unknown scenario_id values: {unknown_list}")

        return self


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
