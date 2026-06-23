"""Security agent models, adapters, orchestration, and deterministic execution primitives."""

from llm_guardian.security_agent.adapters import AdapterExecutionResult, LocalTargetAdapter, TargetAdapter
from llm_guardian.security_agent.agent import SecurityAgent, SecurityScanAgent
from llm_guardian.security_agent.executor import AttackExecutor
from llm_guardian.security_agent.findings import SecurityFindingBuilder
from llm_guardian.security_agent.models import (
    AttackCampaign,
    AttackAttempt,
    AttackPlan,
    Observation,
    PromptMutation,
    SecurityAgentResult,
    SecurityFinding,
    SecurityTestObjective,
    TargetProfile,
    ThreatModel,
    Trajectory,
    Verdict,
)
from llm_guardian.security_agent.mutator import (
    LLMAssistedPromptMutator,
    LLMClient,
    OllamaLLMClient,
    PromptMutator,
    StaticFakeLLMClient,
)
from llm_guardian.security_agent.planner import AttackPlanner
from llm_guardian.security_agent.reporting import (
    SecurityAgentJsonReportBuilder,
    SecurityAgentMarkdownReportBuilder,
)
from llm_guardian.security_agent.target_profiles import (
    TargetProfileLoadError,
    load_target_profile,
    load_target_profiles,
    resolve_max_mutations_per_attack,
)

__all__ = [
    "AdapterExecutionResult",
    "AttackCampaign",
    "AttackAttempt",
    "SecurityAgent",
    "SecurityScanAgent",
    "AttackExecutor",
    "AttackPlan",
    "AttackPlanner",
    "LocalTargetAdapter",
    "LLMAssistedPromptMutator",
    "LLMClient",
    "OllamaLLMClient",
    "Observation",
    "PromptMutation",
    "PromptMutator",
    "SecurityAgentResult",
    "SecurityFinding",
    "SecurityFindingBuilder",
    "SecurityAgentJsonReportBuilder",
    "SecurityAgentMarkdownReportBuilder",
    "SecurityTestObjective",
    "StaticFakeLLMClient",
    "TargetAdapter",
    "TargetProfileLoadError",
    "TargetProfile",
    "ThreatModel",
    "Trajectory",
    "Verdict",
    "load_target_profile",
    "load_target_profiles",
    "resolve_max_mutations_per_attack",
]
