"""Deterministic data preparation for the Streamlit SecurityAgent demo."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from llm_guardian.attacks.loader import load_attack_library
from llm_guardian.config import DEFAULT_ATTACK_LIBRARY_PATH, DEFAULT_TARGET_PROFILES_PATH
from llm_guardian.models import AttackCategory
from llm_guardian.security_agent import (
    SecurityAgent,
    SecurityAgentJsonReportBuilder,
    SecurityAgentMarkdownReportBuilder,
    SecurityAgentResult,
    SecurityTestObjective,
)
from llm_guardian.security_agent.adapters import LocalTargetAdapter
from llm_guardian.security_agent.target_profiles import (
    load_target_profile,
    resolve_max_mutations_per_attack,
)
from llm_guardian.targets.registry import create_target


DEFAULT_SECURITY_AGENT_TARGET = "mutation_challenge_tool_agent"
DEFAULT_SECURITY_AGENT_CATEGORY = "tool_abuse"
DEFAULT_MAX_TOTAL_ATTEMPTS = 10
DEFAULT_MAX_ATTEMPTS_PER_ATTACK = 2


@dataclass(frozen=True)
class SecurityAgentDemoData:
    """Prepared SecurityAgent output for UI rendering and downloads."""

    result: SecurityAgentResult
    payload: dict[str, Any]
    json_report: str
    markdown_report: str


def run_security_agent_demo_scan(
    *,
    target_name: str = DEFAULT_SECURITY_AGENT_TARGET,
    categories: list[str] | None = None,
    max_total_attempts: int = DEFAULT_MAX_TOTAL_ATTEMPTS,
    max_attempts_per_attack: int = DEFAULT_MAX_ATTEMPTS_PER_ATTACK,
    max_mutations_per_attack: int | None = None,
) -> SecurityAgentDemoData:
    """Run the local SecurityAgent demo flow and return render-ready data."""

    selected_categories = _normalize_categories(categories or [DEFAULT_SECURITY_AGENT_CATEGORY])
    target_agent = create_target(target_name)
    target_profile = load_target_profile(DEFAULT_TARGET_PROFILES_PATH, target_name)
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)
    effective_max_mutations_per_attack = resolve_max_mutations_per_attack(
        override_value=max_mutations_per_attack,
        target_profile=target_profile,
    )
    objective = SecurityTestObjective(
        goal="Run a deterministic local security-agent scan.",
        allowed_categories=selected_categories,
        max_attempts_per_attack=max(max_attempts_per_attack, 1),
        max_total_attempts=max(max_total_attempts, 1),
        safety_mode="strict",
        stop_on_success=False,
    )

    result = SecurityAgent(max_mutations_per_attack=effective_max_mutations_per_attack).run(
        target_profile=target_profile,
        objective=objective,
        attacks=library.attacks,
        target_adapter=LocalTargetAdapter(target_agent),
    )
    json_builder = SecurityAgentJsonReportBuilder()
    payload = json_builder.build(result=result, attack_library=library.attacks)
    markdown_report = SecurityAgentMarkdownReportBuilder(json_builder=json_builder).build(
        result=result,
        attack_library=library.attacks,
    )

    return SecurityAgentDemoData(
        result=result,
        payload=payload,
        json_report=_format_json_report(payload),
        markdown_report=markdown_report,
    )


def build_attempt_timeline_rows(payload: dict[str, Any]) -> list[dict[str, object]]:
    """Build compact attempt rows for the demo timeline table."""

    rows: list[dict[str, object]] = []
    for attempt in payload.get("attempt_history", []):
        if not isinstance(attempt, dict):
            continue
        verdict = attempt.get("verdict")
        verdict_status = (
            verdict.get("status", "unknown") if isinstance(verdict, dict) else "unknown"
        )
        rows.append(
            {
                "Attack ID": attempt.get("attack_id", ""),
                "Attempt ID": attempt.get("attempt_id") or _fallback_attempt_id(attempt),
                "Attempt index": attempt.get("attempt_index", ""),
                "Verdict": verdict_status,
                "Success": attempt.get("success"),
                "Mutation strategy": attempt.get("mutation_strategy") or "none",
                "Prompt preview": _snippet(str(attempt.get("prompt", "")), limit=100),
            }
        )
    return rows


def build_security_agent_findings_rows(payload: dict[str, Any]) -> list[dict[str, object]]:
    """Build compact finding rows for the demo findings table."""

    rows: list[dict[str, object]] = []
    for finding in payload.get("findings", []):
        if not isinstance(finding, dict):
            continue
        rows.append(
            {
                "Finding ID": finding.get("finding_id", ""),
                "Attack ID": finding.get("attack_id", ""),
                "Category": finding.get("category", ""),
                "Severity": finding.get("severity", ""),
                "Successful attempt IDs": ", ".join(finding.get("successful_attempt_ids", [])),
                "Mutation strategies": ", ".join(finding.get("mutation_strategies", [])) or "none",
                "Recommendation": finding.get("recommendation", ""),
                "Evidence summary": finding.get("evidence_summary", ""),
            }
        )
    return rows


def get_default_max_mutations_per_attack(target_name: str) -> int:
    """Read the default mutation budget for a target from YAML profile data."""

    target_profile = load_target_profile(DEFAULT_TARGET_PROFILES_PATH, target_name)
    return resolve_max_mutations_per_attack(
        override_value=None,
        target_profile=target_profile,
    )


def _normalize_categories(categories: list[str]) -> list[str]:
    valid_categories = {category.value for category in AttackCategory}
    normalized: list[str] = []
    for category in categories:
        if not category or not category.strip():
            continue
        value = category.strip()
        if value not in valid_categories:
            supported = ", ".join(sorted(valid_categories))
            raise ValueError(f"Unknown category '{value}'. Supported categories: {supported}")
        if value not in normalized:
            normalized.append(value)
    return normalized


def _format_json_report(payload: dict[str, Any]) -> str:
    import json

    return json.dumps(payload, indent=2)


def _fallback_attempt_id(attempt: dict[str, Any]) -> str:
    attack_id = attempt.get("attack_id", "unknown")
    attempt_index = attempt.get("attempt_index", "unknown")
    return f"{attack_id}-attempt-{attempt_index}"


def _snippet(value: str, *, limit: int) -> str:
    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    return f"{compact[: limit - 3]}..."
