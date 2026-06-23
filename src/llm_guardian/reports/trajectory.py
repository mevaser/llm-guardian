"""Trajectory JSON writer for scenario-scan results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from llm_guardian.models import SecurityScanResult


def write_trajectory_log(scan_result: SecurityScanResult, output_path: Path) -> Path:
    """Write a deterministic UTF-8 trajectory log and return the written path."""

    findings_by_scenario_id = {
        finding.scenario_id: finding
        for finding in scan_result.findings
    }
    payload = {
        "scan_id": scan_result.scan_id,
        "target_name": scan_result.target_name,
        "target_profile": _json_compatible(scan_result.target_profile),
        "agent_plan": _json_compatible(
            scan_result.agent_plan.model_dump(mode="json") if scan_result.agent_plan is not None else None
        ),
        "agent_trace": _json_compatible(
            [trace_step.model_dump(mode="json") for trace_step in scan_result.agent_trace]
        ),
        "adaptive_probes": _json_compatible(
            [adaptive_probe.model_dump(mode="json") for adaptive_probe in scan_result.adaptive_probes]
        ),
        "scenarios": [
            {
                "scenario_id": scenario_result.scenario_id,
                "prompt": scenario_result.prompt,
                "target_response": scenario_result.target_response,
                "retrieved_context": scenario_result.retrieved_context,
                "tool_trace": _json_compatible(scenario_result.tool_trace),
                "verdict": findings_by_scenario_id[scenario_result.scenario_id].verdict,
                "severity": findings_by_scenario_id[scenario_result.scenario_id].severity.value,
                "reason": findings_by_scenario_id[scenario_result.scenario_id].reason,
                "evidence": findings_by_scenario_id[scenario_result.scenario_id].evidence,
            }
            for scenario_result in scan_result.scenario_results
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_path


def _json_compatible(value: Any) -> Any:
    """Round-trip data through JSON to reject unsupported runtime objects."""

    try:
        return json.loads(json.dumps(value, ensure_ascii=False))
    except TypeError as exc:
        raise ValueError("trajectory payload contains non-serializable data") from exc
