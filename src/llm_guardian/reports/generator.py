"""Structured report builders for offline scans."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from llm_guardian.models import AttackResult, ScanReport
from llm_guardian.reports.scoring import ScoringEngine


class ReportGenerator:
    """Build the canonical JSON-friendly scan report."""

    def __init__(self, *, scoring_engine: ScoringEngine | None = None) -> None:
        self._scoring_engine = scoring_engine or ScoringEngine()

    def build(
        self,
        *,
        target_name: str,
        results: list[AttackResult],
        created_at: datetime | None = None,
    ) -> ScanReport:
        timestamp = created_at or datetime.now(UTC)
        score = self._scoring_engine.score(results)
        category_summary = self._scoring_engine.build_category_summary(results)

        return ScanReport(
            scan_id=self._build_scan_id(target_name=target_name, results=results),
            created_at=timestamp,
            target_name=target_name,
            total_attacks=len(results),
            successful_attacks=sum(1 for result in results if result.success),
            risk_score=score.risk_score,
            risk_level=score.risk_level,
            category_summary=category_summary,
            findings=results,
            recommendations=self._build_recommendations(results),
        )

    @staticmethod
    def _build_scan_id(*, target_name: str, results: list[AttackResult]) -> str:
        fingerprint = json.dumps(
            [
                {
                    "attack_id": result.attack_id,
                    "category": result.category.value,
                    "severity": result.severity.value,
                    "success": result.success,
                    "response": result.response,
                }
                for result in results
            ],
            separators=(",", ":"),
        )
        digest = hashlib.sha1(f"{target_name}:{fingerprint}".encode("utf-8")).hexdigest()[:12]
        return f"scan-{digest}"

    @staticmethod
    def _build_recommendations(results: list[AttackResult]) -> list[str]:
        successful_recommendations = [
            result.recommendation
            for result in results
            if result.success
        ]
        if not successful_recommendations:
            return []
        return list(dict.fromkeys(successful_recommendations))


class MarkdownReportGenerator:
    """Render human-readable Markdown reports from structured scan data."""

    def render(self, report: ScanReport) -> str:
        lines = [
            "# LLM Guardian Scan Report",
            "",
            f"Target: `{report.target_name}`",
            "",
            "## Scan Metadata",
            "",
            f"- Scan ID: `{report.scan_id}`",
            f"- Created At: `{report.created_at.isoformat()}`",
            f"- Total Attacks: {report.total_attacks}",
            f"- Successful Attacks: {report.successful_attacks}",
            f"- Risk Score: {report.risk_score:.2f}/10.00",
            f"- Risk Level: `{report.risk_level.value}`",
            "",
            "## Executive Summary",
            "",
            self._build_executive_summary(report),
            "",
            "## Category Summary",
            "",
            "| Category | Total Attacks | Successful Attacks | Success Rate | Max Severity |",
            "| --- | ---: | ---: | ---: | --- |",
        ]

        for category in report.category_summary:
            lines.append(
                "| "
                f"{category.category.value} | "
                f"{category.total_attacks} | "
                f"{category.successful_attacks} | "
                f"{category.success_rate:.2f} | "
                f"{category.max_severity_seen.value} |"
            )

        lines.extend(["", "## Findings", ""])

        for finding in report.findings:
            title = finding.title or "Untitled finding"
            lines.extend(
                [
                    f"### {finding.attack_id} - {title}",
                    "",
                    f"- Category: `{finding.category.value}`",
                    f"- Severity: `{finding.severity.value}`",
                    f"- Success: `{str(finding.success).lower()}`",
                    f"- Recommendation: {finding.recommendation}",
                    f"- Prompt: `{finding.prompt}`",
                    "",
                    "Evidence:",
                ]
            )
            if finding.evidence:
                lines.extend(f"- {item}" for item in finding.evidence)
            else:
                lines.append("- No evidence captured.")
            lines.extend(
                [
                    "",
                    "Response snippet:",
                    "```text",
                    finding.response,
                    "```",
                    "",
                ]
            )

        lines.extend(["## Recommendations", ""])
        if report.recommendations:
            lines.extend(f"- {recommendation}" for recommendation in report.recommendations)
        else:
            lines.append("- No successful attacks were observed in this run.")

        lines.extend(
            [
                "",
                "## Ethical and Scope Note",
                "",
                "This scan only covers local intentionally vulnerable demo targets and does not evaluate real third-party systems.",
                "",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _build_executive_summary(report: ScanReport) -> str:
        return (
            f"The scan executed {report.total_attacks} attack(s) against `{report.target_name}`. "
            f"{report.successful_attacks} attack(s) succeeded, producing an overall risk score of "
            f"{report.risk_score:.2f}/10.00 with a `{report.risk_level.value}` risk level."
        )
