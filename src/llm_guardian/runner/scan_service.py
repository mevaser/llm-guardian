"""Reusable scan helpers for CLI and UI entry points."""

from __future__ import annotations

import json
from collections.abc import Iterable

from llm_guardian.attacks.loader import load_attack_library
from llm_guardian.attacks.registry import filter_attacks_by_category
from llm_guardian.config import DEFAULT_ATTACK_LIBRARY_PATH
from llm_guardian.models import AttackCategory, ScanReport
from llm_guardian.reports.generator import MarkdownReportGenerator
from llm_guardian.runner.scan_runner import ScanRunner
from llm_guardian.targets.registry import create_target


def run_offline_scan(
    *,
    target_name: str,
    categories: Iterable[AttackCategory | str] | None = None,
) -> ScanReport:
    """Run a deterministic local scan with an optional pre-execution category filter.

    This helper keeps CLI and Streamlit entry points aligned on one execution
    path so they serialize the same report and trajectory structure.
    """

    target_agent = create_target(target_name)
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)
    attacks = (
        filter_attacks_by_category(library, categories)
        if categories
        else library.attacks
    )
    return ScanRunner(target=target_agent).run(attacks)


def render_report_json(report: ScanReport) -> str:
    """Serialize a scan report to stable indented JSON."""

    return json.dumps(report.model_dump(mode="json"), indent=2)


def render_report_markdown(report: ScanReport) -> str:
    """Render a Markdown report using the canonical report generator."""

    return MarkdownReportGenerator().render(report)
