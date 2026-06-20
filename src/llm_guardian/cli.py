"""Command-line entry points for offline local scans."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from llm_guardian.attacks.loader import AttackLibraryLoadError, load_attack_library
from llm_guardian.config import DEFAULT_ATTACK_LIBRARY_PATH
from llm_guardian.models import ScanReport
from llm_guardian.runner.scan_service import (
    render_report_json,
    render_report_markdown,
    run_offline_scan,
)
from llm_guardian.targets.registry import create_target, list_targets


def _load_default_library():
    return load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)


def list_attacks() -> int:
    library = _load_default_library()
    for attack in library.attacks:
        print(f"{attack.id}\t{attack.category.value}\t{attack.severity.value}\t{attack.title}")
    return 0


def validate_attacks() -> int:
    library = _load_default_library()
    print(f"Attack library valid: {len(library.attacks)} attacks")
    return 0


def list_target_names() -> int:
    for target_name in list_targets():
        print(target_name)
    return 0


def invoke_target(target: str, prompt: str) -> int:
    try:
        response = create_target(target).invoke(prompt)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(response.content)
    return 0


def scan(
    target: str,
    offline: bool,
    output: Path | None,
    markdown_output: Path | None,
) -> int:
    if not offline:
        print("Offline-only scan requires --offline. Real providers are not implemented.", file=sys.stderr)
        return 2

    try:
        report = run_offline_scan(target_name=target)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"Target: {report.target_name}")
    print(f"Total attacks: {report.total_attacks}")
    print(f"Successful attacks: {report.successful_attacks}")
    print(f"Risk score: {report.risk_score:.2f}")
    print(f"Risk level: {report.risk_level.value}")

    if output is not None:
        rendered = render_report_json(report)
        output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote JSON report to {output}")

    if markdown_output is not None:
        rendered_markdown = render_report_markdown(report)
        markdown_output.write_text(rendered_markdown + "\n", encoding="utf-8")
        print(f"Wrote Markdown report to {markdown_output}")

    return 0


def validate_report(path: Path) -> int:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"Could not read report: {path}: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON report: {exc}", file=sys.stderr)
        return 1

    if not isinstance(payload, dict):
        print("Invalid report: top-level JSON value must be an object.", file=sys.stderr)
        return 1

    try:
        ScanReport.model_validate(payload)
    except Exception as exc:
        print(f"Invalid report: {exc}", file=sys.stderr)
        return 1

    print("Report is a valid scan report.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="llm-guardian")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list-attacks", help="List configured attack cases.")
    subparsers.add_parser("validate-attacks", help="Validate the default attack library.")
    subparsers.add_parser("list-targets", help="List available local target agents.")

    invoke_parser = subparsers.add_parser("invoke-target", help="Invoke a local target agent.")
    invoke_parser.add_argument("--target", required=True)
    invoke_parser.add_argument("--prompt", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run an offline scan against a local target.")
    scan_parser.add_argument("--target", required=True)
    scan_parser.add_argument("--offline", action="store_true")
    scan_parser.add_argument("--output", type=Path)
    scan_parser.add_argument("--markdown-output", type=Path)

    report_parser = subparsers.add_parser("validate-report", help="Validate a structured report JSON file.")
    report_parser.add_argument("path", type=Path)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "list-attacks":
            return list_attacks()
        if args.command == "validate-attacks":
            return validate_attacks()
        if args.command == "list-targets":
            return list_target_names()
        if args.command == "invoke-target":
            return invoke_target(target=args.target, prompt=args.prompt)
        if args.command == "scan":
            return scan(
                target=args.target,
                offline=args.offline,
                output=args.output,
                markdown_output=args.markdown_output,
            )
        if args.command == "validate-report":
            return validate_report(args.path)
    except AttackLibraryLoadError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    parser.error(f"Unknown command: {args.command}")
    return 2


def app() -> int:
    """Console script entry point."""

    return main()


if __name__ == "__main__":
    raise SystemExit(main())
