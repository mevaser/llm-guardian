"""Command-line placeholders for the first LLM Guardian vertical slice."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from llm_guardian.attacks.loader import AttackLibraryLoadError, load_attack_library
from llm_guardian.config import DEFAULT_ATTACK_LIBRARY_PATH
from llm_guardian.targets.registry import create_target, list_targets


def _load_default_library() -> Any:
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


def scan(target: str, offline: bool, output: Path | None) -> int:
    if not offline:
        print("Scan placeholder requires --offline. Real providers are not implemented.", file=sys.stderr)
        return 2

    payload = {
        "status": "not_implemented",
        "message": "Scan runner is not implemented yet. No scan was executed.",
        "target": target,
        "offline": offline,
    }
    rendered = json.dumps(payload, indent=2)
    if output is not None:
        output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote placeholder scan status to {output}")
    else:
        print(rendered)
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

    if payload.get("status") == "not_implemented":
        print("Report is a valid placeholder status document.")
        return 0

    required_keys = {"summary", "results"}
    missing = sorted(required_keys - payload.keys())
    if missing:
        print(f"Invalid report: missing keys: {', '.join(missing)}", file=sys.stderr)
        return 1

    print("Report has the required top-level structure.")
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

    scan_parser = subparsers.add_parser("scan", help="Placeholder scan command.")
    scan_parser.add_argument("--target", required=True)
    scan_parser.add_argument("--offline", action="store_true")
    scan_parser.add_argument("--output", type=Path)

    report_parser = subparsers.add_parser("validate-report", help="Validate basic report JSON.")
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
            return scan(target=args.target, offline=args.offline, output=args.output)
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
