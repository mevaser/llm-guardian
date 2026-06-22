"""Command-line entry points for offline local scans."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from pathlib import Path

from llm_guardian.attacks.loader import AttackLibraryLoadError, load_attack_library
from llm_guardian.config import (
    DEFAULT_ATTACK_LIBRARY_PATH,
    DEFAULT_TARGET_PROFILES_PATH,
)
from llm_guardian.models import AttackCategory, ScanReport, SecurityScanResult, Severity
from llm_guardian.runner.scan_service import (
    render_report_json,
    render_report_markdown,
    run_offline_scan,
)
from llm_guardian.scenario_generation import (
    FakeScenarioLLMProvider,
    generate_attack_scenarios,
    write_generated_scenarios_yaml,
)
from llm_guardian.security_agent import (
    LLMAssistedPromptMutator,
    SecurityAgent,
    SecurityAgentJsonReportBuilder,
    SecurityAgentMarkdownReportBuilder,
    SecurityTestObjective,
    OllamaLLMClient,
    SecurityScanAgent,
    StaticFakeLLMClient,
    TargetProfile,
)
from llm_guardian.security_agent.adapters import LocalTargetAdapter
from llm_guardian.security_agent.target_profiles import TargetProfileLoadError, load_target_profile
from llm_guardian.security_agent.target_profiles import resolve_max_mutations_per_attack
from llm_guardian.targets.registry import create_target, list_targets


_AGENT_SCAN_TARGET_SETTINGS = {
    "customer_support": {
        "target_type": "generic_chatbot",
        "capabilities": ["customer_support"],
        "risk_surfaces": ["chat"],
        "allowed_categories": ["prompt_injection", "jailbreak"],
    },
    "memory_agent": {
        "target_type": "memory_agent",
        "capabilities": ["memory"],
        "risk_surfaces": ["memory"],
        "allowed_categories": ["memory_poisoning", "prompt_injection", "jailbreak"],
    },
    "rag_agent": {
        "target_type": "rag_app",
        "capabilities": ["retrieval"],
        "risk_surfaces": ["rag"],
        "allowed_categories": ["rag_injection", "prompt_injection", "jailbreak"],
    },
    "tool_agent": {
        "target_type": "tool_using_agent",
        "capabilities": ["tools", "email", "export", "tickets"],
        "risk_surfaces": ["tools"],
        "allowed_categories": ["tool_abuse", "prompt_injection", "jailbreak"],
    },
    "mutation_challenge_tool_agent": {
        "target_type": "tool_using_agent",
        "capabilities": ["tools", "email", "export", "tickets"],
        "risk_surfaces": ["tools", "mutation_retry"],
        "allowed_categories": ["tool_abuse", "prompt_injection", "jailbreak"],
    },
}
_DEMO_AGENT_SCAN_TARGET = "demo-vulnerable-rag"
_DEFAULT_AGENT_SCAN_OUTPUT_DIR = Path("reports") / "latest_scan"


def _load_default_library():
    return load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def _normalize_agent_scan_categories(
    *,
    category_flags: Iterable[str],
    categories_flags: Iterable[str],
) -> list[str]:
    raw_values: list[str] = []
    for value in category_flags:
        if value and value.strip():
            raw_values.append(value.strip())
    for value in categories_flags:
        if not value or not value.strip():
            continue
        raw_values.extend(item.strip() for item in value.split(",") if item.strip())

    normalized: list[str] = []
    valid_categories = {category.value for category in AttackCategory}
    for value in raw_values:
        if value not in valid_categories:
            supported = ", ".join(sorted(valid_categories))
            raise ValueError(f"Unknown category '{value}'. Supported categories: {supported}")
        if value not in normalized:
            normalized.append(value)
    return normalized


def _build_agent_scan_target_profile(target_name: str) -> TargetProfile:
    target = create_target(target_name)
    try:
        settings = _AGENT_SCAN_TARGET_SETTINGS[target_name]
    except KeyError as exc:
        supported_targets = ", ".join(sorted(_AGENT_SCAN_TARGET_SETTINGS))
        raise ValueError(
            f"Unknown target '{target_name}'. Supported targets: {supported_targets}"
        ) from exc

    return TargetProfile(
        target_type=settings["target_type"],
        capabilities=list(settings["capabilities"]),
        risk_surfaces=list(settings["risk_surfaces"]),
        allowed_categories=list(settings["allowed_categories"]),
        authorization_scope="local_demo_only",
        metadata={
            "target_name": target.name,
            "target_description": target.description,
            "execution_mode": "local_demo_only",
        },
    )


def _build_agent_scan_objective(
    *,
    allowed_categories: list[str],
    max_attempts_per_attack: int,
    max_total_attempts: int,
) -> SecurityTestObjective:
    return SecurityTestObjective(
        goal="Run a deterministic local security-agent scan.",
        allowed_categories=list(allowed_categories),
        max_attempts_per_attack=max_attempts_per_attack,
        max_total_attempts=max_total_attempts,
        safety_mode="strict",
        stop_on_success=False,
    )


def agent_scan(
    *,
    target: str,
    category_flags: list[str],
    categories_flags: list[str],
    max_total_attempts: int,
    max_attempts_per_attack: int,
    max_mutations_per_attack: int | None,
    mutation_strategy_mode: str,
    llm_provider: str,
    llm_model: str | None,
    llm_timeout_seconds: int,
    scenario_file: Path | None,
    output_dir: Path | None,
    output_format: str,
    output_file: Path | None,
    target_profile_path: Path,
) -> int:
    if target == _DEMO_AGENT_SCAN_TARGET:
        try:
            report_path, trajectory_path, summary = _run_demo_agent_scan(
                target=target,
                output_dir=output_dir or _DEFAULT_AGENT_SCAN_OUTPUT_DIR,
                scenario_file=scenario_file,
            )
        except (AttackLibraryLoadError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 1

        print("LLM Guardian Scan Complete")
        print(f"Target: {summary['target']}")
        print(f"Scenarios tested: {summary['scenarios_tested']}")
        print(f"Adaptive probes: {summary['adaptive_probes']}")
        print(f"Passed: {summary['passed']}")
        print(f"Failed: {summary['failed']}")
        print(f"Critical: {summary['critical']}")
        print(f"Overall Risk: {summary['overall_risk']}")
        print(f"Report path: {report_path}")
        print(f"Trajectory path: {trajectory_path}")
        return 0

    try:
        selected_categories = _normalize_agent_scan_categories(
            category_flags=category_flags,
            categories_flags=categories_flags,
        )
        target_agent = create_target(target)
        target_profile = load_target_profile(target_profile_path, target)
        effective_max_mutations_per_attack = resolve_max_mutations_per_attack(
            override_value=max_mutations_per_attack,
            target_profile=target_profile,
        )
    except TargetProfileLoadError as exc:
        print(
            f"Invalid target profile for target '{target}' in {target_profile_path}: {exc}",
            file=sys.stderr,
        )
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    objective = _build_agent_scan_objective(
        allowed_categories=selected_categories,
        max_attempts_per_attack=max_attempts_per_attack,
        max_total_attempts=max_total_attempts,
    )
    try:
        mutator = _build_agent_scan_mutator(
            mutation_strategy_mode=mutation_strategy_mode,
            llm_provider=llm_provider,
            llm_model=llm_model,
            llm_timeout_seconds=llm_timeout_seconds,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    library = _load_default_library()
    result = SecurityAgent(
        max_mutations_per_attack=effective_max_mutations_per_attack,
        mutation_strategy_mode=mutation_strategy_mode,
        mutator=mutator,
    ).run(
        target_profile=target_profile,
        objective=objective,
        attacks=library.attacks,
        target_adapter=LocalTargetAdapter(target_agent),
    )

    if output_format == "json":
        payload = SecurityAgentJsonReportBuilder().build(result=result, attack_library=library.attacks)
        rendered_output = json.dumps(payload, indent=2)
    else:
        rendered_output = SecurityAgentMarkdownReportBuilder().build(
            result=result,
            attack_library=library.attacks,
        )

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(rendered_output + "\n", encoding="utf-8")
        return 0

    sys.stdout.write(rendered_output + "\n")
    return 0


def _run_demo_agent_scan(
    *,
    target: str,
    output_dir: Path,
    scenario_file: Path | None = None,
) -> tuple[Path, Path, dict[str, int | str]]:
    scan_result = SecurityScanAgent().run(
        target_name=target,
        output_dir=output_dir,
        scenario_file=scenario_file,
        scenario_provider="fake" if scenario_file is not None else None,
    )
    resolved_output_dir = Path(output_dir)
    trajectory_path = resolved_output_dir / "trajectory.json"
    report_path = resolved_output_dir / "scan_report.md"
    summary = _build_demo_scan_summary(scan_result)
    return report_path, trajectory_path, summary


def _build_demo_scan_summary(scan_result: SecurityScanResult) -> dict[str, int | str]:
    findings = scan_result.findings
    passed = sum(1 for finding in findings if finding.verdict == "pass")
    failed = len(findings) - passed
    critical = sum(
        1
        for finding in findings
        if finding.verdict == "fail" and finding.severity == Severity.CRITICAL
    )
    overall_risk = _calculate_demo_overall_risk(findings)
    return {
        "target": scan_result.target_name,
        "scenarios_tested": len(findings),
        "adaptive_probes": len(scan_result.adaptive_probes),
        "passed": passed,
        "failed": failed,
        "critical": critical,
        "overall_risk": overall_risk,
    }


def _calculate_demo_overall_risk(findings) -> str:
    failed_severities = {
        finding.severity
        for finding in findings
        if finding.verdict == "fail"
    }
    if Severity.CRITICAL in failed_severities:
        return "CRITICAL"
    if Severity.HIGH in failed_severities:
        return "HIGH"
    if Severity.MEDIUM in failed_severities:
        return "MEDIUM"
    return "LOW"


def _build_agent_scan_mutator(
    *,
    mutation_strategy_mode: str,
    llm_provider: str,
    llm_model: str | None,
    llm_timeout_seconds: int,
):
    if mutation_strategy_mode == "deterministic":
        return None

    llm_client = _build_llm_client(
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_timeout_seconds=llm_timeout_seconds,
    )
    return LLMAssistedPromptMutator(llm_client=llm_client)


def _build_llm_client(*, llm_provider: str, llm_model: str | None, llm_timeout_seconds: int):
    if llm_provider == "fake":
        return StaticFakeLLMClient()

    if llm_provider == "ollama":
        if llm_model is None or not llm_model.strip():
            raise ValueError("Ollama LLM provider requires --llm-model.")
        return OllamaLLMClient(model=llm_model, timeout_seconds=llm_timeout_seconds)

    raise ValueError(f"Unsupported LLM provider '{llm_provider}'.")


def generate_scenarios(
    *,
    target: str,
    count: int,
    output: Path,
    provider: str,
) -> int:
    if provider != "fake":
        print(f"Unsupported scenario provider '{provider}'.", file=sys.stderr)
        return 1

    result = generate_attack_scenarios(
        target_name=target,
        target_profile_summary=(
            "Local intentionally vulnerable demo target with deterministic grading and offline execution."
        ),
        provider=FakeScenarioLLMProvider(),
        count=count,
    )
    write_generated_scenarios_yaml(result.accepted_scenarios, output)

    print("Scenario generation complete")
    print(f"Target: {target}")
    print(f"Provider: {provider}")
    print(f"Requested: {count}")
    print(f"Accepted: {len(result.accepted_scenarios)}")
    print(f"Rejected: {len(result.rejected_scenarios)}")
    print(f"Output path: {output}")
    if result.validation_errors:
        print("Validation errors:")
        for error in result.validation_errors:
            print(f"- {error}")
    return 0


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

    agent_scan_parser = subparsers.add_parser(
        "agent-scan",
        help="Run the SecurityAgent orchestrator against an approved local demo target.",
    )
    agent_scan_parser.add_argument("--target", required=True)
    agent_scan_parser.add_argument("--category", dest="category_flags", action="append", default=[])
    agent_scan_parser.add_argument("--categories", dest="categories_flags", action="append", default=[])
    agent_scan_parser.add_argument("--max-total-attempts", type=_positive_int, default=5)
    agent_scan_parser.add_argument("--max-attempts-per-attack", type=_positive_int, default=1)
    agent_scan_parser.add_argument("--max-mutations-per-attack", type=int, default=None)
    agent_scan_parser.add_argument(
        "--mutation-strategy-mode",
        choices=("deterministic", "llm-assisted"),
        default="deterministic",
    )
    agent_scan_parser.add_argument("--llm-provider", choices=("fake", "ollama"), default="fake")
    agent_scan_parser.add_argument("--llm-model", default=None)
    agent_scan_parser.add_argument("--llm-timeout-seconds", type=_positive_int, default=30)
    agent_scan_parser.add_argument("--scenario-file", type=Path, default=None)
    agent_scan_parser.add_argument("--output-dir", type=Path)
    agent_scan_parser.add_argument("--output-format", choices=("json", "markdown"), default="json")
    agent_scan_parser.add_argument("--output-file", type=Path)
    agent_scan_parser.add_argument("--target-profile", type=Path, default=DEFAULT_TARGET_PROFILES_PATH)

    generate_scenarios_parser = subparsers.add_parser(
        "generate-scenarios",
        help="Generate optional attack scenarios with a provider behind a stable interface.",
    )
    generate_scenarios_parser.add_argument("--target", required=True)
    generate_scenarios_parser.add_argument("--count", type=_positive_int, default=2)
    generate_scenarios_parser.add_argument("--output", type=Path, required=True)
    generate_scenarios_parser.add_argument("--provider", choices=("fake",), default="fake")

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
        if args.command == "agent-scan":
            return agent_scan(
                target=args.target,
                category_flags=args.category_flags,
                categories_flags=args.categories_flags,
                max_total_attempts=args.max_total_attempts,
                max_attempts_per_attack=args.max_attempts_per_attack,
                max_mutations_per_attack=args.max_mutations_per_attack,
                mutation_strategy_mode=args.mutation_strategy_mode,
                llm_provider=args.llm_provider,
                llm_model=args.llm_model,
                llm_timeout_seconds=args.llm_timeout_seconds,
                scenario_file=args.scenario_file,
                output_dir=args.output_dir,
                output_format=args.output_format,
                output_file=args.output_file,
                target_profile_path=args.target_profile,
            )
        if args.command == "generate-scenarios":
            return generate_scenarios(
                target=args.target,
                count=args.count,
                output=args.output,
                provider=args.provider,
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
