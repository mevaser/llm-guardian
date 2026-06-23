"""YAML attack library loader."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from llm_guardian.models import AttackLibrary, AttackScenario, AttackScenarioLibrary


class AttackLibraryLoadError(ValueError):
    """Raised when the attack library cannot be read, parsed, or validated."""


def load_attack_library(path: Path) -> AttackLibrary:
    """Load and validate an attack library YAML file."""

    resolved_path = Path(path)
    try:
        raw_text = resolved_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AttackLibraryLoadError(f"Could not read attack library: {resolved_path}") from exc

    try:
        payload: Any = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise AttackLibraryLoadError(f"Malformed YAML in attack library: {resolved_path}") from exc

    if payload is None:
        raise AttackLibraryLoadError(f"Attack library is empty: {resolved_path}")
    if not isinstance(payload, dict):
        raise AttackLibraryLoadError("Attack library must be a YAML mapping with an 'attacks' key.")

    try:
        return AttackLibrary.model_validate(payload)
    except ValidationError as exc:
        raise AttackLibraryLoadError(f"Invalid attack library schema: {exc}") from exc


def load_attack_scenarios(path: Path) -> list[AttackScenario]:
    """Load and validate an attack scenario YAML file."""

    payload = _read_attack_scenarios_payload(path)

    if "scenarios" not in payload:
        raise AttackLibraryLoadError("Attack scenarios must define a top-level 'scenarios' key.")

    try:
        library = AttackScenarioLibrary.model_validate({"scenarios": payload["scenarios"]})
    except ValidationError as exc:
        error_text = str(exc)
        if "Duplicate attack scenario id(s):" in error_text:
            duplicate_message = error_text.split("Value error, ", maxsplit=1)[-1].split("\n", maxsplit=1)[0]
            raise AttackLibraryLoadError(duplicate_message) from exc
        raise AttackLibraryLoadError(f"Invalid attack scenario schema: {exc}") from exc

    return library.scenarios


def load_attack_scenario_metadata(path: Path) -> dict[str, Any]:
    """Load optional top-level metadata from an attack scenario YAML file."""

    payload = _read_attack_scenarios_payload(path)
    metadata = payload.get("metadata")
    if metadata is None:
        return {}
    if not isinstance(metadata, dict):
        raise AttackLibraryLoadError("Attack scenarios metadata must be a YAML mapping.")
    return dict(metadata)


def _read_attack_scenarios_payload(path: Path) -> dict[str, Any]:
    """Read and parse an attack scenario YAML mapping."""

    resolved_path = Path(path)
    try:
        raw_text = resolved_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AttackLibraryLoadError(f"Could not read attack scenarios: {resolved_path}") from exc

    try:
        payload: Any = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise AttackLibraryLoadError(f"Malformed YAML in attack scenarios: {resolved_path}") from exc

    if payload is None:
        raise AttackLibraryLoadError(f"Attack scenarios file is empty: {resolved_path}")
    if not isinstance(payload, dict):
        raise AttackLibraryLoadError("Attack scenarios must be a YAML mapping with a 'scenarios' key.")
    return payload
