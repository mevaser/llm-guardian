"""YAML attack library loader."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from llm_guardian.models import AttackLibrary


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
