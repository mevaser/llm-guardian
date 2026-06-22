"""YAML TargetProfile loader for security-agent execution contracts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from llm_guardian.security_agent.models import TargetProfile


class TargetProfileLoadError(ValueError):
    """Raised when target profile YAML cannot be read, parsed, or validated."""


_REQUIRED_FIELDS = (
    "id",
    "target_name",
    "target_type",
    "authorization_scope",
    "safety_mode",
    "capabilities",
    "available_tools",
    "allowed_categories",
    "forbidden_actions",
    "risk_surfaces",
    "assets_at_risk",
    "trust_boundaries",
    "assumptions",
    "safety_constraints",
)


def load_target_profiles(path: Path) -> dict[str, TargetProfile]:
    """Load all YAML target profiles keyed by profile id."""

    resolved_path = Path(path)
    try:
        raw_text = resolved_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TargetProfileLoadError(f"Could not read target profiles: {resolved_path}") from exc

    try:
        payload: Any = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise TargetProfileLoadError(f"Malformed YAML in target profiles: {resolved_path}") from exc

    if payload is None:
        raise TargetProfileLoadError(f"Target profiles file is empty: {resolved_path}")
    if not isinstance(payload, dict):
        raise TargetProfileLoadError("Target profiles YAML must be a mapping with a 'targets' key.")

    raw_targets = payload.get("targets")
    if not isinstance(raw_targets, list):
        raise TargetProfileLoadError("Target profiles YAML must define 'targets' as a list.")

    profiles: dict[str, TargetProfile] = {}
    for index, raw_target in enumerate(raw_targets):
        if not isinstance(raw_target, dict):
            raise TargetProfileLoadError(f"Target profile at targets[{index}] must be a mapping.")

        profile_id = _required_text(raw_target, "id", index)
        if profile_id in profiles:
            raise TargetProfileLoadError(f"Duplicate target profile id '{profile_id}'.")

        missing_fields = [field for field in _REQUIRED_FIELDS if field not in raw_target]
        if missing_fields:
            raise TargetProfileLoadError(
                f"Target profile '{profile_id}' is missing required field(s): "
                f"{', '.join(missing_fields)}."
            )

        model_payload = _build_model_payload(raw_target=raw_target, profile_id=profile_id, index=index)
        try:
            profiles[profile_id] = TargetProfile.model_validate(model_payload)
        except ValidationError as exc:
            raise TargetProfileLoadError(
                f"Invalid target profile '{profile_id}' schema: {exc}"
            ) from exc

    return profiles


def load_target_profile(path: Path, target_name: str) -> TargetProfile:
    """Load one target profile by id or target_name."""

    if not target_name or not target_name.strip():
        raise TargetProfileLoadError("Target profile name must be a non-empty string.")

    requested_name = target_name.strip()
    profiles = load_target_profiles(path)
    if requested_name in profiles:
        return profiles[requested_name]

    for profile in profiles.values():
        if profile.target_name == requested_name:
            return profile

    supported_targets = ", ".join(sorted(profiles))
    raise TargetProfileLoadError(
        f"Unknown target profile '{requested_name}'. Supported targets: {supported_targets}"
    )


def resolve_max_mutations_per_attack(
    *,
    override_value: int | None,
    target_profile: TargetProfile,
) -> int:
    """Resolve mutation budget precedence for local security-agent execution."""

    if override_value is not None:
        return max(override_value, 0)

    profile_value = target_profile.mutation_policy.get("max_mutations_per_attack", 0)
    if isinstance(profile_value, bool) or not isinstance(profile_value, int):
        raise ValueError("Target profile mutation_policy.max_mutations_per_attack must be an integer.")
    return max(profile_value, 0)


def _build_model_payload(
    *,
    raw_target: dict[str, Any],
    profile_id: str,
    index: int,
) -> dict[str, Any]:
    raw_metadata = raw_target.get("metadata") or {}
    if not isinstance(raw_metadata, dict):
        raise TargetProfileLoadError(
            f"Target profile '{profile_id}' field 'metadata' must be a mapping when provided."
        )
    metadata = dict(raw_metadata)

    display_name = raw_target.get("display_name") or raw_target.get("name")
    description = raw_target.get("description")
    metadata.update(
        {
            "target_id": profile_id,
            "target_name": _required_text(raw_target, "target_name", index),
        }
    )
    if isinstance(display_name, str) and display_name.strip():
        metadata["display_name"] = display_name.strip()
    if isinstance(description, str) and description.strip():
        metadata["target_description"] = description.strip()
    if "simulated_only" in raw_target:
        metadata["simulated_only"] = bool(raw_target["simulated_only"])

    return {
        "target_name": _required_text(raw_target, "target_name", index),
        "target_type": _required_text(raw_target, "target_type", index),
        "capabilities": _required_text_list(raw_target, "capabilities", profile_id),
        "available_tools": _required_text_list(raw_target, "available_tools", profile_id),
        "risk_surfaces": _required_text_list(raw_target, "risk_surfaces", profile_id),
        "allowed_categories": _required_text_list(raw_target, "allowed_categories", profile_id),
        "forbidden_actions": _required_text_list(raw_target, "forbidden_actions", profile_id),
        "assets_at_risk": _required_text_list(raw_target, "assets_at_risk", profile_id),
        "trust_boundaries": _required_text_list(raw_target, "trust_boundaries", profile_id),
        "assumptions": _required_text_list(raw_target, "assumptions", profile_id),
        "safety_constraints": _required_text_list(raw_target, "safety_constraints", profile_id),
        "authorization_scope": _required_text(raw_target, "authorization_scope", index),
        "safety_mode": _required_text(raw_target, "safety_mode", index),
        "retry_policy": _optional_mapping(raw_target, "retry_policy", profile_id),
        "mutation_policy": _optional_mapping(raw_target, "mutation_policy", profile_id),
        "metadata": metadata,
    }


def _required_text(raw_target: dict[str, Any], field_name: str, index: int) -> str:
    value = raw_target.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise TargetProfileLoadError(
            f"Target profile at targets[{index}] field '{field_name}' must be a non-empty string."
        )
    return value.strip()


def _required_text_list(
    raw_target: dict[str, Any],
    field_name: str,
    profile_id: str,
) -> list[str]:
    value = raw_target.get(field_name)
    if not isinstance(value, list):
        raise TargetProfileLoadError(
            f"Target profile '{profile_id}' field '{field_name}' must be a list of strings."
        )

    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise TargetProfileLoadError(
                f"Target profile '{profile_id}' field '{field_name}' must contain only non-empty strings."
            )
        normalized_item = item.strip()
        if normalized_item not in normalized:
            normalized.append(normalized_item)
    return normalized


def _optional_mapping(
    raw_target: dict[str, Any],
    field_name: str,
    profile_id: str,
) -> dict[str, Any]:
    value = raw_target.get(field_name, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise TargetProfileLoadError(
            f"Target profile '{profile_id}' field '{field_name}' must be a mapping when provided."
        )
    return dict(value)
