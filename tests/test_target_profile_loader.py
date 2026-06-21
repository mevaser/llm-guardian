from pathlib import Path

import pytest

from llm_guardian.security_agent.target_profiles import (
    TargetProfileLoadError,
    load_target_profile,
    load_target_profiles,
)


def test_load_target_profile_from_valid_yaml(tmp_path: Path) -> None:
    profile_path = tmp_path / "profiles.yaml"
    profile_path.write_text(
        """
targets:
  - id: demo_tool
    target_name: demo_tool
    display_name: Demo Tool Agent
    description: Local tool target.
    target_type: tool_using_agent
    authorization_scope: local_demo_only
    safety_mode: strict
    capabilities:
      - tools
    available_tools:
      - simulated_email_tool
    allowed_categories:
      - tool_abuse
    forbidden_actions:
      - external_system_access
    risk_surfaces:
      - tools
    assets_at_risk:
      - customer records
    trust_boundaries:
      - model decision to simulated tool execution
    assumptions:
      - Target is local.
    safety_constraints:
      - No external API calls.
    metadata:
      course: ai_security
""",
        encoding="utf-8",
    )

    profile = load_target_profile(profile_path, "demo_tool")

    assert profile.target_name == "demo_tool"
    assert profile.target_type == "tool_using_agent"
    assert profile.available_tools == ["simulated_email_tool"]
    assert profile.forbidden_actions == ["external_system_access"]
    assert profile.assets_at_risk == ["customer records"]
    assert profile.metadata["target_description"] == "Local tool target."
    assert profile.metadata["course"] == "ai_security"


def test_load_target_profiles_rejects_missing_required_field(tmp_path: Path) -> None:
    profile_path = tmp_path / "profiles.yaml"
    profile_path.write_text(
        """
targets:
  - id: demo_tool
    target_name: demo_tool
    authorization_scope: local_demo_only
    safety_mode: strict
    capabilities: []
    available_tools: []
    allowed_categories: []
    forbidden_actions: []
    risk_surfaces: []
    assets_at_risk: []
    trust_boundaries: []
    assumptions: []
    safety_constraints: []
""",
        encoding="utf-8",
    )

    with pytest.raises(TargetProfileLoadError, match="target_type"):
        load_target_profiles(profile_path)


def test_load_target_profile_rejects_unknown_target(tmp_path: Path) -> None:
    profile_path = tmp_path / "profiles.yaml"
    profile_path.write_text(
        """
targets: []
""",
        encoding="utf-8",
    )

    with pytest.raises(TargetProfileLoadError, match="Unknown target profile 'missing'"):
        load_target_profile(profile_path, "missing")


def test_load_target_profiles_rejects_malformed_metadata_with_loader_error(tmp_path: Path) -> None:
    profile_path = tmp_path / "profiles.yaml"
    profile_path.write_text(
        """
targets:
  - id: demo_tool
    target_name: demo_tool
    target_type: tool_using_agent
    authorization_scope: local_demo_only
    safety_mode: strict
    capabilities: []
    available_tools: []
    allowed_categories: []
    forbidden_actions: []
    risk_surfaces: []
    assets_at_risk: []
    trust_boundaries: []
    assumptions: []
    safety_constraints: []
    metadata: not-a-mapping
""",
        encoding="utf-8",
    )

    with pytest.raises(TargetProfileLoadError, match="metadata"):
        load_target_profiles(profile_path)
