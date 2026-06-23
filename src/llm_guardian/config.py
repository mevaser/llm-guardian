"""Configuration helpers for local repository paths."""

from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
SRC_ROOT = PACKAGE_ROOT.parent
REPOSITORY_ROOT = SRC_ROOT.parent
DEFAULT_ATTACK_LIBRARY_PATH = REPOSITORY_ROOT / "data" / "attack_library.yaml"
DEFAULT_ATTACK_SCENARIOS_PATH = REPOSITORY_ROOT / "data" / "attack_scenarios.yaml"
DEFAULT_TARGET_PROFILES_PATH = REPOSITORY_ROOT / "data" / "target_profiles.yaml"
