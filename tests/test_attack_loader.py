from pathlib import Path

import pytest

from llm_guardian.attacks.loader import AttackLibraryLoadError, load_attack_library
from llm_guardian.config import DEFAULT_ATTACK_LIBRARY_PATH
from llm_guardian.models import AttackCategory, Severity


def test_load_valid_default_attack_library() -> None:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)

    assert len(library.attacks) >= 20
    assert library.attacks[0].id == "PI-001"
    assert library.attacks[0].category is AttackCategory.PROMPT_INJECTION
    assert library.attacks[0].severity is Severity.HIGH


def test_default_attack_library_represents_at_least_four_categories() -> None:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)

    categories = {attack.category for attack in library.attacks}

    assert len(categories) >= 4


def test_default_attack_library_attack_ids_are_unique() -> None:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)

    attack_ids = [attack.id for attack in library.attacks]

    assert len(attack_ids) == len(set(attack_ids))


def test_default_attack_library_attacks_have_success_indicators_and_recommendations() -> None:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)

    assert all(attack.success_indicators for attack in library.attacks)
    assert all(attack.recommendation.strip() for attack in library.attacks)


def test_load_attack_library_rejects_malformed_yaml(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("attacks:\n  - id: [unterminated\n", encoding="utf-8")

    with pytest.raises(AttackLibraryLoadError, match="Malformed YAML"):
        load_attack_library(path)


def test_load_attack_library_rejects_invalid_schema(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(
        """
attacks:
  - id: ""
    category: prompt_injection
    severity: high
    title: Missing prompt
    recommendation: Fix the prompt.
""",
        encoding="utf-8",
    )

    with pytest.raises(AttackLibraryLoadError, match="Invalid attack library schema"):
        load_attack_library(path)


def test_load_attack_library_rejects_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.yaml"
    path.write_text("", encoding="utf-8")

    with pytest.raises(AttackLibraryLoadError, match="empty"):
        load_attack_library(path)
