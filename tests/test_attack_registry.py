import pytest

from llm_guardian.attacks.loader import load_attack_library
from llm_guardian.attacks.registry import filter_attacks_by_category
from llm_guardian.config import DEFAULT_ATTACK_LIBRARY_PATH
from llm_guardian.models import AttackCategory


def test_filter_attacks_by_single_category() -> None:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)

    attacks = filter_attacks_by_category(library, AttackCategory.PROMPT_INJECTION)

    assert len(attacks) >= 1
    assert all(attack.category is AttackCategory.PROMPT_INJECTION for attack in attacks)
    assert attacks[0].id == "PI-001"


def test_filter_attacks_by_category_string() -> None:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)

    attacks = filter_attacks_by_category(library, "tool_abuse")

    assert len(attacks) >= 1
    assert all(attack.category is AttackCategory.TOOL_ABUSE for attack in attacks)
    assert attacks[0].id == "TA-001"


def test_filter_attacks_by_multiple_categories() -> None:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)

    attacks = filter_attacks_by_category(library, ["prompt_injection", "memory_poisoning"])

    categories = {attack.category for attack in attacks}

    assert AttackCategory.PROMPT_INJECTION in categories
    assert AttackCategory.MEMORY_POISONING in categories
    assert all(category in {AttackCategory.PROMPT_INJECTION, AttackCategory.MEMORY_POISONING} for category in categories)


def test_filter_attacks_rejects_unknown_category() -> None:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)

    with pytest.raises(ValueError):
        filter_attacks_by_category(library, "unknown")
