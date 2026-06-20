import pytest

from llm_guardian.attacks.loader import load_attack_library
from llm_guardian.attacks.registry import filter_attacks_by_category
from llm_guardian.config import DEFAULT_ATTACK_LIBRARY_PATH
from llm_guardian.models import AttackCategory


def test_filter_attacks_by_single_category() -> None:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)

    attacks = filter_attacks_by_category(library, AttackCategory.PROMPT_INJECTION)

    assert [attack.id for attack in attacks] == ["PI-001"]


def test_filter_attacks_by_category_string() -> None:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)

    attacks = filter_attacks_by_category(library, "tool_abuse")

    assert [attack.id for attack in attacks] == ["TA-001"]


def test_filter_attacks_by_multiple_categories() -> None:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)

    attacks = filter_attacks_by_category(library, ["prompt_injection", "memory_poisoning"])

    assert [attack.id for attack in attacks] == ["PI-001", "MP-001"]


def test_filter_attacks_rejects_unknown_category() -> None:
    library = load_attack_library(DEFAULT_ATTACK_LIBRARY_PATH)

    with pytest.raises(ValueError):
        filter_attacks_by_category(library, "unknown")
