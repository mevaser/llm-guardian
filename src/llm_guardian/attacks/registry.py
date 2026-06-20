"""Attack library query helpers."""

from collections.abc import Iterable

from llm_guardian.models import AttackCase, AttackCategory, AttackLibrary


def filter_attacks_by_category(
    library: AttackLibrary,
    categories: AttackCategory | str | Iterable[AttackCategory | str],
) -> list[AttackCase]:
    """Return attacks whose category matches any requested category."""

    if isinstance(categories, AttackCategory | str):
        requested = {AttackCategory(categories)}
    else:
        requested = {AttackCategory(category) for category in categories}

    return [attack for attack in library.attacks if attack.category in requested]
