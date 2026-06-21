"""Deterministic attack planning for the central security agent."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from llm_guardian.security_agent.models import AttackPlan, SecurityTestObjective, TargetProfile


class AttackPlanner:
    """Select attack categories and IDs without using external systems or randomness."""

    _TARGET_TYPE_CATEGORIES: dict[str, list[str]] = {
        "rag_app": ["rag_injection", "prompt_injection", "jailbreak"],
        "tool_using_agent": ["tool_abuse", "prompt_injection", "jailbreak"],
        "memory_agent": ["memory_poisoning", "prompt_injection", "jailbreak"],
        "generic_chatbot": ["prompt_injection", "jailbreak"],
        "local_agent": ["prompt_injection", "jailbreak"],
    }
    _CATEGORY_SIGNALS: tuple[tuple[frozenset[str], str], ...] = (
        (frozenset({"rag", "retrieval"}), "rag_injection"),
        (frozenset({"tools", "email", "export", "tickets"}), "tool_abuse"),
        (frozenset({"memory"}), "memory_poisoning"),
    )

    def plan(
        self,
        *,
        target_profile: TargetProfile,
        objective: SecurityTestObjective,
        attack_library: Iterable[object],
    ) -> AttackPlan:
        """Build a deterministic attack plan from target metadata and attack entries."""

        normalized_attacks = [self._normalize_attack_metadata(entry) for entry in attack_library]
        available_categories = self._ordered_unique(
            attack["category"] for attack in normalized_attacks if attack["category"]
        )

        selected_categories: list[str] = []
        strategy_notes: list[str] = []

        target_categories = self._TARGET_TYPE_CATEGORIES.get(target_profile.target_type, [])
        if target_categories:
            selected_categories = self._merge_categories(selected_categories, target_categories)
            strategy_notes.append(
                "Selected base categories from target type "
                f"'{target_profile.target_type}': {', '.join(target_categories)}."
            )

        signal_categories = self._derive_signal_categories(target_profile=target_profile)
        if signal_categories:
            selected_categories = self._merge_categories(selected_categories, signal_categories)
            strategy_notes.append(
                "Expanded categories from target capabilities and risk surfaces: "
                f"{', '.join(signal_categories)}."
            )

        if target_profile.allowed_categories:
            selected_categories = [
                category
                for category in selected_categories
                if category in target_profile.allowed_categories
            ]
            strategy_notes.append(
                "Applied target profile category allow-list: "
                f"{', '.join(target_profile.allowed_categories)}."
            )

        if objective.allowed_categories:
            selected_categories = [
                category
                for category in selected_categories
                if category in objective.allowed_categories
            ]
            strategy_notes.append(
                "Applied objective category filter: "
                f"{', '.join(objective.allowed_categories)}."
            )

        selected_categories = [
            category for category in selected_categories if category in available_categories
        ]
        strategy_notes.append(
            "Dropped categories that are not present in the supplied attack metadata."
        )

        selected_attack_ids = [
            attack["attack_id"]
            for attack in normalized_attacks
            if attack["category"] in selected_categories
        ][: objective.max_total_attempts]

        strategy_notes.append(
            "Selected attack IDs in library order and capped them by "
            f"max_total_attempts={objective.max_total_attempts}."
        )

        budget = {
            "max_total_attempts": objective.max_total_attempts,
            "max_attempts_per_attack": objective.max_attempts_per_attack,
            "planned_attack_count": len(selected_attack_ids),
            "remaining_attempt_capacity": max(objective.max_total_attempts - len(selected_attack_ids), 0),
        }

        return AttackPlan(
            target_profile=target_profile,
            objective=objective,
            selected_categories=selected_categories,
            selected_attack_ids=selected_attack_ids,
            strategy_notes=strategy_notes,
            budget=budget,
        )

    def _derive_signal_categories(self, *, target_profile: TargetProfile) -> list[str]:
        signals = {
            item.strip().lower()
            for item in [*target_profile.capabilities, *target_profile.risk_surfaces]
            if item and item.strip()
        }
        matched_categories: list[str] = []
        for keywords, category in self._CATEGORY_SIGNALS:
            if signals.intersection(keywords):
                matched_categories.append(category)
        return matched_categories

    @staticmethod
    def _normalize_attack_metadata(entry: object) -> dict[str, str]:
        attack_id = AttackPlanner._read_attack_value(entry, "id") or AttackPlanner._read_attack_value(
            entry, "attack_id"
        )
        category = AttackPlanner._read_attack_value(entry, "category")

        if attack_id is None or not attack_id.strip():
            raise ValueError("Attack metadata entry must define a non-empty 'id' or 'attack_id'.")
        if category is None or not category.strip():
            raise ValueError("Attack metadata entry must define a non-empty 'category'.")

        return {"attack_id": attack_id.strip(), "category": category.strip()}

    @staticmethod
    def _read_attack_value(entry: object, key: str) -> str | None:
        if isinstance(entry, dict):
            value = entry.get(key)
        else:
            value = getattr(entry, key, None)

        if value is None:
            return None
        if hasattr(value, "value"):
            value = value.value
        if not isinstance(value, str):
            value = str(value)
        return value

    @staticmethod
    def _merge_categories(base: list[str], additions: Iterable[str]) -> list[str]:
        merged = list(base)
        for category in additions:
            if category not in merged:
                merged.append(category)
        return merged

    @staticmethod
    def _ordered_unique(values: Iterable[str]) -> list[str]:
        unique_values: list[str] = []
        for value in values:
            if value not in unique_values:
                unique_values.append(value)
        return unique_values
