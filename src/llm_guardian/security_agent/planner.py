"""Deterministic attack planning for the central security agent."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from llm_guardian.security_agent.models import (
    AttackCampaign,
    AttackPlan,
    SecurityTestObjective,
    TargetProfile,
    ThreatModel,
)


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

    def build_threat_model(
        self,
        *,
        target_profile: TargetProfile,
        objective: SecurityTestObjective,
    ) -> ThreatModel:
        """Build deterministic security context before attack campaign planning."""

        threat_categories = self._resolve_threat_categories(target_profile=target_profile, objective=objective)
        target_name = self._resolve_target_name(target_profile)
        available_tools = self._read_metadata_list(target_profile.metadata.get("available_tools"))
        assets_at_risk = self._derive_assets_at_risk(target_profile=target_profile)
        trust_boundaries = self._derive_trust_boundaries(target_profile=target_profile)

        return ThreatModel(
            target_name=target_name,
            target_type=target_profile.target_type,
            authorization_scope=target_profile.authorization_scope,
            capabilities=list(target_profile.capabilities),
            available_tools=available_tools,
            risk_surfaces=list(target_profile.risk_surfaces),
            allowed_test_categories=list(target_profile.allowed_categories),
            forbidden_actions=[
                "external_system_access",
                "credential_extraction",
                "real_side_effects",
                "third_party_target_testing",
            ],
            assets_at_risk=assets_at_risk,
            trust_boundaries=trust_boundaries,
            assumptions=[
                "Target is a local deterministic demo.",
                "Attack execution must not call real third-party systems.",
                "Tool actions are simulated only.",
            ],
            safety_constraints=[
                "No external API calls.",
                "No credential extraction.",
                "No real emails, exports, writes, or network side effects.",
            ],
            threat_categories_in_scope=threat_categories,
            rationale=self._build_threat_rationale(
                target_profile=target_profile,
                threat_categories=threat_categories,
                available_tools=available_tools,
            ),
        )

    def create_campaign(
        self,
        *,
        threat_model: ThreatModel,
        target_profile: TargetProfile,
        objective: SecurityTestObjective,
        attack_library: Iterable[object],
        max_mutations_per_attack: int = 0,
    ) -> AttackCampaign:
        """Create a deterministic campaign while preserving the existing AttackPlan contract."""

        normalized_attacks = [self._normalize_attack_metadata(entry) for entry in attack_library]
        attack_plan = self.plan(
            target_profile=target_profile,
            objective=objective,
            attack_library=normalized_attacks,
        )
        available_categories = self._ordered_unique(
            attack["category"] for attack in normalized_attacks if attack["category"]
        )
        selected_attack_ids = set(attack_plan.selected_attack_ids)
        target_name = self._resolve_target_name(target_profile)
        mutation_budget = max(
            0,
            min(max_mutations_per_attack, max(objective.max_attempts_per_attack - 1, 0)),
        )

        return AttackCampaign(
            campaign_id=self._build_campaign_id(target_name=target_name, objective=objective),
            campaign_name=f"Deterministic campaign for {target_name}",
            target_name=target_name,
            target_type=target_profile.target_type,
            threat_model=threat_model,
            attack_plan=attack_plan,
            selected_attack_ids=list(attack_plan.selected_attack_ids),
            selected_categories=list(attack_plan.selected_categories),
            excluded_categories=[
                category
                for category in available_categories
                if category not in attack_plan.selected_categories
            ],
            excluded_attack_ids=[
                attack["attack_id"]
                for attack in normalized_attacks
                if attack["attack_id"] not in selected_attack_ids
            ],
            planning_rationale=list(attack_plan.strategy_notes),
            attack_ordering_rationale="Selected attacks run in deterministic attack library order.",
            retry_policy={
                "stop_on_success": objective.stop_on_success,
                "max_attempts_per_attack": objective.max_attempts_per_attack,
                "max_mutations_per_attack": mutation_budget,
            },
            mutation_budget=mutation_budget,
            max_attempts_per_attack=objective.max_attempts_per_attack,
            safety_mode=objective.safety_mode,
            total_planned_attacks=len(attack_plan.selected_attack_ids),
            deterministic_metadata={
                "objective_goal": objective.goal,
                "max_total_attempts": objective.max_total_attempts,
                "planned_attack_count": len(attack_plan.selected_attack_ids),
                "available_attack_count": len(normalized_attacks),
            },
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

    def _resolve_threat_categories(
        self,
        *,
        target_profile: TargetProfile,
        objective: SecurityTestObjective,
    ) -> list[str]:
        categories: list[str] = []
        categories = self._merge_categories(
            categories,
            self._TARGET_TYPE_CATEGORIES.get(target_profile.target_type, []),
        )
        categories = self._merge_categories(
            categories,
            self._derive_signal_categories(target_profile=target_profile),
        )
        if target_profile.allowed_categories:
            categories = [
                category
                for category in categories
                if category in target_profile.allowed_categories
            ]
        if objective.allowed_categories:
            categories = [
                category
                for category in categories
                if category in objective.allowed_categories
            ]
        return categories

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
    def _resolve_target_name(target_profile: TargetProfile) -> str:
        for key in ("target_name", "target_id", "name", "id"):
            value = target_profile.metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return target_profile.target_type

    @staticmethod
    def _read_metadata_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str) and value.strip():
            return [value.strip()]
        return []

    @staticmethod
    def _derive_assets_at_risk(*, target_profile: TargetProfile) -> list[str]:
        assets = ["system prompt", "conversation context"]
        signals = {
            item.strip().lower()
            for item in [*target_profile.capabilities, *target_profile.risk_surfaces]
            if item and item.strip()
        }
        if signals.intersection({"rag", "retrieval"}):
            assets.append("retrieved context")
        if signals.intersection({"tools", "email", "export", "tickets"}):
            assets.append("simulated tool outputs")
        if "memory" in signals:
            assets.append("agent memory")
        return AttackPlanner._ordered_unique(assets)

    @staticmethod
    def _derive_trust_boundaries(*, target_profile: TargetProfile) -> list[str]:
        boundaries = ["user prompt to target response"]
        signals = {
            item.strip().lower()
            for item in [*target_profile.capabilities, *target_profile.risk_surfaces]
            if item and item.strip()
        }
        if signals.intersection({"rag", "retrieval"}):
            boundaries.append("retrieval content to model context")
        if signals.intersection({"tools", "email", "export", "tickets"}):
            boundaries.append("model decision to simulated tool execution")
        if "memory" in signals:
            boundaries.append("user prompt to persisted memory")
        return AttackPlanner._ordered_unique(boundaries)

    @staticmethod
    def _build_threat_rationale(
        *,
        target_profile: TargetProfile,
        threat_categories: list[str],
        available_tools: list[str],
    ) -> list[str]:
        rationale = [
            f"Target type '{target_profile.target_type}' maps to deterministic threat categories: "
            f"{', '.join(threat_categories) if threat_categories else 'none'}."
        ]
        if target_profile.capabilities or target_profile.risk_surfaces:
            rationale.append(
                "Capabilities and risk surfaces influence the campaign scope: "
                f"{', '.join([*target_profile.capabilities, *target_profile.risk_surfaces])}."
            )
        if available_tools:
            rationale.append(
                "Available tools are simulated but still relevant for tool-abuse evaluation: "
                f"{', '.join(available_tools)}."
            )
        return rationale

    @staticmethod
    def _build_campaign_id(*, target_name: str, objective: SecurityTestObjective) -> str:
        normalized_target = "".join(
            character.lower() if character.isalnum() else "-"
            for character in target_name.strip()
        ).strip("-")
        if not normalized_target:
            normalized_target = "target"
        return f"campaign-{normalized_target}-{objective.max_total_attempts}"

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
