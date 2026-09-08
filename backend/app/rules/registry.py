from typing import Any

from app.rules.base import BaseRule, RuleMatch
from app.rules.behavioral import default_behavioral_rules
from app.rules.signature import SignatureRuleLoader
from app.rules.statistical import default_statistical_rules


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, BaseRule] = {}

    def register(self, rule: BaseRule) -> None:
        self._rules[rule.rule_id] = rule

    def register_all(self, rules: list[BaseRule]) -> None:
        for rule in rules:
            self.register(rule)

    def load_defaults(self) -> None:
        self.register_all(default_statistical_rules())
        self.register_all(default_behavioral_rules())

    def load_signature_file(self, path: str) -> int:
        loaded = SignatureRuleLoader.from_file(path)
        self.register_all(loaded)
        return len(loaded)

    def unregister(self, rule_id: str) -> None:
        self._rules.pop(rule_id, None)

    def get(self, rule_id: str) -> BaseRule | None:
        return self._rules.get(rule_id)

    def all(self) -> list[BaseRule]:
        return list(self._rules.values())

    def by_category(self, category: str) -> list[BaseRule]:
        return [r for r in self._rules.values() if r.category == category]

    def count(self) -> int:
        return len(self._rules)

    def stats(self) -> list[dict]:
        return sorted((r.stats() for r in self._rules.values()), key=lambda s: s["category"])


class RuleEngine:
    def __init__(self, registry: RuleRegistry | None = None) -> None:
        self.registry = registry or RuleRegistry()

    def evaluate(self, features: dict) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        for rule in self.registry.all():
            try:
                match = rule.evaluate(features)
            except Exception:
                continue
            if match is not None:
                matches.append(match)
        return matches

    def result_assessment(self, features: dict) -> dict[str, Any]:
        matches = self.evaluate(features)
        source_scores: dict[str, float] = {}
        for match in matches:
            current = source_scores.get(match.category, 0.0)
            source_scores[match.category] = max(current, match.score)

        total = sum(source_scores.values())
        return {
            "matches": matches,
            "source_scores": source_scores,
            "aggregate_score": min(1.0, total),
            "matched_rule_count": len(matches),
        }