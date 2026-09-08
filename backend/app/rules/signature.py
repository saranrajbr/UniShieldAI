import json
from pathlib import Path
from typing import Any

from app.core.constants import ThreatType
from app.rules.base import BaseRule, RuleMatch


class SignatureRule(BaseRule):
    category = "signature"

    def __init__(self, rule_id: str, rule_name: str, signature: dict[str, Any],
                 weight: float = 1.0, threat_type: ThreatType = ThreatType.SUSPICIOUS_TRAFFIC,
                 severity: int = 2) -> None:
        super().__init__(weight=weight)
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.signature = signature
        self._threat_type = threat_type
        self._severity = severity

    def evaluate(self, features: dict) -> RuleMatch | None:
        score = self._match_signature(features)
        if score > 0:
            return self._match(score, self._threat_type, self._severity,
                               signature=self.rule_id, matched_field=self._matched_field)
        return None

    def _match_signature(self, features: dict) -> float:
        match_score = 0.0
        self._matched_field = None
        for field, pattern in self.signature.items():
            if field not in features:
                continue
            actual = features.get(field)
            if isinstance(pattern, (int, float)):
                if actual == pattern:
                    match_score += 0.6
                    self._matched_field = field
            elif isinstance(pattern, (list, tuple, set)):
                if actual in pattern:
                    match_score += 0.8
                    self._matched_field = field
            elif isinstance(pattern, dict):
                op = pattern.get("op", "eq")
                value = pattern.get("value")
                if self._compare(actual, op, value):
                    match_score += pattern.get("score", 0.6)
                    self._matched_field = field
        return min(1.0, match_score)

    @staticmethod
    def _compare(actual, op: str, value) -> bool:
        try:
            if op == "eq":
                return actual == value
            if op == "gt":
                return actual > value
            if op == "gte":
                return actual >= value
            if op == "lt":
                return actual < value
            if op == "lte":
                return actual <= value
            if op == "neq":
                return actual != value
        except TypeError:
            return False
        return False


class SignatureRuleLoader:
    @staticmethod
    def from_dict(rule_def: dict) -> SignatureRule:
        return SignatureRule(
            rule_id=rule_def["rule_id"],
            rule_name=rule_def["rule_name"],
            signature=rule_def.get("signature", {}),
            weight=rule_def.get("weight", 1.0),
            threat_type=ThreatType(rule_def.get("threat_type", "suspicious_traffic")),
            severity=rule_def.get("severity", 2),
        )

    @staticmethod
    def from_file(path: str | Path) -> list[SignatureRule]:
        path = Path(path)
        rules: list[SignatureRule] = []
        if path.is_dir():
            for file in sorted(path.glob("*.json")):
                rules.extend(SignatureRuleLoader._load_file(file))
        elif path.exists():
            rules.extend(SignatureRuleLoader._load_file(path))
        return rules

    @staticmethod
    def _load_file(path: Path) -> list[SignatureRule]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        definitions = data if isinstance(data, list) else [data]
        return [SignatureRuleLoader.from_dict(d) for d in definitions]